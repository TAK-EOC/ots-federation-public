# taky/cot/federation/fed_server.py
# Stream: transport (INBOUND server side — federation hardening work, phase 3)
#                         real ATAK device)
#/ §5 (loop prevention + hop stamp — shared helper)
#(federation TLS trust, separate from ATAK [ssl]).
# Current taky is outbound-client-only: FederateClient (client.py) DIALS a peer's
# FederatedChannel gRPC server. To federate taky↔taky, ONE taky must RUN the
# FederatedChannel server so the other can connect inbound. FederationServer is
# that server.
# gRPC direction reminder (names are from the SERVER's perspective):
#   ServerEventStream(stream FederatedEvent) -> Subscription
#       The connecting peer streams events TO us. We RECEIVE. Inbound path.
#   ClientEventStream(Subscription) -> stream FederatedEvent
#       We stream events TO the connecting peer. We SEND. Outbound path.
#   getIdentity(Empty) -> Identity
#       We return OUR identity.
# Inbound path (peer → us) is IDENTICAL to FederateClient's inbound path:
#   decode_federated_event → attach evt.fed_meta sidecar → bridge.enqueue.
# The bridge wakes taky's select loop and router.route runs exactly as if a
# real ATAK device sent the event.
# Outbound path (us → peer) reuses the SAME shared helper the client link uses:
#   codec.prepare_outbound_event (loop-prevention + hop-stamp + encode).
# The FederationManager pushes onto a per-peer queue registered here; the
# ClientEventStream generator drains it.

import logging
import queue
import threading
import time
from concurrent import futures

import grpc

from ots_federation.cert_identity import peer_fingerprint_from_grpc_context
from ots_federation.proto import fig_pb2, fig_pb2_grpc


# CoT event type prefix for DELETE events (shared constant)..
_COT_DELETE_TYPE_PREFIX = "t-x-d-d"

# How long ClientEventStream blocks on its queue before re-checking liveness.
_OUTBOUND_POLL_TIMEOUT = 1.0


class _InboundPeerLink:
    """
    Per-connection outbound link to a single inbound peer.

    Created when a peer opens its ClientEventStream (server→client) and
    registered with the FederationManager so on_outbound can fan events to it.
    Carries an outbound queue of encoded FederatedEvent protos and the peer's
    advertised server_id (used for loop-prevention key + src-skip).

    Mirrors the relevant surface of FederateClient that FederationManager relies
    on (send_event, state, request_stop, remote_server_id) so the manager can
    treat client links and inbound-peer links uniformly.
    """

    def __init__(self, peer_server_id, node_id, default_max_hops, group_registry=None):
        self.peer_server_id = peer_server_id
        self.node_id = node_id
        self.default_max_hops = default_max_hops
        # Group registry for outbound group policy applied when sending events
        # back to this inbound peer..
        self.group_registry = group_registry
        self._outbound_q = queue.Queue()
        self._stop_event = threading.Event()
        self.lgr = logging.getLogger(f"InboundPeerLink[{peer_server_id}]")
        # When this link is the router `src` for inbound events, COTRouter reads
        # src.user (router.py broadcast/group_broadcast). A federate peer is an
        # anonymous source from the local router's perspective — there is no
        # local TAKUser — so expose user=None, mirroring FederateClient's
        # TAKClient base (which also starts with user=None).
        self.user = None

    @property
    def remote_server_id(self):
        return self.peer_server_id

    def send_event(self, evt):
        """
        Encode + enqueue a CoT event for this inbound peer.

        Uses the SHARED codec.prepare_outbound_event helper — the exact same
        loop-prevention + hop-stamp + group-policy + encode logic the outbound
        client link uses. Drops (returns) silently on
        loop/hop/group-policy guard.
        """
        from ots_federation.codec import prepare_outbound_event  # pylint: disable=import-outside-toplevel

        try:
            proto = prepare_outbound_event(
                evt,
                node_id=self.node_id,
                default_max_hops=self.default_max_hops,
                registry=self.group_registry,
                peer_id=self.peer_server_id,
            )
        except Exception as exc:  # pylint: disable=broad-except
            self.lgr.warning("Failed to encode event %s: %s", getattr(evt, "uid", "?"), exc)
            return

        if proto is None:
            return

        try:
            self._outbound_q.put_nowait(proto)
        except queue.Full:
            self.lgr.warning(
                "Outbound queue full for inbound peer %s; dropping event %s",
                self.peer_server_id,
                getattr(evt, "uid", "?"),
            )

    def drain_outbound(self):
        """
        Generator yielding queued FederatedEvent protos until stop is requested.

        Used by FederationServer.ClientEventStream as the response generator.
        Blocks up to _OUTBOUND_POLL_TIMEOUT between items so a disconnect or
        shutdown is noticed promptly.
        """
        while not self._stop_event.is_set():
            try:
                proto = self._outbound_q.get(timeout=_OUTBOUND_POLL_TIMEOUT)
            except queue.Empty:
                continue
            yield proto

    def request_stop(self):
        """Signal the ClientEventStream generator to finish."""
        self._stop_event.set()


class FederatedChannelServicer(fig_pb2_grpc.FederatedChannelServicer):
    """
    gRPC servicer hosting the FederatedChannel service for inbound peers.

    Owns the inbound decode path (→ bridge.enqueue) and brokers per-peer
    outbound links through the FederationManager. One servicer per
    FederationServer.

    Parameters
    ----------
    server_id : str
        Our federation server ID ([federation] server_id). Returned in
        getIdentity and used for provenance/loop-prevention.
    server_name : str
        Human-readable server name ([federation] server_name).
    bridge : FederationBridge
        The shared inbound bridge. We enqueue (link, evt) the same way
        FederateClient does, so router.route runs on the main select loop.
    manager : FederationManager
        Back-reference so we can register/deregister inbound-peer outbound links
        as ClientEventStream connections come and go.
    default_max_hops : int
        Global default hop limit for events we originate the relay of.
    """

    def __init__(self, server_id, server_name, bridge, manager, default_max_hops,
                 group_registry=None, allow_federated_delete=False, rol_log_sink=""):
        self.server_id = server_id
        self.server_name = server_name
        self.bridge = bridge
        self.manager = manager
        self.default_max_hops = default_max_hops
        # Group registry for inbound and outbound group filtering.
        # None disables group policy (backward-compatible default).
        self.group_registry = group_registry
        # When False (default), inbound DELETE events are dropped.
        self.allow_federated_delete = allow_federated_delete
        # Filesystem path to append serialized ROL frames to. Empty = noop.
        self.rol_log_sink = rol_log_sink
        self.lgr = logging.getLogger("FederatedChannelServicer")
        # Shortcut-1 Option-1A: TCP peer address → federation server_id.
        # Populated when ClientEventStream or ServerFederateGroupsStream fires
        # (those carry a Subscription with the peer's server_id).  Used by
        # ServerEventStream and ClientFederateGroupsStream (which have no
        # Subscription) to resolve the per-peer registry key instead of falling
        # through to the TCP address string which never matches a stanza.
        self._peer_addr_to_server_id: dict = {}
        self._peer_addr_lock = threading.Lock()

        # Identity binding (bind federation ACL decisions to the authenticated
        # peer certificate, not to a self-asserted wire field): policy is
        # resolved by looking up the PRESENTED certificate's fingerprint in
        # the registry's static, config-time fingerprint->peer_id table
        # (populated from each peer's `fingerprint` config key — see
        # manager.py._build_group_registry). There is deliberately no
        # runtime/trust-on-first-use state here: a fingerprint either matches
        # a configured peer or it does not. An earlier version of this fix
        # used trust-on-first-use keyed on the wire-supplied serverId, which
        # left a startup-race escalation (attacker pre-claims a configured
        # serverId before the real peer connects) and a pre-claim DoS
        # (attacker locks out the real peer for every configured identity).
        # Never reintroduce a first-sight-binds-forever branch here.

    # ------------------------------------------------------------------
    # getIdentity (unary) — return OUR identity..
    # ------------------------------------------------------------------
    def getIdentity(self, request, context):  # noqa: N802 (proto naming)
        return fig_pb2.Identity(
            type=fig_pb2.Identity.ConnectionType.FEDERATION_TAK_SERVER,
            serverId=self.server_id,
            name=self.server_name or self.server_id,
        )

    # ------------------------------------------------------------------
    # ServerEventStream (client→server stream) — we RECEIVE events.
    # ------------------------------------------------------------------
    def ServerEventStream(self, request_iterator, context):  # noqa: N802
        """
        Receive a stream of FederatedEvents from the connecting peer.

        Each inbound FederatedEvent is decoded with the SAME codec the client
        link uses, inbound group policy is applied, the
        FedMeta sidecar is attached to evt, and the event is handed to the
        bridge — the identical inbound path FederateClient uses.
        Returns a Subscription ack when the stream completes.

        Shortcut-1 Option-1A: peer_id is resolved via _resolve_peer_id() which
        checks the TCP→server_id map (populated by ClientEventStream /
        ServerFederateGroupsStream) before falling back to context.peer().  On
        reconnects after the first ClientEventStream, the correct stanza key is
        used for group policy.

        Identity is re-resolved on EVERY event, not once at stream-open: a
        connecting peer typically opens ServerEventStream before its
        ClientEventStream (which is what carries the Subscription that lets
        the TCP→server_id map populate — see _register_peer_addr), so the
        very first events on a fresh connection can arrive before that
        mapping exists. Re-resolving per event means those first few events
        may be evaluated against a not-yet-bound identity (correctly
        conservative — quarantined until bound), while later events on the
        same long-lived stream benefit from the mapping as soon as it lands,
        rather than being stuck with whatever was resolved at connection open.
        """
        from ots_federation.codec import decode_federated_event  # pylint: disable=import-outside-toplevel

        # A lightweight link object stands in as the router `src` for these
        # inbound events (router.route(src, evt)). It is NOT registered for
        # outbound fan-out — that is the ClientEventStream's job — but giving it
        # the peer's server_id lets on_outbound src-skip echo correctly if the
        # same peer also has an outbound link registered. peer_server_id is
        # refreshed below as identity resolution firms up.
        inbound_src = _InboundPeerLink(
            peer_server_id=self._resolve_peer_id(context),
            node_id=self.server_id,
            default_max_hops=self.default_max_hops,
        )

        self.lgr.info("ServerEventStream opened from peer %s", inbound_src.peer_server_id)
        try:
            for fed_event_proto in request_iterator:
                peer_id, quarantined = self._resolve_authenticated_peer(context)
                inbound_src.peer_server_id = peer_id
                try:
                    evt, fed_meta = decode_federated_event(
                        fed_event_proto, local_max_hops=self.default_max_hops
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    self.lgr.warning("Failed to decode inbound FederatedEvent: %s", exc)
                    continue

                if evt is None:
                    # Contact-only / parse failure — already logged by codec.
                    continue

                # --- Inbound DELETE guard ---
                if not self.allow_federated_delete:
                    etype = getattr(evt, "etype", "") or ""
                    if etype.startswith(_COT_DELETE_TYPE_PREFIX):
                        self.lgr.debug(
                            "Dropping inbound federated DELETE event %s from peer %s "
                            "(allow_federated_delete=False)",
                            getattr(evt, "uid", "?"), peer_id,
                        )
                        continue

                # --- Inbound group policy ---
                # Runs for group-less events too: stock TAK Server (with
                # federatedGroupMapping off) never annotates federateGroups, and
                # the registry admits those iff a wildcard accept_as exists
                # (see module docstring: fail-closed for unmapped groups).
                # A quarantined identity (unrecognized or identity-mismatched
                # certificate — see _resolve_authenticated_peer) NEVER consults
                # the registry at all: it gets nothing, not the global default.
                if self.group_registry is not None:
                    remote_groups = list(fed_event_proto.federateGroups)
                    if quarantined:
                        local_groups = None
                    else:
                        local_groups = self.group_registry.map_inbound_groups(
                            peer_id, remote_groups
                        )
                    if local_groups is None:
                        self.lgr.debug(
                            "Inbound group policy: dropping event %s from peer %s "
                            "(no mappable local groups for %s%s)",
                            getattr(evt, "uid", "?"), peer_id, remote_groups,
                            " — quarantined identity" if quarantined else "",
                        )
                        continue
                    # Attach mapped local groups as sidecars.
                    # inbound_local_groups → bridge.drain → bus.inject
                    #   for groups-exchange delivery.
                    # local_acl_groups → prepare_outbound_event relay path.
                    evt.inbound_local_groups = frozenset(local_groups)
                    evt.local_acl_groups = frozenset(local_groups)

                # Attach fed_meta sidecar so on_outbound's send helpers can run
                # loop-prevention against the provenance chain.
                evt.fed_meta = fed_meta
                self.bridge.enqueue(inbound_src, evt)
        finally:
            self.lgr.info("ServerEventStream from peer %s closed", peer_id)

        return self._our_subscription()

    # ------------------------------------------------------------------
    # ClientEventStream (server→client stream) — we SEND events.
    # ------------------------------------------------------------------
    def ClientEventStream(self, subscription, context):  # noqa: N802
        """
        Stream FederatedEvents TO the connecting peer until it disconnects.

        Registers a per-connection outbound link keyed by the peer's server_id
        (from subscription.identity) with the FederationManager, then yields
        encoded events from that link's queue. Deregisters on exit.

        Shortcut-1 Option-1A: when a server_id is resolved from the subscription,
        it is stored in _peer_addr_to_server_id so that subsequent ServerEventStream
        calls on the same TCP connection can resolve the correct stanza key.
        """
        peer_id, quarantined = self._resolve_authenticated_peer(context, subscription)
        # Register TCP→server_id so ServerEventStream can resolve this peer (1A).
        self._register_peer_addr(context, peer_id)

        link = _InboundPeerLink(
            peer_server_id=peer_id,
            node_id=self.server_id,
            default_max_hops=self.default_max_hops,
            group_registry=self.group_registry,
        )
        if quarantined:
            # Do NOT register this link for outbound fan-out: an unrecognized
            # or identity-mismatched certificate gets no policy at all, which
            # for the outbound direction means "never fanned events in the
            # first place" rather than relying on a share_as lookup that would
            # otherwise fall through to the global default for this identity.
            self.lgr.warning(
                "ClientEventStream opened by peer %s with no explicit "
                "federation configuration (or a certificate that disagrees "
                "with a previously-bound identity) — NOT registering for "
                "outbound fan-out (quarantined)", peer_id,
            )
        else:
            self.manager.register_inbound_link(peer_id, link)
            self.lgr.info("ClientEventStream opened to peer %s (registered for fan-out)", peer_id)

        def _on_rpc_done():
            link.request_stop()

        context.add_callback(_on_rpc_done)

        try:
            for proto in link.drain_outbound():
                yield proto
        finally:
            if not quarantined:
                self.manager.deregister_inbound_link(peer_id, link)
            self.lgr.info(
                "ClientEventStream to peer %s closed%s", peer_id,
                " (was quarantined, never registered)" if quarantined else " (deregistered)",
            )

    # ------------------------------------------------------------------
    # HealthCheck (unary) — always SERVING..
    # ------------------------------------------------------------------
    def HealthCheck(self, request, context):  # noqa: N802
        return fig_pb2.ServerHealth(status=fig_pb2.ServerHealth.ServingStatus.SERVING)

    # ------------------------------------------------------------------
    # FederateGroups streams.
    # ------------------------------------------------------------------
    def ClientFederateGroupsStream(self, request_iterator, context):  # noqa: N802
        """
        Peer sends its groups to us (client→server stream).

        Feeds received group announcements into the group registry via
        update_from_federate_groups so that inbound group filtering can
        apply the peer's current group set.

        Shortcut-1 Option-1A: uses _resolve_peer_id so announced groups are
        stored under the correct server_id key (not the TCP address).
        """
        peer_id, quarantined = self._resolve_authenticated_peer(context)
        try:
            for groups_msg in request_iterator:
                remote_groups = list(groups_msg.federateGroups)
                self.lgr.debug(
                    "ClientFederateGroupsStream: peer %s announced groups %s",
                    peer_id, remote_groups,
                )
                if self.group_registry is not None and not quarantined:
                    self.group_registry.update_from_federate_groups(peer_id, remote_groups)
        except grpc.RpcError:
            pass
        return self._our_subscription()

    def ServerFederateGroupsStream(self, subscription, context):  # noqa: N802
        """
        We send OUR federated groups to the connecting peer (server→client stream).

        Derives the announced groups from the outbound group map configured for
        this peer in the registry. When no registry is configured, sends an
        empty set (backward-compatible).

        Shortcut-1 Option-1A: when server_id is resolved from the subscription,
        it is stored in _peer_addr_to_server_id alongside ClientEventStream.
        """
        peer_id, _quarantined = self._resolve_authenticated_peer(context, subscription)
        # Register TCP→server_id so ServerEventStream can resolve this peer (1A).
        self._register_peer_addr(context, peer_id)

        # NOTE: no quarantine gate needed here — reading self.group_registry.
        # _outbound directly (not via map_outbound()) never consults the
        # global default fallback in the first place, so an unrecognized
        # peer_id already announces an empty group list.
        announced: list = []
        if self.group_registry is not None:
            out_map = self.group_registry._outbound.get(peer_id, {})
            announced = list(out_map.values())

        self.lgr.debug(
            "ServerFederateGroupsStream: announcing groups %s to peer %s",
            announced, peer_id,
        )
        # Yield our groups WITH a SERVING health signal. The streamUpdate=SERVING
        # is the trigger TAK Server's TakFigClient needs to call setupEventStream
        # and open its push (ServerEventStream) channel back to us. Without it, TAK
        # never sends events to taky (TAK->taky stays empty)..
        yield fig_pb2.FederateGroups(
            streamUpdate=fig_pb2.ServerHealth(
                status=fig_pb2.ServerHealth.ServingStatus.SERVING
            ),
            federateGroups=announced,
        )
        # HOLD the stream open until the peer disconnects. Returning would be a gRPC
        # stream completion -> TAK's onCompleted -> it tears down before opening its
        # push channel. Staying alive keeps federation bidirectional..
        while context.is_active():
            time.sleep(5)

    # ------------------------------------------------------------------
    # ROL streams — TAK Server opens these during the v2 handshake, so they
    # MUST exist as graceful no-ops or the whole link drops with
    # "Method not implemented!" (confirmed vs TAK Server 5.4).
    # Phase 2 may implement real ROL (mission/policy) handling.
    # ------------------------------------------------------------------
    def ServerROLStream(self, request_iterator, context):  # noqa: N802
        """Peer streams ROL (mission/policy) to us.

        Logs rol.program at INFO and appends raw serialized bytes to
        rol_log_sink (when configured). Mission handling is out of scope
        ..
        """
        try:
            for rol in request_iterator:
                self.lgr.info(
                    "ServerROLStream: received ROL program=%r from peer %s",
                    rol.program,
                    self._peer_id_from_context(context),
                )
                if self.rol_log_sink:
                    try:
                        raw = rol.SerializeToString()
                        with open(self.rol_log_sink, "ab") as f:
                            # 4-byte big-endian length prefix followed by raw proto
                            f.write(len(raw).to_bytes(4, "big") + raw)
                    except OSError as exc:
                        self.lgr.warning(
                            "ServerROLStream: failed to write to sink %r: %s",
                            self.rol_log_sink, exc,
                        )
        except grpc.RpcError:
            pass
        return self._our_subscription()

    def ClientROLStream(self, subscription, context):  # noqa: N802
        """We stream ROL to the peer. Phase 2 — nothing to send."""
        self.lgr.debug("ClientROLStream opened (Phase 2 stub: no ROL)")
        return iter(())

    # ------------------------------------------------------------------
    # Remaining FederatedChannel RPCs — graceful no-ops so an unexpected
    # call never crashes the federation link. Phase 2 may implement these.
    # ------------------------------------------------------------------
    def BinaryMessageStream(self, request_iterator, context):  # noqa: N802
        """Peer streams binary blobs to us. Phase 2 — drain and ignore."""
        try:
            for _blob in request_iterator:
                pass
        except grpc.RpcError:
            pass
        return fig_pb2.Empty()

    def SendOneEvent(self, request, context):  # noqa: N802
        """Single (non-streamed) event from the peer — decode + route, like ServerEventStream."""
        from ots_federation.codec import decode_federated_event  # pylint: disable=import-outside-toplevel
        peer_id, quarantined = self._resolve_authenticated_peer(context)
        try:
            evt, fed_meta = decode_federated_event(
                request, local_max_hops=self.default_max_hops
            )
            if evt is not None:
                # Apply inbound group policy (same as ServerEventStream).
                # Group-less events consult the wildcard policy too.
                # A quarantined identity never reaches the registry (see
                # ServerEventStream's comment on the same gate).
                if self.group_registry is not None:
                    remote_groups = list(request.federateGroups)
                    local_groups = (
                        None if quarantined
                        else self.group_registry.map_inbound_groups(peer_id, remote_groups)
                    )
                    if local_groups is None:
                        self.lgr.debug(
                            "Inbound group policy (SendOneEvent): dropping event %s "
                            "from peer %s (no mappable local groups for %s)",
                            getattr(evt, "uid", "?"), peer_id, remote_groups,
                        )
                        return fig_pb2.Empty()
                    # Attach mapped local groups as sidecars.
                    evt.inbound_local_groups = frozenset(local_groups)
                    evt.local_acl_groups = frozenset(local_groups)

                evt.fed_meta = fed_meta
                inbound_src = _InboundPeerLink(
                    peer_server_id=peer_id,
                    node_id=self.server_id,
                    default_max_hops=self.default_max_hops,
                    group_registry=self.group_registry,
                )
                self.bridge.enqueue(inbound_src, evt)
        except Exception as exc:  # pylint: disable=broad-except
            self.lgr.warning("SendOneEvent decode failed: %s", exc)
        return fig_pb2.Empty()

    def SendOneBlob(self, request, context):  # noqa: N802
        """Single binary blob from the peer. Phase 2 — accept and ignore."""
        return fig_pb2.Empty()

    def GetAuthTokenByX509(self, request, context):  # noqa: N802
        """Hub token exchange — unused in direct cert auth. Empty response."""
        return fig_pb2.FederateTokenResponse()

    def Getx509Identity(self, request, context):  # noqa: N802
        """x509 identity request — unused in direct cert auth. Empty response."""
        return fig_pb2.BinaryBlob()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _register_peer_addr(self, context, server_id: str) -> None:
        """
        Store TCP peer address → federation server_id mapping.

        Called by ClientEventStream and ServerFederateGroupsStream when they
        resolve the peer's server_id from a Subscription.  Lets ServerEventStream
        and ClientFederateGroupsStream (which have no Subscription) look up the
        correct stanza key instead of using the raw TCP address.
        Shortcut-1 Option-1A.
        """
        if not server_id:
            return
        try:
            addr = context.peer()
        except Exception:  # pylint: disable=broad-except
            return
        if addr:
            with self._peer_addr_lock:
                self._peer_addr_to_server_id[addr] = server_id

    def _resolve_peer_id(self, context) -> str:
        """
        Resolve peer identity: check TCP→server_id map, fall back to context.peer().

        ServerEventStream and ClientFederateGroupsStream don't carry a
        Subscription, so the server_id isn't available in-band. If
        ClientEventStream or ServerFederateGroupsStream has already fired on
        this TCP connection (which happens on reconnects after the first
        handshake), the mapping is available and the correct stanza key is
        returned. On a fresh first connection where ServerEventStream fires
        before ClientEventStream, falls back to the TCP address string.
        Shortcut-1 Option-1A.
        """
        try:
            tcp_addr = context.peer() or "unknown-peer"
        except Exception:  # pylint: disable=broad-except
            return "unknown-peer"
        with self._peer_addr_lock:
            return self._peer_addr_to_server_id.get(tcp_addr, tcp_addr)

    def _resolve_authenticated_peer(self, context, subscription=None):
        """
        Resolve this connection's federation identity SOLELY from the
        certificate actually presented on the mTLS transport, never from a
        self-asserted wire field — the fix for the group-ACL bypass where a
        peer could pick its own policy by asserting a different serverId (or
        another configured peer's serverId), or by asserting none at all and
        landing on the global default.

        Returns (peer_id, quarantined):
          peer_id : str
              The config-facing registry key this fingerprint resolves to
              (the peer's declared server_id, or its provisional
              address:port key — see FederationManager._build_group_registry
              / FederateGroupRegistry.register_fingerprint). When quarantined,
              this is a synthetic, never-configurable placeholder string
              derived from the fingerprint itself — guaranteed not to
              collide with any real configured peer_id — used only for
              logging and outbound src-skip bookkeeping, NEVER for a
              group-registry lookup (see quarantined below).
          quarantined : bool
              True when the presented certificate's fingerprint has no
              matching entry in the registry's configured fingerprint table.
              Callers MUST treat quarantined=True as "no policy" — never
              consult group-policy defaults (including a deliberately
              configured wildcard accept_as/share_as) for a quarantined
              connection. An unrecognized or spoofed identity gets nothing;
              it does not fall through to the most permissive config.

        Resolution — deliberately has NO wire-supplied input anywhere in the
        policy decision (Subscription.identity.serverId is not read here at
        all; `subscription` is accepted only for the insecure-channel legacy
        fallback below, kept for existing loopback/testing callers):
          1. fingerprint = the SHA-256 fingerprint of the certificate
             actually presented on THIS transport (via
             context.auth_context()). None on an insecure channel (no mTLS
             material configured — testing only; see FederationServer.start's
             warning) or a context that exposes no verified certificate.
          2. When fingerprint is None: nothing to bind identity to (insecure
             channel). Fall back to the pre-identity-binding candidate-only
             resolution (wire serverId, or the TCP-address-derived key) so
             existing insecure-channel/local-dev unit tests keep working —
             there is no ACL to bypass on an unauthenticated channel in the
             first place.
          3. When self.group_registry is None: no group policy configured at
             all; nothing for a spoofed identity to bypass. Same legacy
             fallback as (2).
          4. Otherwise: look up `fingerprint` in
             self.group_registry.resolve_peer_id_by_fingerprint(). A
             configured match returns that peer_id, never quarantined. No
             match means this certificate has no configuration ANYWHERE —
             quarantine unconditionally. There is no trust-on-first-use, no
             partial match, and no fallthrough to a declared server_id or
             the global default: a fingerprint the operator never configured
             gets nothing, full stop.
        """
        def _legacy_candidate() -> str:
            candidate = ""
            if subscription is not None and subscription.HasField("identity"):
                candidate = subscription.identity.serverId
            if not candidate:
                candidate = self._resolve_peer_id(context)
            return candidate

        fingerprint = peer_fingerprint_from_grpc_context(context)
        if fingerprint is None:
            # No verified certificate on this transport — nothing to bind
            # identity to (insecure/testing channel). Keep legacy behavior.
            return _legacy_candidate(), False

        if self.group_registry is None:
            # No group policy configured at all; there is nothing for a
            # spoofed identity to bypass. Keep legacy behavior.
            return _legacy_candidate(), False

        peer_id = self.group_registry.resolve_peer_id_by_fingerprint(fingerprint)
        if peer_id is None:
            self.lgr.debug(
                "Identity binding: certificate fingerprint %s has no "
                "configured peer (fingerprint absent from every "
                "[federate:*] `fingerprint` key) — quarantining (no policy "
                "applied, default NOT consulted, wire-supplied serverId NOT "
                "consulted)",
                fingerprint,
            )
            return f"unconfigured-cert:{fingerprint}", True

        return peer_id, False

    def _our_subscription(self):
        """Build a Subscription with our identity and server version.

        Used in ServerEventStream, ClientFederateGroupsStream, and ROL stream
        return values so the remote peer knows which version it is talking to.
        .
        """
        from ots_federation.client import _build_ots_version  # pylint: disable=import-outside-toplevel
        return fig_pb2.Subscription(
            identity=self._our_identity(),
            version=_build_ots_version(),
        )

    def _our_identity(self):
        return fig_pb2.Identity(
            type=fig_pb2.Identity.ConnectionType.FEDERATION_TAK_SERVER,
            serverId=self.server_id,
            name=self.server_name or self.server_id,
        )

    @staticmethod
    def _peer_id_from_context(context):
        """
        Best-effort peer identity for streams that don't carry a Subscription.

        ServerEventStream's request type is FederatedEvent (no identity field)
        so the connecting peer identity is not available in-band. We fall back
        to the gRPC peer address string (host:port), which is stable for the
        life of the connection and good enough to key per-connection state.
        (v1 derives identity from the TLS cert; v2 server-side we
        use Subscription.identity when present and the peer address otherwise).
        """
        try:
            return context.peer() or "unknown-peer"
        except Exception:  # pylint: disable=broad-except
            return "unknown-peer"


class FederationServer:
    """
    Hosts the FederatedChannel gRPC server for inbound federate connections.

    Started by FederationManager.start when [federation] listen is enabled.
    Stopped gracefully by FederationManager.stop.

    Parameters
    ----------
    listen_ip : str
        Bind address (e.g. "0.0.0.0" or "127.0.0.1").
    listen_port : int
        Bind port (default 9101 — see config.py).
    server_id, server_name : str
        Our federation identity, surfaced via getIdentity.
    bridge : FederationBridge
        Shared inbound bridge (same instance the client links use).
    manager : FederationManager
        Back-reference for inbound-link register/deregister.
    default_max_hops : int
        Global default hop limit.
    server_credentials : grpc.ServerCredentials | None
        mTLS server credentials from build_grpc_server_credentials. When None
        an insecure port is used (TESTING ONLY — never in production).
    max_workers : int
        gRPC thread-pool size.
    """

    def __init__(
        self,
        listen_ip,
        listen_port,
        server_id,
        server_name,
        bridge,
        manager,
        default_max_hops,
        server_credentials=None,
        max_workers=64,
        group_registry=None,
        allow_federated_delete=False,
        rol_log_sink="",
    ):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.server_credentials = server_credentials
        self.max_workers = max_workers
        self.lgr = logging.getLogger("FederationServer")

        self.servicer = FederatedChannelServicer(
            server_id=server_id,
            server_name=server_name,
            bridge=bridge,
            manager=manager,
            default_max_hops=default_max_hops,
            group_registry=group_registry,
            allow_federated_delete=allow_federated_delete,
            rol_log_sink=rol_log_sink,
        )

        self._server = None
        self._bound_port = None

    @property
    def bound_port(self):
        """The actually-bound port (useful when listen_port=0 for ephemeral)."""
        return self._bound_port

    def start(self):
        """
        Build, bind, and start the gRPC server.

        Uses a secure (mTLS) port when server_credentials is provided, otherwise
        an insecure port (testing only).
        """
        self._server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=self.max_workers),
            # Keepalive: ping the peer every 30s even when idle. Keeps the NAT
            # mapping alive (TAK dials in from behind NAT) and detects a dead
            # peer so the half-open socket is torn down instead of lingering.
            #.
            options=[
                ("grpc.keepalive_time_ms", 30000),
                ("grpc.keepalive_timeout_ms", 10000),
                ("grpc.keepalive_permit_without_calls", 1),
                ("grpc.http2.min_ping_interval_without_data_ms", 10000),
                ("grpc.http2.max_pings_without_data", 0),
            ],
        )
        fig_pb2_grpc.add_FederatedChannelServicer_to_server(self.servicer, self._server)

        address = f"{self.listen_ip}:{self.listen_port}"
        if self.server_credentials is not None:
            self._bound_port = self._server.add_secure_port(
                address, self.server_credentials
            )
            self.lgr.info("FederationServer listening (mTLS) on %s", address)
        else:
            self._bound_port = self._server.add_insecure_port(address)
            self.lgr.warning(
                "FederationServer listening INSECURE on %s (testing only — no mTLS)",
                address,
            )

        if self._bound_port == 0:
            raise OSError(f"FederationServer failed to bind {address}")

        self._server.start()
        return self._bound_port

    def stop(self, grace=5.0):
        """Gracefully stop the gRPC server, draining in-flight RPCs."""
        if self._server is None:
            return
        self.lgr.info("FederationServer stopping")
        event = self._server.stop(grace)
        # Block until the grace period elapses or all RPCs finish.
        event.wait(timeout=grace + 1.0)
        self._server = None
