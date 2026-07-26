# ots_federation/client.py
# Adapted from taky.cot.federation.client (taky-federation branch, commit e12a2af).
# MIT License — copyright Tim K (tkuester).
# Seam change vs. taky (report seam 4):
#   taky: FederateClient(TAKClient) — subclasses TAKClient so that inbound events
#         can be injected into COTRouter.route(federate_client, evt) as if from a
#         real ATAK device. The TAKClient base provides uid tracking, callbacks, etc.
#   ots_federation: FederateClient is a plain class. The TAKClient inheritance
#         is not needed because inbound events go to bus.inject(src, evt), not
#         router.route. The user=None attribute is preserved for interface
#         compatibility with FederationManager.on_outbound and _InboundPeerLink.
#                         → ClientFederateGroupsStream → ClientEventStream → HealthCheck).

import enum
import logging
import queue
import threading
import time

import grpc

from ots_federation.proto import fig_pb2, fig_pb2_grpc


def _build_ots_version() -> "fig_pb2.TakServerVersion":
    """Parse ots_federation version into a TakServerVersion proto..

    Handles PEP-440 dev/post/local suffixes gracefully: only major and minor
    are reliably present in the setuptools-scm version string.
    """
    try:
        import importlib.metadata  # pylint: disable=import-outside-toplevel
        ver_str = importlib.metadata.version("ots-federation")
    except Exception:  # pylint: disable=broad-except
        ver_str = ""

    major = minor = patch = 0
    branch = ""
    # Version strings: "0.1.2", "0.1.2.dev23+gabc1234"
    # Strip local part (+...)
    base = ver_str.split("+")[0].split("-")[0]
    if "dev" in base:
        base, _, dev_suffix = base.partition(".dev")
        branch = f"dev{dev_suffix}"
    parts = base.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        pass

    return fig_pb2.TakServerVersion(
        major=major,
        minor=minor,
        patch=patch,
        branch=branch,
        variant="ots-federation",
    )


# CoT event type prefix for DELETE events..
_COT_DELETE_TYPE_PREFIX = "t-x-d-d"


class PeerIdentityMismatchError(RuntimeError):
    """
    Raised when the dialed server's cryptographic identity cannot be
    established and resolved to a configured peer: the TLS certificate the
    dialed host actually presented during the handshake is unobservable,
    ambiguous, or its SHA-256 fingerprint is not registered for any
    configured peer — or, as defense-in-depth, the wire getIdentity().serverId
    contradicts an explicitly configured expected server_id.

    Mirrors TAK Server's outbound semantics (TakFigClient.java:1268-1311)
    and this codebase's own inbound identity check (fed_server.py):
    group policy is keyed EXCLUSIVELY on the fingerprint of the certificate
    presented on the mTLS transport, resolved through the same per-peer
    `fingerprint` table as inbound. The wire-reported serverId NEVER selects
    policy — a compromised host, or one reached via DNS/BGP hijack of the
    configured address, holds at best its own valid fed-CA certificate,
    whose fingerprint resolves (only) to its own configured policy or to
    nothing at all. There is no fallthrough to the dialed stanza's policy,
    no trust-on-first-use, and no opt-in escape hatch: an unrecognized
    fingerprint is refused unconditionally until the operator configures it.

    run_grpc_thread's generic exception handler catches this and reconnects
    on the normal back-off schedule; that is the intended response — an
    unverifiable peer gets nothing, repeatedly, not a one-time warning
    followed by trust.
    """


class PeerState(enum.Enum):
    """
    Lifecycle state for a single federate peer.

    DISABLED → CONNECTING → HANDSHAKING → ACTIVE ↔ RECONNECTING → DRAINING
    """

    DISABLED = "DISABLED"
    CONNECTING = "CONNECTING"
    HANDSHAKING = "HANDSHAKING"
    ACTIVE = "ACTIVE"
    RECONNECTING = "RECONNECTING"
    DRAINING = "DRAINING"


# Reconnect back-off: base=30s, cap=300s (5 min).
_RECONNECT_BASE = 30.0
_RECONNECT_CAP = 300.0

# How long to wait for the TLS transport to reach READY before observing the
# dialed server's presented certificate. Connection failures surface as
# grpc.FutureTimeoutError and take the normal reconnect back-off path.
_CHANNEL_READY_TIMEOUT = 30.0


class FederateClient:
    """
    gRPC client representing a single outbound federate peer.

    Manages the full connection lifecycle (DISABLED → CONNECTING → HANDSHAKING
    → ACTIVE ↔ RECONNECTING → DRAINING) on a dedicated daemon thread.

    Inbound path (remote → local):
        1. gRPC side-thread receives FederatedEvent from ClientEventStream.
        2. codec.decode_federated_event → (models.Event, FedMeta).
        3. Inbound group policy applied.
        4. bridge.enqueue(self, evt) — wakes the application event loop.
        5. bus.inject(self, evt) — application delivers to OTS / local clients.

    Outbound path (local → remote):
        1. Application calls self.send_event(evt).
        2. Loop prevention: drop if own node_id in evt.fed_meta.seen_server_ids.
        3. Hop enforcement: drop if current_hops >= max_hops.
        4. Group policy applied.
        5. codec.prepare_outbound_event → FederatedEvent proto.
        6. Enqueued on _outbound_q for gRPC side-thread.

    Parameters
    ----------
    peer_name : str
        Human-readable name matching [federate:<name>] config section.
    peer_config : FederatePeerConfig
        Parsed per-peer configuration.
    node_id : str
        This server's federation server ID from [federation] server_id.
    bridge : FederationBridge
        Shared bridge for delivering inbound events to the event loop.
    group_registry : FederateGroupRegistry | None
        Optional group registry. None disables group policy (backward-compat).
    """

    def __init__(self, peer_name, peer_config, node_id, bridge, group_registry=None,
                 allow_federated_delete=False, local_max_hops=3):
        self.peer_name = peer_name
        self.peer_config = peer_config
        self.node_id = node_id
        self.bridge = bridge
        self.group_registry = group_registry
        # When False (default), inbound DELETE events are dropped..
        self.allow_federated_delete = allow_federated_delete
        # This node's configured hop ceiling ([federation] max_hops), used to
        # clamp an absent/zero/negative wire max_hops on INBOUND decode so a
        # peer cannot obtain unlimited relay by omitting the field
        # (hop-clamp fix). Distinct from peer_config.max_hops,
        # which stamps OUR OWN outbound budget when relaying — a per-peer
        # operator choice that may legitimately be unlimited (-1) for a
        # trusted peer even when the inbound ceiling is not.
        self.local_max_hops = local_max_hops

        # user=None: interface compatibility with FederationManager.on_outbound
        # which reads src.user to identify the source (a federate peer has no
        # local user object).
        self.user = None

        # POLICY identity of the dialed peer (the key every group-policy
        # lookup for this session uses). With a group registry present this
        # is bound EXCLUSIVELY from the dialed server's presented TLS
        # certificate fingerprint resolved through the registry's per-peer
        # fingerprint table — never from the wire-reported
        # getIdentity().serverId. Only in legacy no-registry mode (no group
        # policy exists at all) does it fall back to the wire-reported value,
        # for display/echo-skip purposes only.
        self._remote_server_id = None
        # The serverId the remote REPORTED over getIdentity(). Logging and
        # defense-in-depth cross-check only — never a policy key.
        self._reported_server_id = None
        self._state = PeerState.DISABLED
        self._state_lock = threading.Lock()

        self._outbound_q = queue.Queue()
        self._stop_event = threading.Event()

        self.lgr = logging.getLogger(f"FederateClient[{peer_name}]")

    def __repr__(self):
        return (
            f"<FederateClient name={self.peer_name} "
            f"state={self._state.value} "
            f"remote_id={self._remote_server_id}>"
        )

    @property
    def remote_server_id(self):
        """The dialed peer's identity key. None until the handshake binds it.

        With a group registry: the policy key resolved from the peer's
        authenticated certificate fingerprint, NOT the
        wire-reported getIdentity().serverId. Without a registry (legacy,
        group policy disabled): the wire-reported serverId, display only.
        """
        return self._remote_server_id

    @property
    def state(self):
        """Current PeerState."""
        return self._state

    def _set_state(self, new_state: PeerState):
        old = self._state
        self._state = new_state
        if old != new_state:
            self.lgr.info(
                "Peer %s: %s → %s", self.peer_name, old.value, new_state.value
            )

    def send_event(self, evt):
        """
        Send a CoT event to the remote federate peer.

        Implements loop prevention and hop-limit enforcement
         before encoding. Silently drops on any guard failure.

        Parameters
        ----------
        evt : models.Event
            Event to forward. May carry a FedMeta sidecar as evt.fed_meta.
        """
        if self._state != PeerState.ACTIVE:
            return

        from ots_federation.codec import prepare_outbound_event  # pylint: disable=import-outside-toplevel

        try:
            proto = prepare_outbound_event(
                evt,
                node_id=self.node_id,
                default_max_hops=self.peer_config.max_hops,
                registry=self.group_registry,
                peer_id=self._remote_server_id or "",
            )
        except Exception as exc:  # pylint: disable=broad-except
            self.lgr.warning("Failed to encode event %s: %s", evt.uid, exc)
            return

        if proto is None:
            return

        try:
            self._outbound_q.put_nowait(proto)
        except queue.Full:
            self.lgr.warning(
                "Outbound queue full for peer %s; dropping event %s",
                self.peer_name,
                evt.uid,
            )

    def request_stop(self):
        """Signal the gRPC thread to stop. Called by FederationManager.stop()."""
        self._stop_event.set()
        self._set_state(PeerState.DRAINING)

    # ------------------------------------------------------------------
    # gRPC thread entry point
    # ------------------------------------------------------------------

    def run_grpc_thread(self):
        """
        Entry point for the gRPC side-thread. Owns the full channel lifecycle
        with exponential reconnect back-off.
        """
        reconnect_delay = _RECONNECT_BASE

        while not self._stop_event.is_set():
            try:
                self._run_session()
                if self._state == PeerState.DRAINING:
                    break
                self.lgr.warning(
                    "gRPC session for %s ended unexpectedly; reconnecting in %.0fs",
                    self.peer_name,
                    reconnect_delay,
                )
            except grpc.RpcError as exc:
                if self._stop_event.is_set():
                    break
                self.lgr.warning(
                    "gRPC error for peer %s: %s; reconnecting in %.0fs",
                    self.peer_name,
                    exc.code() if hasattr(exc, "code") else exc,
                    reconnect_delay,
                )
            except Exception as exc:  # pylint: disable=broad-except
                if self._stop_event.is_set():
                    break
                self.lgr.error(
                    "Unexpected error for peer %s: %s; reconnecting in %.0fs",
                    self.peer_name,
                    exc,
                    reconnect_delay,
                    exc_info=exc,
                )

            self._set_state(PeerState.RECONNECTING)
            self._remote_server_id = None
            self._reported_server_id = None
            self._stop_event.wait(timeout=reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, _RECONNECT_CAP)

        self.lgr.info("gRPC thread for peer %s exiting", self.peer_name)

    def _build_credentials(self):
        from ots_federation.tls import build_grpc_client_credentials  # pylint: disable=import-outside-toplevel

        pc = self.peer_config
        if pc.ca_cert and pc.client_cert and pc.client_key:
            return build_grpc_client_credentials(
                pc.ca_cert, pc.client_cert, pc.client_key
            )

        self.lgr.warning(
            "Peer %s: no TLS certs configured; using insecure channel (testing only)",
            self.peer_name,
        )
        return grpc.local_channel_credentials()

    def _build_identity(self):
        """Build our Identity proto for Subscription messages.

        Uses display_name from peer_config when set; falls
        back to node_id so the field is never empty.
        """
        display = getattr(self.peer_config, "display_name", "") or self.node_id
        return fig_pb2.Identity(
            type=fig_pb2.Identity.ConnectionType.FEDERATION_TAK_SERVER,
            serverId=self.node_id,
            name=display,
        )

    def _build_subscription(self):
        """Build a Subscription proto with our identity and server version.

        Populates TakServerVersion so the remote peer can version-gate or log
        our version..
        """
        return fig_pb2.Subscription(
            identity=self._build_identity(),
            version=_build_ots_version(),
        )

    def _run_session(self):
        """Single connection attempt + handshake + event loop."""
        address = f"{self.peer_config.address}:{self.peer_config.port}"
        self._set_state(PeerState.CONNECTING)

        credentials = self._build_credentials()
        with grpc.secure_channel(
            address,
            credentials,
            options=[
                ("grpc.keepalive_time_ms", 30000),
                ("grpc.keepalive_timeout_ms", 10000),
                ("grpc.keepalive_permit_without_calls", 1),
                ("grpc.http2.max_pings_without_data", 0),
                # Channelz is how this client observes the certificate the
                # dialed server actually presented on the live TLS transport
                # (see cert_identity.observed_server_cert_fingerprints_for_target
                # for why this mechanism and not auth_context / a verify
                # callback).
                ("grpc.enable_channelz", 1),
            ],
        ) as channel:
            stub = fig_pb2_grpc.FederatedChannelStub(channel)
            self._set_state(PeerState.HANDSHAKING)

            # Step 1: bind this session's POLICY identity from the dialed
            # server's presented TLS certificate — BEFORE any application
            # RPC is issued, mirroring TAK Server, whose outbound federate
            # resolution runs inside the TLS protocol negotiator
            # (TakFigClient.java:1268-1311) and never consults the wire
            # identity. The certificate fingerprint is looked up against the
            # SAME per-peer `fingerprint` table the inbound path uses
            # (groups.py resolve_peer_id_by_fingerprint).
            # Unconfigured / unobservable / ambiguous ⇒
            # PeerIdentityMismatchError ⇒ session refused, reconnect
            # back-off. UNCONDITIONAL: there is no config shape that skips
            # this when a group registry exists (the prior server_id-gated
            # attempt was rejected precisely because server_id defaults
            # empty).
            verified_fp = None
            if self.group_registry is not None:
                self._wait_channel_ready(channel)
                verified_fp, policy_peer_id = self._resolve_dialed_cert_identity(
                    address
                )
                self._remote_server_id = policy_peer_id
                self.lgr.info(
                    "Peer %s: dialed server cert fingerprint verified; "
                    "session policy identity = %r",
                    self.peer_name, policy_peer_id,
                )

            # Step 2: getIdentity — protocol handshake step. The response's
            # serverId is fully remote-controlled and is recorded for
            # logging only; it NEVER selects policy (that happened above,
            # from the certificate).
            identity_resp = stub.getIdentity(fig_pb2.Empty())
            reported_server_id = identity_resp.serverId
            self._reported_server_id = reported_server_id
            self.lgr.info(
                "Peer %s reports serverId=%s (%s)",
                self.peer_name, reported_server_id, identity_resp.name,
            )

            # Defense-in-depth (NOT the primary control): when the operator
            # additionally declared the peer's expected server_id, a
            # contradicting wire report is a strong signal of a broken or
            # hostile peer — refuse. This check can only ever refuse more;
            # it never grants anything, and its absence (server_id unset,
            # the default) changes nothing about the certificate binding
            # above.
            expected_server_id = getattr(self.peer_config, "server_id", "") or ""
            if expected_server_id and reported_server_id != expected_server_id:
                self.lgr.warning(
                    "Peer %s: getIdentity() returned serverId=%r but this "
                    "peer is configured as server_id=%r — refusing session "
                    "(defense-in-depth; policy identity was already bound "
                    "from the certificate and is not affected by wire "
                    "claims).",
                    self.peer_name, reported_server_id, expected_server_id,
                )
                raise PeerIdentityMismatchError(
                    f"peer {self.peer_name!r}: getIdentity() serverId="
                    f"{reported_server_id!r} does not match configured "
                    f"server_id={expected_server_id!r}"
                )

            if self.group_registry is None:
                # Legacy mode: no group policy exists anywhere, so there is
                # no policy to steal; the wire-reported id is used for
                # display / echo-skip only.
                self._remote_server_id = reported_server_id

            sub = self._build_subscription()

            # Step 3: ServerEventStream — we stream events TO peer.
            server_event_future = self._open_server_event_stream(stub, sub)

            # Step 4: ClientFederateGroupsStream — announce our groups to peer.
            groups_send_future = self._open_client_groups_stream(stub)

            # Step 4b: re-verify the transport certificate now that all
            # session RPCs are bound. Closes the (exotic) window where the
            # channel transparently reconnects between the pre-RPC check and
            # stream establishment: any transport now carrying this
            # session's RPCs must still present the verified certificate,
            # or the session is torn down before going ACTIVE.
            if verified_fp is not None:
                self._recheck_dialed_cert(address, verified_fp)

            self._set_state(PeerState.ACTIVE)

            # Steps 5–7: receive events + groups from peer + health checks.
            self._run_event_loop(stub, sub, server_event_future, groups_send_future)

    def _wait_channel_ready(self, channel):
        """Block until the channel's transport is READY (or raise on timeout).

        Split out so unit tests can stub the wait; connection failures raise
        grpc.FutureTimeoutError into run_grpc_thread's reconnect path.
        Polled in short slices so request_stop() interrupts the wait promptly
        (a bare future.result(timeout=30) would pin the thread through
        shutdown and stall FederationManager.stop()'s bounded joins).
        """
        ready_future = grpc.channel_ready_future(channel)
        deadline = time.monotonic() + _CHANNEL_READY_TIMEOUT
        while True:
            if self._stop_event.is_set():
                ready_future.cancel()
                raise grpc.FutureTimeoutError(
                    "stop requested while waiting for channel readiness"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                ready_future.cancel()
                raise grpc.FutureTimeoutError(
                    f"channel to {self.peer_name} not ready within "
                    f"{_CHANNEL_READY_TIMEOUT:.0f}s"
                )
            try:
                ready_future.result(timeout=min(0.5, remaining))
                return
            except grpc.FutureTimeoutError:
                continue

    def _observe_dialed_fingerprints(self, address):
        """Observed cert fingerprints on live transports to *address*.

        Thin wrapper over cert_identity's channelz observation so unit tests
        can stub the observation without touching real channelz state.
        """
        from ots_federation.cert_identity import (  # pylint: disable=import-outside-toplevel
            observed_server_cert_fingerprints_for_target,
        )
        return observed_server_cert_fingerprints_for_target(address)

    def _resolve_dialed_cert_identity(self, address):
        """
        Resolve this session's policy identity from the dialed server's
        presented TLS certificate.

        Returns (fingerprint, policy_peer_id) on success. Raises
        PeerIdentityMismatchError when the certificate is unobservable,
        ambiguous (more than one distinct certificate on live transports to
        this target), or its fingerprint is not registered for any
        configured peer. Never falls through to the dialed stanza's policy,
        a default policy, or anything wire-reported.
        """
        fingerprints = self._observe_dialed_fingerprints(address)

        if not fingerprints:
            self.lgr.warning(
                "Peer %s: could not observe the dialed server's TLS "
                "certificate on the transport to %s (insecure channel, or "
                "channelz observation unavailable) — refusing session. "
                "Group policy requires an mTLS transport whose server "
                "certificate fingerprint is configured for a peer.",
                self.peer_name, address,
            )
            raise PeerIdentityMismatchError(
                f"peer {self.peer_name!r}: no server certificate observable "
                f"on transport to {address!r}; cannot bind policy identity"
            )

        if len(fingerprints) > 1:
            self.lgr.warning(
                "Peer %s: multiple distinct server certificates observed on "
                "live transports to %s (%s) — ambiguous identity, refusing "
                "session.",
                self.peer_name, address, sorted(fingerprints),
            )
            raise PeerIdentityMismatchError(
                f"peer {self.peer_name!r}: ambiguous server certificate on "
                f"transport to {address!r}"
            )

        (fingerprint,) = fingerprints
        policy_peer_id = self.group_registry.resolve_peer_id_by_fingerprint(
            fingerprint
        )
        if policy_peer_id is None:
            # Unrecognized certificate: exactly TAK Server's "fresh, no
            # inherited privilege" outcome, realized as refusal — an
            # outbound session with an empty policy could still reach the
            # [federation]-level default maps through map_inbound/
            # map_outbound's default fallthrough, so no synthetic identity
            # is created at all. The observed fingerprint is logged so the
            # operator can add `fingerprint = <value>` to the intended
            # peer's [federate:*] stanza (quarantine-until-configured, the
            # same breaking tightening as the inbound fix).
            self.lgr.warning(
                "Peer %s: dialed server at %s presented certificate with "
                "fingerprint %s, which is not configured for ANY peer — "
                "refusing session (no policy granted, regardless of any "
                "serverId the host reports). If this is the intended peer, "
                "add `fingerprint = %s` to its [federate:*] section.",
                self.peer_name, address, fingerprint, fingerprint,
            )
            raise PeerIdentityMismatchError(
                f"peer {self.peer_name!r}: dialed server's certificate "
                f"fingerprint {fingerprint} is not configured for any peer"
            )

        return fingerprint, policy_peer_id

    def _recheck_dialed_cert(self, address, verified_fp):
        """Require every live transport to *address* to still present the
        verified certificate; raise PeerIdentityMismatchError otherwise."""
        fingerprints = self._observe_dialed_fingerprints(address)
        if fingerprints != {verified_fp}:
            self.lgr.warning(
                "Peer %s: transport certificate to %s changed after "
                "verification (observed %s, verified %s) — refusing session.",
                self.peer_name, address, sorted(fingerprints), verified_fp,
            )
            raise PeerIdentityMismatchError(
                f"peer {self.peer_name!r}: transport certificate changed "
                f"after verification"
            )

    def _open_server_event_stream(self, stub, sub):
        """Open ServerEventStream (client→server streaming RPC)."""

        def _outbound_generator():
            yield fig_pb2.FederatedEvent()
            while not self._stop_event.is_set():
                try:
                    proto = self._outbound_q.get(timeout=1.0)
                    yield proto
                except queue.Empty:
                    continue

        return stub.ServerEventStream.future(
            _outbound_generator(), wait_for_ready=True
        )

    def _open_client_groups_stream(self, stub):
        """Announce our federated groups to peer."""
        announced: list = []
        if self.group_registry is not None:
            peer_id = self._remote_server_id or f"{self.peer_config.address}:{self.peer_config.port}"
            out_map = self.group_registry._outbound.get(peer_id, {})
            announced = list(out_map.values())

        def _groups_generator():
            yield fig_pb2.FederateGroups(federateGroups=announced)

        return stub.ClientFederateGroupsStream.future(
            _groups_generator(), wait_for_ready=True
        )

    def _run_event_loop(self, stub, sub, server_event_future, groups_send_future):
        """Receive ClientEventStream + HealthChecks until stop."""
        from ots_federation.codec import decode_federated_event  # pylint: disable=import-outside-toplevel

        health_interval = self.peer_config.health_check_interval
        last_health = time.monotonic()

        event_stream = stub.ClientEventStream(sub, wait_for_ready=True)
        groups_stream = stub.ServerFederateGroupsStream(sub, wait_for_ready=True)

        groups_thread = threading.Thread(
            target=self._drain_groups_stream,
            args=(groups_stream,),
            daemon=True,
            name=f"FederateGroups[{self.peer_name}]",
        )
        groups_thread.start()

        try:
            for fed_event_proto in event_stream:
                if self._stop_event.is_set():
                    break

                now = time.monotonic()
                if now - last_health >= health_interval:
                    self._do_health_check(stub)
                    last_health = now

                self._handle_inbound(fed_event_proto, decode_federated_event)

        finally:
            event_stream.cancel()
            groups_stream.cancel()
            server_event_future.cancel()
            groups_send_future.cancel()
            groups_thread.join(timeout=2.0)

    def _handle_inbound(self, proto, decode_fn):
        """
        Decode one FederatedEvent and enqueue via bridge.

        Applies inbound group policy. Silently drops
        events with no mappable local group or decode failures.
        """
        try:
            evt, fed_meta = decode_fn(proto, local_max_hops=self.local_max_hops)
        except Exception as exc:  # pylint: disable=broad-except
            self.lgr.warning("Failed to decode inbound FederatedEvent: %s", exc)
            return

        if evt is None:
            # Contact-only or XML-parse failure; already logged by codec.
            # Attempt to synthesize a CoT event from the ContactListEntry if
            # one is present. Inject via bridge → LocalBus → OTS.
            from ots_federation.codec import (  # pylint: disable=import-outside-toplevel
                decode_contact_entry, synthesize_contact_event,
            )
            contact = decode_contact_entry(proto)
            if contact is not None:
                synth_evt = synthesize_contact_event(contact)
                if synth_evt is not None:
                    self.lgr.debug(
                        "ContactListEntry uid=%s op=%s → synthesized CoT uid=%s",
                        contact.uid, contact.operation, synth_evt.uid,
                    )
                    self.bridge.enqueue(self, synth_evt)
            return

        # --- Inbound DELETE guard ---
        # Drop federated DELETE events unless allow_federated_delete is True.
        # CoT delete events carry type "t-x-d-d" (TAK standard).
        if not self.allow_federated_delete:
            etype = getattr(evt, "etype", "") or ""
            if etype.startswith(_COT_DELETE_TYPE_PREFIX):
                self.lgr.debug(
                    "Dropping inbound federated DELETE event %s (allow_federated_delete=False)",
                    getattr(evt, "uid", "?"),
                )
                return

        # --- Inbound group policy ---
        # Runs for group-less events too — admitted iff a wildcard accept_as
        # exists for this peer or globally.
        if self.group_registry is not None and self._remote_server_id:
            remote_groups = list(proto.federateGroups)
            local_groups = self.group_registry.map_inbound_groups(
                self._remote_server_id, remote_groups
            )
            if local_groups is None:
                self.lgr.debug(
                    "Inbound group policy: dropping event %s from peer %s "
                    "(no mappable local groups for remote groups %s)",
                    getattr(evt, "uid", "?"),
                    self._remote_server_id,
                    remote_groups,
                )
                return
            # Attach mapped local groups as sidecars (multi-hop relay).
            # evt.inbound_local_groups → bridge.drain passes to bus.inject
            #   for groups-exchange delivery.
            # evt.local_acl_groups → used by prepare_outbound_event if this
            #   event is ever relayed outbound to another peer (relay-sidecar).
            evt.inbound_local_groups = frozenset(local_groups)
            evt.local_acl_groups = frozenset(local_groups)

        evt.fed_meta = fed_meta
        self.bridge.enqueue(self, evt)

    def _drain_groups_stream(self, groups_stream):
        """Consume ServerFederateGroupsStream in a background thread."""
        try:
            for groups_msg in groups_stream:
                if self._stop_event.is_set():
                    break
                remote_groups = list(groups_msg.federateGroups)
                self.lgr.debug("Peer %s announced groups: %s", self.peer_name, remote_groups)
                if self.group_registry is not None and self._remote_server_id:
                    self.group_registry.update_from_federate_groups(
                        self._remote_server_id, remote_groups
                    )
        except grpc.RpcError as exc:
            if not self._stop_event.is_set():
                self.lgr.debug(
                    "ServerFederateGroupsStream closed for %s: %s",
                    self.peer_name,
                    exc.code() if hasattr(exc, "code") else exc,
                )

    def _do_health_check(self, stub):
        """Send HealthCheck RPC and log response."""
        try:
            req = fig_pb2.ClientHealth(
                status=fig_pb2.ClientHealth.ServingStatus.SERVING
            )
            resp = stub.HealthCheck(req)
            self.lgr.debug(
                "HealthCheck to %s: server status=%s",
                self.peer_name,
                fig_pb2.ServerHealth.ServingStatus.Name(resp.status),
            )
        except grpc.RpcError as exc:
            self.lgr.warning(
                "HealthCheck to %s failed: %s",
                self.peer_name,
                exc.code() if hasattr(exc, "code") else exc,
            )
