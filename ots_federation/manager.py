# taky/cot/federation/manager.py
# Stream: transport
# FederationManager (a.k.a. FederationBroker in) is injected into
# COTRouter.__init__ as self.fed_broker. It owns the lifecycle of all federate peer
# connections (DISABLED → CONNECTING → HANDSHAKING → ACTIVE ↔ RECONNECTING → DRAINING)
# and the gRPC side-thread per peer.
# COTRouter integration:
#   After broadcast/group_broadcast return, router calls:
#       self.fed_broker.on_outbound(src, evt)
#   This is a no-op when federation is disabled (NullFederationManager below).
# Owns: FederateClient instances (one per enabled peer), inbound event routing.
# Does NOT own: codec (codec.py), group mapping (groups.py), TLS context (tls.py)
#               config parsing (config.py).

import logging
import threading

from ots_federation.bridge import FederationBridge
from ots_federation.config import FederationConfig
from ots_federation.groups import FederateGroupRegistry, parse_group_map

# NOTE: taky.cot.federation.client (and the gRPC stack it pulls in via
# `import grpc`) is imported lazily inside FederationManager.__init__, NOT at
# module top level. This keeps importing this module — and therefore taky.cot
# at large — free of a hard grpcio dependency. NullFederationManager and the
# whole federation-disabled path stay grpc-free; grpc is only required once a
# live FederationManager is constructed, i.e. [federation] is enabled in
# taky.conf (see server.py:_build_fed_manager / router.py default broker).


class NullFederationManager:
    """
    Drop-in no-op used when federation is disabled.

    COTRouter always has a fed_broker; this avoids None-checks throughout
    the routing path.
    """

    def on_outbound(self, src, evt):
        """Called by COTRouter after local broadcast. No-op when disabled."""

    def start(self):
        """Called at server startup. No-op."""

    def stop(self):
        """Called at server shutdown. No-op."""


class FederationManager:
    """
    Broker that manages all federate peer connections.

    One FederationManager exists per taky COT server instance. It is injected
    into COTRouter at construction time.§7.

    Lifecycle states per peer:
        DISABLED → CONNECTING → HANDSHAKING → ACTIVE ↔ RECONNECTING → DRAINING

    Threading model:
        Each FederateClient runs a gRPC channel on a dedicated side-thread.
        Inbound events arrive via queue.Queue (inbound_q); outbound events are
        delivered via FederateClient.send_event which enqueues on the gRPC thread.
        A socketpair wakeup fd (implemented in bridge.py) makes the inbound queue
        selectable from taky's main select loop.

    Integration for COTServer (integration stream wires these):
        1. Add manager.bridge.rx_fd to select read-set.
        2. When rx_fd is readable, call manager.bridge.drain(router).
        3. After broadcast/group_broadcast: call manager.on_outbound(src, evt).

    Parameters
    ----------
    config : FederationConfig
        Parsed federation configuration.
    """

    def __init__(self, config: "FederationConfig"):
        self.lgr = logging.getLogger(self.__class__.__name__)
        self.config = config

        # Lazy grpc-stack import (see module note): only reached when a live
        # FederationManager is built, i.e. federation is enabled. Keeps
        # taky.cot importable without grpcio on the disabled path.
        from ots_federation.client import (  # pylint: disable=import-outside-toplevel
            FederateClient,
            PeerState,
        )

        self._peer_state = PeerState
        self.bridge = FederationBridge()

        # Build the group registry from all configured peer group maps.
        #: registry is the single source of truth for inbound and
        # outbound group filtering. Built here once; passed to FederateClient
        # instances and FederatedChannelServicer..
        self.group_registry = self._build_group_registry(config)

        # Build one FederateClient per enabled peer.
        self._clients = {}  # peer_name → FederateClient
        self._threads = {}  # peer_name → threading.Thread

        # Inbound server (taky↔taky server side). Built lazily in start when
        # listen is enabled.
        self._fed_server = None

        # Per-peer inbound outbound-links, keyed by the connecting peer's
        # server_id. A peer may (re)connect, so each id maps to a list of live
        # links. Mutated from gRPC server threads → guard with a lock.
        self._inbound_links = {}  # peer_server_id → list[_InboundPeerLink]
        self._inbound_lock = threading.Lock()

        for peer_cfg in config.peers:
            if not peer_cfg.enabled:
                self.lgr.info("Peer %s: disabled in config, skipping", peer_cfg.name)
                continue

            client = FederateClient(
                peer_name=peer_cfg.name,
                peer_config=peer_cfg,
                node_id=config.server_id,
                bridge=self.bridge,
                group_registry=self.group_registry,
                allow_federated_delete=getattr(config, "allow_federated_delete", False),
                local_max_hops=getattr(config, "max_hops", 3),
            )
            self._clients[peer_cfg.name] = client
            self.lgr.info(
                "Registered federate peer: %s → %s:%d",
                peer_cfg.name,
                peer_cfg.address,
                peer_cfg.port,
            )

    @staticmethod
    def _build_group_registry(config: "FederationConfig") -> FederateGroupRegistry:
        """
        Build a FederateGroupRegistry from all [federate:*] peer config sections
        plus the [federation]-level default group policy..

        Each peer's group_map_in / group_map_out strings are parsed via
        parse_group_map and registered under the provisional key
        "address:port" (and additionally under the declared server_id when
        set, Option-1A). At runtime, BOTH directions resolve a live
        connection to one of these keys exclusively via the peer's
        configured certificate fingerprint (register_fingerprint /
        resolve_peer_id_by_fingerprint, applied the same way for both
        inbound and outbound); the wire-reported serverId never selects a
        key, and FederateClient no longer rekeys the registry from
        getIdentity().

        The [federation]-level default_group_map_in / default_group_map_out keys
        supply fallback policy for any peer (inbound OR outgoing) whose server_id
        has no explicit per-peer table entry. This is the
        primary mechanism for opening inbound TAK Server peers that have no
        [federate:*] section.

        Parameters
        ----------
        config : FederationConfig

        Returns
        -------
        FederateGroupRegistry
        """
        lgr = logging.getLogger("FederationManager")
        registry = FederateGroupRegistry()

        # --- [federation]-level default group policy ----------
        if config.default_group_map_in:
            try:
                default_in = parse_group_map(config.default_group_map_in, "in")
            except ValueError as exc:
                lgr.warning(
                    "[federation] invalid default_group_map_in %r: %s",
                    config.default_group_map_in, exc
                )
                default_in = []
            if default_in:
                registry.set_default_in_map(default_in)
                lgr.info(
                    "Federation default inbound group policy: %r",
                    config.default_group_map_in,
                )

        if config.default_group_map_out:
            try:
                default_out = parse_group_map(config.default_group_map_out, "out")
            except ValueError as exc:
                lgr.warning(
                    "[federation] invalid default_group_map_out %r: %s",
                    config.default_group_map_out, exc
                )
                default_out = []
            if default_out:
                registry.set_default_out_map(default_out)
                lgr.info(
                    "Federation default outbound group policy: %r",
                    config.default_group_map_out,
                )

        # --- Per-peer maps (keyed by provisional address:port) ----------------
        for peer_cfg in config.peers:
            if not peer_cfg.enabled:
                continue
            # Use the peer address:port as the provisional peer_id key.
            provisional_id = f"{peer_cfg.address}:{peer_cfg.port}"

            # Shortcut-1 Option-1A: if the operator declared an expected
            # server_id for this peer, also key the registry under that string
            # so inbound-only peers (we never dial them) are matched to this
            # stanza's policy rather than falling through to global defaults.
            declared_server_id = getattr(peer_cfg, "server_id", "")

            # Fingerprint-keyed identity binding: register each of this
            # peer's configured certificate fingerprints
            # (comma-separated when the peer's client and server TLS certs
            # are distinct leaves) against whichever key its group tables
            # are registered under (declared server_id when set, else the
            # provisional address:port key). This table is the ONLY way a
            # live connection — inbound (fed_server.py resolving the
            # connecting client cert) or outbound (client.py resolving the
            # dialed server's presented cert) — is matched to a policy;
            # neither direction ever trusts a wire-supplied serverId. A peer
            # with no `fingerprint` configured is simply absent from this
            # table — its inbound connections are quarantined and outbound
            # dials to it refused until the operator sets one; there is no
            # default to fall back to.
            declared_fingerprint = getattr(peer_cfg, "fingerprint", "")
            if declared_fingerprint:
                fingerprint_peer_key = declared_server_id or provisional_id
                for fp_part in declared_fingerprint.split(","):
                    fp_part = fp_part.strip()
                    if not fp_part:
                        continue
                    registry.register_fingerprint(fp_part, fingerprint_peer_key)
                lgr.info(
                    "Peer %s: registered certificate fingerprint(s) for "
                    "identity binding (resolve to %r)",
                    peer_cfg.name, fingerprint_peer_key,
                )

            # Wire fallback_when_no_group_mappings.
            if getattr(peer_cfg, "fallback_when_no_group_mappings", False):
                registry.set_fallback_allow(provisional_id, True)
                if declared_server_id:
                    registry.set_fallback_allow(declared_server_id, True)

            if peer_cfg.group_map_in:
                try:
                    entries = parse_group_map(peer_cfg.group_map_in, "in")
                except ValueError as exc:
                    lgr.warning(
                        "Peer %s: invalid group_map_in %r: %s",
                        peer_cfg.name, peer_cfg.group_map_in, exc
                    )
                    entries = []
                for entry in entries:
                    entry.peer_id = provisional_id
                    registry.add_peer_map(entry)
                # Also register under declared server_id (1A).
                if declared_server_id:
                    for entry in entries:
                        entry.peer_id = declared_server_id
                        registry.add_peer_map(entry)

            if peer_cfg.group_map_out:
                try:
                    entries = parse_group_map(peer_cfg.group_map_out, "out")
                except ValueError as exc:
                    lgr.warning(
                        "Peer %s: invalid group_map_out %r: %s",
                        peer_cfg.name, peer_cfg.group_map_out, exc
                    )
                    entries = []
                for entry in entries:
                    entry.peer_id = provisional_id
                    registry.add_peer_map(entry)
                # Also register under declared server_id (1A).
                if declared_server_id:
                    for entry in entries:
                        entry.peer_id = declared_server_id
                        registry.add_peer_map(entry)

            if declared_server_id:
                lgr.info(
                    "Peer %s: also registered under declared server_id %r (1A)",
                    peer_cfg.name, declared_server_id,
                )

        return registry

    @property
    def clients(self):
        """Read-only view of peer name → FederateClient mapping."""
        return dict(self._clients)

    @property
    def fed_server(self):
        """The inbound FederationServer, or None when listen is disabled."""
        return self._fed_server

    # ------------------------------------------------------------------
    # Inbound-link registry (called from FederationServer gRPC threads)
    # ------------------------------------------------------------------
    def register_inbound_link(self, peer_server_id, link):
        """
        Register a per-connection outbound link to an inbound peer.

        Called by FederatedChannelServicer.ClientEventStream when a peer opens
        its server→client event stream. on_outbound then fans events to this
        link. Thread-safe.
        """
        with self._inbound_lock:
            self._inbound_links.setdefault(peer_server_id, []).append(link)
        self.lgr.info("Registered inbound peer link: %s", peer_server_id)

    def deregister_inbound_link(self, peer_server_id, link):
        """
        Deregister an inbound-peer link when its ClientEventStream closes.

        Thread-safe.
        """
        with self._inbound_lock:
            links = self._inbound_links.get(peer_server_id)
            if links and link in links:
                links.remove(link)
                if not links:
                    del self._inbound_links[peer_server_id]
        self.lgr.info("Deregistered inbound peer link: %s", peer_server_id)

    def _inbound_links_snapshot(self):
        """Return a flat list of (peer_server_id, link) under the lock."""
        with self._inbound_lock:
            return [
                (pid, link)
                for pid, links in self._inbound_links.items()
                for link in links
            ]

    def on_outbound(self, src, evt):
        """
        Called by COTRouter after local broadcast/group_broadcast.

        Fans the event out to BOTH:
          - all ACTIVE outbound FederateClients, and
          - all connected inbound-peer links
        skipping the source and applying loop prevention. Each link's
        send_event runs the SAME shared loop/hop helper
        (codec.prepare_outbound_event) before encoding.

        Parameters
        ----------
        src : TAKClient
            The originating client (local socket, FederateClient, or inbound
            _InboundPeerLink). Used to prevent echoing back to the source.
        evt : models.Event
            The CoT event that was just broadcast locally.
        """
        # Outbound client links.
        for peer_name, client in self._clients.items():
            if client is src:
                continue
            if client.state != self._peer_state.ACTIVE:
                continue
            client.send_event(evt)

        # Inbound peer links (taky↔taky server side). The shared send helper
        # already drops events whose provenance contains a receiver's server_id
        # but we additionally src-skip by identity to avoid an immediate echo to
        # the very connection that delivered the event.
        src_peer_id = getattr(src, "remote_server_id", None)
        for peer_server_id, link in self._inbound_links_snapshot():
            if link is src:
                continue
            if src_peer_id is not None and peer_server_id == src_peer_id:
                # Don't echo back to the peer that sent this event.
                continue
            link.send_event(evt)

    def start(self):
        """
        Start all enabled federate peer connections, plus the inbound server.

        Spawns one daemon side-thread per enabled outbound peer
        and — when [federation] listen_enabled is set — starts the inbound
        FederatedChannel gRPC server so remote peers can connect to us
        . Called from COTServer startup after the main select loop
        is ready.
        """
        for peer_name, client in self._clients.items():
            t = threading.Thread(
                target=client.run_grpc_thread,
                name=f"FederateGRPC[{peer_name}]",
                daemon=True,
            )
            self._threads[peer_name] = t
            t.start()
            self.lgr.info("Started gRPC thread for peer: %s", peer_name)

        if getattr(self.config, "listen_enabled", False):
            self._start_fed_server()

    def _start_fed_server(self):
        """
        Build and start the inbound FederationServer from config.

        Server identity = [federation_ssl] fed_cert/fed_key; client-cert
        verification root = fed_ca_bundle; require_client_auth=True. When the
        cert material is absent the server starts on an INSECURE port (testing
        only) so loopback integration tests can run without certs.
        """
        # Local import avoids importing grpc server machinery (and its thread
        # pool) when federation listening is disabled.
        from ots_federation.fed_server import FederationServer  # pylint: disable=import-outside-toplevel

        ssl_cfg = self.config.ssl
        server_credentials = None
        if ssl_cfg.fed_ca_bundle and ssl_cfg.fed_cert and ssl_cfg.fed_key:
            from ots_federation.tls import build_grpc_server_credentials  # pylint: disable=import-outside-toplevel

            key_pw = ssl_cfg.fed_key_pw.encode("utf-8") if ssl_cfg.fed_key_pw else None
            server_credentials = build_grpc_server_credentials(
                fed_ca_bundle_path=ssl_cfg.fed_ca_bundle,
                fed_cert_path=ssl_cfg.fed_cert,
                fed_key_path=ssl_cfg.fed_key,
                fed_key_password=key_pw,
                require_client_auth=True,
            )
        else:
            self.lgr.warning(
                "Federation listen enabled but [federation_ssl] cert material is "
                "incomplete; starting INSECURE inbound server (testing only)"
            )

        self._fed_server = FederationServer(
            listen_ip=self.config.listen_ip,
            listen_port=self.config.listen_port,
            server_id=self.config.server_id,
            server_name=self.config.server_name,
            bridge=self.bridge,
            manager=self,
            default_max_hops=self.config.max_hops,
            server_credentials=server_credentials,
            group_registry=self.group_registry,
            allow_federated_delete=getattr(self.config, "allow_federated_delete", False),
            rol_log_sink=getattr(self.config, "rol_log_sink", ""),
            max_workers=getattr(self.config, "grpc_max_workers", 64),
        )
        bound = self._fed_server.start()
        self.lgr.info(
            "Inbound FederationServer started on %s:%d",
            self.config.listen_ip,
            bound,
        )

    def stop(self):
        """
        Gracefully drain and close all federate peer connections.

        Signals each client to stop, then joins all threads (up to 5s each).
        Finally closes the bridge socketpair.
        """
        self.lgr.info("FederationManager stopping (%d peers)", len(self._clients))

        # Stop the inbound server first so no new RPCs / links arrive while we
        # drain. This also unblocks ClientEventStream generators.
        if self._fed_server is not None:
            try:
                self._fed_server.stop(grace=5.0)
            except Exception as exc:  # pylint: disable=broad-except
                self.lgr.warning("Error stopping inbound FederationServer: %s", exc)
            self._fed_server = None

        # Signal any still-registered inbound links to finish.
        for _pid, link in self._inbound_links_snapshot():
            link.request_stop()

        # Signal all clients to stop.
        for client in self._clients.values():
            client.request_stop()

        # Join all gRPC threads.
        for peer_name, t in self._threads.items():
            t.join(timeout=5.0)
            if t.is_alive():
                self.lgr.warning(
                    "gRPC thread for peer %s did not stop in 5s", peer_name
                )

        # Close the bridge socketpair.
        self.bridge.close()
        self.lgr.info("FederationManager stopped")
