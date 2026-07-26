# tests/test_federation_loopback.py
# Bidirectional loopback integration test for the INBOUND federation server
# side (epic 3e28a2 Phase 3).
# Adapted from taky test_federation_loopback.py (taky-federation branch, commit e12a2af).
# Changes vs. taky original:
#   - Removed COTRouter + taky.config / taky.cot dependencies.
#   - RouterFakeBus (server_bus) replaces COTRouter: delivers inbound events to
#     bus.events and triggers on_outbound fan-out for the server→client path.
#   - FakeLocalSrc replaces UnittestTAKClient for locally-originated events.
#   - _server_drain_loop drains into server_bus (bridge.drain(server_bus)).
#   - c2s assertions use server_bus.events; client bridge inbound_q used for s2c.
#   - All imports updated: taky.cot.* → ots_federation.*.
# Unlike test_federation_integration.py (which fakes gRPC), THIS test stands up:
#   * a REAL FederationServer (FederatedChannelServicer) over a loopback mTLS
#     gRPC channel on 127.0.0.1, attached to a RouterFakeBus, and
#   * a REAL FederateClient that DIALS that server over the same loopback
#     channel using throwaway federation certs.
# Throwaway CA + server + client certs are generated in a tmp dir via
# gen_fed_ca's generate_ca / generate_peer_cert helpers.  They are NEVER
# committed (tmp dir, removed in tearDown).
# Asserts (epic 3e28a2 Phase 3 acceptance):
#   (1) Client → Server: a CoT event injected at the FederateClient is received
#       by the SERVER's bus (delivered locally, bus.events non-empty).
#   (2) Server → Client: an event originating on the SERVER reaches the
#       FederateClient (client_bridge.inbound_q non-empty).
#   (3) Loop prevention: an event whose provenance already contains the
#       receiver's server_id is dropped (not forwarded across the link).
#   (4) Group mapping: a TAKUser event federates with its group preserved.

import os
import queue
import select
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime as dt, timedelta

from ots_federation.bridge import FederationBridge
from ots_federation.bus import RouterFakeBus
from ots_federation.cert_identity import fingerprint_from_pem
from ots_federation.client import FederateClient, PeerState
from ots_federation.codec import FedMeta
from ots_federation.config import (
    FederatePeerConfig,
    FederationConfig,
    FederationSslConfig,
)
from ots_federation.gen_fed_ca import (
    generate_ca,
    generate_peer_cert,
    _write_cert,
    _write_private_key,
)
from ots_federation.manager import FederationManager
from ots_federation.models import Event
from ots_federation.models.takuser import TAKUser
from tests import FakeLocalSrc


def _gen_loopback_pki(tmp_dir):
    """Generate a throwaway federation CA + server cert + client cert in tmp_dir.

    Both server and client certs are signed by the same CA and carry an IP SAN
    of 127.0.0.1 so the loopback mTLS handshake validates the hostname.
    """
    ca_key, ca_cert = generate_ca(
        cn="loopback-fed-ca", org="ots-test", validity_days=2
    )

    server_key, server_cert = generate_peer_cert(
        cn="127.0.0.1",
        org="ots-test",
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=2,
        san_dns=["localhost"],
        san_ip=["127.0.0.1"],
        is_server=True,
    )
    client_key, client_cert = generate_peer_cert(
        cn="loopback-client",
        org="ots-test",
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=2,
        san_dns=["localhost"],
        san_ip=["127.0.0.1"],
        is_server=False,
    )

    paths = {
        "ca_crt": os.path.join(tmp_dir, "fed-ca.crt"),
        "server_crt": os.path.join(tmp_dir, "server.crt"),
        "server_key": os.path.join(tmp_dir, "server.key"),
        "client_crt": os.path.join(tmp_dir, "client.crt"),
        "client_key": os.path.join(tmp_dir, "client.key"),
    }
    _write_cert(paths["ca_crt"], ca_cert)
    _write_cert(paths["server_crt"], server_cert)
    _write_private_key(paths["server_key"], server_key)
    _write_cert(paths["client_crt"], client_cert)
    _write_private_key(paths["client_key"], client_key)
    return paths


def _make_geo_event(uid, etype="a-f-G-U-C"):
    from ots_federation.models import Point

    now = dt.utcnow()
    evt = Event(
        uid=uid,
        etype=etype,
        how="m-g",
        time=now,
        start=now,
        stale=now + timedelta(seconds=300),
    )
    evt.point = Point(lat=1.234, lon=-3.14, hae=0.0, ce=9.9, le=9999999.0)
    return evt


def _wait_until(predicate, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class FederationLoopbackTest(unittest.TestCase):
    """Real FederateClient ↔ real FederationServer over loopback mTLS.

    RouterFakeBus on the server side replaces COTRouter: inbound events from the
    client land in server_bus.events; on_outbound fan-out is triggered for s2c.
    """

    SERVER_ID = "OTS-SERVER"
    CLIENT_ID = "OTS-CLIENT"

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ots-fed-loopback-")
        self._pki = _gen_loopback_pki(self._tmp)
        with open(self._pki["client_crt"], "rb") as f:
            client_cert_fingerprint = fingerprint_from_pem(f.read())

        # --- SERVER side: FederationManager with inbound listener enabled ---
        server_ssl = FederationSslConfig(
            fed_ca_bundle=self._pki["ca_crt"],
            fed_cert=self._pki["server_crt"],
            fed_key=self._pki["server_key"],
        )
        self.server_cfg = FederationConfig(
            enabled=True,
            server_id=self.SERVER_ID,
            server_name="Loopback Server",
            max_hops=3,
            listen_enabled=True,
            listen_ip="127.0.0.1",
            listen_port=0,  # ephemeral — bound port read back after start
            # Identity binding (bind federation ACL decisions to the
            # authenticated cert fingerprint -- corrected implementation
            # after an earlier trust-on-first-use attempt was rejected in
            # verification): policy is now resolved SOLELY from the
            # connecting certificate's fingerprint against this peer's
            # `fingerprint` — declared server_id is a label only and is never
            # consulted for the policy decision. This loopback client
            # authenticates with a real mTLS certificate but declares no
            # [federate:*] stanza of its own, so its cert's fingerprint must
            # be explicitly registered here to be admitted at all; the group
            # policy itself (wildcard in, White out) is unchanged from
            # before the fix. The address/port below are never dialed — the
            # server only ever receives this peer inbound — the entry exists
            # purely to register the client cert's fingerprint and group
            # policy; FederationManager also spawns a harmless outbound dial
            # thread for it that fails to connect and is stopped cleanly in
            # tearDown.
            peers=[
                FederatePeerConfig(
                    name="loopback-client-identity",
                    enabled=True,
                    address="127.0.0.1",
                    port=1,
                    server_id=self.CLIENT_ID,
                    fingerprint=client_cert_fingerprint,
                    group_map_in="*:White",
                    group_map_out="White:White",
                ),
            ],
            ssl=server_ssl,
        )
        self.server_mgr = FederationManager(self.server_cfg)

        # RouterFakeBus: delivers inbound events + triggers on_outbound fan-out.
        # Replaces COTRouter for the server-side drain loop.
        self.server_bus = RouterFakeBus(self.server_mgr)

        self.server_mgr.start()
        self.bound_port = self.server_mgr.fed_server.bound_port

        # Drain the server bridge into the server bus on a side-thread so
        # inbound events from the client are delivered and fan-out occurs.
        self._server_drain_stop = threading.Event()
        self._server_drain_thread = threading.Thread(
            target=self._server_drain_loop, daemon=True
        )
        self._server_drain_thread.start()

        # A local source for triggering server-originated events (s2c path).
        self.local_src = FakeLocalSrc()

        # --- CLIENT side: a real FederateClient dialing the server ---
        self.client_bridge = FederationBridge()
        self.peer_cfg = FederatePeerConfig(
            name="server",
            enabled=True,
            address="127.0.0.1",
            port=self.bound_port,
            ca_cert=self._pki["ca_crt"],
            client_cert=self._pki["client_crt"],
            client_key=self._pki["client_key"],
            max_hops=3,
            reconnect_interval=1,
            health_check_interval=60,
        )
        self.client = FederateClient(
            peer_name="server",
            peer_config=self.peer_cfg,
            node_id=self.CLIENT_ID,
            bridge=self.client_bridge,
        )
        self._client_thread = threading.Thread(
            target=self.client.run_grpc_thread, daemon=True
        )
        self._client_thread.start()

        # Wait for the client to complete the handshake and reach ACTIVE.
        ok = _wait_until(
            lambda: self.client.state == PeerState.ACTIVE, timeout=15.0
        )
        self.assertTrue(
            ok, f"client never reached ACTIVE (state={self.client.state})"
        )
        self.assertEqual(self.client.remote_server_id, self.SERVER_ID)

    def tearDown(self):
        try:
            self.client.request_stop()
        except Exception:
            pass
        self._server_drain_stop.set()
        try:
            self.server_mgr.stop()
        except Exception:
            pass
        self._client_thread.join(timeout=5.0)
        self._server_drain_thread.join(timeout=5.0)
        try:
            self.client_bridge.close()
        except Exception:
            pass
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _server_drain_loop(self):
        """Mirror COTServer's select loop: drain the server bridge → server_bus."""
        rx = self.server_mgr.bridge.rx_fd
        while not self._server_drain_stop.is_set():
            try:
                r, _, _ = select.select([rx], [], [], 0.2)
                if r:
                    self.server_mgr.bridge.drain(self.server_bus)
            except (OSError, ValueError):
                break

    # ------------------------------------------------------------------

    def test_client_to_server(self):
        """(1) Event injected at the client reaches the SERVER's bus."""
        evt = _make_geo_event("c2s-uid")
        self.client.send_event(evt)

        received = _wait_until(
            lambda: not self.server_bus.events.empty(), timeout=10.0
        )
        self.assertTrue(received, "server never received the client→server event")
        _src, got = self.server_bus.events.get_nowait()
        self.assertEqual(got.uid, "c2s-uid")
        # The client stamped its own provenance on the way out.
        self.assertTrue(hasattr(got, "fed_meta"))
        self.assertIn(self.CLIENT_ID, got.fed_meta.seen_server_ids)

    def test_server_to_client(self):
        """(2) Event originating on the SERVER reaches the FederateClient.

        Uses a TAKUser/White event to satisfy the outbound group policy on the
        server side.  The server is configured with default_group_map_out=
        'White:White' (setUp) so White-group events flow to inbound clients.
        After the ticket-46f6dd fix, events with no determinable group are
        suppressed — a bare geo event without <__group> would be blocked.
        """
        from lxml import etree  # pylint: disable=import-outside-toplevel

        # Wait until the server registered the client's inbound outbound-link
        # (ClientEventStream open) so on_outbound can fan to it.
        ok = _wait_until(
            lambda: bool(self.server_mgr._inbound_links_snapshot()), timeout=10.0
        )
        self.assertTrue(ok, "server never registered an inbound peer link")

        # Build a TAKUser/White event (with <takv>) so it passes the server's
        # outbound group policy (default_group_map_out='White:White').
        detail_elm = etree.Element("detail")
        takv = etree.SubElement(detail_elm, "takv")
        for k in ("os", "version", "device", "platform"):
            takv.set(k, "x")
        contact = etree.SubElement(detail_elm, "contact")
        contact.set("callsign", "S2CTEST")
        contact.set("endpoint", "*:-1:stcp")
        uid_e = etree.SubElement(detail_elm, "uid")
        uid_e.set("Droid", "S2CTEST")
        grp = etree.SubElement(detail_elm, "__group")
        grp.set("name", "White")
        grp.set("role", "Team Member")
        user = TAKUser.from_elm(detail_elm, uid="s2c-uid")

        evt = _make_geo_event("s2c-uid")
        evt.detail = user
        #: set ACL groups sidecar so outbound policy can apply.
        # In production this is populated by the groups-exchange subscriber;
        # here we inject it directly to simulate a warm cache entry.
        evt.local_acl_groups = frozenset(["White"])

        # Trigger on_outbound from the server side with a local source.
        # RouterFakeBus.inject → on_outbound is called by RouterFakeBus
        # but here we want to originate (no fed_meta), so call on_outbound directly.
        self.server_mgr.on_outbound(self.local_src, evt)

        received = _wait_until(
            lambda: not self.client_bridge.inbound_q.empty(), timeout=10.0
        )
        self.assertTrue(received, "client never received the server→client event")
        _src, got = self.client_bridge.inbound_q.get_nowait()
        self.assertEqual(got.uid, "s2c-uid")
        self.assertTrue(hasattr(got, "fed_meta"))
        self.assertIn(self.SERVER_ID, got.fed_meta.seen_server_ids)

    def test_loop_prevention_across_link(self):
        """(3) An event whose provenance already contains the receiver's
        server_id is dropped — not forwarded across the link.

        We send (client → server) an event whose provenance already contains
        the SERVER's id. The server must still receive+route it locally, but
        must NOT echo it back to the client (loop guard + src-skip)."""
        evt = _make_geo_event("loop-uid")
        # Pre-stamp provenance so that after the client adds CLIENT_ID, the chain
        # is [SERVER_ID, CLIENT_ID]. When the server tries to forward back, SERVER_ID
        # is already present → dropped.
        evt.fed_meta = FedMeta(
            seen_server_ids=[self.SERVER_ID], current_hops=1, max_hops=3
        )
        self.client.send_event(evt)

        # Server receives + routes locally.
        received = _wait_until(
            lambda: not self.server_bus.events.empty(), timeout=10.0
        )
        self.assertTrue(received, "server never received the looped event")
        _src, got = self.server_bus.events.get_nowait()
        self.assertEqual(got.uid, "loop-uid")

        # The server must NOT echo it back to the client. Give it a moment.
        time.sleep(1.0)
        self.assertTrue(
            self.client_bridge.inbound_q.empty(),
            "loop prevention failed: event was echoed back to the client",
        )

    def test_group_mapping_preserved(self):
        """(4) A TAKUser event federates with its group preserved end-to-end."""
        from lxml import etree

        detail_elm = etree.Element("detail")
        takv = etree.SubElement(detail_elm, "takv")
        for k in ("os", "version", "device", "platform"):
            takv.set(k, "x")
        contact = etree.SubElement(detail_elm, "contact")
        contact.set("callsign", "GRPTEST")
        contact.set("endpoint", "*:-1:stcp")
        uid_e = etree.SubElement(detail_elm, "uid")
        uid_e.set("Droid", "GRPTEST")
        grp = etree.SubElement(detail_elm, "__group")
        grp.set("name", "Cyan")
        grp.set("role", "Team Member")
        user = TAKUser.from_elm(detail_elm, uid="grp-uid")

        evt = _make_geo_event("grp-uid")
        evt.detail = user

        self.client.send_event(evt)

        received = _wait_until(
            lambda: not self.server_bus.events.empty(), timeout=10.0
        )
        self.assertTrue(received, "server never received the group event")
        _src, got = self.server_bus.events.get_nowait()
        self.assertEqual(got.uid, "grp-uid")
        self.assertIsInstance(got.detail, TAKUser)
        # Phase-1 string migration: group is now a plain str, not Teams enum.
        self.assertEqual(got.detail.group, "Cyan")


class OutboundCertIdentityLoopbackTest(unittest.TestCase):
    """
    REAL-mTLS integration tests for the outbound cert-identity binding: a
    real FederateClient dials a real TLS gRPC FederatedChannel server over
    loopback, and the client's
    session policy identity must be resolved from the certificate the
    server ACTUALLY presented during the TLS handshake — observed through
    the live channelz socket, the real production mechanism — never from
    the serverId the server reports over getIdentity().

    Unlike FederateClientCertIdentityBindingTest (which stubs the
    observation), nothing here is mocked: TLS handshake, channelz
    observation, fingerprint resolution, and refusal all run for real.
    """

    REPORTED_WIRE_ID = "WIRE-REPORTED-ID"  # what the dialed server CLAIMS
    PEER_POLICY_KEY = "OTS-SERVER"         # what its cert actually resolves to

    def setUp(self):
        import grpc
        from concurrent import futures as cf

        from ots_federation.proto import fig_pb2, fig_pb2_grpc

        self._tmp = tempfile.mkdtemp(prefix="ots-fed-outid-")
        self._pki = _gen_loopback_pki(self._tmp)
        with open(self._pki["server_crt"], "rb") as f:
            self.server_cert_fingerprint = fingerprint_from_pem(f.read())

        reported_id = self.REPORTED_WIRE_ID

        class _MiniServicer(fig_pb2_grpc.FederatedChannelServicer):
            """Minimal real-TLS FederatedChannel peer. Reports a wire
            serverId that deliberately differs from any registry key so a
            policy binding to it is unambiguously detectable."""

            def getIdentity(self, request, context):
                return fig_pb2.Identity(
                    serverId=reported_id, name="mini-loopback"
                )

            def ServerEventStream(self, request_iterator, context):
                for _ in request_iterator:
                    pass
                return fig_pb2.Subscription()

            def ClientFederateGroupsStream(self, request_iterator, context):
                for _ in request_iterator:
                    pass
                return fig_pb2.Subscription()

            def ClientEventStream(self, request, context):
                while context.is_active():
                    time.sleep(0.05)
                return
                yield  # pragma: no cover — makes this a generator

            def ServerFederateGroupsStream(self, request, context):
                while context.is_active():
                    time.sleep(0.05)
                return
                yield  # pragma: no cover

            def HealthCheck(self, request, context):
                return fig_pb2.ServerHealth(
                    status=fig_pb2.ServerHealth.ServingStatus.SERVING
                )

        def _read(path):
            with open(path, "rb") as f:
                return f.read()

        self._grpc_server = grpc.server(cf.ThreadPoolExecutor(max_workers=8))
        fig_pb2_grpc.add_FederatedChannelServicer_to_server(
            _MiniServicer(), self._grpc_server
        )
        creds = grpc.ssl_server_credentials(
            [(_read(self._pki["server_key"]), _read(self._pki["server_crt"]))],
            root_certificates=_read(self._pki["ca_crt"]),
            require_client_auth=True,
        )
        self.bound_port = self._grpc_server.add_secure_port(
            "127.0.0.1:0", creds
        )
        self._grpc_server.start()

        self._client = None
        self._client_thread = None
        self._client_bridge = None

    def tearDown(self):
        if self._client is not None:
            try:
                self._client.request_stop()
            except Exception:
                pass
        try:
            self._grpc_server.stop(grace=0)
        except Exception:
            pass
        if self._client_thread is not None:
            self._client_thread.join(timeout=5.0)
        if self._client_bridge is not None:
            try:
                self._client_bridge.close()
            except Exception:
                pass
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _start_client(self, registry):
        self._client_bridge = FederationBridge()
        peer_cfg = FederatePeerConfig(
            name="mini-server",
            enabled=True,
            address="127.0.0.1",
            port=self.bound_port,
            ca_cert=self._pki["ca_crt"],
            client_cert=self._pki["client_crt"],
            client_key=self._pki["client_key"],
            max_hops=3,
            reconnect_interval=1,
            health_check_interval=60,
        )
        self._client = FederateClient(
            peer_name="mini-server",
            peer_config=peer_cfg,
            node_id="OTS-CLIENT",
            bridge=self._client_bridge,
            group_registry=registry,
        )
        self._observed_states = []
        original_set_state = self._client._set_state

        def _tracking_set_state(new_state):
            self._observed_states.append(new_state)
            original_set_state(new_state)

        self._client._set_state = _tracking_set_state
        self._client_thread = threading.Thread(
            target=self._client.run_grpc_thread, daemon=True
        )
        self._client_thread.start()
        return self._client

    def test_configured_server_cert_fingerprint_reaches_active_with_cert_key(self):
        """Honest peer: the dialed server's REAL presented cert resolves via
        the fingerprint table (observed through live channelz over real TLS)
        and the session's policy key is the registry key — NOT the
        unrelated serverId the server reported over getIdentity()."""
        from ots_federation.groups import (
            FederateGroupRegistry,
            FederatePeerGroupMap,
        )

        registry = FederateGroupRegistry()
        registry.add_peer_map(FederatePeerGroupMap(
            peer_id=self.PEER_POLICY_KEY, direction="both",
            remote_group="White", local_group="White",
        ))
        registry.register_fingerprint(
            self.server_cert_fingerprint, self.PEER_POLICY_KEY
        )

        client = self._start_client(registry)

        ok = _wait_until(
            lambda: client.state == PeerState.ACTIVE, timeout=15.0
        )
        self.assertTrue(
            ok, f"client never reached ACTIVE (state={client.state})"
        )
        self.assertEqual(
            client.remote_server_id, self.PEER_POLICY_KEY,
            "policy identity must be the cert-resolved registry key",
        )
        self.assertNotEqual(
            client.remote_server_id, self.REPORTED_WIRE_ID,
            "the wire-reported serverId must never become the policy key",
        )

    def test_unconfigured_server_cert_refused_never_active(self):
        """Attacker-shaped peer: a dialed host whose (real, fed-CA-signed)
        server cert fingerprint is NOT configured for any peer gets no
        session and no policy — regardless of the serverId it reports —
        and a differently-keyed victim peer's tables stay untouched."""
        from ots_federation.groups import (
            FederateGroupRegistry,
            FederatePeerGroupMap,
        )

        registry = FederateGroupRegistry()
        # A victim peer with a privileged map; note the dialed server's
        # actual cert fingerprint is deliberately NOT registered.
        registry.add_peer_map(FederatePeerGroupMap(
            peer_id=self.REPORTED_WIRE_ID, direction="both",
            remote_group="SECRET", local_group="SECRET",
        ))
        victim_fp = "AA:" * 31 + "AA"
        registry.register_fingerprint(victim_fp, self.REPORTED_WIRE_ID)

        client = self._start_client(registry)

        # The session must be refused: the client falls to RECONNECTING
        # after PeerIdentityMismatchError, without ever passing ACTIVE.
        ok = _wait_until(
            lambda: client.state == PeerState.RECONNECTING, timeout=15.0
        )
        self.assertTrue(
            ok,
            f"client never reached RECONNECTING (state={client.state})",
        )
        self.assertNotIn(PeerState.ACTIVE, self._observed_states)
        self.assertIsNone(
            client.remote_server_id,
            "no policy identity may bind for an unconfigured server cert, "
            "regardless of the reported serverId",
        )
        # Victim tables intact and never handed to this session.
        self.assertEqual(
            registry.map_inbound_groups(self.REPORTED_WIRE_ID, ["SECRET"]),
            {"SECRET"},
        )


if __name__ == "__main__":
    unittest.main()
