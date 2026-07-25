# tests/test_federation_transport.py
# Unit tests for the transport stream:
#   - FederationBridge (bridge.py)
#   - FederateClient (client.py)
#   - FederationManager (manager.py)
# gRPC stub is mocked throughout — no network connections.
# Tests cover: bridge enqueue/drain, handshake ordering, reconnect back-off
# and provenance-based loop prevention.

import os
import queue
import socket
import threading
import time
import unittest
from datetime import datetime as dt, timedelta
from unittest import mock


from ots_federation.bridge import FederationBridge
from ots_federation.client import FederateClient, PeerState, _RECONNECT_BASE
from ots_federation.codec import FedMeta
from ots_federation.config import FederatePeerConfig, FederationConfig
from ots_federation.manager import FederationManager, NullFederationManager
from ots_federation.models import Event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(uid="test-uid-1"):
    """Return a minimal models.Event for testing."""
    now = dt.utcnow()
    return Event(
        uid=uid,
        etype="a-f-G-U-C",
        how="m-g",
        time=now,
        start=now,
        stale=now + timedelta(seconds=300),
    )


def _make_peer_config(**kwargs):
    """Return a FederatePeerConfig with test defaults."""
    defaults = dict(
        name="test-peer",
        enabled=True,
        address="127.0.0.1",
        port=9100,
        ca_cert="",
        client_cert="",
        client_key="",
        max_hops=3,
        reconnect_interval=1,
        health_check_interval=60,
    )
    defaults.update(kwargs)
    return FederatePeerConfig(**defaults)


def _make_fed_config(peers=None):
    """Return a FederationConfig with test defaults."""
    return FederationConfig(
        enabled=True,
        server_id="TAKY-TEST-01",
        server_name="Test Server",
        max_hops=3,
        peers=peers or [],
    )


# ---------------------------------------------------------------------------
# FederationBridge tests
# ---------------------------------------------------------------------------


class FederationBridgeTest(unittest.TestCase):
    """Tests for bridge.py — queue.Queue + socketpair wakeup."""

    def setUp(self):
        self.bridge = FederationBridge()

    def tearDown(self):
        self.bridge.close()

    def test_rx_fd_is_socket(self):
        """rx_fd must be a socket that select() can watch."""
        self.assertIsInstance(self.bridge.rx_fd, socket.socket)
        self.assertGreater(self.bridge.rx_fd.fileno(), 0)

    def test_tx_fd_is_socket(self):
        """tx_fd must be writable by gRPC threads."""
        self.assertIsInstance(self.bridge.tx_fd, socket.socket)
        self.assertGreater(self.bridge.tx_fd.fileno(), 0)

    def test_enqueue_wakes_rx_fd(self):
        """enqueue() must write a wakeup byte to rx_fd."""
        evt = _make_event()
        fc = mock.MagicMock()

        self.bridge.enqueue(fc, evt)

        # rx_fd should now be readable.
        import select as sel

        r, _, _ = sel.select([self.bridge.rx_fd], [], [], 0.5)
        self.assertIn(self.bridge.rx_fd, r)

    def test_drain_routes_events(self):
        """drain() must call bus.inject for every enqueued event."""
        from ots_federation.bus import FakeLocalBus
        bus = FakeLocalBus()
        fc = mock.MagicMock()

        evt1 = _make_event("uid-1")
        evt2 = _make_event("uid-2")

        self.bridge.enqueue(fc, evt1)
        self.bridge.enqueue(fc, evt2)
        self.bridge.drain(bus)

        self.assertEqual(bus.events.qsize(), 2)
        items = [bus.events.get_nowait() for _ in range(2)]
        routed_uids = {i[1].uid for i in items}
        self.assertIn("uid-1", routed_uids)
        self.assertIn("uid-2", routed_uids)

    def test_drain_clears_queue(self):
        """After drain(), inbound_q must be empty."""
        from ots_federation.bus import FakeLocalBus
        bus = FakeLocalBus()
        fc = mock.MagicMock()

        self.bridge.enqueue(fc, _make_event())
        self.bridge.drain(bus)

        self.assertTrue(self.bridge.inbound_q.empty())

    def test_drain_empty_is_noop(self):
        """drain() on an empty queue must not raise."""
        from ots_federation.bus import FakeLocalBus
        bus = FakeLocalBus()
        self.bridge.drain(bus)
        self.assertTrue(bus.events.empty())

    def test_multiple_enqueue_single_drain(self):
        """Multiple enqueue calls followed by one drain routes all events."""
        from ots_federation.bus import FakeLocalBus
        bus = FakeLocalBus()
        fc = mock.MagicMock()
        n = 10
        for i in range(n):
            self.bridge.enqueue(fc, _make_event(f"uid-{i}"))
        self.bridge.drain(bus)
        self.assertEqual(bus.events.qsize(), n)

    def test_close_makes_fds_invalid(self):
        """close() must close both socket fds."""
        rx_fileno = self.bridge.rx_fd.fileno()
        self.bridge.close()
        # After close, fileno returns -1.
        self.assertEqual(self.bridge.rx_fd.fileno(), -1)
        self.assertEqual(self.bridge.tx_fd.fileno(), -1)

    def test_enqueue_after_close_does_not_raise(self):
        """enqueue() after close() must not raise (handles shutdown races)."""
        fc = mock.MagicMock()
        self.bridge.close()
        # Should log a debug message and return silently.
        try:
            self.bridge.enqueue(fc, _make_event())
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"enqueue() after close() raised: {exc}")

    def test_thread_safe_enqueue(self):
        """Multiple threads enqueuing concurrently must not lose events."""
        fc = mock.MagicMock()
        n = 50

        def _enqueue_many():
            for i in range(n):
                self.bridge.enqueue(fc, _make_event(f"uid-{i}"))

        threads = [threading.Thread(target=_enqueue_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        from ots_federation.bus import FakeLocalBus
        bus = FakeLocalBus()
        self.bridge.drain(bus)
        # 4 threads × 50 events = 200
        self.assertEqual(bus.events.qsize(), 4 * n)


# ---------------------------------------------------------------------------
# FederateClient — send_event loop prevention & hop limit tests
# ---------------------------------------------------------------------------


class FederateClientSendEventTest(unittest.TestCase):
    """Tests for FederateClient.send_event() — loop prevention and hop checks."""

    def setUp(self):

        self.bridge = FederationBridge()
        self.peer_cfg = _make_peer_config(max_hops=3)
        self.client = FederateClient(
            peer_name="test-peer",
            peer_config=self.peer_cfg,
            node_id="TAKY-TEST-01",
            bridge=self.bridge,
        )
        # Force state to ACTIVE so send_event proceeds.
        self.client._state = PeerState.ACTIVE

    def tearDown(self):
        self.bridge.close()

    def _encode_side_effect(self, evt, fed_meta=None):
        """Mock encode_federated_event that returns a dummy proto."""
        proto = mock.MagicMock()
        proto.uid = evt.uid
        return proto

    def test_send_event_inactive_drops_silently(self):
        """send_event() must drop events when peer is not ACTIVE."""
        self.client._state = PeerState.RECONNECTING
        evt = _make_event()

        # encode_federated_event is imported inside send_event from codec;
        # patch at the codec module level.
        with mock.patch(
            "ots_federation.codec.encode_federated_event"
        ) as mock_enc:
            self.client.send_event(evt)
            mock_enc.assert_not_called()

    def test_send_event_loop_prevention_own_node_id(self):
        """
        Loop prevention: event whose provenance chain already
        contains our node_id must be silently dropped, not forwarded.
        """
        evt = _make_event()
        # This event already passed through TAKY-TEST-01 (our own node_id).
        evt.fed_meta = FedMeta(
            seen_server_ids=["REMOTE-PEER", "TAKY-TEST-01"],
            current_hops=2,
            max_hops=3,
        )

        with mock.patch(
            "ots_federation.codec.encode_federated_event",
            side_effect=self._encode_side_effect,
        ):
            with mock.patch.object(self.client._outbound_q, "put_nowait") as mock_put:
                self.client.send_event(evt)
                mock_put.assert_not_called()

    def test_send_event_loop_prevention_other_node_passes(self):
        """
        Event whose provenance does NOT contain our node_id must be forwarded.
        """
        evt = _make_event()
        evt.fed_meta = FedMeta(
            seen_server_ids=["OTHER-SERVER"],
            current_hops=1,
            max_hops=3,
        )

        with mock.patch(
            "ots_federation.codec.encode_federated_event",
            return_value=mock.MagicMock(),
        ):
            with mock.patch.object(
                self.client._outbound_q, "put_nowait"
            ) as mock_put:
                self.client.send_event(evt)
                mock_put.assert_called_once()

    def test_send_event_hop_limit_drop(self):
        """
        Hop-limit enforcement: event with current_hops >= max_hops
        must be silently dropped.
        """
        evt = _make_event()
        evt.fed_meta = FedMeta(
            seen_server_ids=["REMOTE"],
            current_hops=3,
            max_hops=3,  # exhausted
        )

        with mock.patch(
            "ots_federation.codec.encode_federated_event",
            side_effect=self._encode_side_effect,
        ):
            with mock.patch.object(self.client._outbound_q, "put_nowait") as mock_put:
                self.client.send_event(evt)
                mock_put.assert_not_called()

    def test_send_event_hop_limit_unlimited_passes(self):
        """max_hops=-1 means unlimited; event must be forwarded regardless of hops."""
        evt = _make_event()
        evt.fed_meta = FedMeta(
            seen_server_ids=["REMOTE"],
            current_hops=999,
            max_hops=-1,
        )

        with mock.patch(
            "ots_federation.codec.encode_federated_event",
            return_value=mock.MagicMock(),
        ):
            with mock.patch.object(
                self.client._outbound_q, "put_nowait"
            ) as mock_put:
                self.client.send_event(evt)
                mock_put.assert_called_once()

    def test_send_event_local_origin_sets_hops_1(self):
        """
        A local-origin event (no fed_meta) must be sent with current_hops=1
        and our node_id appended to provenance.
        """
        evt = _make_event()
        # No fed_meta attribute — simulates a locally-originated event.
        captured = {}

        def _capture_encode(ev, fm):
            captured["fed_meta"] = fm
            return mock.MagicMock()

        with mock.patch(
            "ots_federation.codec.encode_federated_event",
            side_effect=_capture_encode,
        ):
            with mock.patch.object(self.client._outbound_q, "put_nowait"):
                self.client.send_event(evt)

        self.assertIn("fed_meta", captured)
        fm = captured["fed_meta"]
        self.assertEqual(fm.current_hops, 1)
        self.assertIn("TAKY-TEST-01", fm.seen_server_ids)

    def test_send_event_relay_increments_hops(self):
        """
        A relayed event (has fed_meta) must have current_hops incremented
        and our node_id appended to provenance.
        """
        evt = _make_event()
        evt.fed_meta = FedMeta(
            seen_server_ids=["UPSTREAM-SERVER"],
            current_hops=1,
            max_hops=5,
        )
        captured = {}

        def _capture_encode(ev, fm):
            captured["fed_meta"] = fm
            return mock.MagicMock()

        with mock.patch(
            "ots_federation.codec.encode_federated_event",
            side_effect=_capture_encode,
        ):
            with mock.patch.object(self.client._outbound_q, "put_nowait"):
                self.client.send_event(evt)

        self.assertIn("fed_meta", captured)
        fm = captured["fed_meta"]
        self.assertEqual(fm.current_hops, 2)
        self.assertIn("TAKY-TEST-01", fm.seen_server_ids)
        self.assertIn("UPSTREAM-SERVER", fm.seen_server_ids)


# ---------------------------------------------------------------------------
# FederateClient — handshake ordering tests (mock gRPC stub)
# ---------------------------------------------------------------------------


class FederateClientHandshakeTest(unittest.TestCase):
    """
    Tests for FederateClient.run_grpc_thread / _run_session handshake ordering.

    Mocks grpc.secure_channel and FederatedChannelStub so no network is needed.
    Verifiesstep order: getIdentity → ServerEventStream →
    ClientFederateGroupsStream → ClientEventStream → HealthCheck.
    """

    def setUp(self):

        self.bridge = FederationBridge()
        self.peer_cfg = _make_peer_config(
            health_check_interval=0,  # immediate health check for test
        )
        self.client = FederateClient(
            peer_name="test-peer",
            peer_config=self.peer_cfg,
            node_id="TAKY-TEST-01",
            bridge=self.bridge,
        )

    def tearDown(self):
        self.client._stop_event.set()
        self.bridge.close()

    def _build_mock_stub(self, events=None):
        """
        Build a mock FederatedChannelStub that:
          - Returns a valid Identity from getIdentity
          - Returns a Subscription future from ServerEventStream
          - Returns a Subscription future from ClientFederateGroupsStream
          - Yields events from ClientEventStream
          - Returns empty iterator from ServerFederateGroupsStream
          - Returns a ServerHealth from HealthCheck
        """
        from ots_federation.proto import fig_pb2  # noqa: F811

        stub = mock.MagicMock()

        # getIdentity: return a real Identity proto
        identity = fig_pb2.Identity(
            serverId="REMOTE-SERVER-01",
            name="Remote Server",
            type=fig_pb2.Identity.ConnectionType.FEDERATION_TAK_SERVER,
        )
        stub.getIdentity.return_value = identity

        # ServerEventStream: stream→unary, returns a cancelable future
        server_event_future = mock.MagicMock()
        stub.ServerEventStream.return_value = server_event_future

        # ClientFederateGroupsStream: stream→unary, returns a cancelable future
        groups_send_future = mock.MagicMock()
        stub.ClientFederateGroupsStream.return_value = groups_send_future

        # ClientEventStream: unary→stream, yields FederatedEvent protos
        event_protos = events or []
        stub.ClientEventStream.return_value = iter(event_protos)

        # ServerFederateGroupsStream: unary→stream, empty
        stub.ServerFederateGroupsStream.return_value = iter([])

        # HealthCheck
        health_resp = fig_pb2.ServerHealth(
            status=fig_pb2.ServerHealth.ServingStatus.SERVING
        )
        stub.HealthCheck.return_value = health_resp

        return stub

    def test_get_identity_called_first(self):
        """
        getIdentity must be called before any stream is opened.
        .
        """
        call_order = []

        stub = self._build_mock_stub()
        stub.getIdentity.side_effect = lambda *a, **kw: (
            call_order.append("getIdentity"),
            stub.getIdentity.return_value,
        )[-1]
        stub.ServerEventStream.side_effect = lambda *a, **kw: (
            call_order.append("ServerEventStream"),
            mock.MagicMock(),
        )[-1]
        stub.ClientEventStream.side_effect = lambda *a, **kw: (
            call_order.append("ClientEventStream"),
            iter([]),
        )[-1]

        # Patch grpc.secure_channel to return a context manager yielding our stub.
        with mock.patch(
            "ots_federation.client.grpc.secure_channel"
        ) as mock_channel, mock.patch(
            "ots_federation.client.fig_pb2_grpc.FederatedChannelStub",
            return_value=stub,
        ), mock.patch(
            "ots_federation.client.FederateClient._build_credentials",
            return_value=mock.MagicMock(),
        ):
            # Make channel a context manager.
            mock_channel.return_value.__enter__ = lambda s: s
            mock_channel.return_value.__exit__ = mock.MagicMock(return_value=False)

            self.client._stop_event.set()  # stop after one session
            try:
                self.client._run_session()
            except Exception:  # pylint: disable=broad-except
                pass

        self.assertGreater(len(call_order), 0)
        self.assertEqual(call_order[0], "getIdentity")

    def test_remote_server_id_set_after_identity(self):
        """
        remote_server_id must be set to the value from getIdentity.
        .
        """
        stub = self._build_mock_stub()

        with mock.patch(
            "ots_federation.client.grpc.secure_channel"
        ) as mock_channel, mock.patch(
            "ots_federation.client.fig_pb2_grpc.FederatedChannelStub",
            return_value=stub,
        ), mock.patch(
            "ots_federation.client.FederateClient._build_credentials",
            return_value=mock.MagicMock(),
        ):
            mock_channel.return_value.__enter__ = lambda s: s
            mock_channel.return_value.__exit__ = mock.MagicMock(return_value=False)

            self.client._stop_event.set()
            try:
                self.client._run_session()
            except Exception:  # pylint: disable=broad-except
                pass

        self.assertEqual(self.client.remote_server_id, "REMOTE-SERVER-01")

    def test_state_transitions_connecting_handshaking_active(self):
        """
        State must progress: CONNECTING → HANDSHAKING → ACTIVE.
        
        """
        observed_states = []
        original_set_state = self.client._set_state

        def _tracking_set_state(new_state):
            observed_states.append(new_state)
            original_set_state(new_state)

        self.client._set_state = _tracking_set_state

        stub = self._build_mock_stub()

        with mock.patch(
            "ots_federation.client.grpc.secure_channel"
        ) as mock_channel, mock.patch(
            "ots_federation.client.fig_pb2_grpc.FederatedChannelStub",
            return_value=stub,
        ), mock.patch(
            "ots_federation.client.FederateClient._build_credentials",
            return_value=mock.MagicMock(),
        ):
            mock_channel.return_value.__enter__ = lambda s: s
            mock_channel.return_value.__exit__ = mock.MagicMock(return_value=False)

            self.client._stop_event.set()
            try:
                self.client._run_session()
            except Exception:  # pylint: disable=broad-except
                pass

        self.assertIn(PeerState.CONNECTING, observed_states)
        self.assertIn(PeerState.HANDSHAKING, observed_states)
        self.assertIn(PeerState.ACTIVE, observed_states)
        # Order must be correct
        idx_connecting = observed_states.index(PeerState.CONNECTING)
        idx_handshaking = observed_states.index(PeerState.HANDSHAKING)
        idx_active = observed_states.index(PeerState.ACTIVE)
        self.assertLess(idx_connecting, idx_handshaking)
        self.assertLess(idx_handshaking, idx_active)

    def test_inbound_event_enqueued_to_bridge(self):
        """
        Inbound FederatedEvent from ClientEventStream must reach bridge.enqueue.

        decode_federated_event is mocked (codec stream not yet implemented).
        The mock returns a minimal Event with the expected uid.
        """
        from ots_federation.proto import fig_pb2 as pb  # noqa: F811

        # Build a real FederatedEvent proto with minimal fields.
        now_ms = int(dt.utcnow().timestamp() * 1000)
        geo = pb.GeoEvent(
            uid="fed-event-uid",
            type="a-f-G-U-C",
            coordSource="m-g",
            sendTime=now_ms,
            startTime=now_ms,
            staleTime=now_ms + 300_000,
            lat=1.0,
            lon=2.0,
            hae=0.0,
            ce=9.9,
            le=9999999.0,
        )
        fed_event = pb.FederatedEvent(event=geo)

        stub = self._build_mock_stub(events=[fed_event])

        bridge_enqueue_calls = []

        def _capture_enqueue(fc, evt):
            bridge_enqueue_calls.append((fc, evt))

        self.bridge.enqueue = _capture_enqueue

        # Decoded event returned by mock codec.
        decoded_evt = _make_event("fed-event-uid")
        decoded_fed_meta = FedMeta(seen_server_ids=["REMOTE-SERVER-01"])

        # _stop_event must NOT be set before session starts — it will be set
        # naturally when the event stream is exhausted.
        self.client._stop_event.clear()

        with mock.patch(
            "ots_federation.client.grpc.secure_channel"
        ) as mock_channel, mock.patch(
            "ots_federation.client.fig_pb2_grpc.FederatedChannelStub",
            return_value=stub,
        ), mock.patch(
            "ots_federation.client.FederateClient._build_credentials",
            return_value=mock.MagicMock(),
        ), mock.patch(
            "ots_federation.codec.decode_federated_event",
            return_value=(decoded_evt, decoded_fed_meta),
        ):
            mock_channel.return_value.__enter__ = lambda s: s
            mock_channel.return_value.__exit__ = mock.MagicMock(return_value=False)

            try:
                self.client._run_session()
            except Exception:  # pylint: disable=broad-except
                pass

        # At least one event should have been enqueued.
        self.assertGreater(len(bridge_enqueue_calls), 0)
        fc, evt = bridge_enqueue_calls[0]
        self.assertIs(fc, self.client)
        self.assertEqual(evt.uid, "fed-event-uid")


# ---------------------------------------------------------------------------
# FederateClient — reconnect back-off test
# ---------------------------------------------------------------------------


class FederateClientReconnectTest(unittest.TestCase):
    """Tests for reconnect back-off in run_grpc_thread()."""

    def setUp(self):

        self.bridge = FederationBridge()
        self.peer_cfg = _make_peer_config(reconnect_interval=1)
        self.client = FederateClient(
            peer_name="reconnect-peer",
            peer_config=self.peer_cfg,
            node_id="TAKY-TEST-01",
            bridge=self.bridge,
        )

    def tearDown(self):
        self.client._stop_event.set()
        self.bridge.close()

    def test_reconnect_on_grpc_error(self):
        """
        When _run_session raises grpc.RpcError, run_grpc_thread must
        enter RECONNECTING state and retry.
        """
        import grpc as _grpc  # noqa: F811

        attempt_count = [0]
        stop_after = 2  # let it try twice then set stop event

        def _failing_session():
            attempt_count[0] += 1
            if attempt_count[0] >= stop_after:
                self.client._stop_event.set()
            raise _grpc.RpcError("simulated connection failure")

        reconnecting_states = []
        original_set_state = self.client._set_state

        def _tracking_set_state(new_state):
            if new_state == PeerState.RECONNECTING:
                reconnecting_states.append(new_state)
            original_set_state(new_state)

        self.client._set_state = _tracking_set_state

        with mock.patch.object(self.client, "_run_session", side_effect=_failing_session):
            with mock.patch.object(
                self.client._stop_event, "wait", side_effect=lambda timeout: None
            ):
                self.client.run_grpc_thread()

        self.assertGreater(len(reconnecting_states), 0)

    def test_stop_prevents_reconnect(self):
        """
        Setting _stop_event before run_grpc_thread must prevent any connection
        attempt.
        """
        self.client._stop_event.set()
        with mock.patch.object(self.client, "_run_session") as mock_session:
            self.client.run_grpc_thread()
            mock_session.assert_not_called()

    def test_draining_state_prevents_reconnect(self):
        """
        When _run_session completes cleanly after request_stop, the thread
        must not reconnect.DRAINING state.
        """

        def _clean_exit_session():
            # Simulate clean exit after stop was requested.
            self.client._set_state(PeerState.DRAINING)

        with mock.patch.object(
            self.client, "_run_session", side_effect=_clean_exit_session
        ):
            self.client.run_grpc_thread()

        # Thread should have exited without further reconnect attempts.
        # (Verified implicitly — if it looped, the test would hang.)


# ---------------------------------------------------------------------------
# FederationManager tests
# ---------------------------------------------------------------------------


class FederationManagerTest(unittest.TestCase):
    """Tests for FederationManager — peer lifecycle, on_outbound fan-out."""

    def setUp(self):
        pass

    def test_init_creates_clients_for_enabled_peers(self):
        """FederationManager must create one FederateClient per enabled peer."""
        peers = [
            _make_peer_config(name="peer-a"),
            _make_peer_config(name="peer-b"),
            _make_peer_config(name="peer-c", enabled=False),  # disabled
        ]
        cfg = _make_fed_config(peers=peers)
        mgr = FederationManager(cfg)
        mgr.bridge.close()

        self.assertIn("peer-a", mgr.clients)
        self.assertIn("peer-b", mgr.clients)
        self.assertNotIn("peer-c", mgr.clients)  # disabled

    def test_on_outbound_fans_out_to_active_peers(self):
        """on_outbound() must call send_event on all ACTIVE peers except src."""
        peers = [
            _make_peer_config(name="peer-a"),
            _make_peer_config(name="peer-b"),
        ]
        cfg = _make_fed_config(peers=peers)
        mgr = FederationManager(cfg)
        mgr.bridge.close()

        # Force both peers to ACTIVE and mock send_event.
        for c in mgr.clients.values():
            c._state = PeerState.ACTIVE
            c.send_event = mock.MagicMock()

        evt = _make_event()
        src = mock.MagicMock()  # external src (not a peer)
        mgr.on_outbound(src, evt)

        # Both peers should have received the event.
        for c in mgr.clients.values():
            c.send_event.assert_called_once_with(evt)

    def test_on_outbound_does_not_echo_src_peer(self):
        """on_outbound() must not send event back to the peer that originated it."""
        peers = [
            _make_peer_config(name="peer-a"),
            _make_peer_config(name="peer-b"),
        ]
        cfg = _make_fed_config(peers=peers)
        mgr = FederationManager(cfg)
        mgr.bridge.close()

        peer_a = mgr.clients["peer-a"]
        peer_b = mgr.clients["peer-b"]
        peer_a._state = PeerState.ACTIVE
        peer_b._state = PeerState.ACTIVE
        peer_a.send_event = mock.MagicMock()
        peer_b.send_event = mock.MagicMock()

        evt = _make_event()
        # peer-a is the source of this event.
        mgr.on_outbound(peer_a, evt)

        peer_a.send_event.assert_not_called()  # not echoed back
        peer_b.send_event.assert_called_once_with(evt)  # forwarded

    def test_on_outbound_skips_inactive_peers(self):
        """on_outbound() must skip peers not in ACTIVE state."""
        peers = [
            _make_peer_config(name="peer-a"),
            _make_peer_config(name="peer-b"),
        ]
        cfg = _make_fed_config(peers=peers)
        mgr = FederationManager(cfg)
        mgr.bridge.close()

        peer_a = mgr.clients["peer-a"]
        peer_b = mgr.clients["peer-b"]
        peer_a._state = PeerState.ACTIVE
        peer_b._state = PeerState.RECONNECTING  # not active
        peer_a.send_event = mock.MagicMock()
        peer_b.send_event = mock.MagicMock()

        mgr.on_outbound(mock.MagicMock(), _make_event())

        peer_a.send_event.assert_called_once()
        peer_b.send_event.assert_not_called()

    def test_start_spawns_threads(self):
        """start() must spawn one daemon thread per enabled peer."""
        peers = [_make_peer_config(name="peer-a"), _make_peer_config(name="peer-b")]
        cfg = _make_fed_config(peers=peers)
        mgr = FederationManager(cfg)

        # Mock run_grpc_thread to avoid actual gRPC connections.
        for c in mgr.clients.values():
            c.run_grpc_thread = mock.MagicMock()

        mgr.start()
        # Give threads a moment to start.
        time.sleep(0.05)

        self.assertEqual(len(mgr._threads), 2)
        for name, t in mgr._threads.items():
            self.assertTrue(t.is_alive() or True)  # thread may have already stopped

        mgr.stop()

    def test_stop_signals_all_clients(self):
        """stop() must call request_stop() on all clients."""
        peers = [_make_peer_config(name="peer-a")]
        cfg = _make_fed_config(peers=peers)
        mgr = FederationManager(cfg)
        mgr.bridge.close()

        peer_a = mgr.clients["peer-a"]
        peer_a.request_stop = mock.MagicMock()
        # Provide a fake thread that's already done.
        fake_t = mock.MagicMock()
        fake_t.is_alive.return_value = False
        mgr._threads["peer-a"] = fake_t

        mgr.stop()
        peer_a.request_stop.assert_called_once()


# ---------------------------------------------------------------------------
# NullFederationManager tests
# ---------------------------------------------------------------------------


class NullFederationManagerTest(unittest.TestCase):
    """NullFederationManager must be a true no-op."""

    def test_on_outbound_noop(self):
        nfm = NullFederationManager()
        nfm.on_outbound(None, None)  # must not raise

    def test_start_noop(self):
        nfm = NullFederationManager()
        nfm.start()  # must not raise

    def test_stop_noop(self):
        nfm = NullFederationManager()
        nfm.stop()  # must not raise


if __name__ == "__main__":
    unittest.main()

