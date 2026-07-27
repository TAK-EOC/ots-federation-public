"""
tests/test_ots_bus.py

Unit tests for OtsRmqBus publish-connection failure handling.

All pika interactions are mocked; no live RabbitMQ required.
Real AMQP integration is verified separately under on ots-fed-node.

Coverage:
  P1 — transient publish failure: after <threshold> consecutive failures a
       successful reconnect resets the counter and the engine continues.
  P2 — persistent publish failure: reconnect also fails → stop_event is set
       so the engine exits cleanly and the plugin watchdog restarts it.
  P3 — successful publish resets consecutive-failure counter to 0.

Mocking strategy:
  - pika is a runtime-only import; it is NOT installed in the dev venv (verified
    under on ots-fed-node).  Tests mock OtsRmqBus._reconnect_pub
    directly to avoid needing a real pika import in test scope.
  - bus._pub_ch and bus._pub_conn are injected directly (bypass connect).
  - bus._stop_event is injected directly (bypass start_consuming).
"""

import threading
import unittest
from unittest.mock import MagicMock, patch

from ots_federation.eud_group_cache import EudGroupCache
from ots_federation.ots_bus import OtsRmqBus

# Minimal valid CoT XML used as the event body for publish calls.
_DUMMY_COT_XML = (
    '<event version="2.0" uid="T1" type="a-f-G-U-C" '
    'time="2026-07-09T12:00:00.000Z" '
    'start="2026-07-09T12:00:00.000Z" '
    'stale="2026-07-09T12:10:00.000Z" how="m-g">'
    '<point lat="0.0" lon="0.0" hae="0" ce="9999999" le="9999999"/>'
    '</event>'
)


def _make_bus(threshold=5):
    """Build an OtsRmqBus with a mocked LoopFilter; bypass connect()."""
    lf = MagicMock()
    lf.should_inject_inbound.return_value = True
    # stamp_inbound is a no-op: return the XML unchanged.
    lf.stamp_inbound.side_effect = lambda xml, meta: xml
    bus = OtsRmqBus(
        host="localhost",
        port=5672,
        user="guest",
        password="guest",
        loop_filter=lf,
        eud_group_cache=EudGroupCache(),
        pub_fail_threshold=threshold,
    )
    return bus, lf


def _make_evt(uid="T1"):
    """Build a minimal mock Event for inject()."""
    evt = MagicMock()
    evt.uid = uid
    evt.fed_meta = None
    return evt


def _wire_bus(bus, threshold):
    """
    Wire mock pub_conn/pub_ch into bus and advance the failure counter to
    one below the threshold, so the next inject failure triggers the
    reconnect path.  Also wires a threading.Event as stop_event.

    Returns (mock_pub_ch, mock_pub_conn, stop_event).
    """
    mock_pub_ch = MagicMock()
    mock_pub_conn = MagicMock()
    bus._pub_ch = mock_pub_ch
    bus._pub_conn = mock_pub_conn
    bus._pub_fail_count = threshold - 1  # one failure away from threshold
    stop_event = threading.Event()
    bus._stop_event = stop_event
    return mock_pub_ch, mock_pub_conn, stop_event


class TestPublishConnectionFailure(unittest.TestCase):
    """
    P1 / P2 / P3 — publish-connection failure handling.

    Tests inject mock connections directly and mock _reconnect_pub so that
    no live pika import is required in the test environment.
    """

    # ------------------------------------------------------------------
    # P1: transient failure recovers via reconnect
    # ------------------------------------------------------------------

    def test_transient_failure_recovers_via_reconnect(self):
        """
        P1 — After threshold consecutive publish failures, a successful
        reconnect (mocked as _reconnect_pub returning True) resets the
        failure counter.  stop_event must NOT be set.
        """
        threshold = 5
        bus, _ = _make_bus(threshold=threshold)
        mock_pub_ch, _, stop_event = _wire_bus(bus, threshold)

        # Publish raises on the call that pushes the counter to the threshold.
        mock_pub_ch.basic_publish.side_effect = Exception("connection reset by peer")

        evt = _make_evt()

        # Mock _reconnect_pub to succeed (simulates RabbitMQ recovering).
        with patch.object(bus, "_reconnect_pub", return_value=True) as mock_reconnect:
            with patch("ots_federation.ots_bus._evt_to_xml", return_value=_DUMMY_COT_XML):
                bus.inject(None, evt)

        # _reconnect_pub must have been called exactly once.
        mock_reconnect.assert_called_once()

        # Failure counter must be reset after successful reconnect.
        self.assertEqual(
            bus._pub_fail_count,
            0,
            "pub_fail_count must reset to 0 after a successful reconnect",
        )

        # Engine must NOT be flagged for termination.
        self.assertFalse(
            stop_event.is_set(),
            "stop_event must NOT be set when reconnect succeeds",
        )

    # ------------------------------------------------------------------
    # P2: persistent failure terminates the engine
    # ------------------------------------------------------------------

    def test_persistent_failure_terminates_engine(self):
        """
        P2 — When threshold consecutive publish failures occur AND the in-place
        reconnect also fails (mocked as _reconnect_pub returning False)
        stop_event must be set so the engine exits cleanly and the plugin
        watchdog (FederationPlugin._watchdog) can restart the process.
        """
        threshold = 5
        bus, _ = _make_bus(threshold=threshold)
        mock_pub_ch, _, stop_event = _wire_bus(bus, threshold)

        # Publish always fails (e.g. RabbitMQ is down).
        mock_pub_ch.basic_publish.side_effect = Exception("connection reset by peer")

        evt = _make_evt()

        # Mock _reconnect_pub to fail (simulates RabbitMQ remaining down).
        with patch.object(bus, "_reconnect_pub", return_value=False) as mock_reconnect:
            with patch("ots_federation.ots_bus._evt_to_xml", return_value=_DUMMY_COT_XML):
                bus.inject(None, evt)

        mock_reconnect.assert_called_once()

        # stop_event must be set so the engine process exits for watchdog restart.
        self.assertTrue(
            stop_event.is_set(),
            "stop_event must be set after threshold publish failures + failed reconnect",
        )

    # ------------------------------------------------------------------
    # P3: successful publish resets the failure counter
    # ------------------------------------------------------------------

    def test_successful_publish_resets_failure_counter(self):
        """
        P3 — A successful publish must reset _pub_fail_count to 0 so that
        a single transient error is not held against the connection.
        """
        threshold = 5
        bus, _ = _make_bus(threshold=threshold)
        mock_pub_ch, _, stop_event = _wire_bus(bus, threshold)

        # Pre-set counter to a non-zero value below threshold.
        bus._pub_fail_count = 2

        # This publish succeeds (no exception).
        mock_pub_ch.basic_publish.side_effect = None

        evt = _make_evt()
        with patch("ots_federation.ots_bus._evt_to_xml", return_value=_DUMMY_COT_XML):
            bus.inject(None, evt)

        self.assertEqual(
            bus._pub_fail_count,
            0,
            "pub_fail_count must reset to 0 after a successful publish",
        )
        self.assertFalse(stop_event.is_set())

    def test_reconnect_not_called_below_threshold(self):
        """
        _reconnect_pub must NOT be called when the failure count is below
        threshold (only the error is logged).
        """
        threshold = 5
        bus, _ = _make_bus(threshold=threshold)
        mock_pub_ch, _, stop_event = _wire_bus(bus, threshold)

        # Start counter well below threshold.
        bus._pub_fail_count = 0

        mock_pub_ch.basic_publish.side_effect = Exception("transient error")

        evt = _make_evt()

        with patch.object(bus, "_reconnect_pub", return_value=True) as mock_reconnect:
            with patch("ots_federation.ots_bus._evt_to_xml", return_value=_DUMMY_COT_XML):
                bus.inject(None, evt)

        # Counter is now 1, still below threshold of 5 — no reconnect yet.
        mock_reconnect.assert_not_called()
        self.assertFalse(stop_event.is_set())
        self.assertEqual(bus._pub_fail_count, 1)


class TestPublishConnectionHeartbeat(unittest.TestCase):
    """
    P4 — publish connection must use heartbeat=0.

    pika.BlockingConnection does not process heartbeats while idle between
    inject() calls (PLI events arrive every 5-8 min in the field). Without
    heartbeat=0, RabbitMQ kills the connection on its 60s heartbeat deadline
    before the next inject() fires.

    Mocking strategy: patch pika.BlockingConnection in the ots_bus module so
    we can capture the ConnectionParameters passed to each call.  The first
    call is the publish connection; subsequent calls are the subscribe
    connections.
    """

    def test_connect_publish_conn_uses_heartbeat_zero(self):
        """
        P4a — OtsRmqBus.connect() must open the publish (first)
        BlockingConnection with heartbeat=0 in its ConnectionParameters.
        """
        import ots_federation.ots_bus as bus_module

        connections_opened = []

        class FakeConn:
            def channel(self):
                ch = MagicMock()
                ch.queue_declare.return_value = MagicMock(method=MagicMock(queue="q"))
                ch.queue_bind.return_value = None
                return ch

        def fake_blocking_connection(params):
            connections_opened.append(params)
            return FakeConn()

        # We also need to mock PlainCredentials and ConnectionParameters so that
        # the pika runtime import resolves even though pika is not installed in
        # the dev venv.
        class FakePlainCreds:
            pass

        class FakeConnectionParams:
            def __init__(self, host, port, credentials, heartbeat=None):
                self.host = host
                self.port = port
                self.heartbeat = heartbeat

        fake_pika = MagicMock()
        fake_pika.PlainCredentials.return_value = FakePlainCreds()
        fake_pika.ConnectionParameters.side_effect = FakeConnectionParams
        fake_pika.BlockingConnection.side_effect = fake_blocking_connection

        bus, _ = _make_bus()

        with patch.dict("sys.modules", {"pika": fake_pika}):
            bus.connect()

        # connect() opens 3 connections: pub, sub (firehose), sub (groups).
        # The first call (index 0) must carry heartbeat=0.
        self.assertGreaterEqual(
            len(connections_opened), 1, "connect() must open at least one connection"
        )
        pub_params = connections_opened[0]
        self.assertEqual(
            pub_params.heartbeat,
            0,
            "Publish (first) connection must use heartbeat=0 to survive "
            "idle intervals between federated PLIs",
        )

    def test_reconnect_pub_uses_heartbeat_zero(self):
        """
        P4b — OtsRmqBus._reconnect_pub() must reconnect the publish
        connection with heartbeat=0 in its ConnectionParameters.
        """
        import ots_federation.ots_bus as bus_module

        reconnect_params = []

        class FakeConn:
            def channel(self):
                return MagicMock()

        class FakePlainCreds:
            pass

        class FakeConnectionParams:
            def __init__(self, host, port, credentials, heartbeat=None):
                self.host = host
                self.port = port
                self.heartbeat = heartbeat

        fake_pika = MagicMock()
        fake_pika.PlainCredentials.return_value = FakePlainCreds()
        fake_pika.ConnectionParameters.side_effect = FakeConnectionParams

        def fake_blocking_connection(params):
            reconnect_params.append(params)
            return FakeConn()

        fake_pika.BlockingConnection.side_effect = fake_blocking_connection

        bus, _ = _make_bus()

        with patch.dict("sys.modules", {"pika": fake_pika}):
            result = bus._reconnect_pub()

        self.assertTrue(result, "_reconnect_pub must return True on success")
        self.assertGreaterEqual(
            len(reconnect_params), 1, "_reconnect_pub must open a connection"
        )
        pub_params = reconnect_params[0]
        self.assertEqual(
            pub_params.heartbeat,
            0,
            "_reconnect_pub must use heartbeat=0",
        )


if __name__ == "__main__":
    unittest.main()
