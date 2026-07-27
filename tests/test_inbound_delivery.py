# tests/test_inbound_delivery.py
# Unit tests for Option D inbound delivery (the "forks resolved" design).
# Architecture: .qmd §4
# Coverage:
#   I1  — inject with local_groups → publishes to groups exchange per group
#   I2  — inject routing keys are exactly "<group>.OUT"
#   I3  — inject with local_groups, inject_cot_parser=False → NO cot_parser publish
#   I4  — inject with local_groups, inject_cot_parser=True → BOTH groups AND cot_parser
#   I5  — inject with local_groups=None → fallback cot_parser only (no groups exchange)
#   I6  — inject with local_groups=frozenset (empty) → fallback cot_parser only
#   I7  — inject __ANON__ suppression: inject_cot_parser=False → __ANON__ NOT touched
#         (no cot_parser publish means cot_parser cannot route to __ANON__.OUT)
#   I8  — multi-group local_groups → one groups exchange publish per group, correct RK
#   I9  — relay sidecar: evt.local_acl_groups set by _handle_inbound → prepare_outbound_event
#         does NOT block the relayed event
#   I10 — FederateClient._handle_inbound: inbound_local_groups and local_acl_groups
#         sidecars are set when group policy allows the event
#   I11 — FederateClient._handle_inbound: event is DROPPED when no mappable local groups
#   I12 — bridge.drain: passes local_groups=inbound_local_groups to bus.inject
#   I13 — bridge.drain: local_groups=None when evt has no inbound_local_groups sidecar
#   I14 — inject_cot_parser config flag: parsed from config (default False)
#   I15 — inject body format for groups exchange: {"uid": ..., "cot": ...} (no user_id)
#   I16 — inject body format for cot_parser: {"uid": ..., "cot": ..., "user_id": None}
# All pika interactions are mocked; no live RabbitMQ required.

import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, call, patch

from lxml import etree

from ots_federation import models
from ots_federation.bridge import FederationBridge
from ots_federation.codec import prepare_outbound_event
from ots_federation.eud_group_cache import EudGroupCache
from ots_federation.groups import FederateGroupRegistry, FederatePeerGroupMap
from ots_federation.models.event import Event
from ots_federation.ots_bus import OtsRmqBus

PEER_ID = "fed-alpha.example.com"
NODE_ID = "taky-local.example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bus(inject_cot_parser=False, eud_group_cache=None):
    """Build an OtsRmqBus with mocked LoopFilter; bypass connect()."""
    lf = MagicMock()
    lf.should_inject_inbound.return_value = True
    lf.stamp_inbound.side_effect = lambda xml, meta: xml
    lf.should_relay_outbound.return_value = True
    lf.clean_for_relay.side_effect = lambda xml: xml
    if eud_group_cache is None:
        eud_group_cache = EudGroupCache()
    bus = OtsRmqBus(
        host="localhost",
        port=5672,
        user="guest",
        password="guest",
        loop_filter=lf,
        eud_group_cache=eud_group_cache,
        pub_fail_threshold=5,
        inject_cot_parser=inject_cot_parser,
    )
    # Install a mock publish channel (bypasses connect).
    mock_ch = MagicMock()
    bus._pub_ch = mock_ch
    return bus, mock_ch


def _minimal_cot_xml(uid="T1") -> str:
    return (
        f'<event version="2.0" uid="{uid}" type="a-f-G-U-C" '
        f'time="2026-07-10T00:00:00.000Z" '
        f'start="2026-07-10T00:00:00.000Z" '
        f'stale="2026-07-10T01:00:00.000Z" how="m-g">'
        f'<point lat="0.0" lon="0.0" hae="0" ce="9999999" le="9999999"/>'
        f'</event>'
    )


def _make_evt(uid="T1", groups=None):
    """Build a minimal Event. Optionally attach local_acl_groups sidecar."""
    now = datetime.utcnow()
    evt = Event(
        uid=uid,
        etype="a-f-G-U-C",
        how="m-g",
        time=now,
        start=now,
        stale=now + timedelta(seconds=300),
    )
    evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
    if groups is not None:
        evt.local_acl_groups = frozenset(groups)
        evt.inbound_local_groups = frozenset(groups)
    return evt


def _collect_publishes(mock_ch):
    """Return list of (exchange, routing_key, body_dict) from basic_publish calls."""
    results = []
    for c in mock_ch.basic_publish.call_args_list:
        kwargs = c.kwargs if c.kwargs else {}
        # handle positional vs keyword calls
        if not kwargs and c.args:
            # basic_publish(exchange=..., routing_key=..., body=...)
            continue
        exchange = kwargs.get("exchange", "")
        rk = kwargs.get("routing_key", "")
        body_raw = kwargs.get("body", b"")
        if isinstance(body_raw, str):
            body_raw = body_raw.encode()
        try:
            body = json.loads(body_raw)
        except Exception:  # noqa: BLE001
            body = {}
        results.append((exchange, rk, body))
    return results


def _inject_evt(bus, uid="T1", local_groups=None):
    """Call bus.inject() with a minimal Event."""
    evt = _make_evt(uid)
    bus.inject(src=None, evt=evt, local_groups=local_groups)
    return evt


# ---------------------------------------------------------------------------
# I1–I8: inject groups exchange delivery
# ---------------------------------------------------------------------------

class TestInjectGroupsExchangeDelivery(unittest.TestCase):
    """I1–I8: inject() delivers to groups exchange when local_groups provided."""

    # I1 — single group → one groups exchange publish
    def test_single_group_publishes_to_groups_exchange(self):
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        _inject_evt(bus, "EUD-1", local_groups=frozenset(["FIRE-OPS"]))

        calls = _collect_publishes(mock_ch)
        groups_calls = [(e, rk) for e, rk, _ in calls if e == "groups"]
        self.assertEqual(len(groups_calls), 1)
        self.assertEqual(groups_calls[0], ("groups", "FIRE-OPS.OUT"))

    # I2 — routing key format is "<group>.OUT"
    def test_routing_key_format(self):
        bus, mock_ch = _make_bus()
        _inject_evt(bus, "EUD-2", local_groups=frozenset(["TACTICAL"]))
        calls = _collect_publishes(mock_ch)
        rk = next(rk for _, rk, _ in calls if _ or True)
        # Find the groups exchange call
        groups_rks = [rk for e, rk, _ in calls if e == "groups"]
        self.assertIn("TACTICAL.OUT", groups_rks)

    # I3 — inject_cot_parser=False → NO cot_parser publish when local_groups present
    def test_no_cot_parser_when_flag_false(self):
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        _inject_evt(bus, "EUD-3", local_groups=frozenset(["FIRE-OPS"]))
        calls = _collect_publishes(mock_ch)
        cot_parser_calls = [e for e, _, _ in calls if e == "cot_parser"]
        self.assertEqual(len(cot_parser_calls), 0,
            "inject_cot_parser=False must NOT publish to cot_parser")

    # I4 — inject_cot_parser=True → BOTH groups exchange AND cot_parser
    def test_both_exchanges_when_flag_true(self):
        bus, mock_ch = _make_bus(inject_cot_parser=True)
        _inject_evt(bus, "EUD-4", local_groups=frozenset(["FIRE-OPS"]))
        calls = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in calls]
        self.assertIn("groups", exchanges, "must publish to groups exchange")
        self.assertIn("cot_parser", exchanges, "must publish to cot_parser when flag=True")

    # I5 — local_groups=None → fallback cot_parser only
    def test_none_local_groups_fallback_to_cot_parser(self):
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        _inject_evt(bus, "EUD-5", local_groups=None)
        calls = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in calls]
        self.assertIn("cot_parser", exchanges, "None local_groups must fall back to cot_parser")
        self.assertNotIn("groups", exchanges, "None local_groups must NOT publish to groups")

    # I6 — local_groups=frozenset (empty) → fallback cot_parser only
    def test_empty_local_groups_fallback_to_cot_parser(self):
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        _inject_evt(bus, "EUD-6", local_groups=frozenset())
        calls = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in calls]
        self.assertIn("cot_parser", exchanges,
            "empty frozenset local_groups must fall back to cot_parser")
        self.assertNotIn("groups", exchanges)

    # I7 — __ANON__ suppression: inject_cot_parser=False → no cot_parser → __ANON__ not touched
    def test_anon_suppressed_when_cot_parser_not_injected(self):
        """
        With inject_cot_parser=False, the cot_parser exchange is never published
        so cot_parser.route_cot (which would publish to __ANON__.OUT) is never
        triggered. Verify no cot_parser publish occurs.
        """
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        _inject_evt(bus, "EUD-7", local_groups=frozenset(["FIRE-OPS"]))
        calls = _collect_publishes(mock_ch)
        # cot_parser publish is the __ANON__ delivery vector
        cot_calls = [e for e, _, _ in calls if e == "cot_parser"]
        self.assertEqual(len(cot_calls), 0,
            "__ANON__ suppressed: no cot_parser publish with inject_cot_parser=False")

    # I8 — multi-group: one groups exchange publish per group
    def test_multi_group_one_publish_per_group(self):
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        groups = frozenset(["FIRE-OPS", "TACTICAL", "LOGISTICS"])
        _inject_evt(bus, "EUD-8", local_groups=groups)
        calls = _collect_publishes(mock_ch)
        groups_rks = {rk for e, rk, _ in calls if e == "groups"}
        expected_rks = {"FIRE-OPS.OUT", "TACTICAL.OUT", "LOGISTICS.OUT"}
        self.assertEqual(groups_rks, expected_rks,
            "must publish once per group with correct routing key")


# ---------------------------------------------------------------------------
# I15–I16: body format verification
# ---------------------------------------------------------------------------

class TestInjectBodyFormat(unittest.TestCase):
    """I15–I16: verify body JSON format for groups and cot_parser exchanges."""

    # I15 — groups exchange body: {"uid": ..., "cot": ...} — no user_id field
    def test_groups_exchange_body_format(self):
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        uid = "EUD-BODY-TEST"
        _inject_evt(bus, uid, local_groups=frozenset(["FIRE-OPS"]))
        calls = _collect_publishes(mock_ch)
        groups_bodies = [body for e, _, body in calls if e == "groups"]
        self.assertEqual(len(groups_bodies), 1)
        body = groups_bodies[0]
        self.assertIn("uid", body, "groups exchange body must have uid field")
        self.assertIn("cot", body, "groups exchange body must have cot field")
        self.assertNotIn("user_id", body,
            "groups exchange body must NOT have user_id field")
        self.assertEqual(body["uid"], uid)

    # I16 — cot_parser body: {"uid": ..., "cot": ..., "user_id": None}
    def test_cot_parser_body_format(self):
        bus, mock_ch = _make_bus(inject_cot_parser=True)
        uid = "EUD-COTPARSER-BODY"
        _inject_evt(bus, uid, local_groups=frozenset(["FIRE-OPS"]))
        calls = _collect_publishes(mock_ch)
        cot_bodies = [body for e, _, body in calls if e == "cot_parser"]
        self.assertEqual(len(cot_bodies), 1)
        body = cot_bodies[0]
        self.assertIn("uid", body)
        self.assertIn("cot", body)
        self.assertIn("user_id", body, "cot_parser body must have user_id field")
        self.assertIsNone(body["user_id"], "cot_parser user_id must be None")

    def test_fallback_cot_parser_body_has_user_id_none(self):
        """Fallback path (no local_groups) must also include user_id=None."""
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        uid = "EUD-FALLBACK"
        _inject_evt(bus, uid, local_groups=None)
        calls = _collect_publishes(mock_ch)
        cot_bodies = [body for e, _, body in calls if e == "cot_parser"]
        self.assertEqual(len(cot_bodies), 1)
        self.assertIn("user_id", cot_bodies[0])
        self.assertIsNone(cot_bodies[0]["user_id"])


# ---------------------------------------------------------------------------
# I9: Relay sidecar — local_acl_groups from inbound path → prepare_outbound_event
# ---------------------------------------------------------------------------

class TestRelaySidecar(unittest.TestCase):
    """
    I9: An event received inbound (with inbound_local_groups + local_acl_groups set)
    must NOT be wrongly blocked by prepare_outbound_event when relayed outbound.

    The current architecture does not relay via firehose (cache miss would block)
    but if prepare_outbound_event is called directly on the inbound event (e.g.
    by a future relay mechanism), the local_acl_groups sidecar must be present and
    the event must forward correctly.
    """

    def _prepare(self, evt, registry=None, peer_id=PEER_ID):
        return prepare_outbound_event(
            evt,
            node_id=NODE_ID,
            default_max_hops=3,
            registry=registry,
            peer_id=peer_id,
        )

    def test_inbound_event_with_local_acl_groups_not_blocked_by_codec(self):
        """
        An event carrying local_acl_groups from the inbound path must be forwarded
        by prepare_outbound_event (not fail-closed blocked) when the group is mapped.
        """
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "FIRE-OPS", "FIRE-OPS"))

        # Simulate what _handle_inbound sets after map_inbound_groups returns {"FIRE-OPS"}
        evt = _make_evt("RELAY-EUD", groups=["FIRE-OPS"])

        proto = self._prepare(evt, registry=reg)
        self.assertIsNotNone(proto,
            "inbound event with local_acl_groups sidecar must NOT be blocked by codec relay path")
        self.assertIn("FIRE-OPS", list(proto.federateGroups))

    def test_inbound_event_without_local_acl_groups_is_blocked(self):
        """
        An event without local_acl_groups (no inbound group mapping) must be
        fail-closed blocked by prepare_outbound_event (cache-miss semantics).
        """
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "FIRE-OPS", "FIRE-OPS"))

        # Event with no sidecar at all — simulates a path that bypassed group policy
        now = datetime.utcnow()
        evt = Event(
            uid="RELAY-NO-SIDECAR",
            etype="a-f-G-U-C",
            how="m-g",
            time=now,
            start=now,
            stale=now + timedelta(seconds=300),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)

        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "event without local_acl_groups must be fail-closed blocked (no relay without groups)")

    def test_relay_multi_group_event_carries_all_mapped_groups(self):
        """Multi-group inbound event relayed outbound must carry all mapped remote groups."""
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "FIRE-OPS", "FIRE-OPS"))
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "TACTICAL", "TACTICAL"))

        evt = _make_evt("RELAY-MULTI", groups=["FIRE-OPS", "TACTICAL"])

        proto = self._prepare(evt, registry=reg)
        self.assertIsNotNone(proto)
        groups = set(proto.federateGroups)
        self.assertIn("FIRE-OPS", groups)
        self.assertIn("TACTICAL", groups)


# ---------------------------------------------------------------------------
# I10–I11: FederateClient._handle_inbound sidecar attachment
# ---------------------------------------------------------------------------

class TestHandleInboundSidecar(unittest.TestCase):
    """
    I10–I11: FederateClient._handle_inbound sets inbound_local_groups and
    local_acl_groups sidecars on the event when group policy allows it.
    """

    def _build_client(self, registry=None):
        """Build a minimal FederateClient with mock bridge and group registry."""
        from ots_federation.client import FederateClient

        mock_bridge = MagicMock()
        enqueued = []

        def _enqueue(src, evt):
            enqueued.append((src, evt))

        mock_bridge.enqueue.side_effect = _enqueue

        pc = MagicMock()
        pc.max_hops = 3
        pc.health_check_interval = 10
        pc.address = "peer.example.com"
        pc.port = 9100

        client = FederateClient(
            peer_name="test-peer",
            peer_config=pc,
            node_id=NODE_ID,
            bridge=mock_bridge,
            group_registry=registry,
        )
        client._remote_server_id = PEER_ID
        return client, mock_bridge, enqueued

    def _build_proto(self, uid="P1", groups=None, cot_xml=None):
        """Build a mock FederatedEvent proto with federateGroups and geoEvent."""
        from ots_federation.proto import fig_pb2

        proto = MagicMock()
        proto.federateGroups = list(groups or [])
        # Minimal geoEvent for decode to succeed
        geo = fig_pb2.GeoEvent()
        geo.uid = uid
        geo.type = "a-f-G-U-C"
        geo.how = "m-g"
        geo.lat = 0.0
        geo.lon = 0.0
        geo.hae = 0.0
        geo.ce = 9999999.0
        geo.le = 9999999.0
        geo.time = 0
        geo.start = 0
        geo.stale = int(datetime.utcnow().timestamp() * 1000) + 3600000
        geo.sendTime = 0
        proto.geoEvent.CopyFrom(geo)
        proto.HasField = lambda f: f == "geoEvent"
        return proto

    def _make_decode_fn(self, uid="P1"):
        """Return a decode function that always succeeds and returns a minimal Event."""
        now = datetime.utcnow()
        evt = Event(
            uid=uid,
            etype="a-f-G-U-C",
            how="m-g",
            time=now,
            start=now,
            stale=now + timedelta(seconds=300),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        from ots_federation.codec import FedMeta
        fed_meta = FedMeta(seen_server_ids=[], current_hops=0)
        return lambda proto, **_kwargs: (evt, fed_meta), evt

    # I10 — sidecars set when group policy allows
    def test_sidecars_set_on_allowed_inbound_event(self):
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "in", "FIRE-OPS", "FIRE-OPS"))

        client, mock_bridge, enqueued = self._build_client(registry=reg)

        decode_fn, expected_evt = self._make_decode_fn("P-SIDECAR")

        proto = MagicMock()
        proto.federateGroups = ["FIRE-OPS"]

        client._handle_inbound(proto, decode_fn)

        self.assertEqual(len(enqueued), 1, "event must be enqueued")
        _, evt = enqueued[0]
        self.assertTrue(hasattr(evt, "inbound_local_groups"),
            "evt must have inbound_local_groups sidecar")
        self.assertTrue(hasattr(evt, "local_acl_groups"),
            "evt must have local_acl_groups sidecar")
        self.assertEqual(evt.inbound_local_groups, frozenset(["FIRE-OPS"]))
        self.assertEqual(evt.local_acl_groups, frozenset(["FIRE-OPS"]))

    # I11 — event dropped when no mappable local groups
    def test_event_dropped_on_no_mappable_groups(self):
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "in", "FIRE-OPS", "FIRE-OPS"))

        client, mock_bridge, enqueued = self._build_client(registry=reg)

        decode_fn, _ = self._make_decode_fn("P-BLOCKED")

        proto = MagicMock()
        proto.federateGroups = ["UNKNOWN-GROUP"]  # not in registry

        client._handle_inbound(proto, decode_fn)

        self.assertEqual(len(enqueued), 0, "event with unmapped group must be dropped")

    def test_no_group_registry_event_passes_without_sidecar(self):
        """Without a registry, events pass through without inbound_local_groups."""
        client, mock_bridge, enqueued = self._build_client(registry=None)

        decode_fn, expected_evt = self._make_decode_fn("P-NO-REG")

        proto = MagicMock()
        proto.federateGroups = ["FIRE-OPS"]

        client._handle_inbound(proto, decode_fn)

        self.assertEqual(len(enqueued), 1, "event without registry must pass through")
        _, evt = enqueued[0]
        # No sidecars set — registry is None so group policy was skipped
        self.assertFalse(
            hasattr(evt, "inbound_local_groups"),
            "inbound_local_groups must not be set when no registry"
        )


# ---------------------------------------------------------------------------
# I12–I13: bridge.drain passes local_groups to bus.inject
# ---------------------------------------------------------------------------

class TestBridgeDrainPassesLocalGroups(unittest.TestCase):
    """I12–I13: FederationBridge.drain() reads inbound_local_groups and passes to inject()."""

    def _make_evt_with_groups(self, uid, groups):
        evt = _make_evt(uid, groups=groups)
        return evt

    def _make_evt_no_groups(self, uid):
        return _make_evt(uid, groups=None)

    # I12 — bridge passes inbound_local_groups to inject
    def test_drain_passes_local_groups_to_inject(self):
        bridge = FederationBridge()
        mock_bus = MagicMock()
        inject_calls = []
        mock_bus.inject.side_effect = lambda src, evt, local_groups=None: inject_calls.append(
            (src, evt, local_groups)
        )

        groups = frozenset(["FIRE-OPS", "TACTICAL"])
        evt = self._make_evt_with_groups("DRAIN-1", list(groups))
        bridge.enqueue(src=None, evt=evt)
        bridge.drain(mock_bus)

        self.assertEqual(len(inject_calls), 1)
        _, _, passed_groups = inject_calls[0]
        self.assertEqual(passed_groups, groups,
            "bridge.drain must pass inbound_local_groups to inject()")

        bridge.close()

    # I13 — bridge passes local_groups=None when no sidecar
    def test_drain_passes_none_when_no_sidecar(self):
        bridge = FederationBridge()
        mock_bus = MagicMock()
        inject_calls = []
        mock_bus.inject.side_effect = lambda src, evt, local_groups=None: inject_calls.append(
            (src, evt, local_groups)
        )

        evt = self._make_evt_no_groups("DRAIN-2")
        bridge.enqueue(src=None, evt=evt)
        bridge.drain(mock_bus)

        self.assertEqual(len(inject_calls), 1)
        _, _, passed_groups = inject_calls[0]
        self.assertIsNone(passed_groups,
            "bridge.drain must pass None to inject() when evt has no inbound_local_groups")

        bridge.close()


# ---------------------------------------------------------------------------
# I14: inject_cot_parser config flag parsing
# ---------------------------------------------------------------------------

class TestInjectCotParserConfig(unittest.TestCase):
    """I14: inject_cot_parser is parsed from config and defaults to False."""

    def _parse_fed_config(self, ini_text):
        import configparser
        from ots_federation.config import get_federation_config
        cfg = configparser.ConfigParser()
        cfg.read_string(ini_text)
        return get_federation_config(cfg)

    def test_default_is_false(self):
        """inject_cot_parser defaults to False when not set."""
        fed_cfg = self._parse_fed_config("""
[federation]
enabled = true
server_id = test-server-01
""")
        self.assertFalse(fed_cfg.inject_cot_parser,
            "inject_cot_parser must default to False")

    def test_explicit_false(self):
        """inject_cot_parser = false parses correctly."""
        fed_cfg = self._parse_fed_config("""
[federation]
enabled = true
server_id = test-server-01
inject_cot_parser = false
""")
        self.assertFalse(fed_cfg.inject_cot_parser)

    def test_explicit_true(self):
        """inject_cot_parser = true parses correctly."""
        fed_cfg = self._parse_fed_config("""
[federation]
enabled = true
server_id = test-server-01
inject_cot_parser = true
""")
        self.assertTrue(fed_cfg.inject_cot_parser,
            "inject_cot_parser = true must parse as True")

    def test_example_config_inject_cot_parser_default(self):
        """examples/federation.ini must parse inject_cot_parser as False (commented out)."""
        import configparser
        import os
        from ots_federation.config import get_federation_config

        examples_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "ots_federation",
            "examples",
        )
        ini_path = os.path.join(examples_dir, "federation.ini")
        cfg = configparser.ConfigParser()
        cfg.read(ini_path)
        fed_cfg = get_federation_config(cfg)
        self.assertFalse(fed_cfg.inject_cot_parser,
            "examples/federation.ini must default inject_cot_parser to False (commented-out)")


# ---------------------------------------------------------------------------
# Integration: inject_cot_parser=True with local_groups → both publishes present
# ---------------------------------------------------------------------------

class TestInjectCotParserIntegration(unittest.TestCase):
    """End-to-end inject() behavior with all combinations of flag × groups."""

    def _run_inject(self, inject_cot_parser, local_groups):
        bus, mock_ch = _make_bus(inject_cot_parser=inject_cot_parser)
        _inject_evt(bus, "EUD-INT", local_groups=local_groups)
        return _collect_publishes(mock_ch)

    def test_flag_false_no_groups_cot_parser_fallback(self):
        """No groups + flag=False → cot_parser fallback only."""
        calls = self._run_inject(inject_cot_parser=False, local_groups=None)
        exchanges = [e for e, _, _ in calls]
        self.assertEqual(exchanges, ["cot_parser"])

    def test_flag_false_with_groups_groups_only(self):
        """With groups + flag=False → groups exchange only."""
        calls = self._run_inject(inject_cot_parser=False, local_groups=frozenset(["FIRE-OPS"]))
        exchanges = [e for e, _, _ in calls]
        self.assertEqual(exchanges, ["groups"])

    def test_flag_true_with_groups_both_exchanges(self):
        """With groups + flag=True → groups AND cot_parser."""
        calls = self._run_inject(inject_cot_parser=True, local_groups=frozenset(["FIRE-OPS"]))
        exchanges = sorted([e for e, _, _ in calls])
        self.assertIn("groups", exchanges)
        self.assertIn("cot_parser", exchanges)

    def test_flag_true_no_groups_cot_parser_only(self):
        """No groups + flag=True → cot_parser fallback (flag only applies when groups present)."""
        calls = self._run_inject(inject_cot_parser=True, local_groups=None)
        exchanges = [e for e, _, _ in calls]
        # Fallback path still goes to cot_parser; groups exchange never invoked
        self.assertIn("cot_parser", exchanges)
        self.assertNotIn("groups", exchanges)


if __name__ == "__main__":
    unittest.main()
