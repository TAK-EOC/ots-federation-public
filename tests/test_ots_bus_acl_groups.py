# tests/test_ots_bus_acl_groups.py
# Unit tests for Option D outbound ACL-group sourcing (//).
# All pika interactions are mocked; no live RabbitMQ required.
# Coverage:
#   B1  — _on_groups_message: .OUT routing key → cache.update called
#   B2  — _on_groups_message: .IN routing key → cache.update NOT called
#   B3  — _on_groups_message: malformed JSON body → warning logged, no crash
#   B4  — _on_groups_message: valid JSON, uid absent → cache.update NOT called
#   B5  — _on_firehose_message: cache miss → block (fail-closed, on_outbound NOT called)
#   B6  — _on_firehose_message: cache hit → evt.local_acl_groups sidecar set + on_outbound called
#   B7  — _on_firehose_message: invalid JSON body → no crash, on_outbound NOT called
#   B8  — _on_firehose_message: empty cot field → no crash, on_outbound NOT called
#   B9  — prepare_outbound_event : local_acl_groups sidecar present + mapped → non-None proto
#   B10 — prepare_outbound_event : local_acl_groups absent → None (no sidecar = cache miss)
#   B11 — prepare_outbound_event : local_acl_groups present, unmapped group → None
#   B12 — prepare_outbound_event : local_acl_groups present, registry=None → non-None proto (no-policy path)

import json
import threading
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from lxml import etree

from ots_federation import models
from ots_federation.codec import prepare_outbound_event
from ots_federation.eud_group_cache import EudGroupCache
from ots_federation.groups import FederateGroupRegistry, FederatePeerGroupMap
from ots_federation.models.detail import Detail
from ots_federation.models.event import Event
from ots_federation.ots_bus import OtsRmqBus

PEER_ID = "fed-alpha.example.com"
NODE_ID = "taky-local.example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bus(eud_group_cache=None):
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
    )
    return bus, lf


def _make_method(routing_key: str):
    """Pika method mock with routing_key attribute."""
    m = MagicMock()
    m.routing_key = routing_key
    return m


def _minimal_cot_xml(uid="T1") -> str:
    return (
        f'<event version="2.0" uid="{uid}" type="a-f-G-U-C" '
        f'time="2026-07-10T00:00:00.000Z" '
        f'start="2026-07-10T00:00:00.000Z" '
        f'stale="2026-07-10T01:00:00.000Z" how="m-g">'
        f'<point lat="0.0" lon="0.0" hae="0" ce="9999999" le="9999999"/>'
        f'</event>'
    )


def _make_groups_body(uid: str, cot_xml: str = "") -> bytes:
    return json.dumps({"uid": uid, "cot": cot_xml or _minimal_cot_xml(uid)}).encode()


def _make_firehose_body(uid: str, cot_xml: str = "") -> bytes:
    return json.dumps({"uid": uid, "cot": cot_xml or _minimal_cot_xml(uid)}).encode()


def _make_evt(uid="T1", group="Blue"):
    """Build a minimal Event with local_acl_groups sidecar (warm cache simulation)."""
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
    evt.local_acl_groups = frozenset([group])
    return evt


def _registry_blue():
    """Registry that maps Blue → Blue for PEER_ID."""
    reg = FederateGroupRegistry()
    reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "Blue", "Blue"))
    return reg


# ---------------------------------------------------------------------------
#: _on_groups_message routing-key parse tests (B1–B4)
# ---------------------------------------------------------------------------

class TestOnGroupsMessage(unittest.TestCase):
    """B1–B4: _on_groups_message routing-key parse and cache interaction."""

    def _call(self, bus, routing_key: str, body: bytes):
        ch = MagicMock()
        method = _make_method(routing_key)
        props = MagicMock()
        bus._on_groups_message(ch, method, props, body)

    # B1 — .OUT key → cache.update called with correct group and uid
    def test_out_routing_key_updates_cache(self):
        cache = MagicMock(spec=EudGroupCache)
        bus, _ = _make_bus(eud_group_cache=cache)
        self._call(bus, "Blue.OUT", _make_groups_body("EUD-1"))
        cache.update.assert_called_once_with("EUD-1", "Blue")

    def test_hyphenated_group_name_parsed(self):
        cache = MagicMock(spec=EudGroupCache)
        bus, _ = _make_bus(eud_group_cache=cache)
        self._call(bus, "FIRE-OPS.OUT", _make_groups_body("EUD-2"))
        cache.update.assert_called_once_with("EUD-2", "FIRE-OPS")

    def test_multi_segment_group_name(self):
        cache = MagicMock(spec=EudGroupCache)
        bus, _ = _make_bus(eud_group_cache=cache)
        self._call(bus, "SECTOR.NORTH.OUT", _make_groups_body("EUD-3"))
        cache.update.assert_called_once_with("EUD-3", "SECTOR.NORTH")

    # B2 — .IN key → cache.update NOT called
    def test_in_routing_key_ignored(self):
        cache = MagicMock(spec=EudGroupCache)
        bus, _ = _make_bus(eud_group_cache=cache)
        self._call(bus, "Blue.IN", _make_groups_body("EUD-4"))
        cache.update.assert_not_called()

    def test_bare_out_routing_key_ignored(self):
        """Routing key '.OUT' with empty group name must be rejected."""
        cache = MagicMock(spec=EudGroupCache)
        bus, _ = _make_bus(eud_group_cache=cache)
        self._call(bus, ".OUT", _make_groups_body("EUD-5"))
        cache.update.assert_not_called()

    # B3 — malformed JSON body → no crash
    def test_malformed_json_does_not_crash(self):
        cache = MagicMock(spec=EudGroupCache)
        bus, _ = _make_bus(eud_group_cache=cache)
        self._call(bus, "Blue.OUT", b"not-valid-json{")
        # Must not raise; cache must not be updated.
        cache.update.assert_not_called()

    # B4 — JSON body with no "uid" field → cache.update NOT called
    def test_missing_uid_in_body_not_cached(self):
        cache = MagicMock(spec=EudGroupCache)
        bus, _ = _make_bus(eud_group_cache=cache)
        body = json.dumps({"cot": _minimal_cot_xml("EUD-6")}).encode()
        self._call(bus, "Blue.OUT", body)
        cache.update.assert_not_called()


# ---------------------------------------------------------------------------
#: _on_firehose_message fail-closed tests (B5–B8)
# ---------------------------------------------------------------------------

class TestOnFirehoseMessage(unittest.TestCase):
    """B5–B8: _on_firehose_message fail-closed and sidecar-attachment."""

    def _call(self, bus, manager, uid, cot_xml=None):
        ch = MagicMock()
        method = MagicMock()
        props = MagicMock()
        body = _make_firehose_body(uid, cot_xml or _minimal_cot_xml(uid))
        bus._on_firehose_message(manager, ch, method, props, body)

    # B5 — cache miss → on_outbound NOT called (fail-closed)
    def test_cache_miss_blocks_event(self):
        cache = EudGroupCache()  # empty: no entries
        bus, _ = _make_bus(eud_group_cache=cache)
        manager = MagicMock()
        self._call(bus, manager, "EUD-UNKNOWN")
        manager.on_outbound.assert_not_called()

    # B6 — cache hit → sidecar set AND on_outbound called
    def test_cache_hit_sets_sidecar_and_calls_on_outbound(self):
        cache = EudGroupCache()
        cache.update("EUD-WARM", "Blue")
        bus, _ = _make_bus(eud_group_cache=cache)
        manager = MagicMock()
        self._call(bus, manager, "EUD-WARM")
        manager.on_outbound.assert_called_once()
        # Extract the evt passed to on_outbound.
        call_args = manager.on_outbound.call_args
        src, evt = call_args[0]
        self.assertIsNone(src, "on_outbound src must be None for locally-originating events")
        self.assertTrue(hasattr(evt, "local_acl_groups"),
            "evt must have local_acl_groups sidecar attached")
        self.assertEqual(evt.local_acl_groups, frozenset(["Blue"]))

    def test_cache_hit_multi_group_sidecar(self):
        cache = EudGroupCache()
        cache.update("EUD-MULTI", "Blue")
        cache.update("EUD-MULTI", "White")
        bus, _ = _make_bus(eud_group_cache=cache)
        manager = MagicMock()
        self._call(bus, manager, "EUD-MULTI")
        manager.on_outbound.assert_called_once()
        _, evt = manager.on_outbound.call_args[0]
        self.assertEqual(evt.local_acl_groups, frozenset(["Blue", "White"]))

    # B7 — invalid JSON body → no crash, on_outbound NOT called
    def test_invalid_json_body_no_crash(self):
        cache = EudGroupCache()
        bus, _ = _make_bus(eud_group_cache=cache)
        manager = MagicMock()
        ch, method, props = MagicMock(), MagicMock(), MagicMock()
        bus._on_firehose_message(manager, ch, method, props, b"not-json!!{")
        manager.on_outbound.assert_not_called()

    # B8 — empty cot field → no crash, on_outbound NOT called
    def test_empty_cot_field_no_crash(self):
        cache = EudGroupCache()
        bus, _ = _make_bus(eud_group_cache=cache)
        manager = MagicMock()
        ch, method, props = MagicMock(), MagicMock(), MagicMock()
        body = json.dumps({"uid": "EUD-X", "cot": ""}).encode()
        bus._on_firehose_message(manager, ch, method, props, body)
        manager.on_outbound.assert_not_called()


# ---------------------------------------------------------------------------
#: prepare_outbound_event ACL sidecar sourcing (B9–B12)
# ---------------------------------------------------------------------------

class TestPrepareOutboundEventAclSidecar(unittest.TestCase):
    """
    B9–B12: prepare_outbound_event reads local_acl_groups sidecar, not CoT <__group>.

    After, the group source for outbound policy is entirely the
    evt.local_acl_groups frozenset (set by the firehose consumer from the
    EudGroupCache).  The CoT <__group> XML element is no longer consulted.
    """

    def _prepare(self, evt, registry=None, peer_id=PEER_ID):
        return prepare_outbound_event(
            evt,
            node_id=NODE_ID,
            default_max_hops=3,
            registry=registry,
            peer_id=peer_id,
        )

    # B9 — sidecar present, group mapped → proto non-None and carries group tag
    def test_sidecar_present_mapped_group_forwards(self):
        reg = _registry_blue()
        evt = _make_evt("T1", "Blue")
        proto = self._prepare(evt, registry=reg)
        self.assertIsNotNone(proto,
            "event with mapped local_acl_groups must be forwarded")
        self.assertIn("Blue", list(proto.federateGroups),
            "federateGroups must carry the mapped remote group name")

    # B10 — no sidecar → None (cache miss / cold-start path)
    def test_no_sidecar_blocks_event(self):
        reg = _registry_blue()
        now = datetime.utcnow()
        evt = Event(
            uid="T2",
            etype="a-f-G-U-C",
            how="m-g",
            time=now,
            start=now,
            stale=now + timedelta(seconds=300),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        # No local_acl_groups sidecar at all.
        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "event without local_acl_groups sidecar must be blocked (fail-closed)")

    # B11 — sidecar present but group unmapped → None (block-unmapped default)
    def test_sidecar_present_unmapped_group_blocks(self):
        """Registry maps only Blue; event carries White → blocked."""
        reg = _registry_blue()
        evt = _make_evt("T3", "White")  # White not in registry
        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "event with unmapped group must be blocked (block-unmapped default)")

    # B12 — registry=None → proto non-None, no group policy enforced
    def test_no_registry_forwards_without_policy(self):
        """Without a registry all events pass through regardless of sidecar."""
        evt = _make_evt("T4", "Blue")
        proto = self._prepare(evt, registry=None)
        self.assertIsNotNone(proto,
            "without a registry, event must pass through regardless of local_acl_groups")
        self.assertEqual(list(proto.federateGroups), [],
            "no group tags expected without a registry")

    def test_no_registry_event_without_sidecar_forwards(self):
        """Without a registry, even events with no sidecar pass through."""
        now = datetime.utcnow()
        evt = Event(
            uid="T5",
            etype="a-f-G-U-C",
            how="m-g",
            time=now,
            start=now,
            stale=now + timedelta(seconds=300),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        proto = self._prepare(evt, registry=None)
        self.assertIsNotNone(proto,
            "without registry, event with no sidecar must still pass through")

    def test_multi_group_sidecar_all_mapped_groups_in_proto(self):
        """
        If a uid belongs to two groups and both are mapped for the peer
        federateGroups must carry both remote names.
        """
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "Blue", "Blue"))
        reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "White", "White"))

        now = datetime.utcnow()
        evt = Event(
            uid="T6",
            etype="a-f-G-U-C",
            how="m-g",
            time=now,
            start=now,
            stale=now + timedelta(seconds=300),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        evt.local_acl_groups = frozenset(["Blue", "White"])

        proto = self._prepare(evt, registry=reg)
        self.assertIsNotNone(proto)
        groups = set(proto.federateGroups)
        self.assertIn("Blue", groups)
        self.assertIn("White", groups)

    def test_sidecar_empty_frozenset_blocks(self):
        """An empty frozenset sidecar is treated as no-groups → block."""
        reg = _registry_blue()
        now = datetime.utcnow()
        evt = Event(
            uid="T7",
            etype="a-f-G-U-C",
            how="m-g",
            time=now,
            start=now,
            stale=now + timedelta(seconds=300),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        evt.local_acl_groups = frozenset()  # explicitly empty
        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "empty local_acl_groups frozenset must block event (no groups = fail-closed)")


if __name__ == "__main__":
    unittest.main()
