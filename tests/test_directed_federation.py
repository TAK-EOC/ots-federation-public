# tests/test_directed_federation.py
#
# Parity tests for the directed-event federation fix.
#
# Reference: taky commit 31e942e (merge 94fb126) fixed three defects:
#   1. OUTBOUND directed GeoChat: router.py route() fired on_outbound.
#   2. OUTBOUND marti: router.py fired on_outbound once per event.
#   3. INBOUND privacy leak: bridge.py drain() dispatched directed events to
#      acl_directed_deliver() instead of acl_group_broadcast().
#
# OTS plugin architecture differs from taky (RabbitMQ firehose outbound,
# cot_parser/groups/dms exchange inbound, OTS core owns EUD delivery).
# Defect mapping (per audit):
#
# OUTBOUND (OTS → peer):
#   ABSENT — directed GeoChat and marti events DO reach the firehose
#   (OTS EudHandler.publish_cot publishes ALL events with sender EUD UID;
#    the EudGroupCache is keyed by EUD UID and hits correctly).
#   manager.on_outbound() fires once per firehose message (one event = one
#   firehose publish = one on_outbound call). No defect. Tests O1–O3 guard
#   against regression.
#
# INBOUND (peer → OTS):
#   Marti-addressed events — PLUGIN DEFECT:
#     Previous code published marti events to groups/<group>.OUT → fan-out to
#     ALL EUDs in the group. OTS native routing sends marti events to the dms
#     direct exchange per callsign (EudHandler binds dms/<uid> and dms/<callsign>
#     per EudHandler.py:596-599; route_cot publishes <dest callsign="..."> to
#     dms/<callsign> per cot_parser.py:1153-1160).
#     Fix: inject() detects has_marti and publishes to dms/<callsign>.
#     Tests I1–I5 cover the fix.
#
#   Directed GeoChat (b-t-f, no <dest> tags) — OTS CORE LIMITATION:
#     OTS core route_cot() has no per-UID GeoChat routing — all GeoChat
#     (directed or broadcast) routes to groups/<group>.OUT. Publishing directed
#     GeoChat to the groups exchange is consistent with OTS native behavior.
#     Plugin cannot fix this without OTS core changes. Human-decision item —
#     see below. Tests I6–I7 document and guard the current behavior.
#
# Coverage map:
#   O1 — OUTBOUND directed GeoChat: on_outbound called exactly once
#   O2 — OUTBOUND marti single callsign: on_outbound called exactly once
#   O3 — OUTBOUND marti multi-callsign: on_outbound called exactly once
#         (not once per callsign)
#   O4 — OUTBOUND cache lookup uses sender EUD UID (not event UID): cache
#         hit for both PLI and GeoChat events
#   I1 — INBOUND marti-addressed: inject publishes to dms/<callsign>, NOT
#         groups/<group>.OUT
#   I2 — INBOUND marti multi-callsign: inject publishes to dms/<each-callsign>
#   I3 — INBOUND marti leak canary: dms exchange used, groups exchange silent
#   I4 — INBOUND marti fallback (no local_groups): cot_parser path unchanged
#         (OTS route_cot handles marti→dms correctly on that path)
#   I5 — INBOUND marti inject_cot_parser=True: dms publish AND cot_parser
#         (DB persistence; OTS route_cot double-delivers to dms — accepted)
#   I6 — INBOUND directed GeoChat: inject still uses groups/<group>.OUT
#         (OTS core limitation — consistent with native OTS GeoChat routing)
#   I7 — INBOUND broadcast GeoChat: inject uses groups/<group>.OUT (unchanged)

import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from lxml import etree

from ots_federation import models
from ots_federation.eud_group_cache import EudGroupCache
from ots_federation.models.detail import Detail
from ots_federation.models.event import Event
from ots_federation.models.geochat import GeoChat
from ots_federation.ots_bus import OtsRmqBus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SENDER_EUD_UID = "ANDROID-alice-1234"
SENDER_CALLSIGN = "ALICE"


def _make_bus(inject_cot_parser=False, eud_group_cache=None):
    """OtsRmqBus with mocked LoopFilter and a real or provided EudGroupCache."""
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
    mock_ch = MagicMock()
    bus._pub_ch = mock_ch
    return bus, mock_ch


def _collect_publishes(mock_ch):
    """Return list of (exchange, routing_key, body_dict) tuples from basic_publish calls."""
    results = []
    for c in mock_ch.basic_publish.call_args_list:
        kwargs = c.kwargs if c.kwargs else {}
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


def _make_minimal_evt(uid="EVT-001", etype="a-f-G-U-C"):
    now = datetime.utcnow()
    evt = Event(
        uid=uid,
        etype=etype,
        how="m-g",
        time=now,
        start=now,
        stale=now + timedelta(seconds=300),
    )
    evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
    return evt


def _make_marti_evt(uid="MARTI-001", callsigns=("CHARLIE",)):
    """Event with <detail><marti><dest callsign="..."/></marti></detail>."""
    evt = _make_minimal_evt(uid=uid)
    detail_elm = etree.Element("detail")
    marti_elm = etree.SubElement(detail_elm, "marti")
    for cs in callsigns:
        dest = etree.SubElement(marti_elm, "dest")
        dest.set("callsign", cs)
    evt.detail = Detail(detail_elm)
    return evt


def _make_directed_geochat_evt(uid="GC-001", dst_uid="ANDROID-bob-5678"):
    """Directed GeoChat DM (chatroom != 'All Chat Rooms', no <dest> tags)."""
    evt = _make_minimal_evt(uid=uid, etype="b-t-f")
    gc = GeoChat(None)
    gc.src_cs = SENDER_CALLSIGN
    gc.src_uid = SENDER_EUD_UID
    gc.src_marker = "a-f-G-U-C"
    gc.chatroom = "BOB"
    gc.chat_parent = "RootContactGroup"
    gc.dst_uid = dst_uid
    gc.dst_team = None
    gc.message = "hello bob"
    gc.message_ts = datetime.utcnow()
    evt.detail = gc
    return evt


def _make_broadcast_geochat_evt(uid="BC-001"):
    """Broadcast GeoChat to 'All Chat Rooms'."""
    from ots_federation.models.geochat import ALL_CHAT_ROOMS
    evt = _make_minimal_evt(uid=uid, etype="b-t-f")
    gc = GeoChat(None)
    gc.src_cs = SENDER_CALLSIGN
    gc.src_uid = SENDER_EUD_UID
    gc.src_marker = "a-f-G-U-C"
    gc.chatroom = ALL_CHAT_ROOMS
    gc.chat_parent = "RootContactGroup"
    gc.dst_uid = None
    gc.dst_team = None
    gc.message = "hello everyone"
    gc.message_ts = datetime.utcnow()
    evt.detail = gc
    return evt


def _firehose_body(uid, evt):
    """Build a firehose message body {"uid": uid, "cot": xml}."""
    xml = etree.tostring(evt.as_element, encoding="unicode")
    return json.dumps({"uid": uid, "cot": xml}).encode()


# ===========================================================================
# O. OUTBOUND: manager.on_outbound fires exactly once per event
# ===========================================================================

class TestOutboundDirectedRelayedOnce(unittest.TestCase):
    """
    O1–O3: The OTS plugin's outbound path (firehose consumer) must call
    manager.on_outbound() exactly once per event, regardless of event type.

    Architecture note: OTS EudHandler.publish_cot() (EudHandler.py:468) publishes
    ALL events to the firehose fanout with body {"uid": self.uid, ...} where
    self.uid is the sender EUD's device UID (not the event UID). The plugin's
    EudGroupCache is keyed by EUD device UID and populated from the groups exchange
    (also uses EUD device UIDs). So directed GeoChat events with a GeoChat event UID
    get a cache hit because the firehose body uid IS the sender EUD device UID.

    on_outbound is called exactly once per event by _on_firehose_message — the
    firehose publishes one message per event, and the callback calls on_outbound once.
    """

    def _make_bus_with_cache(self):
        cache = EudGroupCache()
        # Pre-populate cache with sender EUD uid → FIRE-OPS (simulates a previously
        # seen PLI or groups-exchange delivery from this EUD).
        cache.update(SENDER_EUD_UID, "FIRE-OPS")
        bus, _ = _make_bus(eud_group_cache=cache)
        return bus

    def _run_firehose(self, bus, evt, sender_uid=SENDER_EUD_UID):
        """Drive _on_firehose_message directly; return the mock manager."""
        mock_manager = MagicMock()
        body = _firehose_body(sender_uid, evt)
        bus._on_firehose_message(mock_manager, None, None, None, body)
        return mock_manager

    # O1 — directed GeoChat: on_outbound called exactly once
    def test_directed_geochat_on_outbound_called_once(self):
        """O1: directed GeoChat fires on_outbound exactly once."""
        bus = self._make_bus_with_cache()
        evt = _make_directed_geochat_evt(uid="GC-O1", dst_uid="ANDROID-bob-5678")
        manager = self._run_firehose(bus, evt)
        self.assertEqual(
            manager.on_outbound.call_count, 1,
            "on_outbound must fire exactly once for a directed GeoChat event",
        )

    # O2 — marti single-callsign: on_outbound called exactly once
    def test_marti_single_callsign_on_outbound_called_once(self):
        """O2: marti-addressed event fires on_outbound exactly once."""
        bus = self._make_bus_with_cache()
        evt = _make_marti_evt(uid="MARTI-O2", callsigns=("CHARLIE",))
        manager = self._run_firehose(bus, evt)
        self.assertEqual(
            manager.on_outbound.call_count, 1,
            "on_outbound must fire exactly once for a marti-addressed event",
        )

    # O3 — marti multi-callsign: on_outbound called exactly once (not per callsign)
    def test_marti_multi_callsign_on_outbound_called_once(self):
        """O3: multi-callsign marti event fires on_outbound exactly once."""
        bus = self._make_bus_with_cache()
        evt = _make_marti_evt(uid="MARTI-O3", callsigns=("CHARLIE", "DELTA", "ECHO"))
        manager = self._run_firehose(bus, evt)
        self.assertEqual(
            manager.on_outbound.call_count, 1,
            "on_outbound must fire exactly once regardless of marti dest count",
        )


class TestOutboundCacheLookupByEudUid(unittest.TestCase):
    """
    O4: The firehose body uid is the sender EUD's device UID (not the event UID).
    For directed GeoChat events, the GeoChat event UID differs from the sender EUD UID.
    The plugin must use the firehose body uid (sender EUD UID) for the cache lookup.

    This verifies that directed GeoChat events are not dropped by fail-closed cache
    policy: if the sender EUD was previously seen on the groups exchange, its device
    UID is in the cache, and the firehose message with that same device UID will hit.
    """

    def test_geochat_event_relayed_when_sender_eud_in_cache(self):
        """
        O4: A directed GeoChat event is relayed when the sender EUD's device UID
        (from the firehose body) is in the EudGroupCache, even though the GeoChat
        event UID is different.

        This reproduces the OTS EudHandler.publish_cot() behavior: body["uid"] is
        self.uid (EUD device UID), not the GeoChat event's CoT uid.
        """
        cache = EudGroupCache()
        # Cache populated with EUD device UID (not GeoChat event UID).
        cache.update(SENDER_EUD_UID, "FIRE-OPS")

        bus, _ = _make_bus(eud_group_cache=cache)
        mock_manager = MagicMock()

        # GeoChat event has a different UID from the sender EUD.
        gc_evt = _make_directed_geochat_evt(uid="GeoChat.ANDROID-alice.0001", dst_uid="ANDROID-bob")

        # Firehose body: uid = SENDER_EUD_UID (EUD device UID), not gc_evt.uid.
        body = _firehose_body(SENDER_EUD_UID, gc_evt)
        bus._on_firehose_message(mock_manager, None, None, None, body)

        self.assertEqual(
            mock_manager.on_outbound.call_count, 1,
            "directed GeoChat must be relayed when sender EUD UID is in cache",
        )

    def test_event_dropped_when_sender_eud_not_in_cache(self):
        """
        Cache miss for the sender EUD UID: fail-closed, on_outbound not called.
        """
        cache = EudGroupCache()  # empty cache
        bus, _ = _make_bus(eud_group_cache=cache)
        mock_manager = MagicMock()

        gc_evt = _make_directed_geochat_evt(uid="GeoChat.ANDROID-alice.0002")
        body = _firehose_body(SENDER_EUD_UID, gc_evt)
        bus._on_firehose_message(mock_manager, None, None, None, body)

        mock_manager.on_outbound.assert_not_called()


# ===========================================================================
# I. INBOUND: inject() directed marti delivery via dms exchange
# ===========================================================================

class TestInboundMartiDirectedDelivery(unittest.TestCase):
    """
    I1–I3: inject() with a marti-addressed event must publish to dms/<callsign>
    and must NOT publish to the groups exchange.

    Defect fixed: prior to this fix, inject() published all inbound events to
    <group>.OUT regardless of whether they were directed (marti) or broadcast.
    Directed marti events would fan-out to ALL EUDs in the mapped group instead
    of being delivered only to the named callsign(s).

    Reference: OTS route_cot() (cot_parser.py:1147-1171) routes marti events
    to dms/<callsign>; OTS EUDs bind dms/<their-callsign> on connect.
    """

    # I1 — single-callsign marti: dms exchange, NOT groups
    def test_marti_single_callsign_goes_to_dms_not_groups(self):
        """I1: inject() with a marti event publishes to dms/CHARLIE, not groups exchange."""
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = _make_marti_evt(uid="MARTI-I1", callsigns=("CHARLIE",))

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in publishes]
        rks = [(e, rk) for e, rk, _ in publishes]

        self.assertIn(("dms", "CHARLIE"), rks,
            "marti event must be published to dms/CHARLIE")
        self.assertNotIn("groups", exchanges,
            "marti event must NOT be published to the groups exchange (fan-out leak)")

    # I2 — multi-callsign marti: one dms publish per callsign, no groups
    def test_marti_multi_callsign_goes_to_dms_per_callsign(self):
        """I2: multi-callsign marti event publishes to dms/<each-callsign>, not groups."""
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = _make_marti_evt(uid="MARTI-I2", callsigns=("CHARLIE", "DELTA", "ECHO"))

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        rks = {(e, rk) for e, rk, _ in publishes}
        exchanges = [e for e, _, _ in publishes]

        self.assertIn(("dms", "CHARLIE"), rks, "dms/CHARLIE must be published")
        self.assertIn(("dms", "DELTA"), rks, "dms/DELTA must be published")
        self.assertIn(("dms", "ECHO"), rks, "dms/ECHO must be published")
        self.assertNotIn("groups", exchanges,
            "multi-callsign marti must NOT publish to groups exchange")

    # I3 — leak canary: groups exchange silent for marti events
    def test_marti_leak_canary_groups_exchange_silent(self):
        """
        I3: Leak canary — a marti event addressed to CHARLIE must NOT publish
        to the groups exchange. DELTA (a canary in the same group) must not
        receive it from groups/<group>.OUT.

        This is the definitive privacy regression test for the marti inbound
        defect. DELTA's EUD queue is bound to FIRE-OPS.OUT; if the plugin
        incorrectly publishes to groups/FIRE-OPS.OUT, DELTA would receive the
        marti event addressed exclusively to CHARLIE.
        """
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = _make_marti_evt(uid="MARTI-I3-canary", callsigns=("CHARLIE",))

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        groups_rks = [(e, rk) for e, rk, _ in publishes if e == "groups"]

        self.assertEqual(groups_rks, [],
            "groups exchange must be SILENT for marti-addressed events "
            "(DELTA canary must not receive CHARLIE's directed event)")
        # CHARLIE still gets it:
        dms_rks = [(e, rk) for e, rk, _ in publishes if e == "dms"]
        self.assertIn(("dms", "CHARLIE"), dms_rks)


class TestInboundMartiFallbackPath(unittest.TestCase):
    """
    I4: Fallback path (no local_groups) — marti events go to cot_parser.
    OTS route_cot() detects <dest> tags and routes to dms/<callsign> natively,
    so directed delivery is handled by OTS core on this path. Unchanged.
    """

    def test_marti_fallback_publishes_to_cot_parser(self):
        """I4: marti event with no local_groups falls back to cot_parser (unchanged)."""
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = _make_marti_evt(uid="MARTI-I4-fallback", callsigns=("CHARLIE",))

        bus.inject(src=None, evt=evt, local_groups=None)

        publishes = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in publishes]
        self.assertIn("cot_parser", exchanges,
            "fallback path must publish marti to cot_parser (OTS handles dms routing)")
        self.assertNotIn("dms", exchanges)
        self.assertNotIn("groups", exchanges)


class TestInboundMartiWithInjectCotParser(unittest.TestCase):
    """
    I5: inject_cot_parser=True — marti events publish to dms AND cot_parser.
    OTS route_cot will also send to dms from the cot_parser path (double delivery
    accepted for DB persistence purposes — documented in ots_bus.py).
    """

    def test_marti_with_inject_cot_parser_true_publishes_to_both(self):
        """I5: marti + inject_cot_parser=True → dms/<callsign> AND cot_parser."""
        bus, mock_ch = _make_bus(inject_cot_parser=True)
        evt = _make_marti_evt(uid="MARTI-I5-cot", callsigns=("CHARLIE",))

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in publishes]
        rks = [(e, rk) for e, rk, _ in publishes]

        self.assertIn(("dms", "CHARLIE"), rks,
            "dms/CHARLIE must be published when inject_cot_parser=True")
        self.assertIn("cot_parser", exchanges,
            "cot_parser must be published for DB persistence when inject_cot_parser=True")
        self.assertNotIn("groups", exchanges,
            "groups exchange must remain silent for marti events even with inject_cot_parser=True")


# ===========================================================================
# I6–I7: Directed GeoChat — OTS core limitation, groups exchange preserved
# ===========================================================================

class TestInboundDirectedGeoChatOtsCoreLimit(unittest.TestCase):
    """
    I6–I7: Directed GeoChat and broadcast GeoChat continue to publish to the
    groups exchange. This is consistent with OTS native behavior: OTS route_cot()
    has no per-UID GeoChat routing path (<dest> tags are absent in GeoChat events),
    so OTS also delivers GeoChat to all group members natively.

    This is an OTS CORE LIMITATION — the plugin cannot fix this without OTS
    core changes. These tests document the expected (current) behavior and guard
    against accidental regression.

    Human-decision item: requires an OTS core change to route directed
    GeoChat per-UID; out of scope for this plugin.
    """

    # I6 — directed GeoChat still goes to groups exchange (OTS core limitation)
    def test_directed_geochat_still_goes_to_groups_exchange(self):
        """
        I6: Directed GeoChat (b-t-f, no <dest> tags) publishes to groups/<group>.OUT.
        OTS delivers it to all group members — consistent with native OTS GeoChat routing.
        This is the documented OTS core limitation for directed GeoChat federation.
        """
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = _make_directed_geochat_evt(uid="GC-I6", dst_uid="ANDROID-bob-5678")

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in publishes]
        rks = [(e, rk) for e, rk, _ in publishes]

        self.assertIn("groups", exchanges,
            "directed GeoChat must still go to groups exchange (OTS core limitation)")
        self.assertIn(("groups", "FIRE-OPS.OUT"), rks)
        self.assertNotIn("dms", exchanges,
            "directed GeoChat must NOT go to dms exchange (no <dest> tags in GeoChat)")

    # I7 — broadcast GeoChat unchanged
    def test_broadcast_geochat_goes_to_groups_exchange(self):
        """I7: Broadcast GeoChat publishes to groups/<group>.OUT (unchanged)."""
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = _make_broadcast_geochat_evt(uid="BC-I7")

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        rks = [(e, rk) for e, rk, _ in publishes]

        self.assertIn(("groups", "FIRE-OPS.OUT"), rks,
            "broadcast GeoChat must still go to groups exchange")
        self.assertNotIn("dms", [e for e, _, _ in publishes])


# ===========================================================================
# Regression: existing inbound delivery tests still pass with marti changes
# ===========================================================================

class TestInboundDeliveryRegressionGuard(unittest.TestCase):
    """
    Guard that the marti-directed-delivery change does not regress the existing
    inbound delivery test invariants (I1-I16 in test_inbound_delivery.py).

    Spot-check the critical invariants here to catch any inadvertent breakage
    of the non-marti paths in inject().
    """

    def _make_non_marti_evt(self, uid="NM-001", groups=None):
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

    def test_non_marti_with_groups_still_goes_to_groups_exchange(self):
        """Non-marti PLI event with local_groups still publishes to groups exchange."""
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = self._make_non_marti_evt("PLI-RG1")

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in publishes]
        rks = [(e, rk) for e, rk, _ in publishes]
        self.assertIn("groups", exchanges)
        self.assertIn(("groups", "FIRE-OPS.OUT"), rks)
        self.assertNotIn("dms", exchanges)

    def test_no_local_groups_fallback_to_cot_parser(self):
        """Non-marti event with no local_groups still falls back to cot_parser."""
        bus, mock_ch = _make_bus(inject_cot_parser=False)
        evt = self._make_non_marti_evt("PLI-RG2")

        bus.inject(src=None, evt=evt, local_groups=None)

        publishes = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in publishes]
        self.assertIn("cot_parser", exchanges)
        self.assertNotIn("groups", exchanges)
        self.assertNotIn("dms", exchanges)

    def test_inject_cot_parser_true_non_marti_still_publishes_both(self):
        """Non-marti event with inject_cot_parser=True still publishes to groups + cot_parser."""
        bus, mock_ch = _make_bus(inject_cot_parser=True)
        evt = self._make_non_marti_evt("PLI-RG3")

        bus.inject(src=None, evt=evt, local_groups=frozenset(["FIRE-OPS"]))

        publishes = _collect_publishes(mock_ch)
        exchanges = [e for e, _, _ in publishes]
        self.assertIn("groups", exchanges)
        self.assertIn("cot_parser", exchanges)


if __name__ == "__main__":
    unittest.main()
