"""
tests/test_loop_filter.py

Unit tests for ots_federation.loop_filter.LoopFilter.

Coverage:
  U1  — stamp_inbound + parse_fedprov: round-trip preserves server_id, chain
         max_hops, current_hops.
  U2  — should_relay_outbound: event stamped with our server_id → False (echo).
  U3  — should_relay_outbound + codec.prepare_outbound_event: event with
         current_hops == max_hops is dropped by the codec's hop-limit gate.
  U4  — Per-group hop limits: scoped to codec (Phase 2; placeholder test).
  U5  — Hop increment on relay: stamp records current_hops=N; codec's
         prepare_outbound_event sends outbound with hops=N+1.
  U6  — Provenance accumulation: stamp_inbound appends our id to prior chain
         without deduplication; list grows strictly.
  U7  — Malicious detail element ignored: local event with injected
         <_fedhops max_hops="1000"/> → clean_for_relay strips it;
         should_relay_outbound does NOT drop the event (it's not our injection).

  N1  — Strip detail element (ATAK stripped our stamp): event has no _fedprov →
         should_relay_outbound returns True (treated as local event).
  N2  — Malformed XML: should_relay_outbound and clean_for_relay do not raise;
         graceful degradation.
  N3  — UID dedup window: dedup_window_secs>0 drops second event with same UID
         within the window; accepts it outside the window.
"""

import time
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from lxml import etree

from ots_federation.loop_filter import LoopFilter, FEDPROV_TAG, FEDHOPS_TAG


# ── Shared fixtures ────────────────────────────────────────────────────────────

OUR_SERVER_ID = "ots-test-node"
PEER_A_ID = "peer-alpha"
PEER_B_ID = "peer-bravo"

# Minimal CoT XML without <detail>
_COT_NO_DETAIL = (
    '<event version="2.0" uid="TEST-001" type="a-f-G-U-C" '
    'time="2026-07-09T12:00:00.000Z" '
    'start="2026-07-09T12:00:00.000Z" '
    'stale="2026-07-09T12:10:00.000Z" how="m-g">'
    '<point lat="40.0" lon="-75.0" hae="0" ce="9999999" le="9999999"/>'
    '</event>'
)

# Minimal CoT XML with empty <detail>
_COT_EMPTY_DETAIL = (
    '<event version="2.0" uid="TEST-002" type="a-f-G-U-C" '
    'time="2026-07-09T12:00:00.000Z" '
    'start="2026-07-09T12:00:00.000Z" '
    'stale="2026-07-09T12:10:00.000Z" how="m-g">'
    '<point lat="40.0" lon="-75.0" hae="0" ce="9999999" le="9999999"/>'
    '<detail/>'
    '</event>'
)

# CoT XML with some contact detail (generic, no _fedprov)
_COT_WITH_CONTACT = (
    '<event version="2.0" uid="TEST-003" type="a-f-G-U-C" '
    'time="2026-07-09T12:00:00.000Z" '
    'start="2026-07-09T12:00:00.000Z" '
    'stale="2026-07-09T12:10:00.000Z" how="m-g">'
    '<point lat="40.0" lon="-75.0" hae="0" ce="9999999" le="9999999"/>'
    '<detail>'
    '<contact callsign="TestUser" endpoint="*:-1:stcp"/>'
    '</detail>'
    '</event>'
)


def _make_fed_meta(seen_server_ids=None, current_hops=1, max_hops=3):
    """Build a FedMeta-like object for test use (duck-typed)."""
    m = MagicMock()
    m.seen_server_ids = list(seen_server_ids or [])
    m.current_hops = current_hops
    m.max_hops = max_hops
    return m


def _make_filter(**kwargs):
    return LoopFilter(server_id=OUR_SERVER_ID, **kwargs)


# ── U1: Round-trip encode/decode ───────────────────────────────────────────────

class TestStampInboundRoundTrip(unittest.TestCase):
    """U1 — stamp_inbound + parse_fedprov round-trip."""

    def _stamp_and_parse(self, cot_xml, fed_meta):
        lf = _make_filter()
        stamped = lf.stamp_inbound(cot_xml, fed_meta)
        parsed = lf.parse_fedprov(stamped)
        return stamped, parsed

    def test_stamp_creates_fedprov_element(self):
        """stamp_inbound on a no-detail event creates <_fedprov>."""
        fm = _make_fed_meta(seen_server_ids=[], current_hops=1, max_hops=3)
        _, parsed = self._stamp_and_parse(_COT_NO_DETAIL, fm)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["server_id"], OUR_SERVER_ID)

    def test_stamp_creates_fedhops_element(self):
        """stamp_inbound on a no-detail event creates <_fedhops>."""
        fm = _make_fed_meta(seen_server_ids=[], current_hops=1, max_hops=3)
        _, parsed = self._stamp_and_parse(_COT_NO_DETAIL, fm)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["max_hops"], 3)
        self.assertEqual(parsed["current_hops"], 1)

    def test_round_trip_with_prior_chain(self):
        """Round-trip preserves chain containing prior seen_server_ids."""
        fm = _make_fed_meta(
            seen_server_ids=[PEER_A_ID, PEER_B_ID], current_hops=2, max_hops=5
        )
        _, parsed = self._stamp_and_parse(_COT_EMPTY_DETAIL, fm)
        self.assertEqual(parsed["server_id"], OUR_SERVER_ID)
        self.assertIn(PEER_A_ID, parsed["chain"])
        self.assertIn(PEER_B_ID, parsed["chain"])
        self.assertEqual(parsed["current_hops"], 2)
        self.assertEqual(parsed["max_hops"], 5)

    def test_stamp_preserves_existing_detail_children(self):
        """stamp_inbound appends to existing <detail>; doesn't wipe it."""
        fm = _make_fed_meta()
        lf = _make_filter()
        stamped = lf.stamp_inbound(_COT_WITH_CONTACT, fm)
        root = etree.fromstring(stamped.encode("utf-8"))
        detail = root.find("detail")
        self.assertIsNotNone(detail)
        # Original contact element still present
        self.assertIsNotNone(detail.find("contact"))
        # Stamp added
        self.assertIsNotNone(detail.find(FEDPROV_TAG))
        self.assertIsNotNone(detail.find(FEDHOPS_TAG))

    def test_stamp_unlimited_hops(self):
        """max_hops == -1 (unlimited) is preserved in stamp."""
        fm = _make_fed_meta(current_hops=0, max_hops=-1)
        _, parsed = self._stamp_and_parse(_COT_NO_DETAIL, fm)
        self.assertEqual(parsed["max_hops"], -1)

    def test_stamp_malformed_xml_returns_unchanged(self):
        """stamp_inbound on malformed XML returns original string, no raise."""
        lf = _make_filter()
        fm = _make_fed_meta()
        bad_xml = "<event>NOT CLOSED"
        result = lf.stamp_inbound(bad_xml, fm)
        self.assertEqual(result, bad_xml)


# ── U2: Provenance loop detection (echo suppression) ──────────────────────────

class TestShouldRelayOutboundEchoDetection(unittest.TestCase):
    """U2 — Echo detection via our server_id in <_fedprov server_id>."""

    def _make_echo_xml(self, server_id=OUR_SERVER_ID, chain=""):
        """Build a CoT XML with a <_fedprov> stamped by server_id."""
        chain_attr = f' chain="{chain}"' if chain else ""
        return (
            '<event version="2.0" uid="ECHO-001" type="a-f-G-U-C" '
            'time="2026-07-09T12:00:00.000Z" '
            'start="2026-07-09T12:00:00.000Z" '
            'stale="2026-07-09T12:10:00.000Z" how="m-g">'
            '<point lat="0.0" lon="0.0" hae="0" ce="9999999" le="9999999"/>'
            f'<detail><{FEDPROV_TAG} server_id="{server_id}"{chain_attr}/></detail>'
            '</event>'
        )

    def test_echo_dropped_when_our_id_in_server_id(self):
        """should_relay_outbound → False when _fedprov server_id == our server_id."""
        lf = _make_filter()
        xml = self._make_echo_xml(server_id=OUR_SERVER_ID)
        self.assertFalse(lf.should_relay_outbound(xml))

    def test_echo_dropped_when_our_id_in_chain(self):
        """should_relay_outbound → False when our server_id appears in chain."""
        lf = _make_filter()
        xml = self._make_echo_xml(server_id=PEER_A_ID, chain=OUR_SERVER_ID)
        self.assertFalse(lf.should_relay_outbound(xml))

    def test_non_echo_passed_when_different_server_id(self):
        """should_relay_outbound → True when _fedprov belongs to a different peer."""
        lf = _make_filter()
        xml = self._make_echo_xml(server_id=PEER_A_ID)
        self.assertTrue(lf.should_relay_outbound(xml))

    def test_local_event_no_fedprov_passes(self):
        """should_relay_outbound → True for a local event with no <_fedprov>."""
        lf = _make_filter()
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))

    def test_event_no_detail_passes(self):
        """should_relay_outbound → True when there is no <detail> element."""
        lf = _make_filter()
        self.assertTrue(lf.should_relay_outbound(_COT_NO_DETAIL))


# ── U3: Hop-limit enforcement (via codec.prepare_outbound_event) ───────────────

class TestHopLimitEnforcement(unittest.TestCase):
    """
    U3 — Hop-limit enforcement at the gRPC codec layer.

    codec.prepare_outbound_event checks:
      if fed_meta.current_hops >= fed_meta.max_hops → return None (drop).
    """

    def test_prepare_outbound_drops_at_hop_limit(self):
        """
        prepare_outbound_event returns None when current_hops >= max_hops.
        """
        from ots_federation.codec import prepare_outbound_event, FedMeta
        from ots_federation import models

        evt = models.Event(
            uid="HOP-001",
            etype="a-f-G-U-C",
            how="m-g",
            time=datetime(2026, 7, 9, 12, 0, 0),
            start=datetime(2026, 7, 9, 12, 0, 0),
            stale=datetime(2026, 7, 9, 12, 10, 0),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)

        # fed_meta: at hop limit (current == max)
        fed_meta = FedMeta(
            seen_server_ids=[PEER_A_ID],
            current_hops=2,
            max_hops=2,
        )
        evt.fed_meta = fed_meta

        result = prepare_outbound_event(
            evt,
            node_id=OUR_SERVER_ID,
            default_max_hops=3,
        )
        # Codec MUST drop the event.
        self.assertIsNone(result, "prepare_outbound_event must return None at hop limit")

    def test_prepare_outbound_drops_when_current_exceeds_max(self):
        """prepare_outbound_event drops when current_hops > max_hops."""
        from ots_federation.codec import prepare_outbound_event, FedMeta
        from ots_federation import models

        evt = models.Event(
            uid="HOP-002",
            etype="a-f-G-U-C",
            how="m-g",
            time=datetime(2026, 7, 9, 12, 0, 0),
            start=datetime(2026, 7, 9, 12, 0, 0),
            stale=datetime(2026, 7, 9, 12, 10, 0),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)

        # hops already past the limit
        fed_meta = FedMeta(seen_server_ids=[PEER_A_ID], current_hops=5, max_hops=3)
        evt.fed_meta = fed_meta

        result = prepare_outbound_event(evt, node_id=OUR_SERVER_ID, default_max_hops=3)
        self.assertIsNone(result)

    def test_prepare_outbound_allows_under_hop_limit(self):
        """prepare_outbound_event returns a proto when hops are within limit."""
        from ots_federation.codec import prepare_outbound_event, FedMeta
        from ots_federation import models

        evt = models.Event(
            uid="HOP-003",
            etype="a-f-G-U-C",
            how="m-g",
            time=datetime(2026, 7, 9, 12, 0, 0),
            start=datetime(2026, 7, 9, 12, 0, 0),
            stale=datetime(2026, 7, 9, 12, 10, 0),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)

        fed_meta = FedMeta(seen_server_ids=[PEER_A_ID], current_hops=1, max_hops=3)
        evt.fed_meta = fed_meta

        result = prepare_outbound_event(evt, node_id=OUR_SERVER_ID, default_max_hops=3)
        self.assertIsNotNone(result)


# ── U4: Per-group hop limits (Phase 2 placeholder) ────────────────────────────

class TestPerGroupHopLimits(unittest.TestCase):
    """
    U4 — Per-group hop limits (Phase 2).

    TAK Server's FederateGroupHopLimits proto has no equivalent in the
    current ots_federation CoT detail-element scheme.  This placeholder test
    documents the gap and passes trivially.
    """

    def test_per_group_hop_limits_not_yet_implemented(self):
        """
        Per-group hop limits are a Phase 2 feature; current scheme is global-only.

        If this test starts failing, it means per-group limits have been
        implemented and this placeholder should be replaced with real coverage.
        """
        lf = _make_filter(max_hops=3)
        # A plain local event has no per-group limit metadata.
        # should_relay_outbound should pass it regardless.
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))


# ── U5: Hop increment on relay ────────────────────────────────────────────────

class TestHopIncrementOnRelay(unittest.TestCase):
    """
    U5 — Hop increment: stamp records current_hops=N; prepare_outbound_event
    sends outbound with current_hops=N+1.
    """

    def test_stamp_records_current_hops_as_is(self):
        """stamp_inbound writes fed_meta.current_hops verbatim (N, not N+1)."""
        fm = _make_fed_meta(current_hops=1, max_hops=3)
        lf = _make_filter()
        stamped = lf.stamp_inbound(_COT_NO_DETAIL, fm)
        parsed = lf.parse_fedprov(stamped)
        self.assertEqual(parsed["current_hops"], 1)  # recorded as-is

    def test_codec_increments_hops_on_outbound(self):
        """
        When prepare_outbound_event relays an event with current_hops=1
        the outbound FederatedEvent carries current_hops=2.
        """
        from ots_federation.codec import prepare_outbound_event, FedMeta
        from ots_federation import models

        evt = models.Event(
            uid="RELAY-001",
            etype="a-f-G-U-C",
            how="m-g",
            time=datetime(2026, 7, 9, 12, 0, 0),
            start=datetime(2026, 7, 9, 12, 0, 0),
            stale=datetime(2026, 7, 9, 12, 10, 0),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        evt.fed_meta = FedMeta(seen_server_ids=[PEER_A_ID], current_hops=1, max_hops=5)

        proto = prepare_outbound_event(evt, node_id=OUR_SERVER_ID, default_max_hops=5)
        self.assertIsNotNone(proto)
        # Codec MUST increment current_hops by 1.
        self.assertEqual(proto.federateHops.currentHops, 2)

    def test_hop_increment_chain_grows(self):
        """
        Each relay adds our node_id to the provenance chain and increments hops.
        """
        from ots_federation.codec import prepare_outbound_event, FedMeta
        from ots_federation import models

        evt = models.Event(
            uid="RELAY-002",
            etype="a-f-G-U-C",
            how="m-g",
            time=datetime(2026, 7, 9, 12, 0, 0),
            start=datetime(2026, 7, 9, 12, 0, 0),
            stale=datetime(2026, 7, 9, 12, 10, 0),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        evt.fed_meta = FedMeta(seen_server_ids=[PEER_A_ID], current_hops=1, max_hops=5)

        proto = prepare_outbound_event(evt, node_id=OUR_SERVER_ID, default_max_hops=5)
        self.assertIsNotNone(proto)

        # Our server_id should have been appended to the provenance list.
        prov_ids = {p.federationServerId for p in proto.federateProvenance}
        self.assertIn(OUR_SERVER_ID, prov_ids)
        self.assertIn(PEER_A_ID, prov_ids)


# ── U6: Provenance accumulation ───────────────────────────────────────────────

class TestProvenanceAccumulation(unittest.TestCase):
    """U6 — Provenance list grows strictly; no deduplication across hops."""

    def test_stamp_accumulates_chain_without_dedup(self):
        """
        stamp_inbound records fed_meta.seen_server_ids in 'chain' + our id in
        'server_id'.  Full provenance = chain + server_id = [A, B, OUR].
        """
        fm = _make_fed_meta(
            seen_server_ids=[PEER_A_ID, PEER_B_ID], current_hops=2, max_hops=5
        )
        lf = _make_filter()
        stamped = lf.stamp_inbound(_COT_NO_DETAIL, fm)
        parsed = lf.parse_fedprov(stamped)

        # server_id must be our node_id.
        self.assertEqual(parsed["server_id"], OUR_SERVER_ID)
        # chain must contain prior peers in order.
        self.assertEqual(parsed["chain"], [PEER_A_ID, PEER_B_ID])

    def test_stamp_does_not_dedup_repeated_ids(self):
        """
        Duplicate entries in seen_server_ids are preserved (strict accumulation
        not deduplicated).  This mirrors TAK Server's behaviour where provenance
        is additive and uniqueness enforcement is done by the loop-detection check.
        """
        fm = _make_fed_meta(
            seen_server_ids=[PEER_A_ID, PEER_A_ID], current_hops=2, max_hops=5
        )
        lf = _make_filter()
        stamped = lf.stamp_inbound(_COT_NO_DETAIL, fm)
        parsed = lf.parse_fedprov(stamped)
        # Both occurrences of PEER_A_ID should be in the chain.
        self.assertEqual(parsed["chain"].count(PEER_A_ID), 2)

    def test_codec_appends_our_id_to_provenance_list(self):
        """
        prepare_outbound_event appends our node_id to the proto provenance list
        without removing prior entries.
        """
        from ots_federation.codec import prepare_outbound_event, FedMeta
        from ots_federation import models

        evt = models.Event(
            uid="PROV-001",
            etype="a-f-G-U-C",
            how="m-g",
            time=datetime(2026, 7, 9, 12, 0, 0),
            start=datetime(2026, 7, 9, 12, 0, 0),
            stale=datetime(2026, 7, 9, 12, 10, 0),
        )
        evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)
        # Prior provenance chain: [A, B]
        evt.fed_meta = FedMeta(
            seen_server_ids=[PEER_A_ID, PEER_B_ID], current_hops=2, max_hops=5
        )

        proto = prepare_outbound_event(evt, node_id=OUR_SERVER_ID, default_max_hops=5)
        self.assertIsNotNone(proto)

        prov_ids = [p.federationServerId for p in proto.federateProvenance]
        # All three IDs must be present in the provenance list.
        self.assertIn(PEER_A_ID, prov_ids)
        self.assertIn(PEER_B_ID, prov_ids)
        self.assertIn(OUR_SERVER_ID, prov_ids)
        # Total count: prior (2) + ours (1) = 3.
        self.assertEqual(len(prov_ids), 3)


# ── U7: Malicious detail element ignored ──────────────────────────────────────

class TestMaliciousDetailElementIgnored(unittest.TestCase):
    """
    U7 — Local ATAK client injects <_fedhops max_hops="1000"/> or
    <_fedprov server_id="fake">.

    Spoof defense:
      - should_relay_outbound: returns True (not our server_id → pass through)
      - clean_for_relay: strips the injected elements
      - The relay event reaches prepare_outbound_event WITHOUT inflated hops.
    """

    def _make_spoofed_xml(
        self, uid="SPOOF-001", fake_max_hops=1000, fake_server_id=None
    ):
        """Build CoT XML with injected _fedhops and optionally _fedprov."""
        fedprov_part = (
            f'<{FEDPROV_TAG} server_id="{fake_server_id}"/>'
            if fake_server_id
            else ""
        )
        return (
            f'<event version="2.0" uid="{uid}" type="a-f-G-U-C" '
            'time="2026-07-09T12:00:00.000Z" '
            'start="2026-07-09T12:00:00.000Z" '
            'stale="2026-07-09T12:10:00.000Z" how="m-g">'
            '<point lat="0.0" lon="0.0" hae="0" ce="9999999" le="9999999"/>'
            f'<detail>'
            f'{fedprov_part}'
            f'<{FEDHOPS_TAG} max_hops="{fake_max_hops}" current_hops="0"/>'
            '</detail>'
            '</event>'
        )

    def test_injected_fedhops_does_not_stop_relay(self):
        """
        An event with injected <_fedhops max_hops="1000"/> (no our server_id)
        is NOT blocked by should_relay_outbound — it has no echo stamp.
        """
        lf = _make_filter()
        xml = self._make_spoofed_xml(fake_max_hops=1000)
        self.assertTrue(lf.should_relay_outbound(xml))

    def test_clean_for_relay_strips_injected_fedhops(self):
        """
        clean_for_relay removes injected <_fedhops> from the CoT XML.
        The codec then cannot be fooled by the inflated max_hops.
        """
        lf = _make_filter()
        xml = self._make_spoofed_xml(fake_max_hops=1000)
        cleaned = lf.clean_for_relay(xml)

        # The <_fedhops> element must be gone from the cleaned XML.
        root = etree.fromstring(cleaned.encode("utf-8"))
        detail = root.find("detail")
        self.assertIsNotNone(detail)
        self.assertIsNone(detail.find(FEDHOPS_TAG), "<_fedhops> must be stripped")

    def test_clean_for_relay_strips_injected_fedprov(self):
        """clean_for_relay removes injected <_fedprov> from other servers."""
        lf = _make_filter()
        xml = self._make_spoofed_xml(fake_server_id="fake-peer-id")
        cleaned = lf.clean_for_relay(xml)
        root = etree.fromstring(cleaned.encode("utf-8"))
        detail = root.find("detail")
        self.assertIsNone(detail.find(FEDPROV_TAG), "<_fedprov> must be stripped")

    def test_codec_uses_default_hops_after_strip(self):
        """
        After clean_for_relay, the event has no fed_meta → prepare_outbound_event
        starts fresh with default_max_hops (not inflated from spoofed detail).
        """
        from ots_federation.codec import prepare_outbound_event
        from ots_federation import models

        lf = _make_filter()
        xml = self._make_spoofed_xml(fake_max_hops=1000, uid="SPOOF-002")
        cleaned = lf.clean_for_relay(xml)

        _parser = etree.XMLParser(resolve_entities=False)
        root = etree.fromstring(cleaned.encode("utf-8"), _parser)
        from ots_federation.models.event import Event
        evt = Event.from_elm(root)
        # No fed_meta on local events after cleaning.
        # (Stripped event is treated as fresh local origin.)
        self.assertFalse(hasattr(evt, "fed_meta") and evt.fed_meta is not None,
                         "Local event should not carry a fed_meta after strip")

        default_max_hops = 3  # Our configured default
        proto = prepare_outbound_event(
            evt, node_id=OUR_SERVER_ID, default_max_hops=default_max_hops
        )
        self.assertIsNotNone(proto)
        # Codec should start fresh hops, NOT the injected 1000.
        self.assertEqual(proto.federateHops.maxHops, default_max_hops)
        self.assertEqual(proto.federateHops.currentHops, 1)


# ── N1: ATAK stripped the stamp (missing _fedprov) ────────────────────────────

class TestAtkStripDetection(unittest.TestCase):
    """
    N1 — ATAK client stripped the <_fedprov> stamp before re-broadcasting.

    Known limitation: if ATAK strips unknown detail elements, our echo
    detection cannot fire.  The event will be re-relayed (not silently
    dropped).  should_relay_outbound must handle the missing stamp gracefully
    without crashing and must not drop the event incorrectly.
    """

    def test_missing_fedprov_treated_as_local(self):
        """
        An event WITHOUT <_fedprov> (e.g., ATAK stripped it) is treated as a
        local event and passes should_relay_outbound.
        """
        lf = _make_filter()
        # Plain event — no _fedprov / _fedhops at all.
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))

    def test_missing_fedprov_does_not_raise(self):
        """should_relay_outbound with no <_fedprov> does not raise."""
        lf = _make_filter()
        try:
            result = lf.should_relay_outbound(_COT_NO_DETAIL)
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"should_relay_outbound raised unexpectedly: {exc}")
        self.assertTrue(result)

    def test_known_limitation_documented(self):
        """
        Verify the known limitation: if ATAK strips <_fedprov> from a
        previously-injected event, echo detection will NOT fire and the event
        will be re-relayed.  This test documents the failure mode.

        Mitigation: Operator should configure peers with loop-tolerant TTLs
        or use the UID dedup cache (dedup_window_secs) as a fallback.
        """
        lf = _make_filter()
        # Simulate: we stamped an event but ATAK received it and re-sent
        # without the <_fedprov>.  The re-sent event looks identical to a
        # fresh local event.
        atak_resent = _COT_WITH_CONTACT  # no _fedprov
        result = lf.should_relay_outbound(atak_resent)
        # By design, this returns True (re-relayed, not dropped).
        self.assertTrue(
            result,
            "Known limitation: ATAK strip causes re-relay (not an error in LoopFilter)",
        )


# ── N2: Malformed XML (graceful degradation) ──────────────────────────────────

class TestMalformedXmlGracefulDegradation(unittest.TestCase):
    """N2 — Malformed XML in CoT detail must not crash the plugin."""

    _BAD_XMLS = [
        "",                               # empty string
        "NOT XML AT ALL",                 # plain text
        "<event>NOT CLOSED",              # truncated
        "<event><detail>&undefined;</detail></event>",  # undefined entity
        "<event><detail>\x00\x01</detail></event>",     # null bytes
    ]

    def test_should_relay_outbound_does_not_raise_on_bad_xml(self):
        """should_relay_outbound handles all malformed XML gracefully."""
        lf = _make_filter()
        for bad_xml in self._BAD_XMLS:
            with self.subTest(bad_xml=bad_xml[:40]):
                try:
                    result = lf.should_relay_outbound(bad_xml)
                except Exception as exc:  # pylint: disable=broad-except
                    self.fail(
                        f"should_relay_outbound raised for {bad_xml[:40]!r}: {exc}"
                    )
                # Graceful degradation: treat as local event (True) or drop (False)
                # but never raise.  Current policy: return True (pass through).
                self.assertIsInstance(result, bool)

    def test_clean_for_relay_does_not_raise_on_bad_xml(self):
        """clean_for_relay handles all malformed XML gracefully."""
        lf = _make_filter()
        for bad_xml in self._BAD_XMLS:
            with self.subTest(bad_xml=bad_xml[:40]):
                try:
                    result = lf.clean_for_relay(bad_xml)
                except Exception as exc:  # pylint: disable=broad-except
                    self.fail(
                        f"clean_for_relay raised for {bad_xml[:40]!r}: {exc}"
                    )
                self.assertIsInstance(result, str)

    def test_stamp_inbound_does_not_raise_on_bad_xml(self):
        """stamp_inbound handles malformed XML gracefully."""
        lf = _make_filter()
        fm = _make_fed_meta()
        bad_xml = "<event>TRUNCATED"
        result = lf.stamp_inbound(bad_xml, fm)
        # On error, returns original string unchanged.
        self.assertEqual(result, bad_xml)


# ── N3: UID dedup window ───────────────────────────────────────────────────────

class TestUidDedupWindow(unittest.TestCase):
    """
    N3 — Ambiguous UID with different provenance (hash collision / misconfiguration).

    When dedup_window_secs > 0, a second event with the same UID within the
    window is dropped by should_relay_outbound.  Outside the window, it is
    accepted.  When dedup_window_secs == 0 (default), no dedup is applied.
    """

    def test_second_event_dropped_within_dedup_window(self):
        """Second event with same UID within dedup window → dropped."""
        lf = LoopFilter(server_id=OUR_SERVER_ID, dedup_window_secs=60.0)
        # First event: accepted.
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))
        # Second event with the SAME uid (TEST-003) within 60s: dropped.
        self.assertFalse(
            lf.should_relay_outbound(_COT_WITH_CONTACT),
            "Second event with same UID must be dropped within dedup window",
        )

    def test_second_event_accepted_outside_dedup_window(self):
        """Second event with same UID after dedup TTL expires → accepted."""
        lf = LoopFilter(server_id=OUR_SERVER_ID, dedup_window_secs=0.05)  # 50ms window
        # First event.
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))
        # Wait for dedup window to expire.
        time.sleep(0.1)
        # Second event: accepted (outside window).
        self.assertTrue(
            lf.should_relay_outbound(_COT_WITH_CONTACT),
            "Event must be accepted after dedup window expires",
        )

    def test_different_uids_not_deduped(self):
        """Events with different UIDs are never deduped by the UID cache."""
        lf = LoopFilter(server_id=OUR_SERVER_ID, dedup_window_secs=60.0)

        # Event A
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))  # uid=TEST-003

        # Event B (different uid)
        self.assertTrue(lf.should_relay_outbound(_COT_EMPTY_DETAIL))  # uid=TEST-002

    def test_dedup_disabled_by_default(self):
        """dedup_window_secs=0 (default) → second event with same UID passes."""
        lf = _make_filter()  # dedup_window_secs=0 by default
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))
        # Second event: also passes (no dedup).
        self.assertTrue(lf.should_relay_outbound(_COT_WITH_CONTACT))

    def test_dedup_window_configurable(self):
        """Verify dedup_window_secs is configurable at construction time."""
        lf_no_dedup = LoopFilter(server_id=OUR_SERVER_ID, dedup_window_secs=0)
        lf_dedup = LoopFilter(server_id=OUR_SERVER_ID, dedup_window_secs=30)
        self.assertEqual(lf_no_dedup.dedup_window_secs, 0)
        self.assertEqual(lf_dedup.dedup_window_secs, 30)


# ── Threat model: echo-forge DoS (KNOWN LIMITATION, ACCEPTED) ────────────────

class TestEchoForgeDosThreatModel(unittest.TestCase):
    """
    Threat model — echo-forge DoS (KNOWN, ACCEPTED LIMITATION).

    A local ATAK client that stamps its own event with
    <_fedprov server_id="OUR_SERVER_ID"/> causes should_relay_outbound to
    return False for that event — suppressing only that client's own events
    from federation outbound relay.  This is a SELF-INFLICTED DoS against
    the forging client's own traffic, not a security bypass.

    Severity: local-client-only, low risk.  The forging client suppresses
    only its own events (those carrying the forged stamp); events from all
    other ATAK clients are unaffected.  The bypass direction (inflating hop
    counts or spoofing provenance to force relay) is fully protected by
    clean_for_relay + codec hop-limit logic (see loop_filter module
    docstring threat-model section for full analysis).
    """

    def _make_forged_xml(self, uid="FORGE-001"):
        """Build a CoT event where a local client has forged our server_id."""
        return (
            f'<event version="2.0" uid="{uid}" type="a-f-G-U-C" '
            'time="2026-07-09T12:00:00.000Z" '
            'start="2026-07-09T12:00:00.000Z" '
            'stale="2026-07-09T12:10:00.000Z" how="m-g">'
            '<point lat="40.0" lon="-75.0" hae="0" ce="9999999" le="9999999"/>'
            f'<detail>'
            f'<{FEDPROV_TAG} server_id="{OUR_SERVER_ID}"/>'
            '</detail>'
            '</event>'
        )

    def test_forged_echo_stamp_suppresses_forging_client_event(self):
        """
        KNOWN LIMITATION: a local client forging <_fedprov server_id="OUR_SERVER_ID">
        causes that specific event to be dropped by should_relay_outbound
        (treated as an echo of our own injection).

        Consequence: the forging client's events are silently not federated to
        remote peers.  This is accepted because:
          (a) the forge requires a malicious or misconfigured local process
          (b) only events stamped with the forged server_id are affected — all
              other local events continue to relay normally, and
          (c) there is no bypass vector (codec ignores CoT XML hop fields entirely).
        """
        lf = _make_filter()
        forged_xml = self._make_forged_xml()
        # Echo-detection gate fires — event is suppressed (DoS on own traffic only).
        self.assertFalse(
            lf.should_relay_outbound(forged_xml),
            "Forged server_id == OUR_SERVER_ID must trigger echo suppression "
            "(KNOWN LIMITATION: self-inflicted DoS, not a bypass)",
        )

    def test_forged_echo_stamp_does_not_affect_other_senders(self):
        """
        The DoS scope is limited: a legitimate local event from a different
        sender (no forged _fedprov stamp) passes through should_relay_outbound
        normally even while the forging client's events are suppressed.
        """
        lf = _make_filter()

        # Event WITH forged stamp — suppressed (DoS on this specific event).
        forged_xml = self._make_forged_xml(uid="FORGE-001")
        self.assertFalse(lf.should_relay_outbound(forged_xml))

        # Different event from another ATAK client (no forged stamp) — passes.
        # This verifies the DoS scope: only the forging client is affected.
        self.assertTrue(
            lf.should_relay_outbound(_COT_WITH_CONTACT),
            "Legitimate events from other senders must not be affected by the forge",
        )


if __name__ == "__main__":
    unittest.main()
