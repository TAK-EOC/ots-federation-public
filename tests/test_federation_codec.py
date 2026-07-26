"""
tests/test_federation_codec.py

Bidirectional codec tests: CoT-XML ↔ FederatedEvent (protobuf).

Coverage areas:
  - Round-trip: CoT XML → encode_federated_event → decode_federated_event → CoT XML
    preserves all modelled fields (uid, etype, how, timestamps, point, TAKUser detail).
  - TAKUser named-field mapping (screenName, groupName, groupRole, phone, battery, speed, course).
  - GeoChat and generic Detail pass through `other` XML blob unchanged.
  - Timestamp precision: Unix ms ↔ tz-naive datetime.
  - Timestamp edge cases: epoch (0 ms), Y2K, near-future.
  - FedMeta round-trip: seen_server_ids, current_hops, max_hops.
  - decode_contact_entry: present / absent / CRUD values.
  - XXE safety: external entity in GeoEvent.other must not be resolved.
  - Malformed XML in GeoEvent.other → None event, no exception leakage.
  - Empty GeoEvent.other with named fields → TAKUser synthesised.
  - Missing uid / type fields → None event.
  - FederatedEvent with no event field (contact-only message) → (None, FedMeta).
  - Teams enum fallback: unknown group name maps to Teams.UNKNOWN.
"""

import sys
import os
import unittest
from datetime import datetime

# conftest.py installs the pkg_resources shim and proto sys.path entry before
# any test module is collected; no need to repeat them here.

from ots_federation import models
from ots_federation.proto import fig_pb2
from ots_federation.codec import (
    FedMeta,
    encode_federated_event,
    decode_federated_event,
    decode_contact_entry,
    _dt_to_ms,
    _ms_to_dt,
)


# ── Fixture helpers ───────────────────────────────────────────────────────────

_T0 = datetime(2021, 2, 27, 20, 32, 24, 771000)   # 2021-02-27T20:32:24.771Z
_T1 = datetime(2021, 2, 27, 20, 38, 39, 771000)   # stale


def _make_basic_event() -> models.Event:
    """Minimal event with no detail (generic marker)."""
    evt = models.Event(
        uid="ANDROID-deadbeef",
        etype="a-f-G-U-C",
        how="m-g",
        time=_T0,
        start=_T0,
        stale=_T1,
    )
    evt.point = models.Point(lat=1.234567, lon=-3.141592, hae=-25.7, ce=9.9, le=9999999.0)
    return evt


def _make_takuser_event() -> models.Event:
    """Event with a full TAKUser detail."""
    from lxml import etree

    detail_xml = (
        b'<detail>'
        b'<takv os="29" version="4.0.0.0 (deadbeef).1234567890-CIV"'
        b' device="Some Android Device" platform="ATAK-CIV"/>'
        b'<contact xmppUsername="xmpp@host.com" endpoint="*:-1:stcp"'
        b' callsign="JENNY" phone="+15551234567"/>'
        b'<uid Droid="JENNY"/>'
        b'<__group role="Team Member" name="Cyan"/>'
        b'<status battery="78"/>'
        b'<track course="80.2" speed="1.5"/>'
        b'</detail>'
    )
    elm = etree.fromstring(detail_xml)
    user = models.TAKUser.from_elm(elm, uid="ANDROID-deadbeef")

    evt = _make_basic_event()
    evt.detail = user
    return evt


def _make_geochat_event() -> models.Event:
    """Event with a GeoChat detail."""
    from lxml import etree

    detail_xml = (
        b'<detail>'
        b'<__chat parent="RootContactGroup" groupOwner="false"'
        b' chatroom="All Chat Rooms" id="All Chat Rooms"'
        b' senderCallsign="JENNY">'
        b'<chatgrp uid0="ANDROID-deadbeef" uid1="All Chat Rooms"'
        b' id="All Chat Rooms"/>'
        b'</__chat>'
        b'<link uid="ANDROID-deadbeef" type="a-f-G-U-C" relation="p-p"/>'
        b'<remarks source="BAO.F.ATAK.ANDROID-deadbeef"'
        b' to="All Chat Rooms"'
        b' time="2021-02-27T20:32:24.771Z">Hello world</remarks>'
        b'</detail>'
    )
    elm = etree.fromstring(detail_xml)
    chat = models.GeoChat.from_elm(elm)

    evt = _make_basic_event()
    evt.detail = chat
    return evt


# ── Timestamp helper tests ────────────────────────────────────────────────────


class TestTimestampHelpers(unittest.TestCase):
    def test_epoch_zero(self):
        """Unix ms=0 → epoch datetime."""
        dt = _ms_to_dt(0)
        self.assertEqual(dt, datetime(1970, 1, 1, 0, 0, 0))

    def test_epoch_roundtrip(self):
        """epoch datetime → 0 ms → epoch datetime."""
        epoch = datetime(1970, 1, 1, 0, 0, 0)
        self.assertEqual(_dt_to_ms(epoch), 0)
        self.assertEqual(_ms_to_dt(0), epoch)

    def test_y2k(self):
        """Y2K: 2000-01-01T00:00:00 → 946684800000 ms."""
        y2k = datetime(2000, 1, 1, 0, 0, 0)
        ms = _dt_to_ms(y2k)
        self.assertEqual(ms, 946684800000)
        self.assertEqual(_ms_to_dt(ms), y2k)

    def test_millisecond_precision(self):
        """Sub-second precision is preserved through round-trip.

        2021-02-27T20:32:24.771Z = 1614457944771 ms since Unix epoch (UTC).
        Verified: datetime(2021,2,27,20,32,24,771000,tz=UTC).timestamp*1000
        """
        dt = datetime(2021, 2, 27, 20, 32, 24, 771000)
        ms = _dt_to_ms(dt)
        self.assertEqual(ms, 1614457944771)
        recovered = _ms_to_dt(ms)
        self.assertEqual(recovered, dt)

    def test_none_dt_returns_zero(self):
        """None datetime encodes to 0 ms (safe default)."""
        self.assertEqual(_dt_to_ms(None), 0)

    def test_near_future(self):
        """2030-06-15T12:00:00 round-trips correctly."""
        dt = datetime(2030, 6, 15, 12, 0, 0)
        self.assertEqual(_ms_to_dt(_dt_to_ms(dt)), dt)

    def test_tz_naive(self):
        """Decoded datetimes are always tz-naive (no tzinfo)."""
        dt = _ms_to_dt(1614461544771)
        self.assertIsNone(dt.tzinfo)


# ── encode_federated_event tests ──────────────────────────────────────────────


class TestEncodeBasicEvent(unittest.TestCase):
    def setUp(self):
        self.evt = _make_basic_event()
        self.proto = encode_federated_event(self.evt)

    def test_returns_federated_event(self):
        self.assertIsInstance(self.proto, fig_pb2.FederatedEvent)

    def test_has_event_field(self):
        self.assertTrue(self.proto.HasField("event"))

    def test_uid(self):
        self.assertEqual(self.proto.event.uid, "ANDROID-deadbeef")

    def test_type(self):
        self.assertEqual(self.proto.event.type, "a-f-G-U-C")

    def test_coord_source(self):
        self.assertEqual(self.proto.event.coordSource, "m-g")

    def test_send_time(self):
        self.assertEqual(self.proto.event.sendTime, _dt_to_ms(_T0))

    def test_start_time(self):
        self.assertEqual(self.proto.event.startTime, _dt_to_ms(_T0))

    def test_stale_time(self):
        self.assertEqual(self.proto.event.staleTime, _dt_to_ms(_T1))

    def test_lat(self):
        self.assertAlmostEqual(self.proto.event.lat, 1.234567, places=6)

    def test_lon(self):
        self.assertAlmostEqual(self.proto.event.lon, -3.141592, places=6)

    def test_hae(self):
        self.assertAlmostEqual(self.proto.event.hae, -25.7, places=1)

    def test_ce(self):
        self.assertAlmostEqual(self.proto.event.ce, 9.9, places=1)

    def test_le(self):
        self.assertAlmostEqual(self.proto.event.le, 9999999.0, places=1)

    def test_no_contact_field(self):
        self.assertFalse(self.proto.HasField("contact"))

    def test_no_fed_meta(self):
        """Without FedMeta, provenance list is empty and hops are zero."""
        self.assertEqual(len(self.proto.federateProvenance), 0)
        self.assertEqual(self.proto.federateHops.currentHops, 0)
        self.assertEqual(self.proto.federateHops.maxHops, 0)


class TestEncodeWithFedMeta(unittest.TestCase):
    def setUp(self):
        self.evt = _make_basic_event()
        self.meta = FedMeta(
            seen_server_ids=["SERVER-A", "SERVER-B"],
            current_hops=2,
            max_hops=5,
        )
        self.proto = encode_federated_event(self.evt, fed_meta=self.meta)

    def test_provenance_list(self):
        ids = [p.federationServerId for p in self.proto.federateProvenance]
        self.assertEqual(ids, ["SERVER-A", "SERVER-B"])

    def test_current_hops(self):
        self.assertEqual(self.proto.federateHops.currentHops, 2)

    def test_max_hops(self):
        self.assertEqual(self.proto.federateHops.maxHops, 5)


class TestEncodeTAKUser(unittest.TestCase):
    def setUp(self):
        self.evt = _make_takuser_event()
        self.proto = encode_federated_event(self.evt)
        self.geo = self.proto.event

    def test_screen_name(self):
        self.assertEqual(self.geo.screenName, "JENNY")

    def test_group_name(self):
        self.assertEqual(self.geo.groupName, "Cyan")

    def test_group_role(self):
        self.assertEqual(self.geo.groupRole, "Team Member")

    def test_phone(self):
        self.assertEqual(self.geo.phone, "+15551234567")

    def test_battery(self):
        self.assertEqual(self.geo.battery, 78)

    def test_speed(self):
        self.assertAlmostEqual(self.geo.speed, 1.5, places=1)

    def test_course(self):
        self.assertAlmostEqual(self.geo.course, 80.2, places=1)

    def test_other_xml_populated(self):
        """other field must contain a <detail> element."""
        self.assertTrue(self.geo.other.startswith("<detail"))

    def test_other_contains_takv(self):
        self.assertIn("takv", self.geo.other)


class TestEncodeGeoChat(unittest.TestCase):
    def setUp(self):
        self.evt = _make_geochat_event()
        self.proto = encode_federated_event(self.evt)

    def test_other_xml_populated(self):
        self.assertIn("<detail", self.proto.event.other)

    def test_other_contains_chat(self):
        self.assertIn("__chat", self.proto.event.other)

    def test_other_contains_remarks(self):
        self.assertIn("Hello world", self.proto.event.other)


# ── decode_federated_event tests ──────────────────────────────────────────────


class TestDecodeBasicEvent(unittest.TestCase):
    def setUp(self):
        self.orig = _make_basic_event()
        self.proto = encode_federated_event(self.orig)
        self.evt, self.meta = decode_federated_event(self.proto)

    def test_event_is_not_none(self):
        self.assertIsNotNone(self.evt)

    def test_uid(self):
        self.assertEqual(self.evt.uid, "ANDROID-deadbeef")

    def test_etype(self):
        self.assertEqual(self.evt.etype, "a-f-G-U-C")

    def test_how(self):
        self.assertEqual(self.evt.how, "m-g")

    def test_time_roundtrip(self):
        self.assertEqual(self.evt.time, _T0)

    def test_start_roundtrip(self):
        self.assertEqual(self.evt.start, _T0)

    def test_stale_roundtrip(self):
        self.assertEqual(self.evt.stale, _T1)

    def test_lat(self):
        self.assertAlmostEqual(self.evt.point.lat, 1.234567, places=6)

    def test_lon(self):
        self.assertAlmostEqual(self.evt.point.lon, -3.141592, places=6)

    def test_hae(self):
        self.assertAlmostEqual(self.evt.point.hae, -25.7, places=1)

    def test_ce(self):
        self.assertAlmostEqual(self.evt.point.ce, 9.9, places=1)

    def test_le(self):
        self.assertAlmostEqual(self.evt.point.le, 9999999.0, places=1)

    def test_fed_meta_empty_provenance(self):
        self.assertEqual(self.meta.seen_server_ids, [])

    def test_fed_meta_hops(self):
        # No FedMeta was passed to encode -> maxHops=0 in proto (absent).
        # Hop clamp: absent/zero NEVER resolves to unlimited (-1) anymore
        # -- it resolves to decode_federated_event's local_max_hops, which
        # defaults to 3 here since this test doesn't pass one explicitly.
        self.assertEqual(self.meta.current_hops, 0)
        self.assertEqual(self.meta.max_hops, 3)


class TestDecodeFedMeta(unittest.TestCase):
    """
    Wire max_hops BELOW the local ceiling passes through unclamped -- the
    clamp only ever tightens, never loosens, so a peer declaring a smaller
    budget than ours is honored as-is. local_max_hops=20 is set explicitly
    (above the wire value of 10) so this class exercises the pass-through
    case; TestHopClamp below exercises the clamp itself.
    """

    def setUp(self):
        evt = _make_basic_event()
        meta = FedMeta(
            seen_server_ids=["SRV-1", "SRV-2"],
            current_hops=3,
            max_hops=10,
        )
        proto = encode_federated_event(evt, fed_meta=meta)
        _, self.meta = decode_federated_event(proto, local_max_hops=20)

    def test_seen_server_ids(self):
        self.assertEqual(self.meta.seen_server_ids, ["SRV-1", "SRV-2"])

    def test_current_hops(self):
        self.assertEqual(self.meta.current_hops, 3)

    def test_max_hops(self):
        self.assertEqual(self.meta.max_hops, 10)


class TestHopClamp(unittest.TestCase):
    """
    Hop-budget clamp fix. An absent or non-positive wire max_hops must
    resolve to OUR configured ceiling, never
    to unlimited -- and a peer cannot loosen our ceiling by declaring a
    larger one; it can only ever declare a tighter one.

    This is defense-in-depth: loop_filter.py's provenance chain (refuse to
    re-relay anything already carrying our own node_id) is the primary loop
    guard and is unaffected by any of this. The clamp only bounds how far a
    single event can travel and limits amplification if provenance were
    ever stripped in transit.
    """

    def _decode_with(self, wire_max_hops, wire_current_hops=0, local_max_hops=3):
        """Build a proto with the given wire hop values and decode it."""
        evt = _make_basic_event()
        meta = FedMeta(current_hops=wire_current_hops, max_hops=wire_max_hops)
        proto = encode_federated_event(evt, fed_meta=meta)
        _, decoded_meta = decode_federated_event(proto, local_max_hops=local_max_hops)
        return decoded_meta

    # --- Unit-level: _resolve_max_hops directly -----------------------

    def test_resolve_absent_zero_to_local_default(self):
        from ots_federation.codec import _resolve_max_hops
        self.assertEqual(_resolve_max_hops(0, 3), 3)

    def test_resolve_negative_wire_to_local_default(self):
        """A malicious/malformed negative wire value is treated the same as absent."""
        from ots_federation.codec import _resolve_max_hops
        self.assertEqual(_resolve_max_hops(-1, 3), 3)
        self.assertEqual(_resolve_max_hops(-99, 3), 3)

    def test_resolve_peer_cannot_loosen_past_local_ceiling(self):
        """
        NEGATIVE assertion: a peer claiming maxHops=99 must NOT be honored
        when our local ceiling is 3 -- this is the exact exploit from the
        security review (peer-supplied maxHops=99 honoured verbatim).
        """
        from ots_federation.codec import _resolve_max_hops
        self.assertEqual(_resolve_max_hops(99, 3), 3)

    def test_resolve_peer_may_tighten_budget(self):
        """A peer declaring a SMALLER budget than ours is honored as-is."""
        from ots_federation.codec import _resolve_max_hops
        self.assertEqual(_resolve_max_hops(2, 3), 2)

    def test_resolve_no_local_ceiling_honors_wire_value(self):
        """
        local_max_hops<=0 means the operator explicitly configured no local
        ceiling; there is nothing to clamp against, so a positive wire value
        passes through.
        """
        from ots_federation.codec import _resolve_max_hops
        self.assertEqual(_resolve_max_hops(99, -1), 99)

    def test_resolve_no_local_ceiling_absent_wire_stays_unlimited(self):
        """
        Both absent AND no local ceiling: the only case where the result is
        genuinely -1 -- and it required an explicit operator opt-in
        (local_max_hops=-1), not a default.
        """
        from ots_federation.codec import _resolve_max_hops
        self.assertEqual(_resolve_max_hops(0, -1), -1)

    # --- Integration-level: through decode_federated_event -------------

    def test_decode_absent_hops_clamps_to_configured_default(self):
        """maxHops=0 (absent) resolves to local_max_hops, not -1 (unlimited)."""
        meta = self._decode_with(wire_max_hops=0, local_max_hops=3)
        self.assertEqual(meta.max_hops, 3)

    def test_decode_zero_hops_clamps_to_configured_default(self):
        """Explicit maxHops=0 resolves identically to an absent field."""
        meta = self._decode_with(wire_max_hops=0, local_max_hops=5)
        self.assertEqual(meta.max_hops, 5)

    def test_decode_unbounded_peer_claim_is_clamped(self):
        """
        NEGATIVE assertion: a peer emitting maxHops=99 with our ceiling
        configured at 3 must decode to max_hops=3, never 99 -- confirms the
        wiring from decode_federated_event through to FedMeta, not just the
        helper function in isolation.
        """
        meta = self._decode_with(wire_max_hops=99, local_max_hops=3)
        self.assertEqual(meta.max_hops, 3)

    def test_decode_current_hops_untouched_by_clamp(self):
        """The clamp only touches max_hops; current_hops passes through as-is."""
        meta = self._decode_with(wire_max_hops=0, wire_current_hops=7, local_max_hops=3)
        self.assertEqual(meta.current_hops, 7)


class TestDecodeTAKUser(unittest.TestCase):
    def setUp(self):
        self.orig = _make_takuser_event()
        proto = encode_federated_event(self.orig)
        self.evt, _ = decode_federated_event(proto)
        self.user = self.evt.detail

    def test_detail_is_takuser(self):
        self.assertIsInstance(self.user, models.TAKUser)

    def test_callsign(self):
        self.assertEqual(self.user.callsign, "JENNY")

    def test_group(self):
        # Phase-1: group is now a plain str; Cyan came from <__group name="Cyan"/>.
        self.assertEqual(self.user.group, "Cyan")

    def test_role(self):
        self.assertEqual(self.user.role, "Team Member")

    def test_phone(self):
        self.assertEqual(self.user.phone, "+15551234567")

    def test_battery(self):
        self.assertEqual(self.user.battery, "78")

    def test_speed(self):
        self.assertAlmostEqual(float(self.user.speed), 1.5, places=1)

    def test_course(self):
        self.assertAlmostEqual(float(self.user.course), 80.2, places=1)

    def test_uid_patched(self):
        """TAKUser.uid is patched from the GeoEvent uid, not left empty."""
        self.assertEqual(self.user.uid, "ANDROID-deadbeef")


class TestDecodeGeoChat(unittest.TestCase):
    def setUp(self):
        orig = _make_geochat_event()
        proto = encode_federated_event(orig)
        self.evt, _ = decode_federated_event(proto)
        self.chat = self.evt.detail

    def test_detail_is_geochat(self):
        self.assertIsInstance(self.chat, models.GeoChat)

    def test_message(self):
        self.assertEqual(self.chat.message, "Hello world")

    def test_src_callsign(self):
        self.assertEqual(self.chat.src_cs, "JENNY")

    def test_broadcast(self):
        self.assertTrue(self.chat.broadcast)


# ── Round-trip tests ──────────────────────────────────────────────────────────


class TestRoundTripBasicEvent(unittest.TestCase):
    """CoT XML → encode → decode → verify modelled fields preserved."""

    def _round_trip(self, evt):
        proto = encode_federated_event(evt)
        recovered, _ = decode_federated_event(proto)
        return recovered

    def test_uid_preserved(self):
        evt = _make_basic_event()
        self.assertEqual(self._round_trip(evt).uid, evt.uid)

    def test_etype_preserved(self):
        evt = _make_basic_event()
        self.assertEqual(self._round_trip(evt).etype, evt.etype)

    def test_how_preserved(self):
        evt = _make_basic_event()
        self.assertEqual(self._round_trip(evt).how, evt.how)

    def test_time_preserved(self):
        evt = _make_basic_event()
        self.assertEqual(self._round_trip(evt).time, evt.time)

    def test_start_preserved(self):
        evt = _make_basic_event()
        self.assertEqual(self._round_trip(evt).start, evt.start)

    def test_stale_preserved(self):
        evt = _make_basic_event()
        self.assertEqual(self._round_trip(evt).stale, evt.stale)

    def test_lat_preserved(self):
        evt = _make_basic_event()
        self.assertAlmostEqual(self._round_trip(evt).point.lat, evt.point.lat, places=6)

    def test_lon_preserved(self):
        evt = _make_basic_event()
        self.assertAlmostEqual(self._round_trip(evt).point.lon, evt.point.lon, places=6)

    def test_hae_preserved(self):
        evt = _make_basic_event()
        self.assertAlmostEqual(self._round_trip(evt).point.hae, evt.point.hae, places=1)


class TestRoundTripTAKUser(unittest.TestCase):
    def setUp(self):
        self.orig = _make_takuser_event()
        proto = encode_federated_event(self.orig)
        self.recovered, _ = decode_federated_event(proto)

    def test_callsign_preserved(self):
        self.assertEqual(
            self.recovered.detail.callsign,
            self.orig.detail.callsign,
        )

    def test_group_preserved(self):
        self.assertEqual(self.recovered.detail.group, self.orig.detail.group)

    def test_role_preserved(self):
        self.assertEqual(self.recovered.detail.role, self.orig.detail.role)

    def test_phone_preserved(self):
        self.assertEqual(self.recovered.detail.phone, self.orig.detail.phone)


class TestRoundTripFedMeta(unittest.TestCase):
    """
    max_hops round-trips only when it's at or below the receiving node's own
    configured ceiling (local_max_hops=10 here, above the wire value of 7) --
    see TestHopClamp for the case where a wire value exceeds the local
    ceiling and must be clamped down instead of preserved.
    """

    def setUp(self):
        evt = _make_basic_event()
        self.orig_meta = FedMeta(
            seen_server_ids=["ALPHA", "BETA", "GAMMA"],
            current_hops=2,
            max_hops=7,
        )
        proto = encode_federated_event(evt, fed_meta=self.orig_meta)
        _, self.recovered_meta = decode_federated_event(proto, local_max_hops=10)

    def test_seen_server_ids_preserved(self):
        self.assertEqual(
            self.recovered_meta.seen_server_ids,
            self.orig_meta.seen_server_ids,
        )

    def test_current_hops_preserved(self):
        self.assertEqual(self.recovered_meta.current_hops, self.orig_meta.current_hops)

    def test_max_hops_preserved(self):
        self.assertEqual(self.recovered_meta.max_hops, self.orig_meta.max_hops)


# ── Security / error-handling tests ──────────────────────────────────────────


class TestXXESafety(unittest.TestCase):
    """GeoEvent.other with an XXE payload must NOT trigger entity resolution."""

    XXE_PAYLOAD = (
        '<!DOCTYPE detail ['
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        ']>'
        '<detail><contact callsign="&xxe;"/></detail>'
    )

    def test_xxe_does_not_read_file(self):
        """XXE in other must drop the event, not read the file."""
        proto = fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(
                uid="EVIL-UID",
                type="a-u",
                coordSource="m-g",
                sendTime=1614461544771,
                startTime=1614461544771,
                staleTime=1614461544771,
                lat=0.0,
                lon=0.0,
                hae=0.0,
                other=self.XXE_PAYLOAD,
            )
        )
        evt, _ = decode_federated_event(proto)
        # Event must be dropped (None) — not a crash, and certainly not
        # returning a callsign containing /etc/passwd contents.
        self.assertIsNone(evt)

    def test_xxe_does_not_raise(self):
        """XXE parse failure must not propagate an exception to the caller."""
        proto = fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(
                uid="EVIL-UID",
                type="a-u",
                coordSource="m-g",
                sendTime=1614461544771,
                startTime=1614461544771,
                staleTime=1614461544771,
                lat=0.0,
                lon=0.0,
                hae=0.0,
                other=self.XXE_PAYLOAD,
            )
        )
        try:
            decode_federated_event(proto)
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"decode_federated_event raised unexpectedly: {exc!r}")


class TestMalformedXML(unittest.TestCase):
    """Malformed XML in GeoEvent.other must drop the event, not the connection."""

    def _make_proto_with_other(self, other: str) -> fig_pb2.FederatedEvent:
        return fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(
                uid="TEST-UID",
                type="a-u",
                coordSource="m-g",
                sendTime=1614461544771,
                startTime=1614461544771,
                staleTime=1614461544771,
                lat=1.0,
                lon=2.0,
                hae=0.0,
                other=other,
            )
        )

    def test_truncated_xml_drops_event(self):
        proto = self._make_proto_with_other("<detail><truncated")
        evt, meta = decode_federated_event(proto)
        self.assertIsNone(evt)
        self.assertIsInstance(meta, FedMeta)

    def test_truncated_xml_no_exception(self):
        proto = self._make_proto_with_other("<detail><truncated")
        try:
            decode_federated_event(proto)
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"Unexpected exception: {exc!r}")

    def test_wrong_root_tag_drops_event(self):
        """A root tag other than <detail> must drop the event."""
        proto = self._make_proto_with_other("<event uid='x'/>>")
        evt, _ = decode_federated_event(proto)
        self.assertIsNone(evt)

    def test_binary_garbage_drops_event(self):
        """Garbage bytes that are not valid XML must drop the event."""
        proto = self._make_proto_with_other("\x00\x01\x02\xff\xfe binary garbage")
        evt, _ = decode_federated_event(proto)
        self.assertIsNone(evt)

    def test_empty_other_is_ok(self):
        """Empty other string is fine — event has no detail, but is not dropped."""
        proto = self._make_proto_with_other("")
        evt, _ = decode_federated_event(proto)
        self.assertIsNotNone(evt)
        self.assertIsNone(evt.detail)


class TestMissingRequiredFields(unittest.TestCase):
    def test_missing_uid_drops_event(self):
        proto = fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(
                uid="",
                type="a-u",
                sendTime=1614461544771,
                startTime=1614461544771,
                staleTime=1614461544771,
            )
        )
        evt, meta = decode_federated_event(proto)
        self.assertIsNone(evt)
        self.assertIsInstance(meta, FedMeta)

    def test_missing_type_drops_event(self):
        proto = fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(
                uid="SOME-UID",
                type="",
                sendTime=1614461544771,
                startTime=1614461544771,
                staleTime=1614461544771,
            )
        )
        evt, meta = decode_federated_event(proto)
        self.assertIsNone(evt)
        self.assertIsInstance(meta, FedMeta)


class TestContactOnlyMessage(unittest.TestCase):
    """A FederatedEvent with only a contact field and no event field → (None, FedMeta)."""

    def setUp(self):
        self.proto = fig_pb2.FederatedEvent(
            contact=fig_pb2.ContactListEntry(
                operation=fig_pb2.CRUD.Value("CREATE"),
                uid="REMOTE-UID-1",
                callsign="REMOTE_USER",
                phone="+15559876543",
            )
        )
        self.evt, self.meta = decode_federated_event(self.proto)

    def test_event_is_none(self):
        self.assertIsNone(self.evt)

    def test_meta_is_returned(self):
        self.assertIsInstance(self.meta, FedMeta)


class TestUnknownGroupFallback(unittest.TestCase):
    """Unknown groupName in GeoEvent named fields → empty string (Phase-1 sentinel).

    Phase-1 migration: Teams.UNKNOWN sentinel replaced by "".
    The _synthesize_takuser_from_geo path writes geo.groupName or "" to the XML
    so an unrecognised groupName that isn't in the known-colors set passes through
    as-is; an absent groupName produces group="" which is falsy and blocked by policy.
    """

    def test_absent_group_maps_to_empty_string(self):
        """groupName absent in named-fields synthesis path → group='' (falsy sentinel)."""
        proto = fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(
                uid="TEST-UID",
                type="a-f-G-U-C",
                coordSource="m-g",
                sendTime=1614461544771,
                startTime=1614461544771,
                staleTime=1614461544771,
                lat=0.0,
                lon=0.0,
                hae=0.0,
                screenName="OPERATOR",
                groupName="",  # absent/empty → "" in XML → group=""
                groupRole="Team Lead",
                # No `other` blob — force synthesis path
            )
        )
        evt, _ = decode_federated_event(proto)
        self.assertIsNotNone(evt)
        self.assertIsInstance(evt.detail, models.TAKUser)
        # Empty string is the falsy sentinel (replaces Teams.UNKNOWN).
        # This group will be blocked by outbound policy (detail.group is falsy).
        self.assertEqual(evt.detail.group, "")

    def test_nonexistent_group_name_passes_through(self):
        """An unrecognised groupName passes through as-is (arbitrary string model)."""
        proto = fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(
                uid="TEST-UID-2",
                type="a-f-G-U-C",
                coordSource="m-g",
                sendTime=1614461544771,
                startTime=1614461544771,
                staleTime=1614461544771,
                lat=0.0,
                lon=0.0,
                hae=0.0,
                screenName="OPERATOR",
                groupName="NonexistentTeam",
                groupRole="Team Lead",
                # No `other` blob — force synthesis path
            )
        )
        evt, _ = decode_federated_event(proto)
        self.assertIsNotNone(evt)
        self.assertIsInstance(evt.detail, models.TAKUser)
        # Non-color arbitrary names pass through; no enum rejection.
        self.assertEqual(evt.detail.group, "NonexistentTeam")

    def test_nonstandard_group_name_in_xml_logs_debug(self):
        """Parsing a non-standard <__group name> emits a DEBUG advisory log.

        This is the 'unrecognized-name' observability path added in Phase-1
        : operators can enable DEBUG to see unexpected group
        names without causing a hard exception.
        """
        from lxml import etree
        from ots_federation.models.takuser import TAKUser

        detail_xml = (
            b'<detail>'
            b'<takv os="29" version="4.0" device="x" platform="x"/>'
            b'<contact callsign="TEST" endpoint="*:-1:stcp"/>'
            b'<uid Droid="TEST"/>'
            b'<__group role="Team Member" name="SIGINT"/>'
            b'</detail>'
        )
        elm = etree.fromstring(detail_xml)
        with self.assertLogs("ots_federation.models.takuser", level="DEBUG") as cm:
            user = TAKUser.from_elm(elm, uid="TEST-UID")
        # Group still passes through as-is
        self.assertEqual(user.group, "SIGINT")
        # Advisory log must mention the group name
        log_text = " ".join(cm.output)
        self.assertIn("SIGINT", log_text)


# ── decode_contact_entry tests ────────────────────────────────────────────────


class TestDecodeContactEntry(unittest.TestCase):
    def _make_contact_proto(self, op_name: str, uid: str, callsign: str):
        return fig_pb2.FederatedEvent(
            contact=fig_pb2.ContactListEntry(
                operation=fig_pb2.CRUD.Value(op_name),
                uid=uid,
                callsign=callsign,
                phone="+15551112222",
                sip="sip:test@example.com",
                directConnect="192.168.1.1:4242:tcp",
            )
        )

    def test_returns_none_when_no_contact(self):
        proto = fig_pb2.FederatedEvent(
            event=fig_pb2.GeoEvent(uid="X", type="a-u")
        )
        self.assertIsNone(decode_contact_entry(proto))

    def test_returns_contact_entry_on_create(self):
        proto = self._make_contact_proto("CREATE", "UID-1", "ALICE")
        entry = decode_contact_entry(proto)
        self.assertIsNotNone(entry)
        self.assertIsInstance(entry, fig_pb2.ContactListEntry)

    def test_create_uid(self):
        proto = self._make_contact_proto("CREATE", "UID-1", "ALICE")
        entry = decode_contact_entry(proto)
        self.assertEqual(entry.uid, "UID-1")

    def test_create_callsign(self):
        proto = self._make_contact_proto("CREATE", "UID-1", "ALICE")
        entry = decode_contact_entry(proto)
        self.assertEqual(entry.callsign, "ALICE")

    def test_create_phone(self):
        proto = self._make_contact_proto("CREATE", "UID-1", "ALICE")
        entry = decode_contact_entry(proto)
        self.assertEqual(entry.phone, "+15551112222")

    def test_create_operation_value(self):
        proto = self._make_contact_proto("CREATE", "UID-1", "ALICE")
        entry = decode_contact_entry(proto)
        self.assertEqual(entry.operation, fig_pb2.CRUD.Value("CREATE"))

    def test_update_operation(self):
        proto = self._make_contact_proto("UPDATE", "UID-2", "BOB")
        entry = decode_contact_entry(proto)
        self.assertEqual(entry.operation, fig_pb2.CRUD.Value("UPDATE"))

    def test_delete_operation(self):
        proto = self._make_contact_proto("DELETE", "UID-3", "CAROL")
        entry = decode_contact_entry(proto)
        self.assertEqual(entry.operation, fig_pb2.CRUD.Value("DELETE"))

    def test_read_operation(self):
        proto = self._make_contact_proto("READ", "UID-4", "DAVE")
        entry = decode_contact_entry(proto)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.operation, fig_pb2.CRUD.Value("READ"))

    def test_contact_without_event_also_returns_entry(self):
        """Contact-only message (no event) still yields a ContactListEntry."""
        proto = fig_pb2.FederatedEvent(
            contact=fig_pb2.ContactListEntry(
                operation=fig_pb2.CRUD.Value("CREATE"),
                uid="SOLO-UID",
                callsign="SOLO_USER",
            )
        )
        entry = decode_contact_entry(proto)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.uid, "SOLO-UID")


# ── FedMeta default values ────────────────────────────────────────────────────


class TestFedMetaDefaults(unittest.TestCase):
    def test_defaults(self):
        meta = FedMeta()
        self.assertEqual(meta.seen_server_ids, [])
        self.assertEqual(meta.current_hops, 0)
        self.assertEqual(meta.max_hops, -1)

    def test_unlimited_max_hops(self):
        """max_hops=-1 represents unlimited hops."""
        meta = FedMeta(max_hops=-1)
        self.assertEqual(meta.max_hops, -1)


if __name__ == "__main__":
    unittest.main()

