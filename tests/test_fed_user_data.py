"""
tests/test_fed_user_data.py

Federation user-data test matrix — unit-tier tests.
.  Matrix: .qmd

CoT wire classes covered here (gaps relative to the 441-test baseline):
  Class 1  PLI        Anti-over-sharing through real codec+registry path
  Class 2  Marker     Generic Detail (remarks/color/icon/link) codec round-trip
  Class 3  Geometry   Multi-point u-d-f (polygon + polyline + b-m-r route type)
                      link-list preservation through codec
  Class 5  Geofence   __geofence detail preservation
  Class 6  GeoChat    Directed (dst_uid, non-broadcast) codec round-trip

Cross-cutting:
  Anti-over-sharing   Outbound POSITIVE + NEGATIVE, inbound POSITIVE + NEGATIVE
  Staling             Far-future and tombstone stale round-trips
  Deletion            synthesize_contact_event all CRUD paths, t-x-d-d type code

What the baseline 441 tests already cover (NOT duplicated here):
  - PLI codec round-trip (TAKUser fields)           test_federation_codec.py
  - GeoChat broadcast codec                         test_federation_codec.py
  - FedMeta provenance / hops                       test_federation_codec.py
  - Group mapper API (inbound/outbound/block)        test_federation_groups.py
  - LoopFilter (U1-U7, N1-N3)                       test_loop_filter.py
  - Connection lifecycle / TLS config               test_federation_transport.py etc.
"""

import unittest
from datetime import datetime, timedelta

from lxml import etree

from ots_federation import models
from ots_federation.codec import (
    FedMeta,
    encode_federated_event,
    decode_federated_event,
    prepare_outbound_event,
    synthesize_contact_event,
)
from ots_federation.groups import (
    FederateGroupRegistry,
    FederatePeerGroupMap,
)
from ots_federation.models.geochat import GeoChat
from ots_federation.models.takuser import TAKUser
from ots_federation.models.detail import Detail
from ots_federation.proto import fig_pb2

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

NODE_ID = "ots-test-node"
PEER_A = "peer-alpha-server"
PEER_B = "peer-bravo-server"

_T0 = datetime(2026, 7, 10, 12, 0, 0)
_T1 = datetime(2026, 7, 10, 12, 10, 0)  # stale (+10 min)


def _make_event(uid="TEST-UID-001", etype="a-f-G-U-C") -> models.Event:
    """Minimal event, no detail."""
    evt = models.Event(uid=uid, etype=etype, how="m-g",
                       time=_T0, start=_T0, stale=_T1)
    evt.point = models.Point(lat=40.0, lon=-75.0, hae=100.0,
                             ce=9.0, le=9999999.0)
    return evt


def _make_pli_event(group: str, uid="PLI-001") -> models.Event:
    """PLI event (a-f-G-U-C) with a TAKUser for the given group.

    Phase-1: `group` is a plain str (e.g. "Blue"); was Teams enum.
    Option D : sets evt.local_acl_groups sidecar so prepare_outbound_event
    sources the ACL group from the cache sidecar rather than <__group> XML.
    """
    detail_xml = (
        f'<detail>'
        f'<takv os="29" version="4.0" device="Test" platform="ATAK-CIV"/>'
        f'<contact callsign="TESTUSER" endpoint="*:-1:stcp"/>'
        f'<uid Droid="TESTUSER"/>'
        f'<__group role="Team Member" name="{group}"/>'
        f'</detail>'
    ).encode("utf-8")
    elm = etree.fromstring(detail_xml)
    user = TAKUser.from_elm(elm, uid=uid)

    evt = _make_event(uid=uid, etype="a-f-G-U-C")
    evt.detail = user
    #: ACL cache sidecar — set directly in tests to simulate a warm cache.
    evt.local_acl_groups = frozenset([group])
    return evt


def _make_registry(peer_id: str,
                   in_map: dict = None,
                   out_map: dict = None) -> FederateGroupRegistry:
    """Build a FederateGroupRegistry from plain dicts.

    in_map  : {remote_group_str: str | None}   (None = explicit block)
    out_map : {str: remote_group_str}
    """
    reg = FederateGroupRegistry()
    for remote, local in (in_map or {}).items():
        reg.add_peer_map(FederatePeerGroupMap(
            peer_id=peer_id, direction="in",
            remote_group=remote, local_group=local,
        ))
    for local_team, remote_name in (out_map or {}).items():
        reg.add_peer_map(FederatePeerGroupMap(
            peer_id=peer_id, direction="out",
            remote_group=remote_name, local_group=local_team,
        ))
    return reg


# ===========================================================================
# Class 1 — PLI Anti-Over-Sharing (through real codec+registry path)
# ===========================================================================

class TestAntiOverSharingOutbound(unittest.TestCase):
    """
    Outbound group policy enforced through prepare_outbound_event + real registry.

    Critical: the NEGATIVE assertions (blocking) are the primary specification;
    a silent over-share has no exception — only a forwarded event that shouldn't
    have been forwarded.
    """

    def _outbound(self, evt, registry, peer_id=PEER_A):
        """Run prepare_outbound_event with the real registry."""
        return prepare_outbound_event(
            evt,
            node_id=NODE_ID,
            default_max_hops=3,
            registry=registry,
            peer_id=peer_id,
        )

    # --- POSITIVE: mapped group crosses with correct tag ---

    def test_blue_event_tagged_group1_for_peer(self):
        """Blue PLI → prepare_outbound_event with Blue→Group1 mapping → tagged ['Group1']."""
        evt = _make_pli_event("Blue")
        reg = _make_registry(PEER_A, out_map={"Blue": "Group1"})
        proto = self._outbound(evt, reg)
        self.assertIsNotNone(proto,
                             "Blue event must cross when Blue→Group1 is mapped")
        self.assertIn("Group1", list(proto.federateGroups),
                      "federateGroups must contain the mapped remote name 'Group1'")

    def test_mapped_group_federategroups_field_set(self):
        """The federateGroups repeated field on the outbound proto must be set."""
        evt = _make_pli_event("Cyan")
        reg = _make_registry(PEER_A, out_map={"Cyan": "Cyan"})
        proto = self._outbound(evt, reg)
        self.assertIsNotNone(proto)
        self.assertEqual(list(proto.federateGroups), ["Cyan"])

    def test_multiple_groups_both_tagged(self):
        """If a peer has two outbound mappings and the event's group matches one, only that tag is set."""
        evt = _make_pli_event("White")
        reg = _make_registry(PEER_A, out_map={"White": "White", "Blue": "Blue"})
        proto = self._outbound(evt, reg)
        self.assertIsNotNone(proto)
        self.assertIn("White", list(proto.federateGroups))
        self.assertNotIn("Blue", list(proto.federateGroups))

    # --- NEGATIVE: unmapped group is blocked (does not cross) ---

    def test_white_event_blocked_when_no_white_mapping(self):
        """White PLI → no White outbound mapping → prepare_outbound_event returns None (blocked).

        THIS IS THE CRITICAL ANTI-OVER-SHARING ASSERTION.
        A silent failure here means White events would cross to a peer configured
        for Blue only — a security/operational defect with no exception or log at
        the event-dispatch layer.
        """
        evt = _make_pli_event("White")
        # Registry maps only Blue; no White entry.
        reg = _make_registry(PEER_A, out_map={"Blue": "Blue"})
        result = self._outbound(evt, reg)
        self.assertIsNone(result,
                          "White event MUST be blocked (None) when only Blue is mapped — "
                          "block-unmapped-by-default")

    def test_unmapped_group_stays_local(self):
        """Event from a group with NO entry in the outbound map → None (block-unmapped default).

        This covers the case where the remote peer has a non-empty registry but
        the local event's group simply has no entry — it must NOT fall through.
        """
        evt = _make_pli_event("Purple")
        # Registry has Blue and Cyan; Purple not mapped.
        reg = _make_registry(PEER_A, out_map={
            "Blue": "Blue",
            "Cyan": "Cyan",
        })
        result = self._outbound(evt, reg)
        self.assertIsNone(result,
                          "Purple event must be blocked (None) — no outbound mapping exists")

    def test_empty_registry_blocks_all(self):
        """No outbound config for peer → every group blocked (conservative default)."""
        evt = _make_pli_event("Blue")
        reg = FederateGroupRegistry()  # empty — no peer entries at all
        result = self._outbound(evt, reg)
        self.assertIsNone(result,
                          "Empty registry must block all outbound events (block-unmapped default)")

    def test_per_peer_isolation_no_bleed(self):
        """Mapping configured for PEER_A does NOT leak into PEER_B's outbound check."""
        evt = _make_pli_event("Blue")
        reg = _make_registry(PEER_A, out_map={"Blue": "Blue"})
        # Check against PEER_B which has no mapping.
        result = prepare_outbound_event(
            evt, node_id=NODE_ID, default_max_hops=3,
            registry=reg, peer_id=PEER_B,
        )
        self.assertIsNone(result,
                          "PEER_A mapping must not bleed into PEER_B outbound check")


class TestAntiOverSharingInbound(unittest.TestCase):
    """
    Inbound group policy: map_inbound_groups must admit mapped groups and block unmapped.

    The codec's prepare_outbound_event calls map_outbound_groups; inbound admission
    uses map_inbound_groups called by the transport layer (fed_server.py/client.py).
    We test the registry method directly since that is the unit boundary.
    """

    def test_mapped_inbound_group_admitted(self):
        """federateGroups=["Group1"] with Group1→Blue inbound map → {Blue}."""
        reg = _make_registry(PEER_A, in_map={"Group1": "Blue"})
        result = reg.map_inbound_groups(PEER_A, ["Group1"])
        self.assertIsNotNone(result,
                             "Group1 inbound with Group1→Blue mapping must be admitted")
        self.assertIn("Blue", result)

    def test_unmapped_inbound_group_blocked(self):
        """federateGroups=["White"] with no White inbound mapping → None (drop event).

        NEGATIVE ASSERTION: the most dangerous inbound failure is admitting an event
        to a local group that has no inbound mapping — this would expose local ATAK
        clients to traffic from unauthorized remote groups.
        """
        reg = _make_registry(PEER_A, in_map={"Blue": "Blue"})
        result = reg.map_inbound_groups(PEER_A, ["White"])
        self.assertIsNone(result,
                          "White inbound with only Blue mapped must return None (blocked) — "
                          "NEGATIVE ANTI-OVER-SHARING ASSERTION")

    def test_no_inbound_config_for_peer_blocks(self):
        """No inbound mapping configured for this peer → None (block-unmapped default)."""
        reg = FederateGroupRegistry()
        result = reg.map_inbound_groups(PEER_A, ["AnyGroup"])
        self.assertIsNone(result)

    def test_explicit_block_entry_blocks(self):
        """Explicit None (block) entry in inbound map must block the group."""
        reg = _make_registry(PEER_A, in_map={"Blue": None})  # explicit block
        result = reg.map_inbound_groups(PEER_A, ["Blue"])
        self.assertIsNone(result,
                          "Explicit block entry (local_group=None) must block the inbound event")

    def test_groupless_event_admitted_via_peer_wildcard(self):
        """federateGroups=[] (stock TAK Server, federatedGroupMapping off) with a
        per-peer wildcard accept_as ("*"→Green) → {Green}."""
        reg = _make_registry(PEER_A, in_map={"*": "Green"})
        result = reg.map_inbound_groups(PEER_A, [])
        self.assertIsNotNone(result,
                             "group-less inbound with peer wildcard must be admitted")
        self.assertEqual(result, {"Green"})

    def test_groupless_event_admitted_via_default_wildcard(self):
        """federateGroups=[] from a peer with NO per-peer table, global default
        accept_as *:Green → {Green} — the stock-TAK-Server inbound case."""
        reg = FederateGroupRegistry()
        reg.set_default_in_map([FederatePeerGroupMap(
            peer_id="", direction="in", remote_group="*", local_group="Green",
        )])
        result = reg.map_inbound_groups(PEER_A, [])
        self.assertEqual(result, {"Green"})

    def test_groupless_event_blocked_for_named_scope_peer(self):
        """federateGroups=[] from a peer whose accept_as names specific remote
        groups (no wildcard) → None (fail-closed preserved).

        NEGATIVE ASSERTION: a group-less event must NOT ride into a local group
        the operator scoped to named remote groups only.
        """
        reg = _make_registry(PEER_A, in_map={"TestGroup": "Green"})
        result = reg.map_inbound_groups(PEER_A, [])
        self.assertIsNone(result,
                          "group-less inbound with named-scope accept_as must stay blocked")

    def test_groupless_event_blocked_without_any_mapping(self):
        """federateGroups=[] with no mapping at all → None (block default)."""
        reg = FederateGroupRegistry()
        result = reg.map_inbound_groups(PEER_A, [])
        self.assertIsNone(result)

    def test_groupless_event_fallback_allow_does_not_leak_star(self):
        """fallback_allow passthrough must not mint a literal '*' local group
        for a group-less event."""
        reg = FederateGroupRegistry()
        reg.set_fallback_allow(PEER_A, True)
        result = reg.map_inbound_groups(PEER_A, [])
        self.assertIsNone(result,
                          "fallback_allow must not admit group-less events as '*'")

    def test_mixed_groups_partial_admit(self):
        """federateGroups=["Blue", "White"] with only Blue mapped → {Blue}; White excluded."""
        reg = _make_registry(PEER_A, in_map={"Blue": "Blue"})
        result = reg.map_inbound_groups(PEER_A, ["Blue", "White"])
        self.assertIsNotNone(result)
        self.assertIn("Blue", result)
        self.assertNotIn("White", result)


# ===========================================================================
# Class 2 — Marker Point + Rich Detail
# ===========================================================================

class TestMarkerRichDetailCodec(unittest.TestCase):
    """
    Generic Detail (catch-all: not TAKUser, not GeoChat) must round-trip
    through encode_federated_event / decode_federated_event with all child
    elements intact.

    Error surface: the GeoEvent.other field carries the serialized <detail>
    XML blob.  If any child element is dropped or modified by the codec
    the receiving ATAK client sees an incomplete marker.
    """

    def _make_marker_event(self, uid="MARKER-001"):
        detail_xml = (
            b'<detail>'
            b'<remarks time="2026-07-10T12:00:00.000Z" source="TESTUSER">'
            b'Observation point Alpha</remarks>'
            b'<color argb="-256"/>'
            b'<usericon iconsetpath="34ae1613-9645-4222-a9d2-e5f243dea2865/Military/air_default.png"/>'
            b'<link uid="CONTACT-007" type="a-f-G-U-C" relation="p-p"/>'
            b'<contact callsign="TESTUSER"/>'
            b'</detail>'
        )
        elm = etree.fromstring(detail_xml)
        detail = Detail.from_elm(elm)

        evt = _make_event(uid=uid, etype="a-f-G")
        evt.detail = detail
        return evt

    def setUp(self):
        self.orig = self._make_marker_event()
        proto = encode_federated_event(self.orig)
        self.recovered, _ = decode_federated_event(proto)

    def test_event_not_none(self):
        self.assertIsNotNone(self.recovered)

    def test_uid_preserved(self):
        self.assertEqual(self.recovered.uid, "MARKER-001")

    def test_etype_preserved(self):
        self.assertEqual(self.recovered.etype, "a-f-G")

    def test_detail_is_not_none(self):
        self.assertIsNotNone(self.recovered.detail)

    def test_detail_is_generic_detail(self):
        self.assertIsInstance(self.recovered.detail, Detail)

    def test_remarks_element_present(self):
        elm = self.recovered.detail.as_element
        self.assertIsNotNone(elm.find("remarks"),
                             "<remarks> must be preserved through codec round-trip")

    def test_remarks_text_preserved(self):
        elm = self.recovered.detail.as_element
        remarks = elm.find("remarks")
        self.assertIsNotNone(remarks)
        self.assertIn("Observation point Alpha", remarks.text or "",
                      "<remarks> text must survive encode→decode intact")

    def test_color_element_present(self):
        elm = self.recovered.detail.as_element
        color = elm.find("color")
        self.assertIsNotNone(color, "<color> element must be preserved")

    def test_color_argb_preserved(self):
        elm = self.recovered.detail.as_element
        color = elm.find("color")
        self.assertIsNotNone(color)
        self.assertEqual(color.get("argb"), "-256")

    def test_usericon_element_present(self):
        elm = self.recovered.detail.as_element
        icon = elm.find("usericon")
        self.assertIsNotNone(icon, "<usericon> element must be preserved")

    def test_usericon_iconsetpath_preserved(self):
        elm = self.recovered.detail.as_element
        icon = elm.find("usericon")
        self.assertIsNotNone(icon)
        self.assertIn("air_default.png", icon.get("iconsetpath", ""))

    def test_link_element_present(self):
        elm = self.recovered.detail.as_element
        link = elm.find("link")
        self.assertIsNotNone(link, "<link> element must be preserved in marker detail")

    def test_link_uid_preserved(self):
        elm = self.recovered.detail.as_element
        link = elm.find("link")
        self.assertEqual(link.get("uid"), "CONTACT-007")

    def test_all_five_children_preserved(self):
        """All 5 child elements of <detail> must survive the round-trip."""
        elm = self.recovered.detail.as_element
        children = [child.tag for child in elm.iterchildren()]
        self.assertEqual(len(children), 5,
                         f"Expected 5 child elements, got {len(children)}: {children}")


# ===========================================================================
# Class 3 — Multi-Point Geometry (polygon + polyline + route type code)
# ===========================================================================

class TestMultiPointGeometryCodec(unittest.TestCase):
    """
    Multi-point shapes (u-d-f-m) and routes (b-m-r) both pass through
    Detail.from_elm at the codec tier (Generic Detail catch-all).

    The critical error surface: ALL <link> elements forming the vertex chain
    must survive the GeoEvent.other round-trip.  A partial link list would
    silently corrupt the shape's vertices at the receiving end.
    """

    def _make_polygon_event(self, uid="POLY-001", n_links=4):
        links = "".join(
            f'<link uid="P{i}" type="b-m-p" '
            f'point="{40.0+i*0.001},{-75.0+i*0.001},100.0" '
            f'remarks="Vertex {i}"/>'
            for i in range(n_links)
        )
        detail_xml = (
            f'<detail>'
            f'{links}'
            f'<strokeColor value="-16711936"/>'
            f'<strokeWeight value="3.0"/>'
            f'<fillColor value="-1728053248"/>'
            f'<labels_on value="false"/>'
            f'<shape closed="1"/>'
            f'</detail>'
        ).encode("utf-8")
        elm = etree.fromstring(detail_xml)
        evt = _make_event(uid=uid, etype="u-d-f-m")
        evt.detail = Detail.from_elm(elm)
        return evt

    def _make_polyline_event(self, uid="LINE-001", n_links=3):
        links = "".join(
            f'<link uid="L{i}" type="b-m-p" '
            f'point="{41.0+i*0.001},{-74.0+i*0.001},0.0"/>'
            for i in range(n_links)
        )
        detail_xml = (
            f'<detail>'
            f'{links}'
            f'<strokeColor value="-65536"/>'
            f'<strokeWeight value="2.0"/>'
            f'<shape closed="0"/>'
            f'</detail>'
        ).encode("utf-8")
        elm = etree.fromstring(detail_xml)
        evt = _make_event(uid=uid, etype="u-d-f-m")
        evt.detail = Detail.from_elm(elm)
        return evt

    def _round_trip(self, evt):
        proto = encode_federated_event(evt)
        recovered, _ = decode_federated_event(proto)
        return recovered

    # --- Polygon ---

    def test_polygon_uid_preserved(self):
        recovered = self._round_trip(self._make_polygon_event())
        self.assertEqual(recovered.uid, "POLY-001")

    def test_polygon_etype_preserved(self):
        recovered = self._round_trip(self._make_polygon_event())
        self.assertEqual(recovered.etype, "u-d-f-m")

    def test_polygon_all_four_links_preserved(self):
        """4-vertex polygon: all 4 <link> elements must survive codec round-trip."""
        recovered = self._round_trip(self._make_polygon_event(n_links=4))
        self.assertIsNotNone(recovered)
        elm = recovered.detail.as_element
        links = elm.findall("link")
        self.assertEqual(len(links), 4,
                         f"Polygon must have 4 <link> elements after round-trip, got {len(links)}")

    def test_polygon_link_uids_preserved(self):
        """Link uid attributes must be preserved exactly (vertex identity)."""
        recovered = self._round_trip(self._make_polygon_event(n_links=4))
        elm = recovered.detail.as_element
        link_uids = {link.get("uid") for link in elm.findall("link")}
        self.assertEqual(link_uids, {"P0", "P1", "P2", "P3"})

    def test_polygon_link_point_attributes_preserved(self):
        """Link 'point' attribute (lat,lon,alt) must survive round-trip."""
        recovered = self._round_trip(self._make_polygon_event(n_links=1))
        elm = recovered.detail.as_element
        link = elm.find("link")
        self.assertIsNotNone(link)
        self.assertIn("40.0", link.get("point", ""))

    def test_polygon_closed_shape_attribute_preserved(self):
        """<shape closed="1"> must be preserved (polygon vs polyline discriminator)."""
        recovered = self._round_trip(self._make_polygon_event())
        elm = recovered.detail.as_element
        shape = elm.find("shape")
        self.assertIsNotNone(shape, "<shape> element must be preserved")
        self.assertEqual(shape.get("closed"), "1")

    # --- Polyline ---

    def test_polyline_all_three_links_preserved(self):
        """3-vertex polyline: all 3 <link> elements must survive codec round-trip."""
        recovered = self._round_trip(self._make_polyline_event(n_links=3))
        self.assertIsNotNone(recovered)
        elm = recovered.detail.as_element
        links = elm.findall("link")
        self.assertEqual(len(links), 3,
                         f"Polyline must have 3 <link> elements after round-trip, got {len(links)}")

    def test_polyline_open_shape_attribute_preserved(self):
        """<shape closed="0"> must be preserved (open polyline)."""
        recovered = self._round_trip(self._make_polyline_event())
        elm = recovered.detail.as_element
        shape = elm.find("shape")
        self.assertIsNotNone(shape)
        self.assertEqual(shape.get("closed"), "0")

    # --- Route (b-m-r) folds into Class 3 ---

    def test_route_type_code_preserved(self):
        """Route event (etype=b-m-r) type code must round-trip through codec.

        Route folds into Class 3 at the codec tier: same Detail.from_elm path.
        The only distinction is etype='b-m-r' vs 'u-d-f-m'. Both have identical
        codec error surface.
        """
        links = (
            b'<link uid="WP0" type="b-m-p" point="40.0,-75.0,0.0" remarks="Start"/>'
            b'<link uid="WP1" type="b-m-p" point="40.1,-74.9,0.0" remarks="Waypoint"/>'
            b'<link uid="WP2" type="b-m-p" point="40.2,-74.8,0.0" remarks="End"/>'
        )
        detail_xml = b'<detail>' + links + b'<strokeColor value="-16776961"/></detail>'
        elm = etree.fromstring(detail_xml)

        evt = _make_event(uid="ROUTE-001", etype="b-m-r")
        evt.detail = Detail.from_elm(elm)

        proto = encode_federated_event(evt)
        recovered, _ = decode_federated_event(proto)

        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.etype, "b-m-r",
                         "Route etype=b-m-r must round-trip through codec")

    def test_route_waypoints_preserved(self):
        """Route waypoints (link chain) preserved — same codec path as polygon."""
        links = b"".join(
            f'<link uid="WP{i}" type="b-m-p" point="{40.0+i*0.01},-75.0,0.0"/>'.encode()
            for i in range(3)
        )
        detail_xml = b'<detail>' + links + b'</detail>'
        elm = etree.fromstring(detail_xml)

        evt = _make_event(uid="ROUTE-002", etype="b-m-r")
        evt.detail = Detail.from_elm(elm)

        proto = encode_federated_event(evt)
        recovered, _ = decode_federated_event(proto)

        self.assertIsNotNone(recovered)
        links_out = recovered.detail.as_element.findall("link")
        self.assertEqual(len(links_out), 3)


# ===========================================================================
# Class 5 — Geofence (__geofence in detail)
# ===========================================================================

class TestGeofenceDetailCodec(unittest.TestCase):
    """
    A geofence is a u-d-f-m shape with <__geofence> in <detail>.
    The codec must preserve the <__geofence> element and its attributes
    through encode_federated_event / decode_federated_event.

    Error surface: silent loss of <__geofence> converts a geofence into a
    plain polygon — no exception, but ATAK's geofence trigger logic won't fire.
    """

    def _make_geofence_event(self, uid="GEO-001"):
        detail_xml = (
            b'<detail>'
            b'<link uid="GF0" type="b-m-p" point="40.0,-75.0,0.0"/>'
            b'<link uid="GF1" type="b-m-p" point="40.01,-74.99,0.0"/>'
            b'<link uid="GF2" type="b-m-p" point="40.01,-75.01,0.0"/>'
            b'<__geofence trigger="Entry" monitor="Both" tracking="true"'
            b' minElevation="0.0" maxElevation="9999.0" elevationMonitored="false"/>'
            b'<strokeColor value="-256"/>'
            b'<strokeWeight value="3.0"/>'
            b'<fillColor value="-2130968576"/>'
            b'</detail>'
        )
        elm = etree.fromstring(detail_xml)
        evt = _make_event(uid=uid, etype="u-d-f-m")
        evt.detail = Detail.from_elm(elm)
        return evt

    def setUp(self):
        self.orig = self._make_geofence_event()
        proto = encode_federated_event(self.orig)
        self.recovered, _ = decode_federated_event(proto)

    def test_event_not_none(self):
        self.assertIsNotNone(self.recovered)

    def test_etype_u_d_f_preserved(self):
        self.assertEqual(self.recovered.etype, "u-d-f-m")

    def test_geofence_element_present(self):
        """<__geofence> must survive the codec round-trip."""
        elm = self.recovered.detail.as_element
        gf = elm.find("__geofence")
        self.assertIsNotNone(
            gf,
            "<__geofence> element must be preserved through encode→decode — "
            "loss silently converts geofence to plain polygon"
        )

    def test_geofence_trigger_attribute_preserved(self):
        elm = self.recovered.detail.as_element
        gf = elm.find("__geofence")
        self.assertIsNotNone(gf)
        self.assertEqual(gf.get("trigger"), "Entry")

    def test_geofence_monitor_attribute_preserved(self):
        elm = self.recovered.detail.as_element
        gf = elm.find("__geofence")
        self.assertIsNotNone(gf)
        self.assertEqual(gf.get("monitor"), "Both")

    def test_geofence_tracking_attribute_preserved(self):
        elm = self.recovered.detail.as_element
        gf = elm.find("__geofence")
        self.assertIsNotNone(gf)
        self.assertEqual(gf.get("tracking"), "true")

    def test_geofence_links_all_present(self):
        """All 3 vertex links must survive alongside <__geofence>."""
        elm = self.recovered.detail.as_element
        links = elm.findall("link")
        self.assertEqual(len(links), 3)

    def test_detail_is_generic_detail(self):
        """Geofence detail must not be misclassified as TAKUser or GeoChat."""
        self.assertIsInstance(self.recovered.detail, Detail)
        self.assertNotIsInstance(self.recovered.detail, TAKUser)
        self.assertNotIsInstance(self.recovered.detail, GeoChat)


# ===========================================================================
# Class 6 — GeoChat Directed (dst_uid, non-broadcast)
# ===========================================================================

class TestGeoChatDirectedCodec(unittest.TestCase):
    """
    Directed GeoChat: chatroom=recipient_callsign, dst_uid=recipient_UID.
    GeoChat.broadcast must be False; dst_uid must survive round-trip.

    Error surface: a codec that drops the 'id' attribute in <__chat> silently
    converts a private message into an all-chat-rooms broadcast — visible to
    all ATAK clients, not just the intended recipient.

    The existing test_federation_codec.py covers only broadcast=True.
    This class covers the directed (broadcast=False) sub-case.
    """

    DST_UID = "ANDROID-target-user-001"
    DST_CALLSIGN = "TARGET_USER"
    SRC_UID = "ANDROID-deadbeef"
    SRC_CALLSIGN = "SENDER"

    def _make_directed_geochat_event(self):
        """Build a directed GeoChat targeting a specific UID."""
        detail_xml = (
            f'<detail>'
            f'<__chat parent="RootContactGroup" groupOwner="false"'
            f' chatroom="{self.DST_CALLSIGN}" id="{self.DST_UID}"'
            f' senderCallsign="{self.SRC_CALLSIGN}">'
            f'<chatgrp uid0="{self.SRC_UID}" uid1="{self.DST_UID}"'
            f' id="{self.DST_UID}"/>'
            f'</__chat>'
            f'<link uid="{self.SRC_UID}" type="a-f-G-U-C" relation="p-p"/>'
            f'<remarks source="BAO.F.ATAK.{self.SRC_UID}" to="{self.DST_UID}"'
            f' time="2026-07-10T12:00:00.000Z">Private message for you</remarks>'
            f'</detail>'
        ).encode("utf-8")
        elm = etree.fromstring(detail_xml)
        chat = GeoChat.from_elm(elm)

        evt = _make_event(uid="CHAT-DIRECTED-001", etype="b-t-f")
        evt.detail = chat
        return evt

    def setUp(self):
        self.orig = self._make_directed_geochat_event()
        proto = encode_federated_event(self.orig)
        self.recovered, _ = decode_federated_event(proto)

    def test_event_not_none(self):
        self.assertIsNotNone(self.recovered)

    def test_detail_is_geochat(self):
        self.assertIsInstance(self.recovered.detail, GeoChat)

    def test_not_broadcast(self):
        """Directed GeoChat must NOT be broadcast (broadcast=False)."""
        self.assertFalse(
            self.recovered.detail.broadcast,
            "Directed GeoChat must NOT be broadcast — "
            "broadcast=True would expose the message to all ATAK clients"
        )

    def test_dst_uid_preserved(self):
        """Destination UID must survive the codec round-trip.

        Loss of dst_uid silently converts a directed message to broadcast.
        """
        self.assertEqual(
            self.recovered.detail.dst_uid,
            self.DST_UID,
            f"Directed GeoChat dst_uid must be '{self.DST_UID}' after encode→decode"
        )

    def test_chatroom_is_recipient_callsign(self):
        """chatroom must be the recipient callsign, not 'All Chat Rooms'."""
        self.assertEqual(
            self.recovered.detail.chatroom,
            self.DST_CALLSIGN,
            "Directed GeoChat chatroom must be the recipient callsign, not 'All Chat Rooms'"
        )

    def test_message_preserved(self):
        self.assertEqual(self.recovered.detail.message, "Private message for you")

    def test_src_callsign_preserved(self):
        self.assertEqual(self.recovered.detail.src_cs, self.SRC_CALLSIGN)

    def test_etype_b_t_f_preserved(self):
        self.assertEqual(self.recovered.etype, "b-t-f")


# ===========================================================================
# Cross-Cutting: Staling
# ===========================================================================

class TestStaleTimePropagation(unittest.TestCase):
    """
    Stale time must propagate exactly through the codec at millisecond precision.

    Cross-server staling scenario: Server A federates an event with stale=+24h.
    Server B receives it and must age it out at the same wall-clock time
    (within 1ms rounding tolerance).

    The tombstone scenario (stale < now) is used by the taky deletion pattern:
    a contact is "deleted" by re-sending its UID with stale 1 second in the past.
    """

    def _round_trip_stale(self, stale_dt: datetime) -> datetime:
        evt = _make_event()
        evt.stale = stale_dt
        proto = encode_federated_event(evt)
        recovered, _ = decode_federated_event(proto)
        return recovered.stale

    def test_stale_24h_future_round_trips(self):
        """Cross-server staling: stale=+24h survives codec round-trip within 1ms."""
        stale = datetime(2026, 7, 11, 12, 0, 0)  # exactly 24h ahead
        recovered = self._round_trip_stale(stale)
        # Allow 1 ms tolerance for integer ms rounding.
        delta_ms = abs((recovered - stale).total_seconds() * 1000)
        self.assertLessEqual(delta_ms, 1.0,
                             f"stale round-trip off by {delta_ms:.2f}ms (tolerance 1ms)")

    def test_stale_far_future_round_trips(self):
        """stale=+7 days round-trips correctly."""
        stale = _T0 + timedelta(days=7)
        recovered = self._round_trip_stale(stale)
        delta_ms = abs((recovered - stale).total_seconds() * 1000)
        self.assertLessEqual(delta_ms, 1.0)

    def test_tombstone_stale_past_round_trips(self):
        """Tombstone stale (stale=1s in past) must survive codec round-trip.

        This is the taky deletion pattern: re-send the same UID with stale < now
        so ATAK clients remove the entity from their map.
        """
        tombstone_stale = datetime(2026, 7, 10, 11, 59, 59)  # 1 sec before _T0
        recovered = self._round_trip_stale(tombstone_stale)
        delta_ms = abs((recovered - tombstone_stale).total_seconds() * 1000)
        self.assertLessEqual(delta_ms, 1.0)
        # Confirm it's still in the past after decode.
        self.assertLess(recovered, _T0,
                        "Tombstone stale must remain < now after decode")

    def test_stale_millisecond_precision_maintained(self):
        """Millisecond component of stale is preserved (no floor-to-second)."""
        stale_with_ms = datetime(2026, 7, 10, 12, 5, 30, 771000)
        recovered = self._round_trip_stale(stale_with_ms)
        self.assertEqual(recovered.microsecond, 771000,
                         "Sub-second precision (771ms) must survive stale round-trip")


# ===========================================================================
# Cross-Cutting: Deletion
# ===========================================================================

class TestSynthesizeContactEvent(unittest.TestCase):
    """
    synthesize_contact_event converts ContactListEntry CRUD operations
    into CoT models.Event objects for injection into OTS.

    This function is NOT tested in the 441-baseline.
    """

    def _make_contact(self, op_value: int, uid="CONTACT-001", callsign="REMOTE_USER"):
        return fig_pb2.ContactListEntry(
            operation=op_value,
            uid=uid,
            callsign=callsign,
            phone="+15551234567",
            sip="sip:test@example.com",
            directConnect="192.168.1.1:4242:tcp",
        )

    # --- CREATE (operation=1) ---

    def test_create_returns_event(self):
        contact = self._make_contact(1)
        evt = synthesize_contact_event(contact)
        self.assertIsNotNone(evt, "CREATE must return an Event")

    def test_create_etype_is_presence(self):
        """CREATE → presence event type a-f-G-U-C."""
        evt = synthesize_contact_event(self._make_contact(1))
        self.assertEqual(evt.etype, "a-f-G-U-C")

    def test_create_uid_matches_contact_uid(self):
        evt = synthesize_contact_event(self._make_contact(1, uid="CONTACT-999"))
        self.assertEqual(evt.uid, "CONTACT-999")

    def test_create_stale_in_future(self):
        """CREATE → stale=now+30min (contact is alive)."""
        import datetime as _dt_module
        before = _dt_module.datetime.utcnow()
        evt = synthesize_contact_event(self._make_contact(1))
        after = _dt_module.datetime.utcnow()
        # stale must be strictly in the future from caller's perspective.
        self.assertGreater(evt.stale, before,
                           "CREATE contact stale must be in the future")

    def test_create_detail_has_contact_element(self):
        """CREATE → detail includes <contact callsign> element."""
        evt = synthesize_contact_event(self._make_contact(1, callsign="ALICE"))
        self.assertIsNotNone(evt.detail)
        elm = evt.detail.as_element
        contact_elm = elm.find("contact")
        self.assertIsNotNone(contact_elm, "<contact> element must be in CREATE detail")
        self.assertEqual(contact_elm.get("callsign"), "ALICE")

    # --- UPDATE (operation=3) ---

    def test_update_returns_event(self):
        evt = synthesize_contact_event(self._make_contact(3))
        self.assertIsNotNone(evt, "UPDATE must return an Event")

    def test_update_stale_in_future(self):
        """UPDATE → stale=now+30min (same as CREATE)."""
        import datetime as _dt_module
        before = _dt_module.datetime.utcnow()
        evt = synthesize_contact_event(self._make_contact(3))
        self.assertGreater(evt.stale, before)

    # --- DELETE (operation=4) — tombstone ---

    def test_delete_returns_event(self):
        evt = synthesize_contact_event(self._make_contact(4))
        self.assertIsNotNone(evt, "DELETE must return a tombstone Event")

    def test_delete_stale_in_past(self):
        """DELETE → tombstone: stale < now so ATAK clients remove the entity.

        This is the taky deletion pattern: the contact is "deleted" by
        re-sending its UID with stale already expired.
        """
        import datetime as _dt_module
        evt = synthesize_contact_event(self._make_contact(4))
        after = _dt_module.datetime.utcnow()
        self.assertLess(evt.stale, after,
                        "DELETE tombstone must have stale < now so ATAK removes the contact")

    def test_delete_uid_preserved(self):
        """DELETE tombstone must carry the contact's UID so ATAK matches by UID."""
        evt = synthesize_contact_event(self._make_contact(4, uid="TO-DELETE"))
        self.assertEqual(evt.uid, "TO-DELETE")

    def test_delete_has_detail(self):
        """DELETE tombstone must have a detail element (contact info for ATAK display)."""
        evt = synthesize_contact_event(self._make_contact(4, callsign="CAROL"))
        self.assertIsNotNone(evt.detail)

    # --- READ (operation=2) → no-op ---

    def test_read_returns_none(self):
        """READ is a no-op in taky federation — must return None."""
        evt = synthesize_contact_event(self._make_contact(2))
        self.assertIsNone(evt, "READ contact operation must return None (no-op)")

    # --- INVALID (operation=0) → no-op ---

    def test_invalid_returns_none(self):
        """Invalid operation=0 must return None."""
        evt = synthesize_contact_event(self._make_contact(0))
        self.assertIsNone(evt, "INVALID contact operation must return None")

    # --- Edge case: missing UID ---

    def test_empty_uid_returns_none(self):
        """Contact with empty uid → None (cannot create a CoT event without UID)."""
        contact = fig_pb2.ContactListEntry(operation=1, uid="", callsign="NOUID")
        evt = synthesize_contact_event(contact)
        self.assertIsNone(evt, "Contact with empty uid must return None")


class TestDeletionTypeTxDdCodec(unittest.TestCase):
    """
    Explicit deletion event: etype='t-x-d-d' (CoT delete type).

    The codec must preserve the 't-x-d-d' type code through encode→decode.
    prepare_outbound_event applies block-unmapped group policy to ALL events,
    including t-x-d-d tombstones.  A delete event with no <__group> element
    has no determinable group and is therefore blocked when an outbound group
    registry is configured.
    """

    def _make_delete_event(self, uid="DELETE-UID-001"):
        """CoT delete event — signals ATAK to remove the entity with this UID."""
        evt = _make_event(uid=uid, etype="t-x-d-d")
        # Delete events typically have no meaningful detail.
        return evt

    def test_t_x_d_d_etype_round_trips(self):
        """t-x-d-d type code must survive encode → decode."""
        evt = self._make_delete_event()
        proto = encode_federated_event(evt)
        recovered, _ = decode_federated_event(proto)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.etype, "t-x-d-d",
                         "Delete event type code 't-x-d-d' must round-trip through codec")

    def test_t_x_d_d_uid_preserved(self):
        """Delete event UID must round-trip (ATAK matches deletion by UID)."""
        evt = self._make_delete_event(uid="TARGET-TO-DELETE")
        proto = encode_federated_event(evt)
        recovered, _ = decode_federated_event(proto)
        self.assertEqual(recovered.uid, "TARGET-TO-DELETE")

    def test_t_x_d_d_blocked_by_outbound_policy_no_group(self):
        """Delete events with no determinable group are blocked by outbound policy.

        ALL events (including t-x-d-d tombstones) are subject to outbound
        group policy when a registry is configured.
        A delete event has no TAKUser detail and no <__group> element, so no
        group can be extracted → block-unmapped default applies → suppressed.

        Prior to the fix the test was named
        'test_t_x_d_d_not_blocked_by_outbound_logic' and asserted assertIsNotNone
        — that was documenting the fail-open behaviour (non-TAKUser events
        forwarded unconditionally). The correct secure behaviour is block.

        Operators who need delete events to propagate must either (a) include
        <__group> in the tombstone CoT, or (b) rely on ATAK's own stale-timeout
        handling to age out entities naturally.
        """
        evt = self._make_delete_event()
        # Registry configured for Blue only — delete event has no group → blocked
        reg = _make_registry(PEER_A, out_map={"Blue": "Blue"})
        result = prepare_outbound_event(
            evt, node_id=NODE_ID, default_max_hops=3,
            registry=reg, peer_id=PEER_A,
        )
        self.assertIsNone(
            result,
            "Delete event with no determinable group must be blocked "
            "(block-unmapped default applies to all events)"
        )

    def test_t_x_d_d_tombstone_stale_is_past(self):
        """Delete event's stale time should be in the past (tombstone pattern check)."""
        import datetime as _dt_module
        # Set stale = 1 second before the event time (tombstone).
        del_evt = _make_event(uid="TOMB-001", etype="t-x-d-d")
        del_evt.stale = del_evt.time - timedelta(seconds=1)

        proto = encode_federated_event(del_evt)
        recovered, _ = decode_federated_event(proto)

        self.assertIsNotNone(recovered)
        # Stale must remain before time after round-trip.
        self.assertLess(recovered.stale, recovered.time,
                        "Tombstone stale (< time) must survive codec round-trip")


if __name__ == "__main__":
    unittest.main()
