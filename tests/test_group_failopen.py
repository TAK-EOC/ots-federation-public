# tests/test_group_failopen.py
# Regression tests for — <takv>-absent CoT fail-open (over-share).
# Root cause
# ----------
# prepare_outbound_event extracted the outbound group ONLY from TAKUser
# detail objects.  TAKUser.is_type requires {"takv","contact","__group"};
# events missing <takv> are parsed as generic Detail, not TAKUser.  The old
# guard `if local_groups:` then skipped group policy entirely for non-TAKUser
# events, forwarding them unconditionally to all federation peers.
# This is a fail-open: machine-generated CoT (sensor feeds, direwolf2tak
# traffic, synthetic markers, overlay injects) routinely lacks <takv> but
# carries <__group> indicating intended group membership.  Those events were
# silently over-shared to all peers regardless of the outbound group map.
# Fix
# ---
# 1. Fall back to reading <__group> from the raw XML element for non-TAKUser
#    detail, so <takv>-absent SA events still have their group extracted.
# 2. Always enforce policy: an event with no determinable group yields []
#    remote groups → suppress (block-unmapped default).
# Test layout
# -----------
# The first four test methods in TestNoTakvFailOpen were written to FAIL with
# the unfixed code and PASS after the fix.  They directly confirm the over-share
# path was closed.

import unittest
from datetime import datetime, timedelta

from lxml import etree

from ots_federation import models
from ots_federation.models.detail import Detail
from ots_federation.models.event import Event
from ots_federation.models.teams import Teams
from ots_federation.codec import prepare_outbound_event
from ots_federation.groups import FederateGroupRegistry, FederatePeerGroupMap

PEER_ID = "server-alpha.example.com"
NODE_ID = "taky-local.example.com"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _base_event(uid="sensor-001"):
    """Minimal CoT event scaffolding with no detail."""
    now = datetime.utcnow()
    evt = Event(
        uid=uid,
        etype="a-f-G-E-S",
        how="m-g",
        time=now,
        start=now,
        stale=now + timedelta(seconds=300),
    )
    evt.point = models.Point(lat=10.0, lon=20.0, hae=0.0, ce=9999999.0, le=9999999.0)
    return evt


def _registry_blue_only():
    """Registry that maps only Blue outbound; White/other → blocked."""
    reg = FederateGroupRegistry()
    # Phase-1: local_group is now a plain str, not Teams enum.
    reg.add_peer_map(FederatePeerGroupMap(PEER_ID, "out", "Blue", "Blue"))
    return reg


def _make_notakv_evt(group_name="Blue"):
    """
    Synthetic CoT event with <__group> and <contact> but NO <takv>.

    This is the shape emitted by direwolf2tak, wx-radar-tak sensor injects
    and other non-ATAK producers that set group affiliation but do not
    include an ATAK software version element.  TAKUser.is_type returns
    False for these events → parsed as generic Detail.

    Option D : sets evt.local_acl_groups sidecar (simulating a warm
    EudGroupCache entry for this uid). In production the cache is populated
    by the groups exchange subscriber; the <__group> XML element is no longer
    the source of group information for outbound policy decisions.
    """
    evt = _base_event()
    detail_elm = etree.Element("detail")
    contact = etree.SubElement(detail_elm, "contact")
    contact.set("callsign", "SENSOR-01")
    contact.set("endpoint", "*:-1:stcp")
    uid_elm = etree.SubElement(detail_elm, "uid")
    uid_elm.set("Droid", "SENSOR-01")
    grp = etree.SubElement(detail_elm, "__group")
    grp.set("name", group_name)
    grp.set("role", "Team Member")
    # No <takv> element — prevents TAKUser.is_type from matching.
    evt.detail = Detail(detail_elm)
    #: ACL cache sidecar — set directly in tests to simulate a warm cache.
    evt.local_acl_groups = frozenset([group_name])
    return evt


def _make_no_group_evt():
    """
    CoT event with a <detail> element but NO <__group> child.
    No group affiliation is determinable from the event.
    """
    evt = _base_event(uid="marker-001")
    detail_elm = etree.Element("detail")
    link = etree.SubElement(detail_elm, "link")
    link.set("uid", "SOME-UPSTREAM-UID")
    link.set("type", "a-f-G-E")
    link.set("relation", "p-p")
    evt.detail = Detail(detail_elm)
    return evt


def _make_no_detail_evt():
    """CoT event with no <detail> element at all."""
    return _base_event(uid="bare-001")


# ---------------------------------------------------------------------------
# Main test class
# ---------------------------------------------------------------------------

class TestNoTakvFailOpen(unittest.TestCase):
    """
    Prove that events lacking <takv> (or <__group>, or detail entirely) are
    correctly BLOCKED by outbound group policy.

    test_notakv_white_group_blocked_when_unmapped
    test_no_group_element_blocked_under_registry, and
    test_no_detail_blocked_under_registry were written to FAIL with the
    unfixed code, confirming the fail-open.  After the fix all tests pass.
    test_notakv_blue_group_forwarded_when_mapped failed pre-fix because
    federateGroups was empty (group tag omitted) even when the event did
    forward; post-fix both the forward AND the tag are correct.
    """

    def _prepare(self, evt, registry=None, peer_id=PEER_ID):
        return prepare_outbound_event(
            evt,
            node_id=NODE_ID,
            default_max_hops=3,
            registry=registry,
            peer_id=peer_id,
        )

    # ----------------------------------------------------------------
    # Case 1: <__group Blue> present, no <takv>, Blue IS mapped → FORWARD
    # Pre-fix: forwarded without group tag (federateGroups=[]).
    # Post-fix: forwarded WITH group tag (federateGroups=["Blue"]).
    # ----------------------------------------------------------------
    def test_notakv_blue_group_forwarded_when_mapped(self):
        """<takv>-absent event with <__group Blue> forwards and carries the tag."""
        reg = _registry_blue_only()
        evt = _make_notakv_evt("Blue")
        proto = self._prepare(evt, registry=reg)
        self.assertIsNotNone(proto,
            "expected forward: Blue is mapped but event was blocked")
        self.assertIn("Blue", list(proto.federateGroups),
            "federateGroups must carry the mapped remote group name")

    # ----------------------------------------------------------------
    # Case 2: <__group White> present, no <takv>, only Blue mapped → BLOCK
    # Pre-fix: forwarded unconditionally (FAIL-OPEN confirmed).
    # Post-fix: blocked.
    # ----------------------------------------------------------------
    def test_notakv_white_group_blocked_when_unmapped(self):
        """
        <takv>-absent event with <__group White> MUST be blocked when
        only Blue is mapped for the peer.

        FAIL-OPEN: with unfixed code this assertion fails — the event is
        forwarded instead of suppressed, confirming the over-share.
        """
        reg = _registry_blue_only()
        evt = _make_notakv_evt("White")
        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "FAIL-OPEN: <takv>-absent White event was forwarded when only "
            "Blue is mapped — group policy was bypassed")

    # ----------------------------------------------------------------
    # Case 3: detail present, no <__group> → no group determinable → BLOCK
    # Pre-fix: forwarded unconditionally.
    # Post-fix: blocked.
    # ----------------------------------------------------------------
    def test_no_group_element_blocked_under_registry(self):
        """
        Event with <detail> but no <__group> child has no determinable group.
        Must be blocked under block-unmapped default.
        """
        reg = _registry_blue_only()
        evt = _make_no_group_evt()
        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "event with no <__group> was forwarded (group indeterminate → must block)")

    # ----------------------------------------------------------------
    # Case 4: no detail at all → no group determinable → BLOCK
    # Pre-fix: forwarded unconditionally.
    # Post-fix: blocked.
    # ----------------------------------------------------------------
    def test_no_detail_blocked_under_registry(self):
        """
        Event with no detail at all has no determinable group.
        Must be blocked under block-unmapped default.
        """
        reg = _registry_blue_only()
        evt = _make_no_detail_evt()
        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "event with no detail was forwarded (group indeterminate → must block)")

    # ----------------------------------------------------------------
    # Case 5: registry=None → no policy, all event types pass through
    # (backward-compat; unchanged by fix)
    # ----------------------------------------------------------------
    def test_no_registry_forwards_all_event_types(self):
        """Without a registry, all event types pass through (backward-compat)."""
        for label, evt in [
            ("notakv-with-group", _make_notakv_evt("Blue")),
            ("no-group-element", _make_no_group_evt()),
            ("no-detail", _make_no_detail_evt()),
        ]:
            with self.subTest(event_type=label):
                proto = self._prepare(evt, registry=None)
                self.assertIsNotNone(proto,
                    f"{label}: expected forward when registry=None but got None")
                # No group tags when no registry.
                self.assertEqual(list(proto.federateGroups), [],
                    f"{label}: expected empty federateGroups without registry")

    # ----------------------------------------------------------------
    # Case 6: mapped Blue group → federateGroups carries the remote name
    # ----------------------------------------------------------------
    def test_notakv_blue_group_federategroups_tagged(self):
        """<takv>-absent event with mapped Blue carries exactly one group tag."""
        reg = _registry_blue_only()
        evt = _make_notakv_evt("Blue")
        proto = self._prepare(evt, registry=reg)
        self.assertIsNotNone(proto)
        groups = list(proto.federateGroups)
        self.assertEqual(len(groups), 1,
            f"expected exactly 1 group entry, got: {groups}")
        self.assertEqual(groups[0], "Blue")

    # ----------------------------------------------------------------
    # Case 7: unrecognised group name → Teams.UNKNOWN ("Cyan") → not in
    #         _registry_blue_only → blocked
    # ----------------------------------------------------------------
    def test_notakv_unknown_group_name_blocked(self):
        """
        <takv>-absent event with an unrecognised group name ("SIGINT") is blocked
        because "SIGINT" is not in the outbound map (which only maps "Blue").

        Phase-1 migration note: previously "SIGINT" was converted to Teams.UNKNOWN
        (value "Cyan"), which was then blocked. Now "SIGINT" passes through as-is
        as a plain string — it's still blocked because "SIGINT" != "Blue".
        """
        reg = _registry_blue_only()
        evt = _make_notakv_evt("SIGINT")  # arbitrary non-color group name
        proto = self._prepare(evt, registry=reg)
        self.assertIsNone(proto,
            "event with unmapped group name 'SIGINT' should be blocked "
            "(only Blue is in the outbound map)")


if __name__ == "__main__":
    unittest.main()
