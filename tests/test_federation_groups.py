# tests/test_federation_groups.py
# Tests for taky.cot.federation.groups — FederateGroupRegistry and helpers.
# Coverage targets:
#   1. Block-unmapped default (no mapping → None)
#   2. Bidirectional mapping (in and out, per-peer)
#   3. Opt-in allow/fallback mode
#   4. Per-peer isolation (peer A mapping doesn't bleed into peer B)
#   5. map_inbound_groups multi-group list API
#   6. map_outbound_groups multi-group list API
#   7. update_from_federate_groups / get_announced_groups
#   8. Wildcard catch-all inbound ("*" key)
#   9. Explicit block entry (local_group=None)
#  10. parse_group_map helper

import pytest

from ots_federation.groups import (
    FederateGroupRegistry,
    FederatePeerGroupMap,
    _resolve_by_value,
    parse_group_map,
)
from ots_federation.models.teams import Teams


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PEER_A = "server-alpha.example.com"
PEER_B = "server-bravo.example.com"


def _reg_with_maps(
    peer_id: str,
    in_map: dict,        # {remote_group_str: str | None}  (Phase-1: was Teams | None)
    out_map: dict = None,  # {str: remote_group_str}       (Phase-1: was {Teams: str})
    fallback: bool = False,
) -> FederateGroupRegistry:
    """Helper: build a FederateGroupRegistry from plain dicts."""
    reg = FederateGroupRegistry()
    for remote, local in in_map.items():
        reg.add_peer_map(
            FederatePeerGroupMap(
                peer_id=peer_id,
                direction="in",
                remote_group=remote,
                local_group=local,
            )
        )
    for local_str, remote_name in (out_map or {}).items():
        reg.add_peer_map(
            FederatePeerGroupMap(
                peer_id=peer_id,
                direction="out",
                remote_group=remote_name,
                local_group=local_str,
            )
        )
    if fallback:
        reg.set_fallback_allow(peer_id, True)
    return reg


# ---------------------------------------------------------------------------
# 1. Block-unmapped default
# ---------------------------------------------------------------------------

class TestBlockUnmappedDefault:
    def test_no_peer_config_blocks(self):
        """Registry with no entries blocks any group for any peer."""
        reg = FederateGroupRegistry()
        assert reg.map_inbound(PEER_A, "White") is None

    def test_peer_configured_but_no_matching_entry_blocks(self):
        """Peer has a mapping, but this specific remote group is not in it."""
        reg = _reg_with_maps(PEER_A, {"Blue": "Blue"})
        assert reg.map_inbound(PEER_A, "White") is None

    def test_no_outbound_config_blocks(self):
        """No outbound mapping → None (don't forward)."""
        reg = FederateGroupRegistry()
        assert reg.map_outbound(PEER_A, "White") is None

    def test_outbound_peer_configured_but_group_missing_blocks(self):
        reg = _reg_with_maps(PEER_A, {}, out_map={"Blue": "Blue"})
        assert reg.map_outbound(PEER_A, "White") is None

    def test_map_inbound_groups_empty_list_returns_none(self):
        reg = _reg_with_maps(PEER_A, {"White": "White"})
        # Empty remote_groups list → no groups resolved → None
        result = reg.map_inbound_groups(PEER_A, [])
        assert result is None

    def test_map_inbound_groups_all_unmapped_returns_none(self):
        reg = _reg_with_maps(PEER_A, {"Blue": "Blue"})
        result = reg.map_inbound_groups(PEER_A, ["White", "Green"])
        assert result is None


# ---------------------------------------------------------------------------
# 2. Bidirectional mapping
# ---------------------------------------------------------------------------

class TestBidirectionalMapping:
    def test_inbound_exact_match(self):
        # Phase-1: local_group values are plain strings.
        reg = _reg_with_maps(PEER_A, {"White": "White", "Blue": "Blue"})
        assert reg.map_inbound(PEER_A, "White") == "White"
        assert reg.map_inbound(PEER_A, "Blue") == "Blue"

    def test_outbound_exact_match(self):
        reg = _reg_with_maps(
            PEER_A,
            {},
            out_map={"White": "White", "Green": "OpsGrp-Alpha"},
        )
        assert reg.map_outbound(PEER_A, "White") == "White"
        assert reg.map_outbound(PEER_A, "Green") == "OpsGrp-Alpha"

    def test_inbound_remote_name_different_from_local(self):
        """Remote uses 'OpsGrp-Alpha'; local maps to 'Green'."""
        reg = _reg_with_maps(PEER_A, {"OpsGrp-Alpha": "Green"})
        assert reg.map_inbound(PEER_A, "OpsGrp-Alpha") == "Green"

    def test_outbound_local_maps_to_different_remote_name(self):
        reg = _reg_with_maps(PEER_A, {}, out_map={"Green": "OpsGrp-Alpha"})
        assert reg.map_outbound(PEER_A, "Green") == "OpsGrp-Alpha"

    def test_both_direction_adds_to_both_tables(self):
        reg = FederateGroupRegistry()
        reg.add_peer_map(
            FederatePeerGroupMap(
                peer_id=PEER_A,
                direction="both",
                remote_group="White",
                local_group="White",
            )
        )
        assert reg.map_inbound(PEER_A, "White") == "White"
        assert reg.map_outbound(PEER_A, "White") == "White"

    def test_map_inbound_groups_partial_match(self):
        """Only some groups map — result contains only the mapped ones."""
        reg = _reg_with_maps(PEER_A, {"White": "White", "Blue": "Blue"})
        result = reg.map_inbound_groups(PEER_A, ["White", "SIGINT", "Blue"])
        assert result == {"White", "Blue"}

    def test_map_inbound_groups_all_mapped(self):
        reg = _reg_with_maps(PEER_A, {"White": "White", "Blue": "Blue"})
        result = reg.map_inbound_groups(PEER_A, ["White", "Blue"])
        assert result == {"White", "Blue"}

    def test_map_outbound_groups_filters_unmapped(self):
        reg = _reg_with_maps(
            PEER_A,
            {},
            out_map={"White": "White", "Blue": "Blue"},
        )
        result = reg.map_outbound_groups(PEER_A, ["White", "Green", "Blue"])
        assert set(result) == {"White", "Blue"}
        assert "Green" not in result

    def test_map_outbound_groups_empty_if_all_blocked(self):
        reg = _reg_with_maps(PEER_A, {}, out_map={"Blue": "Blue"})
        result = reg.map_outbound_groups(PEER_A, ["White", "Green"])
        assert result == []


# ---------------------------------------------------------------------------
# 3. Opt-in allow/fallback mode
# ---------------------------------------------------------------------------

class TestFallbackAllowMode:
    def test_fallback_off_blocks_unmapped(self):
        """Without fallback, a group with no mapping is blocked."""
        reg = _reg_with_maps(PEER_A, {}, fallback=False)
        assert reg.map_inbound(PEER_A, "White") is None

    def test_fallback_on_passes_through_as_string(self):
        """With fallback, remote group name is returned as-is (string passthrough).

        Phase-1 behavior change: previously fallback resolved color names only
        (via Teams enum lookup) and blocked non-color names. Now ALL remote group
        names pass through — the local group name equals the remote group name.
        """
        reg = _reg_with_maps(PEER_A, {}, fallback=True)
        result = reg.map_inbound(PEER_A, "White")
        # Fallback passthrough: "White" → "White" (string, not Teams.WHITE enum)
        assert result == "White"

    def test_fallback_on_passes_through_arbitrary_name(self):
        """With fallback, arbitrary non-color names also pass through (Phase-1 change).

        Previously fallback would block "SIGINT" (not a Teams color); now it
        passes through as a valid arbitrary group string.
        """
        reg = _reg_with_maps(PEER_A, {}, fallback=True)
        result = reg.map_inbound(PEER_A, "SIGINT")
        assert result == "SIGINT"  # string passthrough, not None

    def test_fallback_on_explicit_block_takes_precedence(self):
        """Explicit block entry (local_group=None) must override fallback."""
        reg = _reg_with_maps(PEER_A, {"White": None}, fallback=True)
        # Explicit block wins even when fallback is on
        assert reg.map_inbound(PEER_A, "White") is None

    def test_fallback_on_explicit_mapping_takes_precedence(self):
        """Explicit mapping overrides fallback passthrough."""
        reg = _reg_with_maps(PEER_A, {"White": "Blue"}, fallback=True)
        # Explicit map White→Blue, not White→White (which fallback would give)
        assert reg.map_inbound(PEER_A, "White") == "Blue"

    def test_fallback_mode_independent_per_peer(self):
        """Enabling fallback for peer A does not affect peer B."""
        reg = FederateGroupRegistry()
        # Peer A: no mapping, fallback ON
        reg.set_fallback_allow(PEER_A, True)
        # Peer B: no mapping, fallback OFF (default)
        assert reg.map_inbound(PEER_A, "White") == "White"
        assert reg.map_inbound(PEER_B, "White") is None


# ---------------------------------------------------------------------------
# 4. Per-peer isolation
# ---------------------------------------------------------------------------

class TestPerPeerIsolation:
    def setup_method(self):
        self.reg = FederateGroupRegistry()
        # Phase-1: local_group is now a plain str.
        # Peer A: White → White
        self.reg.add_peer_map(
            FederatePeerGroupMap(PEER_A, "in", "White", "White")
        )
        # Peer B: Blue → Blue
        self.reg.add_peer_map(
            FederatePeerGroupMap(PEER_B, "in", "Blue", "Blue")
        )

    def test_peer_a_mapping_not_visible_to_peer_b(self):
        # Peer B has no mapping for "White"
        assert self.reg.map_inbound(PEER_B, "White") is None

    def test_peer_b_mapping_not_visible_to_peer_a(self):
        # Peer A has no mapping for "Blue"
        assert self.reg.map_inbound(PEER_A, "Blue") is None

    def test_peer_a_own_mapping_works(self):
        assert self.reg.map_inbound(PEER_A, "White") == "White"

    def test_peer_b_own_mapping_works(self):
        assert self.reg.map_inbound(PEER_B, "Blue") == "Blue"

    def test_outbound_peer_isolation(self):
        reg = FederateGroupRegistry()
        reg.add_peer_map(
            FederatePeerGroupMap(PEER_A, "out", "White", "White")
        )
        # Peer B has no outbound config at all
        assert reg.map_outbound(PEER_B, "White") is None

    def test_announced_groups_isolated(self):
        reg = FederateGroupRegistry()
        reg.update_from_federate_groups(PEER_A, ["White", "Blue"])
        assert reg.get_announced_groups(PEER_A) == ["White", "Blue"]
        assert reg.get_announced_groups(PEER_B) == []


# ---------------------------------------------------------------------------
# 5. Wildcard catch-all inbound
# ---------------------------------------------------------------------------

class TestWildcardInbound:
    def test_wildcard_block_all_unmapped(self):
        """'*': None blocks anything not explicitly mapped."""
        reg = _reg_with_maps(PEER_A, {"White": "White", "*": None})
        assert reg.map_inbound(PEER_A, "White") == "White"  # exact match
        assert reg.map_inbound(PEER_A, "SIGINT") is None     # wildcard → block
        assert reg.map_inbound(PEER_A, "Blue") is None       # wildcard → block

    def test_wildcard_route_all_unmapped_to_fixed_group(self):
        """'*': 'White' routes all unmapped remote groups to 'White' locally."""
        reg = _reg_with_maps(PEER_A, {"Blue": "Blue", "*": "White"})
        assert reg.map_inbound(PEER_A, "Blue") == "Blue"     # exact match
        assert reg.map_inbound(PEER_A, "SIGINT") == "White"  # wildcard
        assert reg.map_inbound(PEER_A, "OpsGrp") == "White"  # wildcard

    def test_exact_match_takes_precedence_over_wildcard(self):
        """Exact match is checked before wildcard."""
        reg = _reg_with_maps(
            PEER_A, {"White": "White", "*": "Blue"}
        )
        assert reg.map_inbound(PEER_A, "White") == "White"  # not wildcard!


# ---------------------------------------------------------------------------
# 6. Explicit block entry
# ---------------------------------------------------------------------------

class TestExplicitBlock:
    def test_explicit_none_blocks_known_group(self):
        reg = _reg_with_maps(PEER_A, {"White": None})
        assert reg.map_inbound(PEER_A, "White") is None

    def test_explicit_none_does_not_affect_other_groups(self):
        reg = _reg_with_maps(PEER_A, {"White": None, "Blue": "Blue"})
        assert reg.map_inbound(PEER_A, "Blue") == "Blue"
        assert reg.map_inbound(PEER_A, "White") is None

    def test_map_inbound_groups_explicit_block_not_counted(self):
        """Groups that map to None must not appear in the output set."""
        reg = _reg_with_maps(
            PEER_A, {"White": None, "Blue": "Blue"}
        )
        result = reg.map_inbound_groups(PEER_A, ["White", "Blue"])
        assert result == {"Blue"}

    def test_map_inbound_groups_only_blocked_groups_returns_none(self):
        reg = _reg_with_maps(PEER_A, {"White": None})
        result = reg.map_inbound_groups(PEER_A, ["White"])
        assert result is None


# ---------------------------------------------------------------------------
# 7. update_from_federate_groups / get_announced_groups
# ---------------------------------------------------------------------------

class TestAnnounced:
    def test_update_stores_groups(self):
        reg = FederateGroupRegistry()
        reg.update_from_federate_groups(PEER_A, ["White", "Blue", "SIGINT"])
        assert reg.get_announced_groups(PEER_A) == ["White", "Blue", "SIGINT"]

    def test_update_replaces_previous(self):
        reg = FederateGroupRegistry()
        reg.update_from_federate_groups(PEER_A, ["White"])
        reg.update_from_federate_groups(PEER_A, ["Blue", "Green"])
        assert reg.get_announced_groups(PEER_A) == ["Blue", "Green"]

    def test_empty_list_on_unknown_peer(self):
        reg = FederateGroupRegistry()
        assert reg.get_announced_groups("nobody") == []

    def test_update_does_not_create_mappings(self):
        """Announcing groups does NOT auto-create inbound/outbound mappings."""
        reg = FederateGroupRegistry()
        reg.update_from_federate_groups(PEER_A, ["White", "Blue"])
        # Without explicit add_peer_map, all groups are blocked
        assert reg.map_inbound(PEER_A, "White") is None
        assert reg.map_inbound(PEER_A, "Blue") is None

    def test_get_announced_returns_copy(self):
        """Mutating the returned list must not affect internal state."""
        reg = FederateGroupRegistry()
        reg.update_from_federate_groups(PEER_A, ["White"])
        lst = reg.get_announced_groups(PEER_A)
        lst.append("injected")
        assert reg.get_announced_groups(PEER_A) == ["White"]


# ---------------------------------------------------------------------------
# 8. known_peers
# ---------------------------------------------------------------------------

class TestKnownPeers:
    def test_empty_registry(self):
        assert FederateGroupRegistry().known_peers() == []

    def test_peers_from_inbound_config(self):
        reg = _reg_with_maps(PEER_A, {"White": "White"})
        assert PEER_A in reg.known_peers()

    def test_peers_from_outbound_config(self):
        reg = _reg_with_maps(PEER_A, {}, out_map={"White": "White"})
        assert PEER_A in reg.known_peers()

    def test_peer_without_config_not_listed(self):
        reg = _reg_with_maps(PEER_A, {"White": "White"})
        assert PEER_B not in reg.known_peers()

    def test_multiple_peers_listed(self):
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap(PEER_A, "in", "White", "White"))
        reg.add_peer_map(FederatePeerGroupMap(PEER_B, "in", "Blue", "Blue"))
        peers = reg.known_peers()
        assert PEER_A in peers
        assert PEER_B in peers


# ---------------------------------------------------------------------------
# 9. _resolve_by_value helper
# ---------------------------------------------------------------------------

class TestResolveByValue:
    def test_known_values_resolve(self):
        for member in Teams:
            result = _resolve_by_value(member.value)
            assert result is not None
            assert result.value == member.value

    def test_unknown_value_returns_none(self):
        assert _resolve_by_value("SIGINT") is None
        assert _resolve_by_value("") is None
        assert _resolve_by_value("white") is None  # case-sensitive

    def test_cyan_and_unknown_both_resolve_to_cyan_value(self):
        # Teams.CYAN and Teams.UNKNOWN share value "Cyan"
        result = _resolve_by_value("Cyan")
        assert result is not None
        assert result.value == "Cyan"


# ---------------------------------------------------------------------------
# 10. parse_group_map helper
# ---------------------------------------------------------------------------

class TestParseGroupMap:
    def test_parse_inbound_simple(self):
        # Phase-1: local_group is now a plain str, not Teams enum.
        entries = parse_group_map("White:White, Blue:Blue", "in")
        assert len(entries) == 2
        by_remote = {e.remote_group: e.local_group for e in entries}
        assert by_remote["White"] == "White"
        assert by_remote["Blue"] == "Blue"

    def test_parse_inbound_explicit_block(self):
        entries = parse_group_map("White:White, *:", "in")
        by_remote = {e.remote_group: e.local_group for e in entries}
        assert by_remote["White"] == "White"
        assert by_remote["*"] is None  # block

    def test_parse_inbound_remote_name_maps_to_local(self):
        entries = parse_group_map("OpsGrp-Alpha:Green", "in")
        assert len(entries) == 1
        assert entries[0].remote_group == "OpsGrp-Alpha"
        assert entries[0].local_group == "Green"

    def test_parse_outbound_simple(self):
        entries = parse_group_map("White:White, Green:OpsGrp-Alpha", "out")
        by_local = {e.local_group: e.remote_group for e in entries}
        assert by_local["White"] == "White"
        assert by_local["Green"] == "OpsGrp-Alpha"

    def test_parse_inbound_arbitrary_string_accepted(self):
        """Phase-1: arbitrary non-color local group names are now valid (no ValueError)."""
        # Previously 'White:NotATeam' raised ValueError("Unknown local Teams value").
        # After migration, arbitrary strings on the right side are accepted.
        entries = parse_group_map("White:NotATeam", "in")
        assert len(entries) == 1
        assert entries[0].local_group == "NotATeam"

    def test_parse_outbound_arbitrary_string_accepted(self):
        """Phase-1: arbitrary non-color local group names on lhs are now valid."""
        # Previously 'NotATeam:remote' raised ValueError("Unknown local Teams value").
        entries = parse_group_map("NotATeam:remote", "out")
        assert len(entries) == 1
        assert entries[0].local_group == "NotATeam"
        assert entries[0].remote_group == "remote"

    def test_parse_arbitrary_group_name_back_compat(self):
        """'FIRE-OPS:FIRE-OPS' parses cleanly (was previously rejected)."""
        entries = parse_group_map("FIRE-OPS:FIRE-OPS", "in")
        assert len(entries) == 1
        assert entries[0].remote_group == "FIRE-OPS"
        assert entries[0].local_group == "FIRE-OPS"

    def test_parse_empty_string(self):
        entries = parse_group_map("", "in")
        assert entries == []

    def test_parse_outbound_wildcard_skipped(self):
        # Outbound wildcard is future Phase 2 — parsed but skipped (no error)
        entries = parse_group_map("White:White, *:all-remote", "out")
        assert len(entries) == 1
        assert entries[0].local_group == "White"

    def test_parse_direction_set_on_entries(self):
        entries = parse_group_map("Blue:Blue", "in")
        assert all(e.direction == "in" for e in entries)
        entries = parse_group_map("Blue:Blue", "out")
        assert all(e.direction == "out" for e in entries)

    def test_parse_peer_id_sentinel(self):
        """parse_group_map sets peer_id to sentinel ''."""
        entries = parse_group_map("White:White", "in")
        assert all(e.peer_id == "" for e in entries)

    def test_parse_missing_colon_raises(self):
        """Missing ':' separator in an entry raises ValueError (format error)."""
        with pytest.raises(ValueError, match="expected 'remote:local' format"):
            parse_group_map("White", "in")

