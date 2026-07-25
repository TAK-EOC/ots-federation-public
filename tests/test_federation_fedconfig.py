# tests/test_federation_fedconfig.py
# Adapted from taky test_federation_fedconfig.py (taky-federation branch).
# Import paths updated from taky.cot.* → ots_federation.*
# Tests for — accept_as / share_as friendly key aliases.
# Four behaviours under test:
#   1. accept_as in [federation] drives inbound group filtering (flags inbound data
#      as the configured local group).
#   2. share_as in [federation] drives outbound group tagging (tags outbound events
#      with the configured remote group name).
#   3. Unlisted local groups are blocked outbound (not in share_as → not shared).
#   4. Old keys (default_group_map_in / default_group_map_out / group_map_in /
#      group_map_out) still work as aliases; new key wins when both are present.
# All tests use get_federation_config to parse an INI string, then verify the
# resolved FederationConfig fields or downstream registry behaviour.

import configparser
import io
import logging
import unittest

from ots_federation.config import get_federation_config
from ots_federation.groups import (
    FederateGroupRegistry,
    parse_group_map,
)
from ots_federation.models.teams import Teams


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg_from_str(ini_text: str) -> configparser.ConfigParser:
    """Parse an INI string into a ConfigParser (same way taky.config does it)."""
    cfg = configparser.ConfigParser()
    cfg.read_file(io.StringIO(ini_text))
    return cfg


def _minimal_federation_ini(extra_keys: str = "") -> str:
    """Minimal valid [federation] section with optional extra key lines."""
    return (
        "[taky]\n"
        "node_id = test\n"
        "[cot_server]\n"
        "[federation]\n"
        "enabled = true\n"
        "server_id = taky-test\n"
        f"{extra_keys}\n"
    )


def _peer_ini(peer_keys: str = "") -> str:
    """Minimal valid [federation] + [federate:peer] section."""
    return (
        _minimal_federation_ini()
        + "[federate:peer]\n"
        "address = 10.0.0.1\n"
        "display_name = test-peer\n"
        f"{peer_keys}\n"
    )


# ---------------------------------------------------------------------------
# 1. accept_as in [federation] drives inbound group filtering
# ---------------------------------------------------------------------------

class TestAcceptAsGlobalInbound(unittest.TestCase):
    """
    [federation] accept_as flags inbound data from unmapped peers to the
    right local group.
    """

    def _registry_from_ini(self, ini_text: str) -> FederateGroupRegistry:
        """Parse INI → FederationConfig → build a registry via parse_group_map."""
        cfg = _cfg_from_str(ini_text)
        fed_cfg = get_federation_config(cfg)
        # Simulate what FederationManager._build_group_registry does for the default.
        reg = FederateGroupRegistry()
        if fed_cfg.default_group_map_in:
            entries = parse_group_map(fed_cfg.default_group_map_in, "in")
            reg.set_default_in_map(entries)
        return reg

    def test_accept_as_star_cyan_flags_any_inbound_as_cyan(self):
        """accept_as = *:Cyan routes any remote group to local 'Cyan' string."""
        ini = _minimal_federation_ini("accept_as = *:Cyan")
        reg = self._registry_from_ini(ini)

        # Phase-1: map_inbound returns str, not Teams enum.
        result = reg.map_inbound("some-peer-id", "White")
        self.assertEqual(result, "Cyan")
        result = reg.map_inbound("some-peer-id", "SIGINT")
        self.assertEqual(result, "Cyan")

    def test_accept_as_explicit_mapping_flags_inbound_correctly(self):
        """accept_as = White:White, Blue:Blue routes each remote group to its local equivalent."""
        ini = _minimal_federation_ini("accept_as = White:White, Blue:Blue, *:")
        reg = self._registry_from_ini(ini)

        # Phase-1: results are strings, not Teams enum members.
        self.assertEqual(reg.map_inbound("peer-x", "White"), "White")
        self.assertEqual(reg.map_inbound("peer-x", "Blue"), "Blue")
        # Wildcard block: SIGINT not in map → blocked
        self.assertIsNone(reg.map_inbound("peer-x", "SIGINT"))

    def test_accept_as_empty_blocks_all_inbound(self):
        """accept_as = (empty) blocks all inbound from unmapped peers."""
        ini = _minimal_federation_ini("accept_as =")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        # Empty string → default_group_map_in is "" → no default set in registry
        # → conservative block.
        reg = FederateGroupRegistry()
        if fed_cfg.default_group_map_in:
            entries = parse_group_map(fed_cfg.default_group_map_in, "in")
            reg.set_default_in_map(entries)
        self.assertIsNone(reg.map_inbound("any-peer", "White"))

    def test_accept_as_loaded_into_default_group_map_in(self):
        """get_federation_config sets default_group_map_in from accept_as."""
        ini = _minimal_federation_ini("accept_as = *:White")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.default_group_map_in, "*:White")


# ---------------------------------------------------------------------------
# 2. share_as in [federation] drives outbound group tagging
# ---------------------------------------------------------------------------

class TestShareAsGlobalOutbound(unittest.TestCase):
    """
    [federation] share_as tags outbound events with the right remote group name.
    """

    def _registry_from_ini(self, ini_text: str) -> FederateGroupRegistry:
        cfg = _cfg_from_str(ini_text)
        fed_cfg = get_federation_config(cfg)
        reg = FederateGroupRegistry()
        if fed_cfg.default_group_map_out:
            entries = parse_group_map(fed_cfg.default_group_map_out, "out")
            reg.set_default_out_map(entries)
        return reg

    def test_share_as_cyan_cyan_tags_outbound_as_cyan(self):
        """share_as = Cyan:Cyan tags outbound 'Cyan' events as 'Cyan' to peers."""
        ini = _minimal_federation_ini("share_as = Cyan:Cyan")
        reg = self._registry_from_ini(ini)

        # Phase-1: map_outbound takes a str, not a Teams enum.
        result = reg.map_outbound("any-peer", "Cyan")
        self.assertEqual(result, "Cyan")

    def test_share_as_maps_local_to_custom_remote_name(self):
        """share_as = White:OpsGrp tags outbound 'White' events as 'OpsGrp'."""
        ini = _minimal_federation_ini("share_as = White:OpsGrp")
        reg = self._registry_from_ini(ini)

        result = reg.map_outbound("any-peer", "White")
        self.assertEqual(result, "OpsGrp")

    def test_share_as_loaded_into_default_group_map_out(self):
        """get_federation_config sets default_group_map_out from share_as."""
        ini = _minimal_federation_ini("share_as = White:White, Blue:Blue")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.default_group_map_out, "White:White, Blue:Blue")


# ---------------------------------------------------------------------------
# 3. Unlisted local groups are blocked outbound
# ---------------------------------------------------------------------------

class TestUnlistedGroupsBlockedOutbound(unittest.TestCase):
    """
    Local groups NOT in share_as are silently blocked — not forwarded outbound.
    """

    def _registry_from_ini(self, ini_text: str) -> FederateGroupRegistry:
        cfg = _cfg_from_str(ini_text)
        fed_cfg = get_federation_config(cfg)
        reg = FederateGroupRegistry()
        if fed_cfg.default_group_map_out:
            entries = parse_group_map(fed_cfg.default_group_map_out, "out")
            reg.set_default_out_map(entries)
        return reg

    def test_unlisted_local_group_is_not_shared(self):
        """'Blue' is not in share_as → map_outbound returns None for 'Blue'."""
        ini = _minimal_federation_ini("share_as = White:White")
        reg = self._registry_from_ini(ini)

        # Phase-1: map_outbound takes a str, not a Teams enum.
        self.assertEqual(reg.map_outbound("peer", "White"), "White")
        self.assertIsNone(reg.map_outbound("peer", "Blue"))

    def test_no_share_as_blocks_all_outbound(self):
        """Without share_as (or empty), no local groups are shared outbound."""
        ini = _minimal_federation_ini()  # no share_as or share_as absent
        reg = self._registry_from_ini(ini)

        for color in ("White", "Blue", "Cyan", "Green"):
            self.assertIsNone(reg.map_outbound("peer", color),
                              f"'{color}' should be blocked with no share_as")

    def test_multiple_groups_partial_match(self):
        """Only groups explicitly in share_as are forwarded; others are blocked."""
        ini = _minimal_federation_ini("share_as = White:White, Cyan:Cyan")
        reg = self._registry_from_ini(ini)

        self.assertEqual(reg.map_outbound("peer", "White"), "White")
        self.assertEqual(reg.map_outbound("peer", "Cyan"), "Cyan")
        self.assertIsNone(reg.map_outbound("peer", "Blue"))
        self.assertIsNone(reg.map_outbound("peer", "Green"))


# ---------------------------------------------------------------------------
# 4a. Old global keys (default_group_map_in / default_group_map_out) still work
# ---------------------------------------------------------------------------

class TestLegacyGlobalKeyAliases(unittest.TestCase):
    """
    default_group_map_in / default_group_map_out still work as aliases.
    """

    def test_default_group_map_in_still_parsed(self):
        """Old key default_group_map_in works identically to accept_as."""
        ini = _minimal_federation_ini("default_group_map_in = *:Cyan")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.default_group_map_in, "*:Cyan")

    def test_default_group_map_out_still_parsed(self):
        """Old key default_group_map_out works identically to share_as."""
        ini = _minimal_federation_ini("default_group_map_out = White:White")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.default_group_map_out, "White:White")

    def test_new_key_wins_over_old_global_key(self):
        """When both accept_as and default_group_map_in are set, accept_as wins."""
        ini = _minimal_federation_ini(
            "accept_as = *:Cyan\ndefault_group_map_in = *:White"
        )
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.default_group_map_in, "*:Cyan",
                         "accept_as must win over default_group_map_in")

    def test_new_share_key_wins_over_old_global_key(self):
        """When both share_as and default_group_map_out are set, share_as wins."""
        ini = _minimal_federation_ini(
            "share_as = Cyan:Cyan\ndefault_group_map_out = White:White"
        )
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.default_group_map_out, "Cyan:Cyan",
                         "share_as must win over default_group_map_out")

    def test_both_keys_present_warns(self):
        """When both old and new keys are present, a warning is logged."""
        ini = _minimal_federation_ini(
            "accept_as = *:Cyan\ndefault_group_map_in = *:White"
        )
        cfg = _cfg_from_str(ini)
        with self.assertLogs("ots_federation.config", level="WARNING") as cm:
            get_federation_config(cfg)
        self.assertTrue(
            any("accept_as" in line and "default_group_map_in" in line for line in cm.output),
            f"Expected warning mentioning both keys; got: {cm.output}",
        )


# ---------------------------------------------------------------------------
# 4b. Old per-peer keys (group_map_in / group_map_out) still work as aliases
# ---------------------------------------------------------------------------

class TestLegacyPeerKeyAliases(unittest.TestCase):
    """
    group_map_in / group_map_out still work in [federate:<name>] as aliases.
    """

    def test_group_map_in_still_parsed_in_peer_section(self):
        """group_map_in in [federate:peer] still populates peer.group_map_in."""
        ini = _peer_ini("group_map_in = White:White, Blue:Blue")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(len(fed_cfg.peers), 1)
        self.assertEqual(fed_cfg.peers[0].group_map_in, "White:White, Blue:Blue")

    def test_group_map_out_still_parsed_in_peer_section(self):
        """group_map_out in [federate:peer] still populates peer.group_map_out."""
        ini = _peer_ini("group_map_out = White:White")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(len(fed_cfg.peers), 1)
        self.assertEqual(fed_cfg.peers[0].group_map_out, "White:White")

    def test_accept_as_in_peer_section_wins_over_group_map_in(self):
        """accept_as in [federate:peer] wins over group_map_in when both present."""
        ini = _peer_ini("accept_as = *:Cyan\ngroup_map_in = White:White")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].group_map_in, "*:Cyan",
                         "accept_as must override group_map_in in peer section")

    def test_share_as_in_peer_section_wins_over_group_map_out(self):
        """share_as in [federate:peer] wins over group_map_out when both present."""
        ini = _peer_ini("share_as = Cyan:Cyan\ngroup_map_out = White:White")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].group_map_out, "Cyan:Cyan",
                         "share_as must override group_map_out in peer section")

    def test_accept_as_only_in_peer_section(self):
        """accept_as alone (no group_map_in) populates peer.group_map_in."""
        ini = _peer_ini("accept_as = Blue:Blue, *:")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].group_map_in, "Blue:Blue, *:")

    def test_share_as_only_in_peer_section(self):
        """share_as alone (no group_map_out) populates peer.group_map_out."""
        ini = _peer_ini("share_as = White:OpsGrp-Alpha")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].group_map_out, "White:OpsGrp-Alpha")

    def test_peer_alias_conflict_warns(self):
        """When both accept_as and group_map_in appear in peer section, a warning is logged."""
        ini = _peer_ini("accept_as = *:Cyan\ngroup_map_in = White:White")
        cfg = _cfg_from_str(ini)
        with self.assertLogs("ots_federation.config", level="WARNING") as cm:
            get_federation_config(cfg)
        self.assertTrue(
            any("accept_as" in line and "group_map_in" in line for line in cm.output),
            f"Expected warning mentioning both keys; got: {cm.output}",
        )


if __name__ == "__main__":
    unittest.main()

