# tests/test_config_parity.py
# Tests for CoreConfig federation parity knobs

import configparser
import io
import unittest

from ots_federation.config import ConfigError, get_federation_config


def _cfg_from_str(ini_text: str) -> configparser.ConfigParser:
    """Parse an INI string into a ConfigParser."""
    cfg = configparser.ConfigParser()
    cfg.read_file(io.StringIO(ini_text))
    return cfg


def _minimal_federation_ini(extra_global_keys: str = "") -> str:
    """Minimal valid [federation] section."""
    lines = [
        "[taky]",
        "node_id = test",
        "[cot_server]",
        "[federation]",
        "enabled = true",
        "server_id = taky-test",
    ]
    if extra_global_keys:
        lines.append(extra_global_keys)
    return "\n".join(lines) + "\n"


def _peer_section(peer_name: str, address: str, display_name: str, extra_keys: str = "") -> str:
    """Create a [federate:<name>] section."""
    lines = [
        f"[federate:{peer_name}]",
        f"address = {address}",
        f"display_name = {display_name}",
    ]
    if extra_keys:
        lines.append(extra_keys)
    return "\n".join(lines) + "\n"


# ============================================================================
# Global [federation] Section Tests
# ============================================================================

class TestGlobalFederationKnobs(unittest.TestCase):
    """Test all 10 new global [federation] section knobs."""

    def test_allow_federated_delete_default_true(self):
        """allow_federated_delete defaults to True."""
        ini = _minimal_federation_ini()
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertTrue(fed_cfg.allow_federated_delete)

    def test_allow_federated_delete_set_false(self):
        """allow_federated_delete can be set to False."""
        ini = _minimal_federation_ini("allow_federated_delete = false")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertFalse(fed_cfg.allow_federated_delete)

    def test_allow_mission_federation_default_true(self):
        """allow_mission_federation defaults to True."""
        ini = _minimal_federation_ini()
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertTrue(fed_cfg.allow_mission_federation)

    def test_allow_mission_federation_set_false(self):
        """allow_mission_federation can be set to False."""
        ini = _minimal_federation_ini("allow_mission_federation = false")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertFalse(fed_cfg.allow_mission_federation)

    def test_initialization_delay_secs_default_30(self):
        """initialization_delay_secs defaults to 30."""
        ini = _minimal_federation_ini()
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.initialization_delay_secs, 30)

    def test_initialization_delay_secs_custom(self):
        """initialization_delay_secs can be customized."""
        ini = _minimal_federation_ini("initialization_delay_secs = 60")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.initialization_delay_secs, 60)

    def test_max_message_size_bytes_default(self):
        """max_message_size_bytes defaults to 268435456 (256 MB)."""
        ini = _minimal_federation_ini()
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.max_message_size_bytes, 268435456)

    def test_max_message_size_bytes_custom(self):
        """max_message_size_bytes can be customized."""
        ini = _minimal_federation_ini("max_message_size_bytes = 536870912")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.max_message_size_bytes, 536870912)


# ============================================================================
# Per-Peer [federate:<name>] Section Tests
# ============================================================================

class TestPeerFederationKnobs(unittest.TestCase):
    """Test all 21 new per-peer [federate:<name>] section knobs."""

    def test_display_name_required_missing_raises_error(self):
        """display_name is MUST — ConfigError if missing."""
        ini = (
            "[taky]\nnode_id = test\n[cot_server]\n"
            "[federation]\nenabled = true\nserver_id = taky-test\n"
            "[federate:peer]\naddress = 10.0.0.1\n"
        )
        cfg = _cfg_from_str(ini)
        with self.assertRaises(ConfigError) as ctx:
            get_federation_config(cfg)
        self.assertIn("display_name", str(ctx.exception))

    def test_display_name_present(self):
        """display_name is parsed correctly."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].display_name, "test-peer")

    def test_protocol_version_default_2(self):
        """protocol_version defaults to 2."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].protocol_version, 2)

    def test_protocol_version_custom(self):
        """protocol_version can be set."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "protocol_version = 3")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].protocol_version, 3)

    def test_filter_none_by_default(self):
        """filter defaults to None."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertIsNone(fed_cfg.peers[0].filter)

    def test_filter_custom(self):
        """filter can be set to an XPath/CoT expression."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "filter = //event[@type='a-f-type']")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].filter, "//event[@type='a-f-type']")

    def test_max_retries_default_minus_one(self):
        """max_retries defaults to -1 (unlimited)."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].max_retries, -1)

    def test_max_retries_custom(self):
        """max_retries can be set."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "max_retries = 5")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].max_retries, 5)

    def test_unlimited_retries_default_true(self):
        """unlimited_retries defaults to True."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertTrue(fed_cfg.peers[0].unlimited_retries)

    def test_fallback_none_by_default(self):
        """fallback defaults to None."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertIsNone(fed_cfg.peers[0].fallback)

    def test_fallback_custom(self):
        """fallback can be set to a secondary address."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "fallback = 10.0.0.2")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].fallback, "10.0.0.2")

    def test_use_token_default_false(self):
        """use_token defaults to False."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertFalse(fed_cfg.peers[0].use_token)

    def test_connection_token_none_when_absent(self):
        """connection_token returns None if absent (never a default string)."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertIsNone(fed_cfg.peers[0].connection_token)

    def test_connection_token_present(self):
        """connection_token is parsed when present."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "connection_token = secret-abc")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].connection_token, "secret-abc")

    def test_share_alerts_default_true(self):
        """share_alerts defaults to True."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertTrue(fed_cfg.peers[0].share_alerts)

    def test_share_alerts_false(self):
        """share_alerts can be set to False."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "share_alerts = false")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertFalse(fed_cfg.peers[0].share_alerts)

    def test_archive_default_true(self):
        """archive defaults to True."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertTrue(fed_cfg.peers[0].archive)

    def test_archive_false(self):
        """archive can be set to False."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "archive = false")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertFalse(fed_cfg.peers[0].archive)

    def test_mission_federate_default_default_true(self):
        """mission_federate_default defaults to True."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertTrue(fed_cfg.peers[0].mission_federate_default)

    def test_mission_federate_default_false(self):
        """mission_federate_default can be set to False."""
        ini = _minimal_federation_ini() + _peer_section("peer", "10.0.0.1", "test-peer", "mission_federate_default = false")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertFalse(fed_cfg.peers[0].mission_federate_default)


if __name__ == "__main__":
    unittest.main()
