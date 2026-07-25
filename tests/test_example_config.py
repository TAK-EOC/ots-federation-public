# tests/test_example_config.py
# Guard: load the shipped examples/federation.ini through the real parse path
# (get_federation_config) and assert it is valid and yields the two documented
# example peers.  Any doc drift that introduces invented keys or removes
# required fields will fail CI here.
# Added in — packaging polish / doc defect fix.

import configparser
import os
import unittest

from ots_federation.config import get_federation_config

# Path to the shipped example file, resolved relative to this test file so
# that the test works whether run from the repo root or via pytest --rootdir.
_EXAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ots_federation",
    "examples",
)
_EXAMPLE_INI = os.path.join(_EXAMPLES_DIR, "federation.ini")


def _load_example_cfg() -> configparser.ConfigParser:
    """Load examples/federation.ini via configparser (same path as production)."""
    cfg = configparser.ConfigParser()
    read_files = cfg.read(_EXAMPLE_INI)
    if not read_files:
        raise FileNotFoundError(f"Example INI not found at {_EXAMPLE_INI}")
    return cfg


class TestExampleFederationIni(unittest.TestCase):
    """Verify the shipped example config parses without error."""

    def setUp(self):
        self.cfg = _load_example_cfg()

    def test_parses_without_error(self):
        """examples/federation.ini must parse through get_federation_config()."""
        fed_cfg = get_federation_config(self.cfg)
        self.assertTrue(fed_cfg.enabled, "expected enabled=true in example config")

    def test_yields_exactly_two_peers(self):
        """Example must document exactly two [federate:*] peers."""
        fed_cfg = get_federation_config(self.cfg)
        self.assertEqual(
            len(fed_cfg.peers),
            2,
            f"expected 2 peers, got {len(fed_cfg.peers)}: {[p.name for p in fed_cfg.peers]}",
        )

    def test_peer_names(self):
        """Both expected peer names must be present."""
        fed_cfg = get_federation_config(self.cfg)
        peer_names = {p.name for p in fed_cfg.peers}
        self.assertIn("tak-server-east", peer_names)
        self.assertIn("taky-peer-minimal", peer_names)

    def test_full_peer_has_display_name(self):
        """Full example peer must have a non-empty display_name."""
        fed_cfg = get_federation_config(self.cfg)
        full_peer = next(p for p in fed_cfg.peers if p.name == "tak-server-east")
        self.assertTrue(full_peer.display_name, "display_name must not be empty")

    def test_minimal_peer_has_required_fields(self):
        """Minimal example peer must have address and display_name."""
        fed_cfg = get_federation_config(self.cfg)
        minimal_peer = next(p for p in fed_cfg.peers if p.name == "taky-peer-minimal")
        self.assertTrue(minimal_peer.address)
        self.assertTrue(minimal_peer.display_name)

    def test_ssl_section_parsed(self):
        """[federation_ssl] must supply non-empty fed_ca_bundle, fed_cert, fed_key."""
        fed_cfg = get_federation_config(self.cfg)
        self.assertTrue(fed_cfg.ssl.fed_ca_bundle)
        self.assertTrue(fed_cfg.ssl.fed_cert)
        self.assertTrue(fed_cfg.ssl.fed_key)

    def test_server_id_present(self):
        """[federation] server_id must be non-empty."""
        fed_cfg = get_federation_config(self.cfg)
        self.assertTrue(fed_cfg.server_id)
