# tests/test_federation_inbound_server_id.py
#
# Shortcut-1 Option-1A tests.
# Mirror of forks/taky tests/test_federation_inbound_server_id.py; import
# paths updated to ots_federation.*.
#
# Three test groups:
#   1. Config parsing: server_id parsed from [federate:X] stanza.
#   2. Registry: stanza with declared server_id registers policy under both
#      keys (provisional address:port AND declared server_id).
#   3. FederatedChannelServicer: TCP→server_id mapping populated and queried.
#
# All tests are pure unit tests (no gRPC process started).

import configparser
import io
import threading
import unittest
from unittest.mock import MagicMock

from ots_federation.config import FederatePeerConfig, get_federation_config
from ots_federation.groups import FederateGroupRegistry, parse_group_map
from ots_federation.manager import FederationManager
from ots_federation.fed_server import FederatedChannelServicer


# ---------------------------------------------------------------------------
# Helpers shared by all groups
# ---------------------------------------------------------------------------

def _cfg_from_str(ini_text: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_file(io.StringIO(ini_text))
    return cfg


def _base_ini() -> str:
    return (
        "[taky]\nnode_id = test\n"
        "[cot_server]\n"
        "[federation]\nenabled = true\nserver_id = local-server\n"
    )


def _peer_ini(extra: str = "") -> str:
    """Minimal stanza with a peer; extra lines injected after address."""
    return (
        _base_ini()
        + "[federate:taky-peer]\n"
        "address = 10.0.0.2\n"
        "port = 9100\n"
        "display_name = taky-peer\n"
        + extra + "\n"
    )


def _build_registry_from_ini(ini_text: str):
    """Parse INI → FederationConfig → build group registry."""
    cfg = _cfg_from_str(ini_text)
    fed_cfg = get_federation_config(cfg)
    return FederationManager._build_group_registry(fed_cfg)


# ---------------------------------------------------------------------------
# 1. Config parsing
# ---------------------------------------------------------------------------

class TestServerIdParsed(unittest.TestCase):
    """server_id key in [federate:X] is parsed into FederatePeerConfig."""

    def test_server_id_parsed(self):
        """server_id = taky-peer-prod-01 is loaded into peer.server_id."""
        ini = _peer_ini("server_id = taky-peer-prod-01\naccept_as = __ANON__:__ANON__")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(len(fed_cfg.peers), 1)
        self.assertEqual(fed_cfg.peers[0].server_id, "taky-peer-prod-01")

    def test_stanza_without_server_id_defaults_to_empty(self):
        """[federate:X] without server_id → peer.server_id == '' (back-compat)."""
        ini = _peer_ini("accept_as = __ANON__:__ANON__")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].server_id, "")

    def test_server_id_whitespace_stripped(self):
        """server_id value is stripped of surrounding whitespace by configparser."""
        ini = _peer_ini("server_id =   aws-prod-01  \naccept_as = *:White")
        cfg = _cfg_from_str(ini)
        fed_cfg = get_federation_config(cfg)
        self.assertEqual(fed_cfg.peers[0].server_id, "aws-prod-01")


# ---------------------------------------------------------------------------
# 2. Registry — dual-key registration
# ---------------------------------------------------------------------------

class TestRegistryDualKey(unittest.TestCase):
    """
    When server_id is declared, _build_group_registry registers policy under
    both the provisional address:port key AND the declared server_id key.
    """

    def _registry_with_peer(self, server_id_line: str):
        """Build registry from INI that includes a peer stanza."""
        ini = _peer_ini(server_id_line + "\naccept_as = __ANON__:__ANON__\nshare_as = Cyan:__ANON__")
        return _build_registry_from_ini(ini)

    def test_declared_server_id_matches_inbound_policy(self):
        """Peer presenting declared server_id gets per-stanza inbound policy."""
        registry = self._registry_with_peer("server_id = taky-peer-prod-01")
        result = registry.map_inbound("taky-peer-prod-01", "__ANON__")
        self.assertEqual(result, "__ANON__",
                         "Inbound event from declared server_id should get stanza policy")

    def test_declared_server_id_matches_outbound_policy(self):
        """Outbound group policy is also keyed by declared server_id."""
        registry = self._registry_with_peer("server_id = taky-peer-prod-01")
        result = registry.map_outbound("taky-peer-prod-01", "Cyan")
        self.assertEqual(result, "__ANON__",
                         "Outbound Cyan should map to __ANON__ for declared server_id")

    def test_provisional_key_still_works(self):
        """Provisional address:port key still works (outbound rekey path)."""
        registry = self._registry_with_peer("server_id = taky-peer-prod-01")
        result = registry.map_inbound("10.0.0.2:9100", "__ANON__")
        self.assertEqual(result, "__ANON__",
                         "Provisional address:port key should still return stanza policy")

    def test_unmatched_inbound_peer_falls_to_global(self):
        """Peer with a server_id NOT in any stanza falls to global [federation] policy."""
        ini = (
            _base_ini()
            + "accept_as = *:White\n"   # global default
            + "[federate:taky-peer]\n"
            "address = 10.0.0.2\n"
            "port = 9100\n"
            "display_name = taky-peer\n"
            "server_id = taky-peer-prod-01\n"
            "accept_as = __ANON__:__ANON__\n"
        )
        registry = _build_registry_from_ini(ini)
        result = registry.map_inbound("unknown-server", "__ANON__")
        self.assertEqual(result, "White",
                         "Unknown inbound peer should fall to global [federation] policy")

    def test_stanza_without_server_id_unchanged(self):
        """Back-compat: stanza without server_id behaves exactly as before."""
        ini = _peer_ini("accept_as = Cyan:Cyan")
        registry = _build_registry_from_ini(ini)
        result = registry.map_inbound("10.0.0.2:9100", "Cyan")
        self.assertEqual(result, "Cyan",
                         "Provisional key should still work without declared server_id")
        result_no_match = registry.map_inbound("some-server-id", "Cyan")
        self.assertIsNone(result_no_match,
                          "Unmatched server_id with no global default should block")

    def test_fallback_allow_propagated_to_server_id_key(self):
        """fallback_when_no_group_mappings is also registered under declared server_id."""
        ini = _peer_ini(
            "server_id = taky-peer-prod-01\n"
            "accept_as = Red:Red\n"
            "fallback_when_no_group_mappings = true\n"
        )
        registry = _build_registry_from_ini(ini)
        result = registry.map_inbound("taky-peer-prod-01", "Cyan")
        self.assertEqual(result, "Cyan",
                         "fallback_when_no_group_mappings should apply under declared server_id key")


# ---------------------------------------------------------------------------
# 3. FederatedChannelServicer — TCP→server_id mapping
# ---------------------------------------------------------------------------

class TestServicerPeerAddrMapping(unittest.TestCase):
    """
    _register_peer_addr / _resolve_peer_id helpers on FederatedChannelServicer.
    """

    def _make_servicer(self):
        return FederatedChannelServicer(
            server_id="local-server",
            server_name="Local",
            bridge=MagicMock(),
            manager=MagicMock(),
            default_max_hops=3,
            group_registry=None,
        )

    def _mock_context(self, peer_addr: str):
        ctx = MagicMock()
        ctx.peer.return_value = peer_addr
        return ctx

    def test_register_then_resolve_returns_server_id(self):
        """After registering, _resolve_peer_id returns the server_id for that address."""
        svc = self._make_servicer()
        ctx = self._mock_context("ipv4:1.2.3.4:56789")
        svc._register_peer_addr(ctx, "taky-peer-prod-01")
        result = svc._resolve_peer_id(ctx)
        self.assertEqual(result, "taky-peer-prod-01")

    def test_unregistered_address_returns_tcp_addr(self):
        """Without a mapping, _resolve_peer_id falls back to context.peer()."""
        svc = self._make_servicer()
        ctx = self._mock_context("ipv4:9.9.9.9:12345")
        result = svc._resolve_peer_id(ctx)
        self.assertEqual(result, "ipv4:9.9.9.9:12345")

    def test_register_empty_server_id_is_noop(self):
        """Registering an empty server_id does not store anything (back-compat)."""
        svc = self._make_servicer()
        ctx = self._mock_context("ipv4:1.2.3.4:56789")
        svc._register_peer_addr(ctx, "")
        result = svc._resolve_peer_id(ctx)
        self.assertEqual(result, "ipv4:1.2.3.4:56789")

    def test_resolve_with_context_peer_exception_returns_unknown(self):
        """If context.peer() raises, _resolve_peer_id returns 'unknown-peer'."""
        svc = self._make_servicer()
        ctx = MagicMock()
        ctx.peer.side_effect = RuntimeError("no peer")
        result = svc._resolve_peer_id(ctx)
        self.assertEqual(result, "unknown-peer")

    def test_thread_safety_concurrent_register_resolve(self):
        """Concurrent _register_peer_addr / _resolve_peer_id do not deadlock or corrupt."""
        svc = self._make_servicer()
        errors = []

        def worker(addr, sid):
            ctx = self._mock_context(addr)
            try:
                svc._register_peer_addr(ctx, sid)
                svc._resolve_peer_id(ctx)
            except Exception as exc:  # pylint: disable=broad-except
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(f"ipv4:1.2.3.4:{5000+i}", f"server-{i}"))
            for i in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
        self.assertEqual(errors, [], f"Thread errors: {errors}")


if __name__ == "__main__":
    unittest.main()
