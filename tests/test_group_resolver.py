# Tests for synchronous group resolution as a cache-miss fallback.
import json
import unittest
from unittest.mock import MagicMock

from ots_federation.ots_bus import OtsRmqBus
from ots_federation.eud_group_cache import EudGroupCache
from ots_federation.group_resolver import GroupResolver, GroupResolveError


def _make_bus(cache=None, resolver=None):
    lf = MagicMock()
    lf.should_relay_outbound.return_value = True
    lf.clean_for_relay.side_effect = lambda xml: xml
    return OtsRmqBus(
        host="localhost", port=5672, user="guest", password="guest",
        loop_filter=lf, eud_group_cache=cache or EudGroupCache(),
        group_resolver=resolver,
    )


def _cot(uid):
    return (
        f'<event version="2.0" uid="{uid}" type="a-f-G-U-C" '
        f'time="2026-07-10T00:00:00.000Z" start="2026-07-10T00:00:00.000Z" '
        f'stale="2026-07-10T00:05:00.000Z">'
        f'<point lat="1" lon="2" hae="0" ce="9" le="9"/><detail/></event>'
    )


def _body(uid):
    return json.dumps({"uid": uid, "cot": _cot(uid)}).encode()


def _fire(bus, manager, uid):
    bus._on_firehose_message(manager, MagicMock(), MagicMock(), MagicMock(), _body(uid))


class TestSyncResolution(unittest.TestCase):
    def test_cache_miss_resolves_from_db_then_relays(self):
        resolver = MagicMock()
        resolver.resolve.return_value = frozenset({"Green"})
        cache = EudGroupCache()
        bus = _make_bus(cache=cache, resolver=resolver)
        manager = MagicMock()
        _fire(bus, manager, "EUD-DB")
        resolver.resolve.assert_called_once_with("EUD-DB")
        manager.on_outbound.assert_called_once()          # relayed, not dropped
        self.assertEqual(cache.get_groups("EUD-DB"), frozenset({"Green"}))  # cached

    def test_db_empty_result_fails_closed(self):
        resolver = MagicMock()
        resolver.resolve.return_value = frozenset()        # genuinely no groups
        bus = _make_bus(resolver=resolver)
        manager = MagicMock()
        _fire(bus, manager, "EUD-NOGRP")
        manager.on_outbound.assert_not_called()            # fail-closed

    def test_db_error_fails_closed(self):
        resolver = MagicMock()
        resolver.resolve.side_effect = GroupResolveError("db down")
        bus = _make_bus(resolver=resolver)
        manager = MagicMock()
        _fire(bus, manager, "EUD-DBERR")
        manager.on_outbound.assert_not_called()            # fail-closed on DB error

    def test_no_resolver_stays_fail_closed(self):
        # Backward-compat: without a resolver, a cache miss still blocks.
        bus = _make_bus(resolver=None)
        manager = MagicMock()
        _fire(bus, manager, "EUD-NORES")
        manager.on_outbound.assert_not_called()

    def test_cache_hit_skips_resolver(self):
        resolver = MagicMock()
        cache = EudGroupCache()
        cache.set_groups("EUD-HOT", {"Blue"})
        bus = _make_bus(cache=cache, resolver=resolver)
        manager = MagicMock()
        _fire(bus, manager, "EUD-HOT")
        resolver.resolve.assert_not_called()               # cache is the fast path
        manager.on_outbound.assert_called_once()


class TestGroupResolverUnit(unittest.TestCase):
    def test_none_dburi_raises(self):
        with self.assertRaises(GroupResolveError):
            GroupResolver(None).resolve("X")

    def test_set_groups_atomic(self):
        c = EudGroupCache()
        c.set_groups("U", {"A", "B"})
        self.assertEqual(c.get_groups("U"), frozenset({"A", "B"}))
        c.set_groups("U", {"C"})                            # wholesale replace
        self.assertEqual(c.get_groups("U"), frozenset({"C"}))


if __name__ == "__main__":
    unittest.main()
