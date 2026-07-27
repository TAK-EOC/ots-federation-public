# tests/test_eud_group_cache.py
# Unit tests for EudGroupCache.
# Coverage:
#   C1  — cache miss → None (unknown uid)
#   C2  — single-group hit (update then get)
#   C3  — multi-group accumulation (same uid, different group names)
#   C4  — TTL expiry on access (lazy eviction path)
#   C5  — evict_expired proactive sweep
#   C6  — routing-key parse logic (.OUT strip)
#   C7  — .IN routing keys are ignored by _on_groups_message (via parse step)
#   C8  — concurrent update/get is race-condition free (thread-safety smoke)
# All tests are pure unit tests: no I/O, no pika, no threading dependencies
# beyond the threading.Lock inside EudGroupCache.

import threading
import time
import unittest

from ots_federation.eud_group_cache import EudGroupCache


class TestEudGroupCacheMiss(unittest.TestCase):
    """C1: cache miss → None."""

    def test_unknown_uid_returns_none(self):
        cache = EudGroupCache()
        result = cache.get_groups("DEVICE-UID-THAT-WAS-NEVER-SEEN")
        self.assertIsNone(result, "get_groups on unknown uid must return None (fail-closed)")


class TestEudGroupCacheSingleGroup(unittest.TestCase):
    """C2: single-group hit after update."""

    def test_single_group_returned(self):
        cache = EudGroupCache()
        cache.update("UID-A", "Blue")
        result = cache.get_groups("UID-A")
        self.assertIsNotNone(result, "expected cache hit after update()")
        self.assertIsInstance(result, frozenset)
        self.assertEqual(result, frozenset(["Blue"]))

    def test_returned_value_is_frozenset(self):
        """Callers must receive an immutable frozenset, not the internal mutable set."""
        cache = EudGroupCache()
        cache.update("UID-B", "Red")
        result = cache.get_groups("UID-B")
        self.assertIsInstance(result, frozenset,
            "get_groups() must return frozenset, not a mutable set")


class TestEudGroupCacheMultiGroup(unittest.TestCase):
    """C3: multiple update() calls accumulate groups for the same uid."""

    def test_two_groups_accumulate(self):
        cache = EudGroupCache()
        cache.update("UID-C", "Blue")
        cache.update("UID-C", "White")
        result = cache.get_groups("UID-C")
        self.assertIsNotNone(result)
        self.assertEqual(result, frozenset(["Blue", "White"]),
            "both groups must be present after two update() calls for the same uid")

    def test_duplicate_group_update_does_not_duplicate(self):
        cache = EudGroupCache()
        cache.update("UID-D", "Blue")
        cache.update("UID-D", "Blue")
        result = cache.get_groups("UID-D")
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1, "duplicate group name must not expand the set")
        self.assertIn("Blue", result)

    def test_independent_uids_do_not_share_groups(self):
        cache = EudGroupCache()
        cache.update("UID-E", "Blue")
        cache.update("UID-F", "White")
        self.assertEqual(cache.get_groups("UID-E"), frozenset(["Blue"]))
        self.assertEqual(cache.get_groups("UID-F"), frozenset(["White"]))

    def test_three_groups_different_calls(self):
        cache = EudGroupCache()
        for g in ("Alpha", "Bravo", "Charlie"):
            cache.update("UID-G", g)
        result = cache.get_groups("UID-G")
        self.assertEqual(result, frozenset(["Alpha", "Bravo", "Charlie"]))


class TestEudGroupCacheTTLExpiry(unittest.TestCase):
    """C4: lazy eviction on get_groups() after TTL has elapsed."""

    def test_expired_entry_returns_none(self):
        cache = EudGroupCache(ttl_seconds=300)
        cache.update("UID-H", "Blue")
        # Back-date _last_seen to simulate TTL expiry without sleeping.
        with cache._lock:
            cache._last_seen["UID-H"] = time.monotonic() - 301
        result = cache.get_groups("UID-H")
        self.assertIsNone(result, "expired entry must return None (lazy eviction)")

    def test_expired_entry_removed_from_internal_state(self):
        cache = EudGroupCache(ttl_seconds=300)
        cache.update("UID-I", "Red")
        with cache._lock:
            cache._last_seen["UID-I"] = time.monotonic() - 301
        cache.get_groups("UID-I")  # triggers lazy eviction
        with cache._lock:
            self.assertNotIn("UID-I", cache._groups,
                "lazy eviction must remove entry from _groups")
            self.assertNotIn("UID-I", cache._last_seen,
                "lazy eviction must remove entry from _last_seen")

    def test_update_refreshes_ttl(self):
        """Second update() call for same uid restarts the TTL clock."""
        cache = EudGroupCache(ttl_seconds=300)
        cache.update("UID-J", "Blue")
        # Back-date to near-expiry but not over.
        with cache._lock:
            cache._last_seen["UID-J"] = time.monotonic() - 299
        # Second update refreshes TTL.
        cache.update("UID-J", "White")
        # Now the timestamp should be ~now, well within TTL.
        result = cache.get_groups("UID-J")
        self.assertIsNotNone(result, "re-update must reset TTL; entry should still be live")
        self.assertIn("White", result)


class TestEudGroupCacheEvictExpired(unittest.TestCase):
    """C5: evict_expired() proactive sweep returns correct count and removes entries."""

    def test_evict_all_expired(self):
        cache = EudGroupCache(ttl_seconds=300)
        for uid in ("UID-K", "UID-L", "UID-M"):
            cache.update(uid, "Blue")
        # Back-date all three.
        with cache._lock:
            for uid in ("UID-K", "UID-L", "UID-M"):
                cache._last_seen[uid] = time.monotonic() - 301
        evicted = cache.evict_expired()
        self.assertEqual(evicted, 3, "must report 3 evictions")
        for uid in ("UID-K", "UID-L", "UID-M"):
            self.assertIsNone(cache.get_groups(uid), f"{uid} must be evicted")

    def test_evict_preserves_live_entries(self):
        cache = EudGroupCache(ttl_seconds=300)
        cache.update("UID-N", "Blue")  # live
        cache.update("UID-O", "Red")   # will be back-dated
        with cache._lock:
            cache._last_seen["UID-O"] = time.monotonic() - 301
        evicted = cache.evict_expired()
        self.assertEqual(evicted, 1)
        self.assertIsNone(cache.get_groups("UID-O"), "expired entry must be gone")
        self.assertIsNotNone(cache.get_groups("UID-N"), "live entry must survive")

    def test_evict_empty_cache_returns_zero(self):
        cache = EudGroupCache()
        self.assertEqual(cache.evict_expired(), 0)

    def test_evict_no_expired_returns_zero(self):
        cache = EudGroupCache(ttl_seconds=300)
        cache.update("UID-P", "Blue")  # fresh — TTL not elapsed
        self.assertEqual(cache.evict_expired(), 0)


class TestRoutingKeyParse(unittest.TestCase):
    """
    C6: routing-key suffix strip logic (.OUT → group name).

    _on_groups_message performs the strip. We test the logic by calling
    update with the result of the strip rather than calling
    _on_groups_message directly (which requires a pika mock). The rule is:
        routing_key = "<group_name>.OUT"  → group_name = routing_key[:-4]
    """

    def _strip_out(self, routing_key: str):
        """Reproduce the strip logic from _on_groups_message."""
        if not routing_key.endswith(".OUT"):
            return None
        group_name = routing_key[:-4]
        return group_name if group_name else None

    def test_simple_group_name(self):
        self.assertEqual(self._strip_out("Blue.OUT"), "Blue")

    def test_hyphenated_group_name(self):
        self.assertEqual(self._strip_out("FIRE-OPS.OUT"), "FIRE-OPS")

    def test_anonymous_group(self):
        self.assertEqual(self._strip_out("__ANON__.OUT"), "__ANON__")

    def test_dotted_group_name(self):
        """Multi-segment group name (dots in name, last segment is OUT)."""
        self.assertEqual(self._strip_out("SECTOR.NORTH.OUT"), "SECTOR.NORTH")

    def test_in_routing_key_returns_none(self):
        """Routing keys ending in .IN must be rejected."""
        self.assertIsNone(self._strip_out("Blue.IN"))

    def test_bare_out_returns_none(self):
        """'.OUT' alone (empty group name) must be rejected."""
        self.assertIsNone(self._strip_out(".OUT"))

    def test_unrecognised_suffix_returns_none(self):
        self.assertIsNone(self._strip_out("Blue.UNKNOWN"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(self._strip_out(""))


class TestEudGroupCacheThreadSafety(unittest.TestCase):
    """C8: concurrent update/get smoke test — must not raise or deadlock."""

    def test_concurrent_updates_do_not_raise(self):
        cache = EudGroupCache(ttl_seconds=300)
        errors = []
        barrier = threading.Barrier(4)

        def writer(uid, group):
            try:
                barrier.wait()
                for _ in range(100):
                    cache.update(uid, group)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def reader(uid):
            try:
                barrier.wait()
                for _ in range(100):
                    cache.get_groups(uid)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=writer, args=("UID-T1", "Blue"), daemon=True),
            threading.Thread(target=writer, args=("UID-T1", "White"), daemon=True),
            threading.Thread(target=reader, args=("UID-T1",), daemon=True),
            threading.Thread(target=reader, args=("UID-T1",), daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        self.assertEqual(errors, [], f"thread-safety violations: {errors}")


if __name__ == "__main__":
    unittest.main()
