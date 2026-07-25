# ots_federation/eud_group_cache.py
# Thread-safe in-process cache: EUD uid → frozenset of OTS ACL IN group names.
# Populated passively by the groups-exchange subscriber (:
# OtsRmqBus._groups_subscribe_loop). Consumed by the firehose consumer (:
# OtsRmqBus._on_firehose_message).
# TTL is per uid entry, not per group-within-entry. Any update call for the
# uid refreshes the whole entry's TTL clock. Stale entries are evicted lazily
# on get_groups and proactively by evict_expired.
# Design notes:
#   - Cache miss → fail-closed (caller blocks the event; do NOT forward).
#   - Cold-start window: one SA broadcast cycle per EUD (~5 s for ATAK default)
#     after plugin restart. Accepted for Phase 1; Phase 2 adds DB bootstrap.
#   - Multi-group: a single uid may belong to multiple IN groups. Each update
#     call adds one group name to the uid's set; the set accumulates across calls.
#   - TTL default 300 s.

import threading
import time
from typing import Dict, FrozenSet, Optional, Set


class EudGroupCache:
    """
    Thread-safe mapping: EUD uid → frozenset of OTS ACL IN group names.

    Populated by the groups exchange subscriber thread.
    Read by the firehose consumer thread.

    TTL is per uid entry (not per group-within-entry). Any update for a uid
    refreshes the entry's TTL clock. The entry is evicted lazily on the first
    get_groups call after TTL expiry, or proactively by evict_expired.

    Parameters
    ----------
    ttl_seconds : int
        Entry lifetime in seconds after the last update for the uid.
        Default 300 (5 minutes).-D-forks-resolved.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._groups: Dict[str, Set[str]] = {}       # uid → mutable group set
        self._last_seen: Dict[str, float] = {}        # uid → monotonic timestamp
        self._ttl: int = ttl_seconds
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write path — called from the groups exchange subscriber thread
    # ------------------------------------------------------------------

    def update(self, uid: str, group_name: str) -> None:
        """
        Add *group_name* to uid's ACL group set and refresh the TTL clock.

        Thread-safe. Multiple groups accumulate in the set across calls. TTL
        is refreshed on every call for the same uid (not per-group).

        Parameters
        ----------
        uid : str
            EUD UID from the groups-exchange message body (``{"uid": ...}``).
        group_name : str
            OTS ACL IN group name derived from the routing key (``"X.OUT"``
            with ``".OUT"`` stripped → ``"X"``).
        """
        with self._lock:
            self._groups.setdefault(uid, set()).add(group_name)
            self._last_seen[uid] = time.monotonic()

    def set_groups(self, uid: str, group_names) -> None:
        """
        Replace uid's ACL group set wholesale and refresh the TTL clock.

        Used by the synchronous DB resolver: a single authoritative
        read yields the full group set, so we set it atomically rather than
        accumulating one .OUT routing key at a time. Thread-safe.
        """
        with self._lock:
            self._groups[uid] = set(group_names)
            self._last_seen[uid] = time.monotonic()

    # ------------------------------------------------------------------
    # Read path — called from the firehose consumer thread
    # ------------------------------------------------------------------

    def get_groups(self, uid: str) -> Optional[FrozenSet[str]]:
        """
        Return the cached ACL group set for *uid*, or None on miss / TTL expiry.

        None is the fail-closed sentinel: the caller must block the event rather
        than forwarding it with unknown / stale group membership.

        Expired entries are evicted lazily on the first access after TTL
        expiry (no separate timer thread required).

        Parameters
        ----------
        uid : str

        Returns
        -------
        frozenset[str] | None
            Frozenset of ACL group name strings, or None on cache miss.
        """
        with self._lock:
            if uid not in self._groups:
                return None
            if time.monotonic() - self._last_seen[uid] > self._ttl:
                # Lazy eviction: entry has expired.
                del self._groups[uid]
                del self._last_seen[uid]
                return None
            return frozenset(self._groups[uid])

    # ------------------------------------------------------------------
    # Maintenance — periodic housekeeping
    # ------------------------------------------------------------------

    def evict_expired(self) -> int:
        """
        Proactively evict all entries whose TTL has elapsed.

        Call this periodically (e.g., every ``ttl_seconds``) to prevent
        unbounded cache growth when EUDs churn without transmitting (so
        their entries never reach the lazy eviction path).

        Returns
        -------
        int
            Number of entries evicted.
        """
        now = time.monotonic()
        with self._lock:
            expired = [
                uid for uid, ts in self._last_seen.items()
                if now - ts > self._ttl
            ]
            for uid in expired:
                del self._groups[uid]
                del self._last_seen[uid]
        return len(expired)
