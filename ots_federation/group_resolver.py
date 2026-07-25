# ots_federation/group_resolver.py
# Synchronous ACL-group resolution from OTS's authoritative store.
#
# Mirrors TAK Server's in-process GroupManager.getGroups(user): given a CoT event
# uid, resolve the sending EUD's OUT ACL groups directly from the OTS DB, so the
# federation outbound path never races the async groups exchange.
#
# This is the SAME query OTS cot_parser uses to populate the groups exchange
# (opentakserver/cot_parser/cot_parser.py:975) — same authoritative source,
# resolved synchronously instead of over an independent async channel.
#
# Security: parameterized query only (PY-7). Read path only — never writes.

import logging
from typing import Optional, FrozenSet

log = logging.getLogger(__name__)

# uid -> OUT ACL group names. euds.uid is unique-indexed, so this is one indexed
# lookup. direction='OUT' + enabled filter matches OTS's own outbound routing.
_QUERY = (
    "SELECT g.name "
    "FROM euds e "
    "JOIN groups_users gu "
    "  ON gu.user_id = e.user_id AND gu.direction = 'OUT' AND gu.enabled = true "
    "JOIN groups g ON g.id = gu.group_id "
    "WHERE e.uid = %s"
)


class GroupResolveError(Exception):
    """Raised when the DB is unavailable — caller MUST fail closed (drop)."""


class GroupResolver:
    """
    Synchronous OTS-DB group resolver, keyed by event uid.

    Holds one lazily-opened psycopg connection (autocommit, read path). On a
    connection error it drops the handle and retries once on the next call, so a
    transient DB blip self-heals rather than wedging the engine.

    resolve(uid) contract:
      - returns frozenset[str] (possibly EMPTY) on a successful query — EMPTY
        means the EUD genuinely has no OUT groups (caller fail-closes).
      - raises GroupResolveError if the DB cannot be reached — caller fail-closes
        but logs it distinctly from a genuine no-group result.

    A None dburi yields a resolver that always raises GroupResolveError (used when
    the engine runs without DB access, e.g. standalone taky mode / tests). This
    preserves prior fail-closed behavior on cache miss rather than crashing.
    """

    def __init__(self, dburi: Optional[str]):
        self._dburi = dburi
        self._conn = None

    def _connect(self):
        if self._dburi is None:
            raise GroupResolveError("no SQLALCHEMY_DATABASE_URI provided to engine")
        import psycopg  # deferred: only needed when DB resolution is active
        # SQLAlchemy-style URI (postgresql+psycopg://...) -> libpq DSN psycopg wants.
        dsn = self._dburi.replace("postgresql+psycopg://", "postgresql://", 1)
        self._conn = psycopg.connect(dsn, autocommit=True, connect_timeout=5)

    def resolve(self, uid: str) -> FrozenSet[str]:
        """Return the EUD's OUT ACL groups. Raises GroupResolveError on DB failure."""
        for attempt in (1, 2):  # one reconnect retry on a dropped connection
            try:
                if self._conn is None or self._conn.closed:
                    self._connect()
                with self._conn.cursor() as cur:
                    cur.execute(_QUERY, (uid,))
                    rows = cur.fetchall()
                return frozenset(r[0] for r in rows)
            except GroupResolveError:
                raise
            except Exception as exc:  # noqa: BLE001 — any driver/conn error -> fail closed
                log.warning(
                    "group_resolver: DB lookup for uid=%s failed (attempt %d): %s",
                    uid, attempt, exc,
                )
                try:
                    if self._conn is not None:
                        self._conn.close()
                finally:
                    self._conn = None
                if attempt == 2:
                    raise GroupResolveError(str(exc)) from exc
        raise GroupResolveError("unreachable")  # pragma: no cover

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None
