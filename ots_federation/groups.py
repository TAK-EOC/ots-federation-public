# taky/cot/federation/groups.py
# Stream: groups
# Phase-1 string migration: group types are now
# arbitrary strings throughout. ATAK color names ("White", "Blue", etc.) are
# still accepted as valid string values for backward-compat with existing configs.
# The Teams enum is no longer used as a type constraint in this module.
# Two-direction mapping per peer:
#   Inbound (remote → local): remote_group_name → str | None (None = block)
#   Outbound (local → remote): local_group_str → remote_group_name string
# Config format:
#   group_map_in  = White:White, Blue:Blue, *:   (trailing colon = block)
#   group_map_out = White:White, Blue:Cyan
#   Now also accepts: group_map_in = FIRE-OPS:FIRE-OPS, *:
# Conservative defaults ( validated against TAK Server source):
#   Inbound unmapped groups: BLOCK (safe default).
#     Matches TAK Server when federatedGroupMapping=true
#     fallbackWhenNoGroupMappings=false (CoreConfig.xsd:1237 default).
#   Outbound unmapped groups: BLOCK.
#   Phase 2: expose allow/fallback opt-in (equivalent to fallbackWhenNoGroupMappings=true).

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Set

# Well-known ATAK team color names. Not a type constraint — used only for
# parse-time advisory logging to help operators spot typos in group configs.
# _resolve_by_value (below) still imports Teams for backward-compat.
_KNOWN_COLOR_NAMES: frozenset = frozenset([
    "White", "Yellow", "Orange", "Magenta", "Red", "Maroon",
    "Purple", "Dark Blue", "Blue", "Cyan", "Teal", "Green",
    "Dark Green", "Brown",
])

log = logging.getLogger(__name__)


@dataclass
class FederatePeerGroupMap:
    """
    Group mapping for a single direction on a single federate peer.

    Phase-1 string migration: local_group is now Optional[str].
    ATAK color names ("White", "Blue", etc.) are valid string values;
    arbitrary names like "FIRE-OPS" are equally valid.

    Attributes
    ----------
    peer_id : str
        The peer's federation server ID (matches FederateProvenance.federationServerId).
    direction : Literal["in", "out", "both"]
        Which direction this mapping applies.
    remote_group : str
        Group name as announced by the remote peer (arbitrary string).
    local_group : str | None
        Mapped local group name (arbitrary string). None = block (do not forward).
    """

    peer_id: str
    direction: Literal["in", "out", "both"]
    remote_group: str
    local_group: Optional[str]


class FederateGroupRegistry:
    """
    Per-server registry of group mappings for all configured federate peers.

    Used by FederationManager.on_outbound (outbound direction) and by
    codec.decode_federated_event (inbound direction) to apply group filtering.

     validated: block-unmapped default matches TAK Server
    production behaviour (federatedGroupMapping=true, fallbackWhenNoGroupMappings=false).

    Parameters
    ----------
    (populated via add_peer_map from config.py during FederationManager init)

    Attributes
    ----------
    _inbound : Dict[str, Dict[str, Optional[str]]]
        {peer_id: {remote_group: local_group_or_None}}
        None value = explicit block entry.
    _outbound : Dict[str, Dict[str, str]]
        {peer_id: {local_group_str: remote_group_name}}
    _announced : Dict[str, List[str]]
        {peer_id: [remote_group_name, ...]} — updated from FederateGroups stream.
    _fallback_allow : Dict[str, bool]
        {peer_id: bool} — when True, unmapped inbound groups are passed through
        with the remote group name used as the local group name (string passthrough).
        Opt-in only. Default False.
        Equivalent to TAK Server's fallbackWhenNoGroupMappings=true.
    _fingerprint_to_peer : Dict[str, str]
        {normalized_fingerprint_colon_hex: peer_id} — the ONLY table inbound
        identity binding resolves against. Populated at config-parse time
        from each peer's `fingerprint` key, never from anything observed
        on the wire. A connecting
        certificate whose fingerprint is absent from this table has no
        peer_id to resolve to at all — the caller (fed_server.py) must
        quarantine, never fall through to a default.
    """

    def __init__(self):
        # {peer_id: {remote_group: str | None}}  — None means explicit BLOCK
        self._inbound: Dict[str, Dict[str, Optional[str]]] = {}
        # {peer_id: {local_group_str: remote_group_name}}
        self._outbound: Dict[str, Dict[str, str]] = {}
        # {peer_id: [remote_group_name, ...]} from FederateGroups stream
        self._announced: Dict[str, List[str]] = {}
        # {peer_id: bool} — opt-in fallback / allow-unmapped mode
        self._fallback_allow: Dict[str, bool] = {}
        # Default policy for peers with no explicit per-peer map entry.
        # Applied by map_inbound / map_outbound when the per-peer table is absent.
        # None (the sentinel, distinct from an empty dict {}) means "no default
        # configured" → preserve block-unmapped behaviour..
        self._default_inbound: Optional[Dict[str, Optional[str]]] = None
        self._default_outbound: Optional[Dict[str, str]] = None
        # {normalized_fingerprint_colon_hex: peer_id} — config-time only, see
        # class docstring. Keys are already normalized (upper-case colon-hex)
        # by config.py before register_fingerprint is called.
        self._fingerprint_to_peer: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_peer_map(self, peer_map: FederatePeerGroupMap) -> None:
        """
        Register a group mapping entry for a peer.

        Called by config.py parsing logic during FederationManager.__init__.
        A direction of "both" registers the entry in both inbound and outbound
        tables. Multiple calls for the same peer accumulate; later entries for
        the same remote_group / local_group key overwrite earlier ones.

        Parameters
        ----------
        peer_map : FederatePeerGroupMap
        """
        pid = peer_map.peer_id

        if peer_map.direction in ("in", "both"):
            self._inbound.setdefault(pid, {})[peer_map.remote_group] = peer_map.local_group

        if peer_map.direction in ("out", "both"):
            if peer_map.local_group is not None:
                out_key = peer_map.local_group  # already a string
                self._outbound.setdefault(pid, {})[out_key] = peer_map.remote_group

    def set_fallback_allow(self, peer_id: str, enabled: bool) -> None:
        """
        Enable or disable opt-in fallback/allow-unmapped mode for a peer.

        When enabled, inbound events whose remote group has no explicit mapping
        are passed through using the remote group name as the local group name
        (string passthrough). This matches TAK Server's fallbackWhenNoGroupMappings=true
        semantics for arbitrary-string groups.

        Note (Phase-1 behavior change): previously this resolved the remote group
        name against the Teams enum — only color names passed through; others were
        blocked. Now ALL remote group names pass through in fallback mode, including
        arbitrary names like "FIRE-OPS". This is correct for the new string model.

        Default is False (block-unmapped). Setting True is an operator opt-in.

        Parameters
        ----------
        peer_id : str
        enabled : bool
        """
        self._fallback_allow[peer_id] = enabled

    def set_default_in_map(self, entries: List["FederatePeerGroupMap"]) -> None:
        """
        Set the default inbound group policy, applied to peers with no
        explicit per-peer map.

        Called by FederationManager._build_group_registry when
        [federation] default_group_map_in is configured. Entries must have
        direction "in" (or "both"). The peer_id field on each entry is ignored
        here — the default is peer-id-agnostic..

        Parameters
        ----------
        entries : List[FederatePeerGroupMap]
            Parsed default entries (peer_id sentinel value is irrelevant).
        """
        table: Dict[str, Optional[str]] = {}
        for e in entries:
            if e.direction in ("in", "both"):
                table[e.remote_group] = e.local_group
        self._default_inbound = table

    def set_default_out_map(self, entries: List["FederatePeerGroupMap"]) -> None:
        """
        Set the default outbound group policy, applied to peers with no
        explicit per-peer outbound map.

        Called by FederationManager._build_group_registry when
        [federation] default_group_map_out is configured..

        Parameters
        ----------
        entries : List[FederatePeerGroupMap]
            Parsed default entries (peer_id sentinel value is irrelevant).
        """
        table: Dict[str, str] = {}
        for e in entries:
            if e.direction in ("out", "both") and e.local_group is not None:
                out_key = e.local_group  # already a string
                table[out_key] = e.remote_group
        self._default_outbound = table

    def register_fingerprint(self, fingerprint: str, peer_id: str) -> None:
        """
        Register a configured peer's certificate fingerprint → peer_id.

        Called by FederationManager._build_group_registry at config-parse
        time from each peer's `fingerprint` config key. This is the ONLY
        table fed_server.py's inbound identity binding may resolve a
        connecting certificate against — never a wire-supplied field.

        Parameters
        ----------
        fingerprint : str
            Normalized (upper-case colon-hex) SHA-256 fingerprint —
            config.py normalizes before calling this.
        peer_id : str
            The registry key this fingerprint resolves to (the peer's
            declared server_id when set, else its provisional
            "address:port" key — whichever key add_peer_map registered
            this peer's group tables under).
        """
        if not fingerprint:
            return
        self._fingerprint_to_peer[fingerprint] = peer_id

    def resolve_peer_id_by_fingerprint(self, fingerprint: str) -> Optional[str]:
        """
        Resolve a connecting certificate's fingerprint to a configured
        peer_id, or None if no peer configured this fingerprint.

        Callers (fed_server.py) MUST treat None as "quarantine" — no policy,
        no fallthrough to a global default. There is no partial match: a
        fingerprint either exactly matches a configured peer or it does not.

        Parameters
        ----------
        fingerprint : str
            Normalized (upper-case colon-hex) SHA-256 fingerprint, as
            produced by cert_identity.peer_fingerprint_from_grpc_context.

        Returns
        -------
        str | None
        """
        return self._fingerprint_to_peer.get(fingerprint)

    def known_fingerprints(self) -> List[str]:
        """Return all configured peer certificate fingerprints. Diagnostics only."""
        return sorted(self._fingerprint_to_peer)

    def rekey_peer(self, old_id: str, new_id: str) -> None:
        """
        Re-key all per-peer registry entries from old_id to new_id.

        DEFENSE-IN-DEPTH ONLY: FederateClient no longer calls this at
        all — the outbound session's policy key is
        resolved exclusively from the dialed server's presented certificate
        fingerprint via resolve_peer_id_by_fingerprint (the same table the
        inbound path uses), so there is no wire-derived rekey on any
        production path. The method (and its collision guard below) is kept
        so that no future caller can be handed a remote-controlled new_id
        and silently destroy or capture another peer's tables. This method
        itself does not, and must not, trust its caller's honesty about
        what new_id means. §key-consistency.

        If old_id == new_id or old_id is not in the registry, this is a
        no-op (safe to call unconditionally).

        COLLISION SAFETY: if new_id ALREADY has an entry in any
        table — i.e. new_id is some OTHER configured peer's key, not merely
        this peer's own previously-provisional key — this is a collision,
        not a legitimate rekey, and is refused outright. The old behavior
        popped (deleted) old_id's entry unconditionally and only skipped the
        overwrite, which silently destroyed old_id's own restrictive policy
        for no benefit while leaving new_id's (the collided-with peer's)
        table completely intact — exactly the shape a peer claiming another
        peer's server_id would produce. Refusing the whole operation on
        collision means BOTH keys keep their original entries untouched, and
        the caller's own peer_id (old_id) still resolves to its own policy
        rather than silently losing it.

        Parameters
        ----------
        old_id : str
            The provisional key used at startup (e.g. "10.0.0.1:9100").
        new_id : str
            The key to move the entries to. Must never be a wire-reported
            value — no production path passes one anymore (see above).
        """
        if old_id == new_id or not old_id:
            return

        collision = (
            new_id in self._inbound
            or new_id in self._outbound
            or new_id in self._fallback_allow
        )
        if collision:
            log.warning(
                "rekey_peer: refusing to rekey %r -> %r — %r already has its "
                "own registered policy (collision); leaving both entries "
                "untouched rather than destroying either one",
                old_id, new_id, new_id,
            )
            return

        if old_id in self._inbound:
            self._inbound[new_id] = self._inbound.pop(old_id)
        if old_id in self._outbound:
            self._outbound[new_id] = self._outbound.pop(old_id)
        if old_id in self._fallback_allow:
            self._fallback_allow[new_id] = self._fallback_allow.pop(old_id)

    def map_inbound(self, peer_id: str, remote_group: str) -> Optional[str]:
        """
        Map a remote group name to a local group string.

        Returns None if the group should be blocked (no mapping or explicit block).
        Default (no mapping configured for peer): BLOCK (conservative
         — matches TAK Server default for federatedGroupMapping=true).

        Wildcard entry ``"*"`` in the inbound map acts as a catch-all for groups
        that have no specific mapping. ``"*": None`` means block-all-unmapped
        (the config-file ``*:`` entry). ``"*": <str>`` means route-all-unmapped
        to that local group string.

        Opt-in fallback (set_fallback_allow=True): if no explicit mapping exists
        and no wildcard, the remote group name is passed through as-is as the local
        group string. This is equivalent to TAK Server's fallbackWhenNoGroupMappings=true
        for the arbitrary-string group model. Phase-1 behavior change: previously
        this only admitted Teams color names; now all strings pass through.

        Parameters
        ----------
        peer_id : str
            Federation server ID of the remote peer.
        remote_group : str
            Group name string from FederatedEvent.federateGroups or
            GeoEvent.groupName.

        Returns
        -------
        str | None
            Mapped local group string, or None to drop the event.
        """
        peer_map = self._inbound.get(peer_id)

        if peer_map is not None:
            # Exact match first
            if remote_group in peer_map:
                return peer_map[remote_group]  # may be None (explicit block)

            # Wildcard fallback within configured map
            if "*" in peer_map:
                return peer_map["*"]  # may be None (block all unmapped)

        else:
            # No per-peer table: consult the [federation]-level default policy.
            # — this is what opens inbound TAK Server peers.
            if self._default_inbound is not None:
                if remote_group in self._default_inbound:
                    return self._default_inbound[remote_group]
                if "*" in self._default_inbound:
                    return self._default_inbound["*"]

        # No table, or table present but no matching entry and no wildcard:
        # check opt-in fallback allow mode.
        if self._fallback_allow.get(peer_id, False):
            # String passthrough: remote group name is used as the local group.
            # In Phase 1 this admits all strings (including non-color arbitrary names).
            return remote_group

        # BLOCK (default)
        return None

    def map_inbound_groups(
        self, peer_id: str, remote_groups: List[str]
    ) -> Optional[Set[str]]:
        """
        Translate an inbound event's federateGroups list to a set of local group strings.

        This is the multi-group variant called by the codec / transport layer.
        Semantics (matching TAK Server):
          - Map each remote group through map_inbound.
          - Collect successful (non-None) mappings.
          - If the result set is empty (all groups blocked or unmapped), return None
            — caller must drop the event entirely.
          - Otherwise return the set of matched local group strings.

        Parameters
        ----------
        peer_id : str
        remote_groups : List[str]

        Returns
        -------
        set[str] | None
            None means drop the event (no groups routable locally).
        """
        if not remote_groups:
            # Stock TAK Server with federatedGroupMapping off (the default) sends
            # FederatedEvents with NO federateGroups annotation. TAK Server's own
            # inbound semantic assigns groups from LOCAL config (the federate's
            # inboundGroups), never from the wire — so a group-less event is
            # admitted iff the operator configured an explicit wildcard
            # accept_as ("*:<local>") for this peer (or globally). Peers scoped
            # to named remote groups stay fail-closed.
            local = self.map_inbound(peer_id, "*")
            if local == "*":
                # fallback_allow passthrough echoes the probe string; "*" is a
                # match key, never a real local group — treat as unmapped.
                local = None
            return {local} if local is not None else None

        result: Set[str] = set()
        for rg in remote_groups:
            local = self.map_inbound(peer_id, rg)
            if local is not None:
                result.add(local)
        return result if result else None

    def map_outbound(self, peer_id: str, local_group: str) -> Optional[str]:
        """
        Map a local group string to a remote group name string for a given peer.

        Returns None if the event should NOT be sent to this peer for this group
        (block-unmapped default).

        Wildcard outbound is not implemented in Phase 1 — there is no safe wildcard
        for outbound because the local group value must map to a specific remote
        string. Phase 2 may add ``*:*`` (pass-through same name) for dev/testing.

        Parameters
        ----------
        peer_id : str
            Federation server ID of the target peer.
        local_group : str
            The originating event's group string (from TAKUser.group or XML fallback).

        Returns
        -------
        str | None
            Remote group name to use in FederatedEvent.federateGroups
            or None to suppress forwarding.
        """
        peer_map = self._outbound.get(peer_id)
        if peer_map is None:
            # No per-peer outbound table: consult the [federation]-level default.
            #.
            if self._default_outbound is not None:
                return self._default_outbound.get(local_group)
            return None  # BLOCK — no outbound config for this peer

        return peer_map.get(local_group)  # None if not mapped

    def map_outbound_groups(
        self, peer_id: str, local_groups: List[str]
    ) -> List[str]:
        """
        Map a list of local group strings to remote group name strings for a peer.

        Groups with no outbound mapping are silently excluded. The caller
        (FederationManager.on_outbound / FederateClient.send_event) should
        suppress sending the event entirely if the returned list is empty.

        Parameters
        ----------
        peer_id : str
        local_groups : List[str]

        Returns
        -------
        List[str]
            Remote group name strings to set in FederatedEvent.federateGroups.
            Empty list means the event must not be forwarded to this peer.
        """
        result = []
        for lg in local_groups:
            remote = self.map_outbound(peer_id, lg)
            if remote is not None:
                result.append(remote)
        return result

    def update_from_federate_groups(self, peer_id: str, remote_groups: List[str]) -> None:
        """
        Update the known remote group list for a peer from a received FederateGroups stream.

        Called by FederateClient when
        ServerFederateGroupsStream delivers new group announcements.

        Stores the announced groups for inspection / future dynamic mapping.
        Does NOT automatically create mapping entries — operators configure
        group_map_in / group_map_out explicitly. The announced list is available
        for informational logging and Phase 2 ROL / dynamic mapping.

        Parameters
        ----------
        peer_id : str
        remote_groups : List[str]
            Group name strings from FederateGroups.federateGroups.
        """
        self._announced[peer_id] = list(remote_groups)

    def get_announced_groups(self, peer_id: str) -> List[str]:
        """
        Return the last announced remote group list for a peer.

        Returns an empty list if no FederateGroups stream has been received yet.

        Parameters
        ----------
        peer_id : str

        Returns
        -------
        List[str]
        """
        return list(self._announced.get(peer_id, []))

    def known_peers(self) -> List[str]:
        """
        Return all peer IDs that have at least one inbound or outbound mapping.

        Useful for diagnostics and config validation.

        Returns
        -------
        List[str]
        """
        return sorted(set(self._inbound) | set(self._outbound))


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _resolve_by_value(name: str):
    """
    Look up a Teams member whose .value matches ``name`` (case-sensitive).

    Dead code since Phase-1 string migration (ebd62f): map_inbound no longer
    calls this — the fallback-allow path now returns the remote group string
    directly. Kept for backward-compat with test imports. Scheduled for removal
    in a later cleanup ticket.

    Returns None if no match found.

    Note: Teams.UNKNOWN and Teams.CYAN share the value "Cyan"; the first
    match (enum declaration order) is returned — Teams.CYAN (index 12).
    """
    from ots_federation.models.teams import Teams  # local import: dead-code path
    for member in Teams:
        if member.value == name:
            return member
    return None


def parse_group_map(raw: str, direction: Literal["in", "out", "both"]) -> List[FederatePeerGroupMap]:
    """
    Parse a ``group_map_in`` or ``group_map_out`` config string into a list of
    FederatePeerGroupMap entries (peer_id is set to a sentinel placeholder
    ``""`` — caller must set peer_id before registering).

    Format: ``"White:White, Blue:Blue, FIRE-OPS:FIRE-OPS, *:"``
      - Left side: remote group name (inbound) or local group string (outbound).
      - Right side: local group string (inbound) or remote group name (outbound).
      - Empty right side means BLOCK.
      - ``*`` on the left is a wildcard catch-all.

    Phase-1 string migration (ebd62f): both sides now accept arbitrary strings.
    ATAK color names ("White", "Blue", etc.) continue to work as before. Arbitrary
    names like "FIRE-OPS" are now also valid without raising ValueError.

    For direction="in":
      Right side is an arbitrary local group string, empty (→ None/block)
      or ``"*"`` (→ wildcard, block unless fallback mode enabled).
    For direction="out":
      Left side is a local group string (arbitrary) or ``"*"`` (wildcard, future).
      Right side is an arbitrary remote group name string, or empty (→ skip/None).

    Non-color group names are logged at DEBUG to help operators spot unintentional
    typos while still accepting them as valid arbitrary group names.

    Parameters
    ----------
    raw : str
        The raw config string value (comma-separated key:value pairs).
    direction : Literal["in", "out", "both"]

    Returns
    -------
    List[FederatePeerGroupMap]
        Entries with peer_id="" (sentinel); caller must set peer_id.

    Raises
    ------
    ValueError
        Only if an entry is missing the ``:`` separator (format error).
    """
    entries: List[FederatePeerGroupMap] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" not in token:
            raise ValueError(
                f"Invalid group map entry {token!r}: expected 'remote:local' format"
            )
        lhs, _, rhs = token.partition(":")
        lhs = lhs.strip()
        rhs = rhs.strip()

        if direction in ("in", "both"):
            # lhs = remote_group (arbitrary string), rhs = local group string or ""
            local_group: Optional[str] = None
            if rhs == "" or rhs is None:
                local_group = None  # explicit block
            elif rhs == "*":
                # wildcard rhs for inbound: block unless fallback mode enabled
                local_group = None
            else:
                # Arbitrary string is valid; log if it's not a well-known color.
                if rhs not in _KNOWN_COLOR_NAMES:
                    log.debug(
                        "parse_group_map: inbound local group %r is not a standard "
                        "ATAK color name — treating as arbitrary group string (valid)",
                        rhs,
                    )
                local_group = rhs
            entries.append(
                FederatePeerGroupMap(
                    peer_id="",
                    direction=direction,
                    remote_group=lhs,
                    local_group=local_group,
                )
            )

        elif direction == "out":
            # lhs = local group string (arbitrary) or "*" (wildcard, future)
            if lhs == "*":
                # Outbound wildcard: future Phase 2; not implemented
                # Skip silently to avoid breaking config parsing
                continue
            # Arbitrary string is valid; log if it's not a well-known color.
            if lhs not in _KNOWN_COLOR_NAMES:
                log.debug(
                    "parse_group_map: outbound local group %r is not a standard "
                    "ATAK color name — treating as arbitrary group string (valid)",
                    lhs,
                )
            remote_name = rhs if rhs else None
            entries.append(
                FederatePeerGroupMap(
                    peer_id="",
                    direction="out",
                    remote_group=remote_name or "",
                    local_group=lhs if lhs else None,
                )
            )

    return entries
