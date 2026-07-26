# taky/cot/federation/codec.py
# Stream: codec
# The codec is bidirectional:
#   encode_federated_event(evt, fed_meta) → fig_pb2.FederatedEvent
#   decode_federated_event(proto)         → (models.Event, FedMeta)
# FedMeta is a thin dataclass (Option 5A) carrying provenance and hop
# data as a sidecar to models.Event. It is ONLY used inside the federation layer;
# COTRouter always sees plain models.Event.
# Security note:
#   GeoEvent.other is a raw CoT XML detail string from an untrusted remote.
#   Parse with lxml.etree.fromstring using resolve_entities=False. Catch all
#   etree exceptions — a malformed `other` drops the event, not the connection.
# ── Lossy / unmapped fields (Phase 1 — intentionally dropped) ──────────────────
# GeoEvent fields dropped on inbound and not populated on outbound:
#   access (field 27)       — MIL-STD-6090 classification string; no taky model.
#                             Phase 2 concern for MIL-grade federation.
#   caveat (field 28)       — MIL-STD-6090 caveat string; no taky model.
#   releaseableTo (field 29)— MIL-STD-6090 release string; no taky model.
#   feedUid (field 25)      — feed/mission UID; taky has no feed model.
#   missionNames (field 26) — repeated string; taky has no mission model.
#   binary (field 22)       — BinaryBlob (image/icon); taky has no image model.
#   bloads (field 30)       — repeated BinaryPayload; binary mission data; dropped.
#   ploc (field 14)         — precision location string; no taky equivalent.
#   palt (field 15)         — precision altitude string; no taky equivalent.
# ptpUids / ptpCallsigns (GeoEvent fields 23-24):
#   Carried in `other` XML blob via the GeoChat detail serialisation. Not
#   extracted into standalone GeoEvent fields on outbound (XML round-trips
#   them implicitly through the `other` blob). The transport stream (bridge.py)
#   is responsible for p2p routing decisions; the codec passes them through `other`.
# Group names (Phase-1 string migration):
#   detail.group and related fields are now plain str, not Teams enum members.
#   Non-color group names ("FIRE-OPS", etc.) pass through as-is.
#   Empty string is the falsy sentinel (replaces Teams.UNKNOWN).
# ──────────────────────────────────────────────────────────────────────────────

import sys
import os
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from lxml import etree

from ots_federation import models
from ots_federation.models.detail import Detail
from ots_federation.models.geochat import GeoChat, GEOCHAT_TAGS
from ots_federation.models.takuser import TAKUser, TAKUSER_TAGS

# ── Proto import shim ─────────────────────────────────────────────────────────
# The protoc-generated fig_pb2.py uses a bare `import binarypayload_pb2` (no
# package prefix) because older grpcio-tools emit that style. We temporarily
# add the proto package directory to sys.path so that bare import resolves.
_PROTO_DIR = os.path.join(os.path.dirname(__file__), "proto")
if _PROTO_DIR not in sys.path:
    sys.path.insert(0, _PROTO_DIR)

from ots_federation.proto import fig_pb2  # noqa: E402 (after sys.path shim)

# ──────────────────────────────────────────────────────────────────────────────

log = logging.getLogger(__name__)


@dataclass
class FedMeta:
    """
    Sidecar metadata for federated events. Option 5A.

    Never attached to models.Event directly; carried alongside it in the
    federation layer only (bridge.py inbound_q, FederateClient.send_event).

    Attributes
    ----------
    seen_server_ids : List[str]
        Ordered list of federation server IDs from FederateProvenance chain.
        Used for loop prevention: if own node_id is in this list
        drop the event before encoding.
    current_hops : int
        Value from FederateHops.currentHops in the received FederatedEvent.
    max_hops : int
        Value from FederateHops.maxHops (-1 means unlimited).
    """

    seen_server_ids: List[str] = field(default_factory=list)
    current_hops: int = 0
    max_hops: int = -1
    group_hop_limits: Optional["fig_pb2.FederateGroupHopLimits"] = None
    # Per-group hop-limit overrides from the received FederatedEvent, or None.
    # When useFederateGroupHopLimits=True and a limit entry for the event's
    # group exists, that limit is enforced instead of the global max_hops.
    #.


# ── Timestamp helpers ─────────────────────────────────────────────────────────


def _dt_to_ms(dt_val: Optional[datetime]) -> int:
    """Convert a tz-naive UTC datetime to Unix milliseconds (GeoEvent wire format).

    GeoEvent.sendTime / startTime / staleTime are int64 Unix milliseconds.
    taky uses tz-naive datetime objects representing UTC (see event.py line 52–54).

    Parameters
    ----------
    dt_val : datetime or None
        tz-naive UTC datetime. None is treated as epoch (0 ms).

    Returns
    -------
    int
        Unix milliseconds.
    """
    if dt_val is None:
        return 0
    # datetime.utcfromtimestamp / timestamp both assume naive == local on
    # older Pythons, but taky's convention is naive == UTC throughout.
    # We use calendar math instead to be unambiguous.
    epoch = datetime(1970, 1, 1)
    delta = dt_val - epoch
    return int(delta.total_seconds() * 1000)


def _ms_to_dt(ms: int) -> datetime:
    """Convert Unix milliseconds to a tz-naive UTC datetime.

    Matches taky's convention: isoparse(...).replace(tzinfo=None).

    Parameters
    ----------
    ms : int
        Unix milliseconds since epoch.

    Returns
    -------
    datetime
        tz-naive datetime representing UTC.
    """
    return datetime.utcfromtimestamp(ms / 1000.0)


# ── XML serialisation helpers ─────────────────────────────────────────────────


def _detail_to_xml_string(detail) -> str:
    """Serialise a detail object to an XML string for GeoEvent.other.

    Returns an empty string if detail is None.
    """
    if detail is None:
        return ""
    elm = detail.as_element
    if elm is None:
        return ""
    return etree.tostring(elm, encoding="unicode")


def _parse_other(other: str) -> Optional[object]:
    """Parse GeoEvent.other (untrusted CoT <detail> XML) into a detail object.

    Security: uses resolve_entities=False (XXE-safe).
    Any parse error returns None — the caller drops the event, not the connection.

    Parameters
    ----------
    other : str
        Raw XML string, expected to be a <detail>…</detail> element.

    Returns
    -------
    Detail | TAKUser | GeoChat | None
        Parsed detail object, or None on parse failure.
    """
    if not other:
        return None

    try:
        parser = etree.XMLParser(resolve_entities=False)
        elm = etree.fromstring(other.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as exc:
        log.warning("codec: malformed GeoEvent.other XML (dropping event): %s", exc)
        return None
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("codec: unexpected XML parse error in GeoEvent.other (dropping event): %s", exc)
        return None

    if elm.tag != "detail":
        log.warning(
            "codec: GeoEvent.other root tag is <%s>, expected <detail> (dropping event)",
            elm.tag,
        )
        return None

    d_tags = {child.tag for child in elm.iterchildren()}
    try:
        if TAKUser.is_type(d_tags):
            # TAKUser.from_elm needs the event UID for the uid field; use empty
            # string as placeholder — the caller will overwrite evt.detail.uid
            # from evt.uid after decoding.
            return TAKUser.from_elm(elm, uid="")
        elif GeoChat.is_type(d_tags):
            return GeoChat.from_elm(elm)
        else:
            return Detail.from_elm(elm)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("codec: error building detail from GeoEvent.other (dropping event): %s", exc)
        return None


# ── Public API ─────────────────────────────────────────────────────────────────


def encode_federated_event(
    evt: models.Event,
    fed_meta: Optional[FedMeta] = None,
) -> "fig_pb2.FederatedEvent":
    """Encode a taky models.Event (+ optional FedMeta) into a FederatedEvent proto.

    Field map:
        Event.uid          → GeoEvent.uid (field 9)
        Event.etype        → GeoEvent.type (field 10)
        Event.how          → GeoEvent.coordSource (field 11)
        Event.time         → GeoEvent.sendTime (Unix ms)
        Event.start        → GeoEvent.startTime (Unix ms)
        Event.stale        → GeoEvent.staleTime (Unix ms)
        Event.point.lat    → GeoEvent.lat
        Event.point.lon    → GeoEvent.lon
        Event.point.hae    → GeoEvent.hae
        Event.point.ce     → GeoEvent.ce
        Event.point.le     → GeoEvent.le
        TAKUser.callsign   → GeoEvent.screenName (if detail is TAKUser)
        TAKUser.group      → GeoEvent.groupName
        TAKUser.role       → GeoEvent.groupRole
        TAKUser.phone      → GeoEvent.phone
        TAKUser.course     → GeoEvent.course
        TAKUser.speed      → GeoEvent.speed
        TAKUser.battery    → GeoEvent.battery (int32; parse from string)
        Event.detail (xml) → GeoEvent.other (serialized <detail> subtree)

    Provenance: caller (FederateClient.send_event) is responsible
    for appending own FederateProvenance before calling this function.

    Parameters
    ----------
    evt : models.Event
        The CoT event to encode.
    fed_meta : FedMeta, optional
        Sidecar provenance/hop metadata from a prior relay hop.
        If None, this is an origin event from a local ATAK client.

    Returns
    -------
    fig_pb2.FederatedEvent
    """
    geo = fig_pb2.GeoEvent(
        uid=evt.uid or "",
        type=evt.etype or "",
        coordSource=evt.how or "",
        sendTime=_dt_to_ms(evt.time),
        startTime=_dt_to_ms(evt.start),
        staleTime=_dt_to_ms(evt.stale),
        lat=evt.point.lat,
        lon=evt.point.lon,
        hae=evt.point.hae,
        ce=evt.point.ce,
        le=evt.point.le,
    )

    # Populate named TAKUser fields AND `other` for maximum interop.
    # For GeoChat / generic Detail: `other` only.
    if isinstance(evt.detail, TAKUser):
        user = evt.detail
        if user.callsign:
            geo.screenName = user.callsign
        if user.group:  # truthy: non-empty string (Phase-1: group is str, not Teams)
            geo.groupName = user.group
        if user.role:
            geo.groupRole = user.role
        if user.phone:
            geo.phone = user.phone
        if user.course is not None:
            geo.course = float(user.course)
        if user.speed is not None:
            geo.speed = float(user.speed)
        if user.battery is not None:
            try:
                geo.battery = int(user.battery)
            except (ValueError, TypeError):
                pass  # drop non-integer battery strings

    # Always serialise detail to `other` (covers all types including TAKUser)
    xml_str = _detail_to_xml_string(evt.detail)
    if xml_str:
        geo.other = xml_str

    fed_evt = fig_pb2.FederatedEvent(event=geo)

    # Carry provenance chain and hop counts through from fed_meta
    if fed_meta is not None:
        for server_id in fed_meta.seen_server_ids:
            prov = fig_pb2.FederateProvenance(federationServerId=server_id)
            fed_evt.federateProvenance.append(prov)
        fed_evt.federateHops.CopyFrom(
            fig_pb2.FederateHops(
                maxHops=fed_meta.max_hops,
                currentHops=fed_meta.current_hops,
            )
        )
        # Propagate per-group hop limits when present..
        if fed_meta.group_hop_limits is not None:
            fed_evt.federateGroupHopLimits.CopyFrom(fed_meta.group_hop_limits)

    return fed_evt


def _resolve_max_hops(wire_max_hops: int, local_max_hops: int) -> int:
    """
    Resolve a received FederateHops.maxHops against OUR configured ceiling.

    Never let a peer obtain unlimited relay simply by omitting the field
    (proto3 defaults an absent int32 to 0) or by sending an explicit
    non-positive value. A peer MAY tighten the effective hop budget by
    declaring a smaller positive max_hops than ours; it can never loosen it
    past our own configured limit.

    This is defense-in-depth, not the primary loop guard — the provenance
    chain (loop_filter.py: refuse to re-relay anything carrying our own
    node_id) is what actually prevents a cycle; this clamp only bounds how
    far a single event can travel before that guard would matter, and
    limits amplification if provenance were ever stripped in transit.

    Parameters
    ----------
    wire_max_hops : int
        The value read from the wire (FederateHops.maxHops). 0 covers both
        an explicitly-sent zero and an absent field (proto3 scalar default).
    local_max_hops : int
        This node's configured ceiling ([federation] max_hops, or a per-peer
        override). -1 means the operator has explicitly configured no local
        ceiling (unlimited); there is then nothing to clamp against, so the
        peer's own (positive) declared budget is honored as-is.

    Returns
    -------
    int
        The max_hops value to carry in FedMeta.
    """
    if wire_max_hops <= 0:
        return local_max_hops
    if local_max_hops <= 0:
        return wire_max_hops
    return min(wire_max_hops, local_max_hops)


def decode_federated_event(
    proto: "fig_pb2.FederatedEvent",
    local_max_hops: int = 3,
) -> Tuple[Optional[models.Event], FedMeta]:
    """Decode a FederatedEvent proto into (models.Event, FedMeta).

    Field map:
        GeoEvent.sendTime    → Event.time  (Unix ms → datetime.utcfromtimestamp)
        GeoEvent.uid         → Event.uid
        GeoEvent.type        → Event.etype
        GeoEvent.coordSource → Event.how
        GeoEvent.lat/lon/hae/ce/le → Event.point.*
        GeoEvent.screenName / groupName / groupRole → TAKUser detail (if present)
        GeoEvent.other       → parse as lxml XML with resolve_entities=False

    Security:
        GeoEvent.other is untrusted XML. Parse with resolve_entities=False.
        Any lxml exception → drop event (return None, FedMeta) — do not propagate.

    Parameters
    ----------
    proto : fig_pb2.FederatedEvent
        The received protobuf message.
    local_max_hops : int
        This node's configured hop ceiling ([federation] max_hops, default
        3). An absent or non-positive wire max_hops resolves to this value
        rather than to unlimited — see _resolve_max_hops. Defaults to 3
        (the FederationConfig default) for callers that don't have a config
        object in hand; production call sites pass their own configured
        value explicitly.

    Returns
    -------
    tuple[models.Event | None, FedMeta]
        Event is None if the proto lacks a GeoEvent or if XML parsing of
        GeoEvent.other fails fatally. FedMeta is always returned (populated
        from proto.federateProvenance and proto.federateHops).
    """
    # Always build FedMeta from the envelope, regardless of payload type.
    # Extract per-group hop limits when useFederateGroupHopLimits is set.
    #.
    group_hop_limits = None
    if (proto.HasField("federateGroupHopLimits")
            and proto.federateGroupHopLimits.useFederateGroupHopLimits
            and proto.federateGroupHopLimits.limits):
        group_hop_limits = proto.federateGroupHopLimits

    fed_meta = FedMeta(
        seen_server_ids=[p.federationServerId for p in proto.federateProvenance],
        current_hops=proto.federateHops.currentHops,
        max_hops=_resolve_max_hops(proto.federateHops.maxHops, local_max_hops),
        group_hop_limits=group_hop_limits,
    )

    # A FederatedEvent may carry a contact entry instead of (or in addition to)
    # a GeoEvent. If there is no GeoEvent, return (None, fed_meta).
    if not proto.HasField("event"):
        return None, fed_meta

    geo = proto.event

    # Validate required fields
    if not geo.uid:
        log.warning("codec: received GeoEvent with no uid — dropping")
        return None, fed_meta
    if not geo.type:
        log.warning("codec: received GeoEvent with no type — dropping")
        return None, fed_meta

    evt = models.Event(
        uid=geo.uid,
        etype=geo.type,
        how=geo.coordSource or "m-g",
        time=_ms_to_dt(geo.sendTime),
        start=_ms_to_dt(geo.startTime),
        stale=_ms_to_dt(geo.staleTime),
    )

    evt.point = models.Point(
        lat=geo.lat,
        lon=geo.lon,
        hae=geo.hae,
        ce=geo.ce if geo.ce != 0.0 else 9999999.0,
        le=geo.le if geo.le != 0.0 else 9999999.0,
    )

    # Prefer `other` XML blob as the ground truth for the detail subtree.
    # Named fields (screenName, groupName, groupRole) are a fallback for
    # remotes that do not populate `other`.
    detail = None
    if geo.other:
        detail = _parse_other(geo.other)
        if detail is None:
            # Malformed XML — drop the event, not the connection
            log.warning("codec: dropping event uid=%s due to malformed GeoEvent.other", geo.uid)
            return None, fed_meta
        # If we parsed a TAKUser from `other`, patch in the event UID (which
        # TAKUser.from_elm received as empty-string placeholder above).
        if isinstance(detail, TAKUser):
            detail.uid = geo.uid

    elif geo.screenName or geo.groupName or geo.groupRole:
        # Synthesize a minimal TAKUser from named fields
        try:
            detail = _synthesize_takuser_from_geo(geo, evt.uid)
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("codec: failed to synthesize TAKUser from named fields: %s", exc)

    evt.detail = detail
    return evt, fed_meta


def _synthesize_takuser_from_geo(geo: "fig_pb2.GeoEvent", uid: str) -> TAKUser:
    """Build a minimal TAKUser from GeoEvent named fields (no `other` blob).

    Used as a fallback when a remote sends screenName/groupName/groupRole but
    no `other` XML blob. The resulting TAKUser has elm=None so as_element will
    regenerate XML (requires callsign, group, role, endpoint fields — all
    optional fields are left None if not present in the proto).

    Parameters
    ----------
    geo : fig_pb2.GeoEvent
    uid : str
        CoT UID for this event (populates TAKUser.uid).

    Returns
    -------
    TAKUser
    """
    # Build a minimal <detail> element so TAKUser.from_elm can parse it.
    # We must supply at least the three required tags: takv, contact, __group.
    detail_elm = etree.Element("detail")

    takv_elm = etree.SubElement(detail_elm, "takv")
    takv_elm.set("os", "")
    takv_elm.set("version", "")
    takv_elm.set("device", "")
    takv_elm.set("platform", "")

    contact_elm = etree.SubElement(detail_elm, "contact")
    contact_elm.set("callsign", geo.screenName or "")
    contact_elm.set("endpoint", "*:-1:stcp")
    if geo.phone:
        contact_elm.set("phone", geo.phone)

    uid_elm = etree.SubElement(detail_elm, "uid")
    uid_elm.set("Droid", geo.screenName or "")

    group_elm = etree.SubElement(detail_elm, "__group")
    # Phase-1: Teams.UNKNOWN sentinel removed; empty string is the falsy sentinel.
    # An empty name parses back as group="" in TAKUser → falsy → blocked by policy.
    group_elm.set("name", geo.groupName or "")
    group_elm.set("role", geo.groupRole or "")

    user = TAKUser.from_elm(detail_elm, uid=uid)

    # Overlay numeric fields from named proto fields
    if geo.speed != 0.0:
        user.speed = geo.speed
    if geo.course != 0.0:
        user.course = geo.course
    if geo.battery != 0:
        user.battery = str(geo.battery)

    return user


def prepare_outbound_event(
    evt: "models.Event",
    node_id: str,
    default_max_hops: int,
    registry=None,
    peer_id: str = "",
) -> Optional["fig_pb2.FederatedEvent"]:
    """Shared outbound link helper: loop-prevention + hop-stamp + group-policy + encode.

    This is the single source of truth for the loop-prevention, hop-stamp, and
    outbound group-policy logic used by BOTH the outbound client link
    (FederateClient.send_event) and the inbound server link
    (FederationServer per-peer outbound queue). Keeping it here — alongside the
    codec it wraps — means the two link directions can never drift in their loop
    or group-policy semantics.(loop prevention via provenance)
    (hop-limit enforcement + provenance append)
    (outbound group policy — FederatedEvent.federateGroups).

    Decision logic (in order):
      1. If our own node_id is already in the event's provenance chain, return
         None (drop — we have already seen this event; forwarding it would loop).
      2. If a finite hop limit is set and current_hops >= max_hops, return None
         (drop — hop budget exhausted).
      3. Group policy (when registry + peer_id supplied): map the event's local
         group(s) to remote group name strings for this peer. If the result is
         empty (all groups unmapped / blocked), return None —
         block-unmapped default. The mapped remote group names are set on the
         returned FederatedEvent.federateGroups repeated field.
      4. Build an updated FedMeta with our node_id appended to provenance and
         current_hops incremented (origin events with no prior FedMeta start at
         hops=1 with max_hops=default_max_hops).
      5. Encode and return the FederatedEvent proto (with federateGroups set).

    Encoding failures are NOT swallowed here — the caller logs and drops, since
    the client and server links want slightly different log context. Loop/hop/
    group-policy drops return None silently (they are normal, not errors).

    Parameters
    ----------
    evt : models.Event
        The CoT event to forward. May carry a FedMeta sidecar as evt.fed_meta
        (set on the inbound path); plain local-origin events have none.
    node_id : str
        This server's federation server ID (config [federation] server_id). Used
        for the provenance loop-check and for stamping our own provenance.
    default_max_hops : int
        The max_hops to apply to a fresh (local-origin) event. -1 = unlimited.
        For relay hops the max_hops already on the event's FedMeta is preserved.
    registry : FederateGroupRegistry | None
        Optional group registry. When supplied (along with peer_id), outbound
        group mapping is enforced: events with no mapped remote groups for this
        peer are suppressed. When None, group tagging is skipped (no-op
        backward-compatible)..
    peer_id : str
        The remote peer's federation server ID, used for registry lookups.
        Only meaningful when registry is not None.

    Returns
    -------
    fig_pb2.FederatedEvent | None
        Encoded proto ready to enqueue, or None if the event was dropped by
        loop-prevention, hop-limit, or group-policy. Raises on encode failure.
    """
    fed_meta = getattr(evt, "fed_meta", None)

    # --- Loop prevention ---
    if fed_meta and node_id in fed_meta.seen_server_ids:
        log.debug(
            "Loop prevention: dropping event %s (own node_id %s in provenance)",
            getattr(evt, "uid", "?"),
            node_id,
        )
        return None

    # --- Hop-limit enforcement ---
    if fed_meta and fed_meta.max_hops != -1:
        if fed_meta.current_hops >= fed_meta.max_hops:
            log.debug(
                "Hop limit: dropping event %s (hops %d >= max %d)",
                getattr(evt, "uid", "?"),
                fed_meta.current_hops,
                fed_meta.max_hops,
            )
            return None

    # --- Per-group hop-limit enforcement ---
    # When the inbound FederatedEvent carried FederateGroupHopLimits with
    # useFederateGroupHopLimits=True, check whether this event's group has a
    # tighter limit than the global max_hops. If so, apply it instead.
    # Option D : group name now sourced from evt.local_acl_groups sidecar
    # (set by firehose consumer) instead of TAKUser.group. If the sidecar
    # is absent (e.g. relay events from a peer, not from the local firehose)
    # the per-group hop-limit check is skipped (event_group_name stays None).
    if fed_meta and fed_meta.group_hop_limits is not None:
        limits = fed_meta.group_hop_limits
        if limits.useFederateGroupHopLimits:
            _local_acl = getattr(evt, "local_acl_groups", None)
            event_group_name = next(iter(_local_acl), None) if _local_acl else None

            if event_group_name is not None:
                for lim in limits.limits:
                    if lim.groupName == event_group_name:
                        # lim.currentHops tracks relay count within this group scope.
                        # If already at or past this group's limit, drop.
                        if lim.maxHops != -1 and lim.currentHops >= lim.maxHops:
                            log.debug(
                                "Per-group hop limit: dropping event %s "
                                "(group=%s hops %d >= group-max %d)",
                                getattr(evt, "uid", "?"),
                                event_group_name,
                                lim.currentHops,
                                lim.maxHops,
                            )
                            return None
                        break

    # --- Outbound group policy ---
    # Source: ACL cache sidecar (evt.local_acl_groups), set by the firehose
    # consumer ( / OtsRmqBus._on_firehose_message) from EudGroupCache.
    # This is the Phase-1→D source swap: replaces the CoT
    # <__group> XML extraction used in the Phase-1 interim fix.
    # Fail-closed semantics:
    #   - No sidecar (evt.local_acl_groups absent or None/empty): suppress.
    #     This covers cold-start cache misses, TTL-expired entries, and any
    #     event that was not dispatched through the OtsRmqBus firehose path.
    #   - Sidecar present but no outbound mapping for this peer: suppress
    #     (block-unmapped default; no change from prior behaviour).
    remote_groups: Optional[List[str]] = None  # None = no tagging
    if registry is not None and peer_id:
        local_acl_groups = getattr(evt, "local_acl_groups", None)
        if not local_acl_groups:
            # Cache miss or sidecar absent → fail-closed block.
            log.info(
                "Group policy: suppressing event uid=%s type=%s for peer %s "
                "(no ACL groups sidecar — cache miss, cold-start, or TTL expired)",
                getattr(evt, "uid", "?"),
                getattr(evt, "etype", "?"),
                peer_id,
            )
            return None

        local_groups = list(local_acl_groups)  # List[str] for map_outbound_groups
        remote_groups = registry.map_outbound_groups(peer_id, local_groups)
        if not remote_groups:
            # INFO-level drop-log: uid, etype, local groups, peer — observability
            # per human-requested convention.
            log.info(
                "Group policy: suppressing event uid=%s type=%s local_groups=%r "
                "for peer %s (no mapped outbound group — block-unmapped default)",
                getattr(evt, "uid", "?"),
                getattr(evt, "etype", "?"),
                local_groups,
                peer_id,
            )
            return None

    # --- Provenance append + hop increment ---
    if fed_meta is None:
        new_fed_meta = FedMeta(
            seen_server_ids=[node_id],
            current_hops=1,
            max_hops=default_max_hops,
        )
    else:
        new_fed_meta = FedMeta(
            seen_server_ids=list(fed_meta.seen_server_ids) + [node_id],
            current_hops=fed_meta.current_hops + 1,
            max_hops=fed_meta.max_hops,
        )

    proto = encode_federated_event(evt, new_fed_meta)

    # --- Set FederatedEvent.federateGroups ---
    if remote_groups:
        del proto.federateGroups[:]
        proto.federateGroups.extend(remote_groups)

    return proto


def decode_contact_entry(
    proto: "fig_pb2.FederatedEvent",
) -> Optional["fig_pb2.ContactListEntry"]:
    """Extract a ContactListEntry from a FederatedEvent, if present.

    Returns None if proto.contact is not set (HasField returns False).
    CRUD semantics:
        CREATE (1) / UPDATE (3) → insert/update FederatedContactRegistry
        DELETE (4)              → remove from FederatedContactRegistry
        READ (2)                → ignored (no-op in Phase 1)
        INVALID (0)             → ignored

    The registry management itself is owned by the transport layer
    (FederateClient / FederatedContactRegistry); this function only extracts
    and returns the ContactListEntry for the caller to act on.

    Parameters
    ----------
    proto : fig_pb2.FederatedEvent

    Returns
    -------
    fig_pb2.ContactListEntry | None
    """
    if not proto.HasField("contact"):
        return None
    return proto.contact


def synthesize_contact_event(
    contact: "fig_pb2.ContactListEntry",
) -> Optional[models.Event]:
    """Synthesize a CoT models.Event from a federated ContactListEntry.

    Implements the minimal contact routing specified in:
      CREATE (1) / UPDATE (3) → a-f-G-U-C presence event (stale +30 min)
      DELETE (4)               → tombstone a-f-G-U-C (stale 1 s in the past)
      READ (2) / INVALID (0)  → None (ignored)

    The synthesized event carries a <detail> with <contact> and <uid Droid>
    sub-elements so clients display the entry in their contact list.
    No position data is available from ContactListEntry, so lat/lon/hae are
    left at 0.0 — ATAK treats position-less presence events as contact-list
    entries only (no map plot).

    ContactListEntry routing: the synthesized CoT event is injected via
    LocalBus → OTS using bridge.enqueue, the same path as regular inbound
    events..

    Parameters
    ----------
    contact : fig_pb2.ContactListEntry

    Returns
    -------
    models.Event | None
        Synthesized event, or None for ignored CRUD operations.
    """
    _CRUD_CREATE = 1
    _CRUD_READ = 2
    _CRUD_UPDATE = 3
    _CRUD_DELETE = 4

    op = contact.operation
    if op in (_CRUD_READ, 0):  # INVALID or READ
        return None

    uid = contact.uid
    if not uid:
        log.debug("synthesize_contact_event: ContactListEntry has no uid — ignoring")
        return None

    now = datetime.utcnow()
    if op in (_CRUD_CREATE, _CRUD_UPDATE):
        stale = now + timedelta(minutes=30)
    elif op == _CRUD_DELETE:
        # Tombstone: stale already past so clients remove the contact from their list.
        stale = now - timedelta(seconds=1)
    else:
        return None

    evt = models.Event(
        uid=uid,
        etype="a-f-G-U-C",
        how="h-g-i-g-o",
        time=now,
        start=now,
        stale=stale,
    )
    # No position data available from ContactListEntry; leave at proto-default 0.
    evt.point = models.Point(lat=0.0, lon=0.0, hae=0.0, ce=9999999.0, le=9999999.0)

    # Build a minimal <detail> element for contact display in ATAK / OTS.
    detail_elm = etree.Element("detail")
    contact_elm = etree.SubElement(detail_elm, "contact")
    contact_elm.set("callsign", contact.callsign or uid)
    if contact.phone:
        contact_elm.set("phone", contact.phone)
    if contact.sip:
        contact_elm.set("xmppUsername", contact.sip)
    if contact.directConnect:
        contact_elm.set("endpoint", contact.directConnect)

    uid_elm = etree.SubElement(detail_elm, "uid")
    uid_elm.set("Droid", contact.callsign or uid)

    evt.detail = Detail(detail_elm)
    return evt
