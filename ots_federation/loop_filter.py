# ots_federation/loop_filter.py
# LoopFilter — Option A (CoT detail-element mapping) implementation.
# Decision: closed (Option A confirmed 2026-07-09).
# Research basis: .qmd
# Two seams are provided so the filter is injectable (constructor arg):
#   stamp_inbound(cot_xml, fed_meta) → str
#     Called by OtsRmqBus.inject BEFORE publishing to the cot_parser exchange.
#     Stamps <_fedprov server_id="our_id" chain="prior,..."/> and
#     <_fedhops max_hops="M" current_hops="C"/> into the CoT <detail> element.
#     This enables echo detection when the event returns on the firehose.
#   should_relay_outbound(cot_xml, fed_meta) → bool
#     Called by OtsRmqBus start_consuming loop for every firehose event.
#     Returns False (drop) when:
#       - <_fedprov server_id="our_id"> found (echo: our own injection)
#       - our_id appears in <_fedprov chain="..."> (transitive loop)
#     Returns True for local events (no _fedprov present).
#     Malformed XML → True (graceful degradation; test N2).
#   clean_for_relay(cot_xml) → str
#     Strips all <_fedprov> and <_fedhops> from <detail> before parsing into
#     models.Event and calling manager.on_outbound. Spoof defense: prevents
#     local ATAK clients from injecting false provenance or inflated hop counts
#     that would be passed to the gRPC encoding layer (test U7).
#   should_inject_inbound(cot_xml, fed_meta) → bool
#     Injectable seam for the inbound-from-peer path. Currently always True:
#     OTS should receive all federated events for local ATAK client delivery.
#     Hop-limit enforcement for relay to SUBSEQUENT peers is handled by
#     codec.prepare_outbound_event (which checks fed_meta.current_hops).
# Dedup cache (optional, test N3):
#     LoopFilter accepts dedup_window_secs=0 (disabled). When >0, a rolling
#     TTL dict keyed by (uid, time-bucket) suppresses duplicate UIDs within
#     the window. Useful when two OTS peers are misconfigured with the same
#     UID namespace.
# Threat model — echo-forge DoS (KNOWN LIMITATION, ACCEPTED):
#     A local ATAK client that forges <_fedprov server_id="OUR_SERVER_ID"/>
#     into its outbound CoT event causes should_relay_outbound to return
#     False for that specific event (echo-suppression DoS — the event is
#     silently not federated to peers).
#     Affected scope: ONLY the forging client's own events are suppressed.
#     All events from other senders continue to pass should_relay_outbound
#     normally; this is NOT a broadcast DoS.  Severity: LOCAL CLIENT, OWN
#     EVENTS ONLY.
#     The bypass direction is fully protected: clean_for_relay strips all
#     <_fedprov>/<_fedhops> direct children of <detail> before the event
#     reaches codec.prepare_outbound_event; the codec reads hop counts
#     exclusively from fed_meta (decoded from the gRPC proto), never from
#     the CoT XML detail element.  A local client cannot inflate hop counts
#     or spoof provenance to bypass the relay layer.
#     See also: test_loop_filter.py::TestEchoForgeDosThreatModel.

import logging
import time
from collections import OrderedDict
from typing import List, Optional

from lxml import etree

log = logging.getLogger(__name__)

FEDPROV_TAG = "_fedprov"
FEDHOPS_TAG = "_fedhops"

# Maximum entries in the dedup cache before oldest are evicted.
_DEDUP_CACHE_MAX = 2048


class LoopFilter:
    """
    CoT detail-element loop prevention filter (Option A).

    Injectable: pass an instance to OtsRmqBus constructor so tests can
    substitute custom subclasses or spy instances.

    Parameters
    ----------
    server_id : str
        This server's stable federation identity (matches [federation] server_id
        in federation.ini). Used for echo detection and provenance stamping.
    max_hops : int
        Global default hop limit. -1 = unlimited.  Used in stamp_inbound when
        fed_meta.max_hops == -1 (i.e. no per-event override).
    dedup_window_secs : float
        Time window for UID-based dedup (test N3).  0 = disabled (default).
        When >0, a second event with the same UID within this window is dropped
        by should_relay_outbound regardless of provenance.
    """

    def __init__(
        self,
        server_id: str,
        max_hops: int = 3,
        dedup_window_secs: float = 0.0,
    ):
        self.server_id = server_id
        self.max_hops = max_hops
        self.dedup_window_secs = dedup_window_secs
        # Dedup cache: uid → last_seen_time (OrderedDict for LRU eviction)
        self._dedup: "OrderedDict[str, float]" = OrderedDict()

    # ------------------------------------------------------------------
    # Inbound path helpers (peers → OTS cot_parser)
    # ------------------------------------------------------------------

    def stamp_inbound(self, cot_xml: str, fed_meta) -> str:
        """
        Stamp ``<_fedprov>`` and ``<_fedhops>`` into a CoT XML string.

        Called by OtsRmqBus.inject before publishing to the cot_parser
        exchange so the firehose consumer can recognise this event as our
        injection (echo detection via should_relay_outbound).

        Provenance accumulation (test U6): fed_meta.seen_server_ids are written
        to the ``chain`` attribute; our server_id is written to ``server_id``.
        The full path is therefore chain + server_id (monotonically growing).

        Hop recording (test U1, U5): current_hops and max_hops are recorded
        as-is from fed_meta.  Hop INCREMENT when forwarding to a subsequent
        peer is handled by codec.prepare_outbound_event at the gRPC level.

        Parameters
        ----------
        cot_xml : str
            Raw CoT event XML string.
        fed_meta
            FedMeta sidecar (ots_federation.codec.FedMeta) from the decoded
            FederatedEvent proto.  Must have seen_server_ids, current_hops
            max_hops attributes.

        Returns
        -------
        str
            Modified CoT XML.  On parse error returns cot_xml unchanged.
        """
        try:
            parser = etree.XMLParser(resolve_entities=False)
            root = etree.fromstring(cot_xml.encode("utf-8"), parser=parser)
        except etree.XMLSyntaxError as exc:
            log.warning(
                "loop_filter.stamp_inbound: XML parse error, not stamping: %s", exc
            )
            return cot_xml

        # Find or create <detail>
        detail = root.find("detail")
        if detail is None:
            detail = etree.SubElement(root, "detail")

        # Build <_fedprov server_id="our_id" chain="prior1,prior2,..."/>
        # The chain attribute records all server IDs that processed this event
        # BEFORE us.  Together with server_id they form the full provenance list
        # (test U6: no deduplication; list strictly grows per hop).
        prior_ids: List[str] = list(getattr(fed_meta, "seen_server_ids", []))
        fedprov_elm = etree.SubElement(detail, FEDPROV_TAG)
        fedprov_elm.set("server_id", self.server_id)
        if prior_ids:
            fedprov_elm.set("chain", ",".join(prior_ids))

        # Build <_fedhops max_hops="M" current_hops="C"/>
        # max_hops from fed_meta; fall back to our configured default when -1
        # (unlimited) is not explicitly desired (edge: fed_meta.max_hops == 0
        # should not happen after the codec's None→-1 normalisation, but guard
        # it anyway by treating 0 == -1 per codec convention).
        max_hops_val = getattr(fed_meta, "max_hops", -1)
        if max_hops_val == 0:
            max_hops_val = -1
        current_hops_val = getattr(fed_meta, "current_hops", 0)

        fedhops_elm = etree.SubElement(detail, FEDHOPS_TAG)
        fedhops_elm.set("max_hops", str(max_hops_val))
        fedhops_elm.set("current_hops", str(current_hops_val))

        return etree.tostring(root, encoding="unicode")

    def should_inject_inbound(self, cot_xml: str, fed_meta=None) -> bool:
        """
        Returns True if a federated event from a peer should be injected into OTS.

        Currently always True: OTS should receive all federated events for local
        ATAK delivery regardless of hop count.  Hop-limit enforcement for relay
        to SUBSEQUENT peers is handled by codec.prepare_outbound_event (which
        increments current_hops and compares against max_hops).

        This is the injectable seam; override in subclasses to add pre-inject
        filtering (e.g., content-type gating, group-level admission control).

        Parameters
        ----------
        cot_xml : str
            Raw CoT XML (pre-stamp).
        fed_meta : FedMeta, optional
            Provenance sidecar.

        Returns
        -------
        bool
        """
        return True

    # ------------------------------------------------------------------
    # Outbound path helpers (firehose → federation peers)
    # ------------------------------------------------------------------

    def should_relay_outbound(self, cot_xml: str, fed_meta=None) -> bool:
        """
        Returns True if a firehose event should be relayed to federation peers.

        Drop conditions (return False):
        1. Our server_id in any ``<_fedprov server_id="...">`` attribute
           (echo: our own injection returning via OTS firehose).
        2. Our server_id in any ``<_fedprov chain="...">`` comma-separated list
           (transitive loop: event already passed through us on a prior hop).
        3. UID-based dedup: if dedup_window_secs > 0 and the same UID was seen
           within the dedup window (test N3).

        Events with ``<_fedprov>`` from OTHER servers (local ATAK re-broadcasting
        a previously received federated event) are NOT dropped here — the caller
        must then call clean_for_relay to strip the elements before encoding
        (spoof defense, test U7).

        Malformed XML → True (graceful degradation, test N2).
        Missing ``<detail>`` or no ``<_fedprov>`` → True (local event).

        Parameters
        ----------
        cot_xml : str
            CoT XML string from the OTS firehose consumer.
        fed_meta
            Unused (kept for injectable interface symmetry with
            should_inject_inbound).

        Returns
        -------
        bool
        """
        try:
            parser = etree.XMLParser(resolve_entities=False)
            root = etree.fromstring(cot_xml.encode("utf-8"), parser=parser)
        except etree.XMLSyntaxError as exc:
            log.warning(
                "loop_filter.should_relay_outbound: malformed XML, treating as "
                "local event: %s",
                exc,
            )
            return True  # N2: graceful degradation
        except Exception as exc:  # pylint: disable=broad-except
            log.warning(
                "loop_filter.should_relay_outbound: unexpected parse error, "
                "treating as local event: %s",
                exc,
            )
            return True

        uid = root.get("uid", "")

        # Dedup cache check (test N3): optional, disabled by default.
        if self.dedup_window_secs > 0 and uid:
            now = time.time()
            last_seen = self._dedup.get(uid)
            if last_seen is not None and (now - last_seen) < self.dedup_window_secs:
                log.debug(
                    "loop_filter: UID dedup drop uid=%s (seen %.1fs ago, window=%.1fs)",
                    uid,
                    now - last_seen,
                    self.dedup_window_secs,
                )
                return False
            # Update / insert in dedup cache with LRU eviction.
            self._dedup[uid] = now
            self._dedup.move_to_end(uid)
            if len(self._dedup) > _DEDUP_CACHE_MAX:
                self._dedup.popitem(last=False)

        detail = root.find("detail")
        if detail is None:
            return True  # No detail → no fedprov stamp → local event

        for elem in detail.findall(FEDPROV_TAG):
            stamped_by = elem.get("server_id", "")
            if stamped_by == self.server_id:
                log.debug(
                    "loop_filter: echo detected (server_id=%s in _fedprov), "
                    "dropping uid=%s",
                    self.server_id,
                    uid,
                )
                return False  # U2: echo suppression

            # Check the chain attribute for transitive loops (U2 extended).
            chain_raw = elem.get("chain", "")
            if chain_raw:
                for chain_id in chain_raw.split(","):
                    if chain_id.strip() == self.server_id:
                        log.debug(
                            "loop_filter: transitive loop (server_id=%s in chain), "
                            "dropping uid=%s",
                            self.server_id,
                            uid,
                        )
                        return False

        return True

    def clean_for_relay(self, cot_xml: str) -> str:
        """
        Strip all ``<_fedprov>`` and ``<_fedhops>`` child elements from ``<detail>``.

        Called AFTER should_relay_outbound returns True, before parsing the
        event into models.Event and calling manager.on_outbound.

        Spoof defense (test U7): even if a local ATAK client injects
        ``<_fedhops max_hops="1000"/>`` or ``<_fedprov server_id="fake">``, we
        strip them so the gRPC codec layer receives clean CoT.
        codec.prepare_outbound_event then stamps fresh hops independently
        (re-stamps from its own tracking, not from the CoT XML detail).

        Malformed XML → returns cot_xml unchanged (no crash, test N2).

        Parameters
        ----------
        cot_xml : str
            CoT XML string (possibly containing ``<_fedprov>``/``<_fedhops>``).

        Returns
        -------
        str
            Cleaned CoT XML.
        """
        try:
            parser = etree.XMLParser(resolve_entities=False)
            root = etree.fromstring(cot_xml.encode("utf-8"), parser=parser)
        except etree.XMLSyntaxError:
            return cot_xml  # N2: graceful degradation
        except Exception:  # pylint: disable=broad-except
            return cot_xml

        detail = root.find("detail")
        if detail is None:
            return cot_xml

        # Remove direct <_fedprov> and <_fedhops> children of <detail>.
        for tag in (FEDPROV_TAG, FEDHOPS_TAG):
            for elem in list(detail.findall(tag)):
                detail.remove(elem)

        return etree.tostring(root, encoding="unicode")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def parse_fedprov(self, cot_xml: str):
        """
        Extract provenance and hop data from a stamped CoT XML string.

        Used by tests for round-trip verification (U1).

        Returns
        -------
        dict with keys:
            server_id : str   (from <_fedprov server_id="...">)
            chain : list[str] (from <_fedprov chain="..."> split on ',')
            max_hops : int    (from <_fedhops max_hops="...">)
            current_hops : int (from <_fedhops current_hops="...">)
        Returns None if the elements are not found.
        """
        try:
            parser = etree.XMLParser(resolve_entities=False)
            root = etree.fromstring(cot_xml.encode("utf-8"), parser=parser)
        except Exception:  # pylint: disable=broad-except
            return None

        detail = root.find("detail")
        if detail is None:
            return None

        fedprov_elm = detail.find(FEDPROV_TAG)
        fedhops_elm = detail.find(FEDHOPS_TAG)

        if fedprov_elm is None and fedhops_elm is None:
            return None

        result = {}
        if fedprov_elm is not None:
            result["server_id"] = fedprov_elm.get("server_id", "")
            chain_raw = fedprov_elm.get("chain", "")
            result["chain"] = [x.strip() for x in chain_raw.split(",") if x.strip()] if chain_raw else []

        if fedhops_elm is not None:
            try:
                result["max_hops"] = int(fedhops_elm.get("max_hops", "-1"))
                result["current_hops"] = int(fedhops_elm.get("current_hops", "0"))
            except ValueError:
                pass

        return result or None
