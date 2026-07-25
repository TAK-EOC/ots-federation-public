# ots_federation/ots_bus.py
# OtsRmqBus — RabbitMQ-backed LocalBus implementation for the OTS bridge child
# process (engine_main.py).
# Implements bus.LocalBus.inject so the FederationBridge can deliver inbound
# federated events into OTS via the cot_parser exchange. Also provides the
# firehose consumer that picks up local OTS events and routes them through
# manager.on_outbound to federation peers.
# Ticket: 2fd76c (bridge module)
# Research: .qmd §5
#           .qmd §3
# Option D additions (tickets 3d5216/ad6034/aa9b62, epic 1c88b3):
#   - EudGroupCache: thread-safe uid→ACL-groups cache (eud_group_cache.py).
#   - Groups exchange subscriber : dedicated pika connection consuming
#     the OTS 'groups' topic exchange with '#' binding; populates the cache.
#   - Firehose fail-closed sidecar : firehose on_message looks up the
#     cache; miss → fail-closed block; hit → attaches local_acl_groups sidecar
#     to evt before calling manager.on_outbound.
# Threading model:
#   Three separate pika.BlockingConnections are used:
#     - _pub_conn         : publish path (inject from bridge-drain thread)
#     - _sub_conn         : firehose subscribe (main thread, start_consuming)
#     - _groups_sub_conn  : groups exchange subscribe (daemon thread
#                           _groups_subscribe_loop, started by
#                           start_groups_subscriber)
#   pika.BlockingConnection is NOT thread-safe; keeping them separate is required.
# Graceful shutdown:
#   Caller sets a threading.Event (stop_event) before calling stop_consuming
#   or letting the SIGTERM handler fire.  start_consuming polls stop_event
#   via process_data_events(time_limit=1.0) and returns when it is set.
#   The groups subscriber loop uses the same stop_event.

import json
import logging
import threading
from typing import TYPE_CHECKING, FrozenSet, Optional

from lxml import etree

from ots_federation.models.event import Event
from ots_federation.models.errors import UnmarshalError
from ots_federation.eud_group_cache import EudGroupCache

if TYPE_CHECKING:
    import pika
    from ots_federation.loop_filter import LoopFilter
    from ots_federation.manager import FederationManager

log = logging.getLogger(__name__)

# RabbitMQ exchange names (must match OTS defaults, app.py:162-174)
_EXCHANGE_FIREHOSE = "firehose"
_EXCHANGE_COT_PARSER = "cot_parser"
_ROUTING_KEY_COT_PARSER = "cot_parser"

# Groups topic exchange (OTS, Option D —)
_EXCHANGE_GROUPS = "groups"
_ROUTING_KEY_GROUPS_WILDCARD = "#"  # matches all routing keys incl. nested dots

# DMs direct exchange: OTS EUDs bind per-callsign queues here (EudHandler.py:596-599).
# Marti-addressed inbound events must be published here so OTS delivers only to the
# named callsign(s), not to every EUD in the mapped ACL group.
# Reference: vendor/OpenTAKServer/opentakserver/cot_parser/cot_parser.py:1153-1160
_EXCHANGE_DMS = "dms"


def _evt_to_xml(evt: "Event") -> str:
    """Serialise a models.Event to a CoT XML string."""
    return etree.tostring(evt.as_element, encoding="unicode")


def _parse_cot_xml(cot_xml: str) -> Optional["Event"]:
    """
    Parse a CoT XML string into a models.Event.

    Returns None on any parse failure (malformed XML, missing required
    fields, etc.).  Does not raise.
    """
    if not cot_xml:
        return None
    try:
        parser = etree.XMLParser(resolve_entities=False)
        root = etree.fromstring(cot_xml.encode("utf-8"), parser=parser)
        return Event.from_elm(root)
    except UnmarshalError as exc:
        log.warning("ots_bus: CoT parse error (UnmarshalError): %s", exc)
        return None
    except etree.XMLSyntaxError as exc:
        log.warning("ots_bus: CoT XML syntax error: %s", exc)
        return None
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("ots_bus: unexpected CoT parse error: %s", exc)
        return None


class OtsRmqBus:
    """
    RabbitMQ-backed LocalBus for the federation engine child process.

    Bridges two directions:
      - Inbound (peer → OTS): inject(src, evt) publishes to cot_parser exchange.
      - Outbound (OTS → peers): start_consuming reads from firehose fanout and
        calls manager.on_outbound for events that pass the loop filter and
        ACL cache lookup.

    Option D:
      A third pika connection subscribes to the OTS 'groups' topic exchange
      (via start_groups_subscriber) and populates the EudGroupCache. The
      firehose consumer uses the cache for fail-closed group policy enforcement
      before calling manager.on_outbound.

    Parameters
    ----------
    host : str
        RabbitMQ host (OTS_RMQHOST).
    port : int
        RabbitMQ AMQP port (OTS_RMQPORT, typically 5672).
    user : str
        RabbitMQ username (OTS_RMQUSER).
    password : str
        RabbitMQ password (OTS_RMQPASS).
    loop_filter : LoopFilter
        LoopFilter instance for echo detection and spoof defense.
    eud_group_cache : EudGroupCache
        Cache populated by groups exchange subscriber; consumed by firehose
        consumer for fail-closed ACL group sourcing (Option D/).
    pub_fail_threshold : int
        Number of consecutive publish failures that trigger an in-place
        reconnect attempt of the publish connection.  If the reconnect also
        fails, stop_event is set so the engine exits cleanly and the plugin
        watchdog restarts the process.  Default 5.
    inject_cot_parser : bool
        Option D inbound delivery flag (-D-forks-resolved).
        When False (default): inbound events are published ONLY to the 'groups'
        topic exchange (routing-key <local_group>.OUT per mapped group) — clean
        delivery, no __ANON__ over-share.  When True: ALSO publish to cot_parser
        for OTS DB persistence (accepts the __ANON__ side-delivery).
        Default False.
    """

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        loop_filter: "LoopFilter",
        eud_group_cache: EudGroupCache,
        pub_fail_threshold: int = 5,
        inject_cot_parser: bool = False,
        group_resolver=None,
    ):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._loop_filter = loop_filter
        self._eud_group_cache = eud_group_cache
        self._pub_fail_threshold = pub_fail_threshold
        self._inject_cot_parser = inject_cot_parser
        # Authoritative synchronous group resolver (OTS DB). On a cache
        # miss we resolve directly instead of racing the async groups exchange.
        # None => no DB access; cache miss stays fail-closed (prior behavior).
        self._group_resolver = group_resolver

        # pika connections; set after connect
        self._pub_conn: Optional["pika.BlockingConnection"] = None
        self._pub_ch = None
        self._sub_conn: Optional["pika.BlockingConnection"] = None
        self._sub_ch = None
        self._sub_queue_name: str = ""

        # Groups exchange subscriber connection (Option D)
        self._groups_sub_conn: Optional["pika.BlockingConnection"] = None
        self._groups_sub_ch = None
        self._groups_queue_name: str = ""

        # Serialise inject calls from the bridge-drain thread.
        self._pub_lock = threading.Lock()

        # Consecutive publish-failure counter (reset on success or reconnect).
        self._pub_fail_count: int = 0

        # Reference to the engine's stop_event; set by start_consuming.
        # When a publish-connection failure cannot be recovered, this is set
        # so the engine exits cleanly and the plugin watchdog restarts it.
        self._stop_event: Optional[threading.Event] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """
        Open all three pika connections (publish, firehose subscribe, groups subscribe).

        Call this once from engine_main before starting the groups subscriber
        thread, bridge-drain thread, and the firehose consuming loop.
        """
        import pika  # runtime import; pika not required at module load time

        creds = pika.PlainCredentials(self._user, self._password)
        params = pika.ConnectionParameters(
            host=self._host,
            port=self._port,
            credentials=creds,
        )
        # Publish connection uses heartbeat=0: pika.BlockingConnection does NOT
        # process heartbeats while idle between inject() calls.  The connection
        # can sit unused for 5-8 min between federated PLIs; RabbitMQ's default
        # 60s heartbeat deadline kills it before the next inject() fires.
        # heartbeat=0 disables the server-side enforcement; TCP keepalives handle
        # liveness on the loopback connection.  The subscribe connections are not
        # affected — they call process_data_events(time_limit=1.0) in a tight
        # loop which drives the heartbeat I/O path normally.  Ticket: 3fc530.
        pub_params = pika.ConnectionParameters(
            host=self._host,
            port=self._port,
            credentials=creds,
            heartbeat=0,
        )

        # --- Publish connection (inject path) ---
        self._pub_conn = pika.BlockingConnection(pub_params)
        self._pub_ch = self._pub_conn.channel()
        log.info(
            "Connected to RabbitMQ publish channel (%s:%d)", self._host, self._port
        )

        # --- Firehose subscribe connection (main thread consumer) ---
        self._sub_conn = pika.BlockingConnection(params)
        self._sub_ch = self._sub_conn.channel()

        # Declare an ephemeral, auto-delete queue and bind to the firehose fanout.
        # OTS declares the firehose exchange at startup (app.py:162), so we just
        # bind.  queue='', auto_delete=True gives us a server-named ephemeral queue.
        result = self._sub_ch.queue_declare(queue="", auto_delete=True)
        self._sub_queue_name = result.method.queue
        self._sub_ch.queue_bind(
            exchange=_EXCHANGE_FIREHOSE, queue=self._sub_queue_name
        )
        log.info(
            "Connected to firehose exchange (ephemeral queue: %s)",
            self._sub_queue_name,
        )

        # --- Groups exchange subscribe connection (Option D) ---
        # Separate connection required: pika.BlockingConnection is not thread-safe.
        self._groups_sub_conn = pika.BlockingConnection(params)
        self._groups_sub_ch = self._groups_sub_conn.channel()

        # Ephemeral auto-delete queue bound to the 'groups' topic exchange.
        # '#' wildcard matches all routing keys (e.g. 'FIRE-OPS.OUT', '__ANON__.OUT').
        groups_result = self._groups_sub_ch.queue_declare(queue="", auto_delete=True)
        self._groups_queue_name = groups_result.method.queue
        self._groups_sub_ch.queue_bind(
            exchange=_EXCHANGE_GROUPS,
            queue=self._groups_queue_name,
            routing_key=_ROUTING_KEY_GROUPS_WILDCARD,
        )
        log.info(
            "Connected to groups exchange (ephemeral queue: %s)",
            self._groups_queue_name,
        )

    def _reconnect_pub(self) -> bool:
        """
        Attempt to reconnect the publish connection in-place.

        MUST be called while self._pub_lock is held (i.e. from inject).
        Closes any existing broken publish connection, opens a fresh one, and
        re-assigns self._pub_conn / self._pub_ch.

        Returns
        -------
        bool
            True if the reconnect succeeded; False otherwise.
        """
        log.warning("ots_bus: closing broken publish connection for reconnect")
        if self._pub_conn is not None:
            try:
                self._pub_conn.close()
            except Exception:  # pylint: disable=broad-except
                pass
        self._pub_conn = None
        self._pub_ch = None

        try:
            import pika  # runtime import (same as connect)

            creds = pika.PlainCredentials(self._user, self._password)
            # heartbeat=0 here for the same reason as in connect(): the publish
            # connection is idle between inject() calls.  Ticket: 3fc530.
            pub_params = pika.ConnectionParameters(
                host=self._host,
                port=self._port,
                credentials=creds,
                heartbeat=0,
            )
            self._pub_conn = pika.BlockingConnection(pub_params)
            self._pub_ch = self._pub_conn.channel()
            log.info(
                "ots_bus: publish-connection reconnect succeeded (%s:%d)",
                self._host,
                self._port,
            )
            return True
        except Exception as exc:  # pylint: disable=broad-except
            log.error("ots_bus: publish-connection reconnect failed: %s", exc)
            self._pub_conn = None
            self._pub_ch = None
            return False

    def close(self) -> None:
        """Close all three pika connections cleanly."""
        for name, conn in (
            ("publish", self._pub_conn),
            ("subscribe", self._sub_conn),
            ("groups-subscribe", self._groups_sub_conn),
        ):
            if conn is not None:
                try:
                    conn.close()
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("ots_bus: error closing %s connection: %s", name, exc)
        self._pub_conn = None
        self._pub_ch = None
        self._sub_conn = None
        self._sub_ch = None
        self._groups_sub_conn = None
        self._groups_sub_ch = None

    # ------------------------------------------------------------------
    # Inbound path: LocalBus.inject implementation
    # ------------------------------------------------------------------

    def inject(
        self,
        src,
        evt,
        local_groups: Optional[FrozenSet[str]] = None,
    ) -> None:
        """
        Inject a federated event from a peer into OTS.

        Called by FederationBridge.drain for each decoded inbound FederatedEvent.
        The evt may carry a FedMeta sidecar as evt.fed_meta (set by the transport
        layer before bridge.enqueue).

        Option D inbound delivery (-D-forks-resolved):

        When *local_groups* is provided and non-empty:
          - Publish to the OTS 'groups' topic exchange with routing key
            ``<local_group>.OUT`` for each mapped local group.  This delivers
            the event to SSL-grouped EUDs whose queues are bound to those routing
            keys, WITHOUT touching __ANON__ (clean group-only delivery).
          - If ``self._inject_cot_parser`` is True: ALSO publish to the
            cot_parser exchange for OTS DB persistence.  This accepts the
            __ANON__ side-delivery that cot_parser.route_cot causes when
            user_id=None is injected.

        When *local_groups* is None or empty (no group mapping — e.g. synthesized
        contact events, or events where no inbound group policy applied):
          - Fall back to the original cot_parser-only publish (backward compat).

        Steps:
          1. should_inject_inbound check (injectable seam — always True for now).
          2. Serialise evt to CoT XML.
          3. Stamp <_fedprov>/<_fedhops> via loop_filter.stamp_inbound.
          4a. If local_groups: publish to groups exchange per group.
          4b. If inject_cot_parser or no local_groups: publish to cot_parser.

        Thread safety: protected by self._pub_lock so the bridge-drain thread can
        call this while the main thread manages the subscription connection.

        Parameters
        ----------
        src
            The federate peer link that delivered the event (passed through for
            loop-prevention in on_outbound; not used here).
        evt : models.Event
            Decoded CoT event with optional evt.fed_meta sidecar.
        local_groups : frozenset[str] | None
            Mapped local OTS ACL group names (from evt.inbound_local_groups set by
            the transport layer after registry.map_inbound_groups).  None means
            no group mapping is available; fall back to cot_parser publish.
        """
        fed_meta = getattr(evt, "fed_meta", None)

        # Injectable seam: skip inject if filter says no.
        cot_xml = _evt_to_xml(evt)
        if not self._loop_filter.should_inject_inbound(cot_xml, fed_meta):
            log.debug("ots_bus.inject: should_inject_inbound=False, dropping uid=%s", evt.uid)
            return

        # Stamp provenance and hop data into the CoT XML before injecting.
        if fed_meta is not None:
            cot_xml = self._loop_filter.stamp_inbound(cot_xml, fed_meta)

        with self._pub_lock:
            if self._pub_ch is None:
                log.error("ots_bus.inject: publish channel not open, dropping uid=%s", evt.uid)
                return
            try:
                if local_groups:
                    # Directed-event detection:
                    #   Marti-addressed events (<detail><marti><dest callsign="..."/></marti>)
                    #   must be published to the OTS 'dms' direct exchange with per-callsign
                    #   routing keys so OTS delivers them only to the named EUD(s).
                    #   Publishing marti events to '<group>.OUT' would fan-out to ALL EUDs in
                    #   the group — a privacy leak not present in native OTS routing.
                    #
                    #   Reference: OTS route_cot() (cot_parser.py:1147-1171) publishes marti
                    #   events to dms/<callsign>; EUDs bind dms/<callsign> per EudHandler.py:596-599.
                    #
                    #   Directed GeoChat (b-t-f, no <dest> tags) is left on the groups exchange:
                    #   OTS core also delivers GeoChat to all group members natively (route_cot
                    #   has no per-UID GeoChat routing path).  That is an OTS core limitation,
                    #   not a plugin defect. This is a human-decision item — see the module's test suite.
                    _detail = evt.detail
                    if _detail is not None and getattr(_detail, "has_marti", False):
                        # --- Marti-addressed: dms exchange, per callsign ---
                        body_dms = json.dumps({"uid": evt.uid, "cot": cot_xml})
                        for callsign in _detail.marti_cs:
                            if callsign:
                                self._pub_ch.basic_publish(
                                    exchange=_EXCHANGE_DMS,
                                    routing_key=callsign,
                                    body=body_dms,
                                )
                                log.debug(
                                    "ots_bus.inject: published uid=%s to dms/%s "
                                    "(marti-addressed directed delivery)",
                                    evt.uid, callsign,
                                )
                    else:
                        # --- Non-marti: groups exchange delivery ---
                        # Publish once per mapped local group so SSL-grouped EUDs
                        # receive the event without __ANON__ over-share.
                        # Directed GeoChat is included here — OTS core delivers
                        # GeoChat to all group members regardless of addressing.
                        body_groups = json.dumps({"uid": evt.uid, "cot": cot_xml})
                        for group_name in local_groups:
                            self._pub_ch.basic_publish(
                                exchange=_EXCHANGE_GROUPS,
                                routing_key=f"{group_name}.OUT",
                                body=body_groups,
                            )
                            log.debug(
                                "ots_bus.inject: published uid=%s to groups/%s.OUT",
                                evt.uid, group_name,
                            )

                    # Additionally publish to cot_parser for DB persistence only
                    # when explicitly opted in (accepts __ANON__ side-delivery for
                    # group events; marti events get a second dms delivery from OTS
                    # route_cot — accepted for DB persistence).
                    if self._inject_cot_parser:
                        body_cot = json.dumps({"uid": evt.uid, "cot": cot_xml, "user_id": None})
                        self._pub_ch.basic_publish(
                            exchange=_EXCHANGE_COT_PARSER,
                            routing_key=_ROUTING_KEY_COT_PARSER,
                            body=body_cot,
                        )
                        log.debug(
                            "ots_bus.inject: published uid=%s to cot_parser (inject_cot_parser=True)",
                            evt.uid,
                        )
                else:
                    # --- Fallback: cot_parser only (no local_groups — backward compat) ---
                    # For marti events on this path, OTS route_cot will handle directed
                    # delivery to dms/<callsign> correctly (route_cot detects <dest> tags).
                    body = json.dumps({"uid": evt.uid, "cot": cot_xml, "user_id": None})
                    self._pub_ch.basic_publish(
                        exchange=_EXCHANGE_COT_PARSER,
                        routing_key=_ROUTING_KEY_COT_PARSER,
                        body=body,
                    )
                    log.debug("ots_bus.inject: published uid=%s to cot_parser (fallback)", evt.uid)

                self._pub_fail_count = 0  # reset consecutive-failure counter

            except Exception as exc:  # pylint: disable=broad-except
                log.error("ots_bus.inject: publish failed for uid=%s: %s", evt.uid, exc)
                self._pub_fail_count += 1
                if self._pub_fail_count >= self._pub_fail_threshold:
                    log.warning(
                        "ots_bus: %d consecutive publish failures (threshold=%d); "
                        "attempting in-place publish-connection reconnect",
                        self._pub_fail_count,
                        self._pub_fail_threshold,
                    )
                    if self._reconnect_pub():
                        self._pub_fail_count = 0
                    else:
                        log.error(
                            "ots_bus: publish-connection reconnect failed; "
                            "signalling engine termination so the watchdog "
                            "can restart the process cleanly",
                        )
                        if self._stop_event is not None:
                            self._stop_event.set()

    # ------------------------------------------------------------------
    # Groups exchange subscriber (Option D)
    # ------------------------------------------------------------------

    def _on_groups_message(self, ch, method, props, body: bytes) -> None:
        """
        Callback for the groups topic exchange consumer.

        Routing key format: ``<group_name>.OUT`` (e.g. ``FIRE-OPS.OUT``).
        Body format: ``{"uid": "<eud-uid>", "cot": "<xml>"}``.

        Extracts the ACL group name from the routing key (strips ``.OUT``) and
        the EUD uid from the body, then calls EudGroupCache.update.

        Parameters
        ----------
        ch, method, props
            Standard pika callback signature; only method.routing_key is used.
        body : bytes
            Raw message body (JSON).
        """
        routing_key = method.routing_key  # e.g. "FIRE-OPS.OUT" or "__ANON__.OUT"

        # Only process .OUT routing keys (EUD → group routing direction).
        if not routing_key.endswith(".OUT"):
            return  # skip .IN routing keys (rare in OTS; sender direction)

        group_name = routing_key[:-4]  # strip ".OUT" suffix
        if not group_name:
            return

        try:
            msg = json.loads(body)
            uid = msg.get("uid")
            if uid:
                self._eud_group_cache.update(uid, group_name)
                log.debug(
                    "ots_bus: groups cache updated uid=%s → group=%s", uid, group_name
                )
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("ots_bus: groups exchange message parse error: %s", exc)

    def _groups_subscribe_loop(self, stop_event: threading.Event) -> None:
        """
        Groups exchange subscriber loop. Runs in the EudGroupCacheSub daemon thread.

        Processes delivery notifications from the OTS 'groups' topic exchange
        calling _on_groups_message for each delivery to update the EudGroupCache.

        Exits when stop_event is set (shared with start_consuming).

        Parameters
        ----------
        stop_event : threading.Event
            The engine's shared shutdown event.
        """
        try:
            self._groups_sub_ch.basic_consume(
                queue=self._groups_queue_name,
                on_message_callback=self._on_groups_message,
                auto_ack=True,
            )
            log.info(
                "ots_bus: groups subscriber started (queue=%s)", self._groups_queue_name
            )
            while not stop_event.is_set():
                self._groups_sub_conn.process_data_events(time_limit=1.0)
        except Exception as exc:  # pylint: disable=broad-except
            log.warning(
                "ots_bus: groups subscriber error (cache updates stopped): %s", exc
            )
            # Signal engine termination; the watchdog will restart the process
            # and the cache will repopulate from live groups exchange traffic.
            stop_event.set()
        log.info("ots_bus: groups subscriber exiting")

    def start_groups_subscriber(self, stop_event: threading.Event) -> None:
        """
        Start the groups exchange subscriber as a daemon thread.

        Must be called after connect. The groups subscriber populates the
        EudGroupCache from OTS 'groups' topic exchange traffic. The cache is
        consumed by the firehose consumer for fail-closed group policy.

        Parameters
        ----------
        stop_event : threading.Event
            The engine's shared shutdown event. Causes the subscriber loop to
            exit cleanly (same event used by start_consuming).
        """
        t = threading.Thread(
            target=self._groups_subscribe_loop,
            args=(stop_event,),
            name="EudGroupCacheSub",
            daemon=True,
        )
        t.start()
        log.info("ots_bus: EudGroupCacheSub daemon thread started")

    # ------------------------------------------------------------------
    # Outbound path: firehose consumer
    # ------------------------------------------------------------------

    def _on_firehose_message(
        self,
        manager: "FederationManager",
        ch,
        method,
        props,
        body: bytes,
    ) -> None:
        """
        Process a single firehose message from the OTS RabbitMQ firehose exchange.

        Extracted from the start_consuming closure for testability ( tests
        inject mock bodies directly without running the consuming loop).

        Decision chain:
          1. Parse body JSON → uid, cot_xml.
          2. loop_filter.should_relay_outbound → drop echoes/loops.
          3. loop_filter.clean_for_relay → strip untrusted fedprov elements.
          4. Parse CoT XML → models.Event.
          5. EudGroupCache.get_groups(uid) → Option D fail-closed :
               - None (cache miss / cold-start) → block, log, return.
               - frozenset → attach as evt.local_acl_groups sidecar.
          6. manager.on_outbound(None, evt) → fan out to federation peers.

        Parameters
        ----------
        manager : FederationManager
        ch, method, props : pika callback args (not used in message processing)
        body : bytes
            Raw AMQP message body (JSON).
        """
        try:
            msg = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            log.warning("ots_bus: firehose message JSON parse error: %s", exc)
            return

        cot_xml = msg.get("cot", "")
        uid = msg.get("uid", "?")

        if not cot_xml:
            return

        # Loop filter: drop echoes and transitive loops.
        if not self._loop_filter.should_relay_outbound(cot_xml, None):
            return

        # Spoof defense: strip any _fedprov/_fedhops before feeding to codec.
        clean_xml = self._loop_filter.clean_for_relay(cot_xml)

        # Parse CoT into models.Event.
        evt = _parse_cot_xml(clean_xml)
        if evt is None:
            log.warning(
                "ots_bus: failed to parse firehose CoT for uid=%s, skipping", uid
            )
            return

        # --- Option D: ACL group lookup ---
        # Cache is an optimization layer. On a miss, resolve SYNCHRONOUSLY from
        # OTS's authoritative DB (mirrors TAK Server GroupManager.getGroups) so
        # the outbound path never races the async groups exchange.
        acl_groups = self._eud_group_cache.get_groups(uid)
        if acl_groups is None and self._group_resolver is not None:
            try:
                resolved = self._group_resolver.resolve(uid)
            except Exception as exc:  # GroupResolveError etc. — DB unreachable
                log.warning(
                    "ots_bus: group resolve for uid=%s failed (DB unreachable) "
                    "— fail-closed: %s", uid, exc,
                )
                return  # fail-closed: DB error, not a group decision
            if resolved:
                # Populate the optimization cache and proceed.
                self._eud_group_cache.set_groups(uid, resolved)
                acl_groups = resolved
                log.debug(
                    "ots_bus: cache miss for uid=%s resolved synchronously from DB "
                    "→ groups=%s", uid, sorted(resolved),
                )
            else:
                log.debug(
                    "ots_bus: uid=%s has no OUT ACL groups in DB — blocking "
                    "(fail-closed, genuine no-group)", uid,
                )
                return  # fail-closed: EUD genuinely ungrouped
        if acl_groups is None:
            log.debug(
                "ots_bus: cache miss for uid=%s and no group resolver — blocking "
                "(fail-closed)", uid,
            )
            return  # fail-closed: no cache entry, no DB resolver

        # Attach the resolved ACL groups as a sidecar for prepare_outbound_event.
        # codec.py reads evt.local_acl_groups instead of CoT <__group>.
        evt.local_acl_groups = acl_groups  # frozenset[str]

        log.debug("ots_bus: relaying firehose uid=%s to federation peers", uid)
        manager.on_outbound(None, evt)

    def start_consuming(
        self,
        manager: "FederationManager",
        stop_event: threading.Event,
    ) -> None:
        """
        Block and consume OTS firehose events, relaying local events to peers.

        Runs until stop_event is set.  Uses process_data_events(time_limit=1.0)
        so stop_event is checked at least once per second.

        Parameters
        ----------
        manager : FederationManager
            The FederationManager to call on_outbound against.
        stop_event : threading.Event
            Set by the SIGTERM handler to trigger graceful shutdown.
        """
        if self._sub_ch is None:
            raise RuntimeError("OtsRmqBus.start_consuming: not connected (call connect() first)")

        # Store reference so inject's failure path can signal engine termination.
        self._stop_event = stop_event

        def on_message(ch, method, props, body):
            self._on_firehose_message(manager, ch, method, props, body)

        self._sub_ch.basic_consume(
            queue=self._sub_queue_name,
            on_message_callback=on_message,
            auto_ack=True,
        )

        log.info("ots_bus: firehose consumer started")
        while not stop_event.is_set():
            self._sub_conn.process_data_events(time_limit=1.0)

        log.info("ots_bus: stop_event set, exiting consuming loop")
