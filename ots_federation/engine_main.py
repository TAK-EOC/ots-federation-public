# ots_federation/engine_main.py
# Child-process entry point for the OTS federation engine.
# Invoked by the plugin (plugin.py) as:
#   python -m ots_federation.engine_main --config /opt/ots/config/federation.ini
# RabbitMQ credentials arrive via environment variables set by the plugin's
# activate method:
#   OTS_RMQHOST  — RabbitMQ server address
#   OTS_RMQPORT  — RabbitMQ AMQP port (default: 5672)
#   OTS_RMQUSER  — RabbitMQ username (default: guest)
#   OTS_RMQPASS  — RabbitMQ password
# NEVER pass credentials via CLI args — they would be visible in ps output.
# Threading model:
#   Main thread  : pika firehose consumer (OtsRmqBus.start_consuming loop)
#   Daemon threads per peer : gRPC side-threads (managed by FederationManager)
#   Bridge-drain thread     : polls FederationBridge.rx_fd, delivers inbound
#                             federated events to OTS via OtsRmqBus.inject
# Shutdown sequence (SIGTERM):
#   1. stop_event.set  → breaks firehose loop (start_consuming returns)
#   2. manager.stop    → drains gRPC threads (up to 5s each peer)
#   3. bridge_thread.join(timeout=5)
#   4. bus.close       → closes pika connections
#   5. sys.exit(0)       → clean exit, plugin watchdog does NOT restart

from __future__ import annotations

import argparse
import configparser
import logging
import os
import select
import signal
import sys
import threading
import time

log = logging.getLogger(__name__)


def _read_rmq_env():
    """Read RabbitMQ credentials from environment.  Raises if OTS_RMQPASS absent."""
    host = os.environ.get("OTS_RMQHOST", "127.0.0.1")
    port_str = os.environ.get("OTS_RMQPORT", "5672")
    user = os.environ.get("OTS_RMQUSER", "guest")
    password = os.environ.get("OTS_RMQPASS")

    if password is None:
        raise EnvironmentError(
            "OTS_RMQPASS environment variable is not set.  "
            "The plugin's activate() must export RabbitMQ credentials "
            "before spawning this process."
        )

    try:
        port = int(port_str)
    except ValueError:
        raise EnvironmentError(
            f"OTS_RMQPORT={port_str!r} is not a valid integer port."
        )

    return host, port, user, password


def _bridge_drain_loop(
    bridge,
    bus,
    stop_event: threading.Event,
):
    """
    Drain inbound federated events from the gRPC bridge to OTS.

    Runs in a daemon thread.  Polls bridge.rx_fd (the readable end of the
    wakeup socketpair) with select(timeout=0.5).  When readable, calls
    bridge.drain(bus) to deliver all queued (src, evt) pairs via bus.inject.

    bridge.rx_fd is a raw socket; select is safe across threads.
    """
    rx_fd = bridge.rx_fd
    while not stop_event.is_set():
        try:
            readable, _, _ = select.select([rx_fd], [], [], 0.5)
            if readable:
                bridge.drain(bus)
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("bridge_drain_loop: error: %s", exc)


def main(argv=None):
    """
    Main entry point for the federation engine child process.

    Parameters
    ----------
    argv : list[str] | None
        Command-line arguments.  Uses sys.argv when None.
    """
    # PY-31: log level is runtime-tunable, never hardcoded. Resolve from env so an
    # operator can raise verbosity on a running deployment without a code edit.
    # The plugin supervisor injects OTS_FED_LOG_LEVEL into this child's env.
    _level = getattr(
        logging, os.environ.get("OTS_FED_LOG_LEVEL", "INFO").upper(), logging.INFO
    )
    logging.basicConfig(
        level=_level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    # SIGHUP re-reads OTS_FED_LOG_LEVEL live (no restart) — gold-standard tunability.
    def _reload_log_level(_signum, _frame):
        lvl = getattr(
            logging, os.environ.get("OTS_FED_LOG_LEVEL", "INFO").upper(), logging.INFO
        )
        logging.getLogger().setLevel(lvl)
        log.info("log level reloaded to %s via SIGHUP", logging.getLevelName(lvl))

    try:
        import signal
        signal.signal(signal.SIGHUP, _reload_log_level)
    except (ValueError, OSError):
        pass  # not on main thread / unsupported — env-at-startup still applies

    parser = argparse.ArgumentParser(
        prog="ots_federation.engine_main",
        description="OTS federation engine child process",
    )
    parser.add_argument(
        "--config",
        required=True,
        metavar="PATH",
        help="Path to federation.ini configuration file",
    )
    args = parser.parse_args(argv)

    # --- Load federation config ---
    try:
        cfg_parser = configparser.ConfigParser()
        read_files = cfg_parser.read(args.config)
        if not read_files:
            log.error("federation config not found: %s", args.config)
            sys.exit(1)
    except configparser.Error as exc:
        log.error("Error reading federation config: %s", exc)
        sys.exit(1)

    from ots_federation.config import get_federation_config  # noqa (deferred to avoid grpc at import)
    try:
        fed_config = get_federation_config(cfg_parser)
    except configparser.Error as exc:
        log.error("Invalid federation config: %s", exc)
        sys.exit(1)

    if not fed_config.enabled:
        log.error(
            "Federation is disabled in %s ([federation] enabled = false). "
            "Engine started unnecessarily — exiting.",
            args.config,
        )
        sys.exit(1)

    # --- Read RabbitMQ credentials from env (set by plugin.py activate) ---
    try:
        rmq_host, rmq_port, rmq_user, rmq_password = _read_rmq_env()
    except EnvironmentError as exc:
        log.error("RabbitMQ env error: %s", exc)
        sys.exit(1)

    log.info(
        "OTS federation engine starting: server_id=%s, %d peer(s), RMQ=%s:%d",
        fed_config.server_id,
        len(fed_config.peers),
        rmq_host,
        rmq_port,
    )

    # --- Build components ---
    from ots_federation.loop_filter import LoopFilter
    from ots_federation.ots_bus import OtsRmqBus
    from ots_federation.manager import FederationManager
    from ots_federation.eud_group_cache import EudGroupCache
    from ots_federation.group_resolver import GroupResolver

    loop_filter = LoopFilter(
        server_id=fed_config.server_id,
        max_hops=fed_config.max_hops,
    )

    # Option D (/): construct the EUD ACL group cache before the bus.
    # TTL=300 s per-D-forks-resolved.
    eud_group_cache = EudGroupCache(ttl_seconds=300)

    # Synchronous authoritative group resolver (OTS DB). The plugin
    # passes the DB URI via OTS_FED_DBURI; None => no DB access, cache miss stays
    # fail-closed (prior behavior). Cache is now an optimization of this lookup.
    _dburi = os.environ.get("OTS_FED_DBURI") or None
    group_resolver = GroupResolver(_dburi)
    if _dburi:
        log.info("group resolver active (synchronous DB group resolution)")
    else:
        log.warning(
            "OTS_FED_DBURI not set — cache miss stays fail-closed (no synchronous "
            "group resolution); federation may drop events on cold cache"
        )

    bus = OtsRmqBus(
        host=rmq_host,
        port=rmq_port,
        user=rmq_user,
        password=rmq_password,
        loop_filter=loop_filter,
        eud_group_cache=eud_group_cache,
        inject_cot_parser=fed_config.inject_cot_parser,
        group_resolver=group_resolver,
    )

    manager = FederationManager(config=fed_config)

    # --- Shutdown coordination ---
    stop_event = threading.Event()

    def _sigterm_handler(signum, frame):
        log.info("SIGTERM received, initiating graceful shutdown")
        stop_event.set()

    signal.signal(signal.SIGTERM, _sigterm_handler)
    signal.signal(signal.SIGINT, _sigterm_handler)

    # --- Connect to RabbitMQ ---
    try:
        bus.connect()
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Failed to connect to RabbitMQ (%s:%d): %s", rmq_host, rmq_port, exc)
        sys.exit(1)

    # --- Start the federation manager (gRPC side-threads, inbound server) ---
    try:
        manager.start()
    except Exception as exc:  # pylint: disable=broad-except
        log.error("FederationManager.start() failed: %s", exc)
        bus.close()
        sys.exit(1)

    if fed_config.listen_enabled:
        log.info(
            "gRPC federation listener on port %d", fed_config.listen_port
        )

    # --- Option D : groups exchange subscriber daemon thread ---
    # Populates eud_group_cache from OTS 'groups' topic exchange traffic.
    # Must start after bus.connect so the groups connection is open.
    # Uses the same stop_event as start_consuming for coordinated shutdown.
    bus.start_groups_subscriber(stop_event)

    # --- Bridge-drain thread: inbound federated events → OTS inject ---
    bridge_thread = threading.Thread(
        target=_bridge_drain_loop,
        args=(manager.bridge, bus, stop_event),
        name="FedBridgeDrain",
        daemon=True,
    )
    bridge_thread.start()

    # --- Main loop: firehose consumer (blocks until stop_event is set) ---
    exit_code = 0
    try:
        bus.start_consuming(manager=manager, stop_event=stop_event)
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Fatal error in firehose consumer: %s", exc)
        exit_code = 1
    finally:
        stop_event.set()  # ensure bridge_thread also exits

    # --- Graceful shutdown ---
    log.info("Stopping FederationManager...")
    try:
        manager.stop()
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("Error stopping FederationManager: %s", exc)

    log.info("Joining bridge-drain thread...")
    bridge_thread.join(timeout=5.0)
    if bridge_thread.is_alive():
        log.warning("Bridge-drain thread did not stop in 5s")

    log.info("Closing RabbitMQ connections...")
    bus.close()

    log.info("OTS federation engine stopped (exit_code=%d)", exit_code)
    sys.exit(exit_code)


if __name__ == "__main__":  # pragma: no cover
    main()
