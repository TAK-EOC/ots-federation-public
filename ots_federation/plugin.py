# ots_federation/plugin.py
# FederationPlugin — OTS plugin scaffold for the federation engine.
# Entry point declared in pyproject.toml:
#   [project.entry-points."opentakserver.plugin"]
#   federation = "ots_federation.plugin:FederationPlugin"
# Lifecycle:
#   activate  → read RabbitMQ creds from app.config, spawn engine child
#                 process via subprocess.Popen, register APScheduler watchdog
#   stop      → SIGTERM child, wait 10s, SIGKILL if still alive
#   get_info  → child pid, status, uptime_secs
#   load_metadata → name, distro, author, version from importlib.metadata
# Child process interface:
#   Command:    python -m ots_federation.engine_main --config <fed_ini_path>
#   Env vars:   OTS_RMQHOST, OTS_RMQPORT, OTS_RMQUSER, OTS_RMQPASS
#   (Password is NEVER passed as a CLI arg — visible in ps output)
# Watchdog:
#   APScheduler job 'federation_watchdog' runs every 30s.
#   If child has died, restart up to MAX_RESTART_COUNT times.
#   After that many restarts, log an error and stop trying (operator action needed).

from __future__ import annotations

import importlib.metadata
import os
import signal
import subprocess
import sys
import time
import traceback

from flask import Blueprint, Flask, jsonify

# Auth guards for the federation REST blueprint.  Provided by the host OTS app
# (opentakserver depends on flask-security-too), same as `flask` above — no
# separate declaration in pyproject.toml.  These endpoints expose federation
# topology and peer state, so they are administrator-only, matching the
# decorator stack OTS uses on its own admin routes.
from flask_security import auth_required, roles_accepted

# Conditionally inherit from OTS Plugin base class.
# When ots-federation is installed inside the OTS venv, this import succeeds
# and FederationPlugin passes OTS PluginManager's issubclass(plugin_class, Plugin)
# check. When run outside the OTS venv (unit tests, dev), it falls back to
# object so the module loads cleanly without a hard dependency on opentakserver.
try:
    from opentakserver.plugins.Plugin import Plugin as _OtsPlugin  # type: ignore[import]
except ImportError:  # pragma: no cover — only absent outside OTS venv
    _OtsPlugin = object  # type: ignore[assignment,misc]

def _set_pdeathsig_linux() -> None:
    """
    Set PR_SET_PDEATHSIG=SIGTERM so the child process receives SIGTERM if
    the parent (OTS) dies unexpectedly without invoking stop.

    Intended to run as preexec_fn in subprocess.Popen, so it executes in the
    child process before the engine interpreter starts.  Linux-only; silently
    no-ops on other platforms (ImportError / OSError are swallowed so the
    Popen call can succeed unconditionally).

    Orphan-defence layering:
      1. PRIMARY:  systemd cgroup cleanup.  Production deployment REQUIRES
                   systemd supervision of the OTS service; when the OTS unit
                   is stopped or crashes, the cgroup is torn down and all
                   descendant processes (including the engine child) are killed
                   automatically.  This is the reliable defence.
      2. BELT-AND-BRACES: this prctl call.  Covers bare (non-systemd) runs and
                   crash scenarios before the cgroup gate fires.  Has no effect
                   if OTS exits cleanly via stop.
    """
    try:
        import ctypes
        import ctypes.util

        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)
        PR_SET_PDEATHSIG = 1  # from <sys/prctl.h>
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
    except Exception:  # pylint: disable=broad-except
        # Non-Linux, prctl unavailable, or libc not found.  Fail silently;
        # systemd cgroup cleanup remains the primary orphan defence.
        pass


MAX_RESTART_COUNT = 5
_WATCHDOG_JOB_ID = "federation_watchdog"
_WATCHDOG_INTERVAL_S = 30
_STOP_WAIT_S = 10


def _get_default_fed_config_path(app) -> str:
    """Return the federation.ini path from config or fallback to data folder."""
    explicit = app.config.get("OTS_FEDERATION_CONFIG", "")
    if explicit:
        return explicit
    data_folder = app.config.get("OTS_DATA_FOLDER", "/opt/ots/data")
    return os.path.join(data_folder, "federation.ini")


class FederationPlugin(_OtsPlugin):
    """
    OTS plugin that supervises the ots_federation engine child process.

    OTS discovers this class via the entry point group 'opentakserver.plugin'.
    It must extend Plugin (opentakserver.plugins.Plugin.Plugin), validated by
    OTS PluginManager's issubclass(plugin_class, Plugin) check.  The base
    class is imported at module level via a try/except so the module loads
    cleanly outside the OTS venv (unit tests, standalone tools).

    Note: the opentakserver package is NOT listed as a dependency of
    ots-federation (it lives in OTS's own venv).  This import only succeeds
    when the wheel is installed inside OTS's venv.
    """

    # OTS PluginManager reads this class attribute to discover the entry-point
    # group.  Mirrors Plugin.group (opentakserver/plugins/Plugin.py:26).
    group = "opentakserver.plugin"

    # Blueprint registered by PluginManager.activate after we set it in
    # our activate.
    blueprint: Blueprint | None = None

    def __init__(self):
        self._app: Flask | None = None
        self._config: dict = {}
        self.metadata: dict = {}
        self.name: str = "ots-federation"
        self.distro: str = "ots-federation"
        self.routes: list = []

        self._proc: subprocess.Popen | None = None
        self._start_time: float | None = None
        self._restart_count: int = 0

    # ------------------------------------------------------------------
    # Plugin lifecycle (OTS calls these)
    # ------------------------------------------------------------------

    def _load_default_config(self, app: Flask) -> None:
        """
        Seed DefaultConfig keys into app.config without clobbering values the
        operator already set via config.yml (OTS loads config.yml into
        app.config before plugin activation, so setdefault preserves them).
        """
        from ots_federation.default_config import DefaultConfig

        for key in dir(DefaultConfig):
            if key.isupper():
                self._config[key] = app.config.setdefault(
                    key, getattr(DefaultConfig, key)
                )

    def activate(self, app: Flask, enabled: bool) -> None:
        """
        Called by OTS PluginManager during startup.

        Reads RabbitMQ credentials from app.config, determines the federation
        config path, spawns the engine child process, registers the APScheduler
        watchdog, and builds the REST blueprint.

        Parameters
        ----------
        app : Flask
            The OTS Flask application.
        enabled : bool
            Whether this plugin is enabled in the plugins DB table.
        """
        # Defer OTS-specific imports to activate to avoid import errors when
        # running unit tests outside the OTS venv.
        try:
            from opentakserver.extensions import apscheduler, logger as ots_logger
        except ImportError:
            import logging
            ots_logger = logging.getLogger(__name__)
            apscheduler = None

        self._app = app
        self.load_metadata()
        self._load_default_config(app)

        if not enabled:
            ots_logger.info("FederationPlugin is disabled; not starting engine")
            self._build_blueprint()
            return

        # Validate that federation.ini exists before spawning.
        fed_cfg_path = _get_default_fed_config_path(app)
        if not os.path.exists(fed_cfg_path):
            ots_logger.warning(
                "FederationPlugin: federation config not found at %s; "
                "engine will not start until the file exists",
                fed_cfg_path,
            )
            self._build_blueprint()
            return

        # Extract RabbitMQ credentials from OTS app.config (never from CLI args).
        rmq_host = str(app.config.get("OTS_RABBITMQ_SERVER_ADDRESS", "127.0.0.1"))
        rmq_port = str(app.config.get("OTS_RABBITMQ_PORT", 5672))
        rmq_user = str(app.config.get("OTS_RABBITMQ_USERNAME", "guest"))
        rmq_pass = str(app.config.get("OTS_RABBITMQ_PASSWORD", "guest"))

        self._rmq_env = {
            **os.environ,
            "OTS_RMQHOST": rmq_host,
            "OTS_RMQPORT": rmq_port,
            "OTS_RMQUSER": rmq_user,
            "OTS_RMQPASS": rmq_pass,
            # PY-31: pass the runtime-tunable log level down to the engine child.
            "OTS_FED_LOG_LEVEL": str(
                app.config.get("OTS_FEDERATION_LOG_LEVEL", "INFO")
            ),
            # Authoritative DB URI for synchronous group resolution.
            "OTS_FED_DBURI": str(app.config.get("SQLALCHEMY_DATABASE_URI", "")),
        }
        self._fed_cfg_path = fed_cfg_path

        try:
            self._spawn_engine(ots_logger)
            ots_logger.info(
                "FederationPlugin: engine started (pid=%s)",
                self._proc.pid if self._proc else "?",
            )
        except Exception as exc:  # pylint: disable=broad-except
            ots_logger.error("FederationPlugin: failed to spawn engine: %s", exc)
            ots_logger.error(traceback.format_exc())

        # Register APScheduler watchdog job.
        if apscheduler is not None:
            try:
                apscheduler.add_job(
                    func=self._watchdog,
                    trigger="interval",
                    seconds=_WATCHDOG_INTERVAL_S,
                    id=_WATCHDOG_JOB_ID,
                    replace_existing=True,
                )
                ots_logger.info("FederationPlugin: watchdog registered (%ds interval)", _WATCHDOG_INTERVAL_S)
            except Exception as exc:  # pylint: disable=broad-except
                ots_logger.warning("FederationPlugin: could not register watchdog: %s", exc)

        self._build_blueprint()

    def stop(self) -> None:
        """
        Called by OTS PluginManager on shutdown or plugin disable.

        Sends SIGTERM to the child process, waits up to 10s, then SIGKILL.
        Cancels the APScheduler watchdog job.
        """
        try:
            from opentakserver.extensions import apscheduler, logger as ots_logger
        except ImportError:
            import logging
            ots_logger = logging.getLogger(__name__)
            apscheduler = None

        # Cancel watchdog first so it doesn't try to restart while we're stopping.
        if apscheduler is not None:
            try:
                apscheduler.remove_job(_WATCHDOG_JOB_ID)
            except Exception:  # pylint: disable=broad-except
                pass

        if self._proc is None:
            return

        ots_logger.info("FederationPlugin: stopping engine (pid=%d)", self._proc.pid)
        try:
            self._proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            self._proc = None
            return

        try:
            self._proc.wait(timeout=_STOP_WAIT_S)
            ots_logger.info("FederationPlugin: engine exited cleanly")
        except subprocess.TimeoutExpired:
            ots_logger.warning(
                "FederationPlugin: engine did not exit in %ds, sending SIGKILL",
                _STOP_WAIT_S,
            )
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except Exception as exc:  # pylint: disable=broad-except
                ots_logger.error("FederationPlugin: SIGKILL failed: %s", exc)

        self._proc = None
        self._start_time = None

    def get_info(self) -> dict | None:
        """Return plugin status for the OTS web UI."""
        pid = None
        status = "stopped"
        uptime_secs = None

        if self._proc is not None:
            rc = self._proc.poll()
            if rc is None:
                pid = self._proc.pid
                status = "running"
                if self._start_time is not None:
                    uptime_secs = int(time.time() - self._start_time)
            else:
                status = f"exited:{rc}"

        return {
            "name": self.name,
            "pid": pid,
            "status": status,
            "uptime_secs": uptime_secs,
            "restart_count": self._restart_count,
        }

    def load_metadata(self) -> dict:
        """Load package metadata from importlib.metadata (installed wheel)."""
        try:
            meta = importlib.metadata.metadata("ots-federation")
            result = {
                "name": meta.get("Name", "ots-federation"),
                "distro": "ots-federation",
                "author": meta.get("Author", ""),
                "version": meta.get("Version", "0.0.0"),
            }
        except importlib.metadata.PackageNotFoundError:
            result = {
                "name": "ots-federation",
                "distro": "ots-federation",
                "author": "",
                "version": "dev",
            }

        self.name = result["name"]
        self.distro = result["distro"]
        self.metadata = result
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _spawn_engine(self, logger=None) -> None:
        """
        Spawn the engine_main child process.

        Orphan mitigation:
          preexec_fn=_set_pdeathsig_linux sets PR_SET_PDEATHSIG=SIGTERM in the
          child so the engine receives SIGTERM if OTS crashes unexpectedly.
          This is a belt-and-braces measure only; the PRIMARY orphan defence is
          systemd cgroup cleanup.

          PRODUCTION DEPLOYMENT REQUIREMENT: the OTS service MUST be managed
          by systemd (or another init system that performs cgroup cleanup on
          service stop/crash).  Without cgroup cleanup, a bare OTS crash leaves
          the engine child running and consuming RabbitMQ connections until the
          next system reboot.  pdeathsig mitigates this for SIGKILL-on-crash
          scenarios but is not a substitute for proper process supervision.
        """
        if logger is None:
            import logging
            logger = logging.getLogger(__name__)

        cmd = [
            sys.executable,
            "-m",
            "ots_federation.engine_main",
            "--config",
            self._fed_cfg_path,
        ]
        self._proc = subprocess.Popen(
            cmd,
            env=self._rmq_env,
            # Let child inherit parent's stdout/stderr for logging
            stdout=None,
            stderr=None,
            # Belt-and-braces orphan guard: child gets SIGTERM on parent crash.
            # Linux-only; _set_pdeathsig_linux is a no-op on other platforms.
            # Primary orphan defence is systemd cgroup cleanup — see docstring.
            preexec_fn=_set_pdeathsig_linux if sys.platform.startswith("linux") else None,
        )
        self._start_time = time.time()
        logger.info("FederationPlugin: spawned engine pid=%d cmd=%r", self._proc.pid, cmd)

    def _watchdog(self) -> None:
        """
        APScheduler job: check if the engine is still alive; restart if dead.

        Runs every _WATCHDOG_INTERVAL_S seconds in a gevent greenlet.
        Max restarts: MAX_RESTART_COUNT. After that, logs an error and stops
        trying (operator intervention required).
        """
        try:
            from opentakserver.extensions import logger as ots_logger
        except ImportError:
            import logging
            ots_logger = logging.getLogger(__name__)

        if self._proc is None:
            return

        rc = self._proc.poll()
        if rc is None:
            # Child is still running.
            return

        # Child has exited.
        ots_logger.warning(
            "FederationPlugin: engine exited (pid=%d rc=%d)", self._proc.pid, rc
        )
        self._proc = None
        self._start_time = None

        if self._restart_count >= MAX_RESTART_COUNT:
            ots_logger.error(
                "FederationPlugin: engine has been restarted %d times; "
                "not restarting again.  Check logs and fix the configuration.",
                self._restart_count,
            )
            return

        self._restart_count += 1
        backoff = min(2 ** (self._restart_count - 1), 60)
        ots_logger.info(
            "FederationPlugin: restarting engine (attempt %d/%d, backoff=%ds)",
            self._restart_count,
            MAX_RESTART_COUNT,
            backoff,
        )

        import time as _time
        _time.sleep(backoff)

        try:
            self._spawn_engine(ots_logger)
        except Exception as exc:  # pylint: disable=broad-except
            ots_logger.error("FederationPlugin: restart failed: %s", exc)

    def _build_blueprint(self) -> None:
        """Build and assign the federation REST blueprint."""
        bp = Blueprint("federation_plugin", __name__, url_prefix="/api/federation")

        @bp.route("/status", methods=["GET"])
        @auth_required()
        @roles_accepted("administrator")
        def status():
            return jsonify(self.get_info())

        @bp.route("/config", methods=["GET"])
        @auth_required()
        @roles_accepted("administrator")
        def config():
            """Return parsed federation.ini without key material."""
            import configparser as _cp
            fed_path = getattr(self, "_fed_cfg_path", None)
            if not fed_path or not os.path.exists(fed_path):
                return jsonify({"error": "federation.ini not found"}), 404

            cfg = _cp.ConfigParser()
            cfg.read(fed_path)

            safe = {}
            for section in cfg.sections():
                safe[section] = {}
                for key, val in cfg.items(section):
                    # Strip key material from the response.
                    if any(k in key for k in ("key", "pass", "password", "secret")):
                        safe[section][key] = "***"
                    else:
                        safe[section][key] = val

            return jsonify(safe)

        # NOTE: there is deliberately no per-peer enable/disable route here.
        # The official Federation Hub has no such endpoint — `outgoingEnabled`
        # is a property of the policy document, applied live by the broker
        # (FederationHubBrokerService.updateOutgoingConnections).  Our engine
        # reads [federate:*] enabled once at startup and cannot re-apply peer
        # state without a restart, so a REST toggle here could only ever be
        # advisory.  If live enable/disable is wanted, build it engine-side to
        # match the hub's semantics rather than reintroducing a no-op route.

        self.blueprint = bp
