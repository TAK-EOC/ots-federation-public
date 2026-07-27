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
# Ticket: e3fbe5 (plugin scaffold)
# Epic:   1c88b3

from __future__ import annotations

import importlib.metadata
import os
import signal
import subprocess
import sys
import time
import traceback

from flask import Blueprint, Flask, jsonify, redirect, request, send_file, url_for

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

# Must equal importlib.metadata Name (pyproject.toml [project].name), lower-
# cased — this is the string OTS's PluginManager keys plugins under
# (`self.plugins[plugin.distro.lower()]`) and the string OTS's own web UI
# uses to build both the settings-tab fetch and the plugin-UI iframe src:
# `/api/plugins/${distro}/ui` (see OpenTAKServer-UI src/pages/Plugin.tsx).
# Confirmed against docs.opentakserver.io/plugins.html and the reference
# OTS-SkyFi-Plugin implementation — every plugin route must live under this
# exact prefix or neither the Settings tab nor the UI iframe will find it.
DISTRO = "ots-federation"
API_PREFIX = f"/api/plugins/{DISTRO}"


def _admin_only(fn):
    """
    Restrict a route to logged-in OTS administrators.

    Thin wrapper around flask_security.roles_accepted("administrator") — the
    same decorator OTS core's own plugin routes use (opentakserver/blueprints/
    ots_api/plugin_api.py) and the reference OTS-SkyFi-Plugin UI routes use.
    Falls back to a no-op outside the OTS venv (unit tests, dev) so this
    module keeps importing cleanly without a hard flask_security dependency
    at import time.
    """
    try:
        from flask_security import roles_accepted  # type: ignore[import]
        return roles_accepted("administrator")(fn)
    except ImportError:  # pragma: no cover — only absent outside OTS venv
        return fn


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
        self._fed_cfg_path: str | None = None
        self._rmq_env: dict | None = None

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

        # Resolved unconditionally, before any early return: the admin UI's
        # "generate federation.ini" flow and restart() both need this even
        # when the plugin is disabled or the file doesn't exist yet — those
        # are recoverable states (operator hasn't run quickstart yet), not a
        # permanent shutdown.
        self._fed_cfg_path = _get_default_fed_config_path(app)
        self._rmq_env = {
            **os.environ,
            "OTS_RMQHOST": str(app.config.get("OTS_RABBITMQ_SERVER_ADDRESS", "127.0.0.1")),
            "OTS_RMQPORT": str(app.config.get("OTS_RABBITMQ_PORT", 5672)),
            "OTS_RMQUSER": str(app.config.get("OTS_RABBITMQ_USERNAME", "guest")),
            "OTS_RMQPASS": str(app.config.get("OTS_RABBITMQ_PASSWORD", "guest")),
            "OTS_FED_LOG_LEVEL": str(app.config.get("OTS_FEDERATION_LOG_LEVEL", "INFO")),
            "OTS_FED_DBURI": str(app.config.get("SQLALCHEMY_DATABASE_URI", "")),
        }

        if not enabled:
            ots_logger.info("FederationPlugin is disabled; not starting engine")
            self._build_blueprint()
            return

        # Validate that federation.ini exists before spawning.
        fed_cfg_path = self._fed_cfg_path
        if not os.path.exists(fed_cfg_path):
            ots_logger.warning(
                "FederationPlugin: federation config not found at %s; "
                "engine will not start until the file exists",
                fed_cfg_path,
            )
            self._build_blueprint()
            return

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

        self.stop_engine_only(ots_logger)

    def restart(self) -> dict:
        """
        Stop and respawn the engine child process so on-disk federation.ini
        edits (peer add/edit/delete, global settings) take effect.

        This is the same stop()/_spawn_engine() sequence the watchdog uses
        on an unexpected exit, invoked on demand from the admin UI's
        "Restart Engine" button (POST {API_PREFIX}/restart) rather than in
        response to a crash. Does not re-run activate()'s config-seeding or
        RabbitMQ-credential lookup — those don't change between edits — only
        the parts that must re-read federation.ini: stop the old process,
        spawn a new one against the same self._fed_cfg_path.

        Returns {"success": True} or {"success": False, "error": "..."}.
        """
        try:
            from opentakserver.extensions import logger as ots_logger
        except ImportError:
            import logging
            ots_logger = logging.getLogger(__name__)

        if self._fed_cfg_path is None or not os.path.exists(self._fed_cfg_path):
            return {"success": False, "error": "federation.ini not found; nothing to restart"}

        try:
            self.stop_engine_only(ots_logger)
            self._restart_count = 0  # operator-initiated restart resets the watchdog backoff
            self._spawn_engine(ots_logger)
            return {"success": True}
        except Exception as exc:  # pylint: disable=broad-except
            ots_logger.error("FederationPlugin: restart failed: %s", exc)
            ots_logger.error(traceback.format_exc())
            return {"success": False, "error": str(exc)}

    def stop_engine_only(self, ots_logger=None) -> None:
        """
        Terminate the engine child process without cancelling the APScheduler
        watchdog job (unlike stop(), which is the full OTS-lifecycle shutdown).
        Shared by restart() so a manual restart doesn't have to re-register
        the watchdog afterward.
        """
        if ots_logger is None:
            import logging
            ots_logger = logging.getLogger(__name__)

        if self._proc is None:
            return

        ots_logger.info("FederationPlugin: stopping engine for restart (pid=%d)", self._proc.pid)
        try:
            self._proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            self._proc = None
            return

        try:
            self._proc.wait(timeout=_STOP_WAIT_S)
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
            "distro": self.distro,
            "pid": pid,
            "status": status,
            "uptime_secs": uptime_secs,
            "restart_count": self._restart_count,
        }

    def load_metadata(self) -> dict:
        """
        Load package metadata from importlib.metadata (installed wheel).

        Returns the full metadata dict (project_url, author_email, license,
        summary, description, etc.) — not just name/distro/author/version —
        because OTS core's own Plugin.tsx About tab reads several of these
        fields directly, including `about.project_url.forEach(...)` with NO
        null-check on project_url itself (only on `about`). A metadata dict
        missing that key throws inside OTS core's own JS and blanks the
        entire plugin detail page — including the UI iframe tab — before
        anything of ours gets a chance to render. See pyproject.toml's
        [project.urls] section, which is what populates it.
        """
        try:
            meta = importlib.metadata.metadata(DISTRO)
            result = dict(meta.json)
            result["distro"] = DISTRO
            result.setdefault("name", DISTRO)
            result.setdefault("version", "0.0.0")
            result.setdefault("author", meta.get("Author", ""))
            result.setdefault("project_url", [])
        except importlib.metadata.PackageNotFoundError:
            result = {
                "name": DISTRO,
                "distro": DISTRO,
                "author": "",
                "version": "dev",
                "project_url": [],
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

    def _fed_cfg_path_or_404(self):
        """Return self._fed_cfg_path, or a (jsonify, 404) tuple if unset/missing."""
        fed_path = getattr(self, "_fed_cfg_path", None)
        if not fed_path or not os.path.exists(fed_path):
            return None, (jsonify({"success": False, "error": "federation.ini not found"}), 404)
        return fed_path, None

    def _build_blueprint(self) -> None:
        """
        Build and assign the plugin's Flask blueprint.

        Routes live under API_PREFIX = /api/plugins/ots-federation, which is
        the prefix OTS core's own web UI expects for every plugin (settings
        tab fetch + plugin-UI iframe src both hit
        /api/plugins/<distro>/{config,ui}). This replaces the earlier
        /api/federation/* scaffold, which predated wiring up the OTS iframe
        convention and was never a published/stable API — nothing outside
        this plugin depended on that prefix.
        """
        from ots_federation import ini_writer

        bp = Blueprint("federation_plugin", __name__, url_prefix=API_PREFIX)

        # -- engine status -------------------------------------------------

        @bp.route("/status", methods=["GET"])
        @_admin_only
        def status():
            return jsonify(self.get_info())

        @bp.route("/restart", methods=["POST"])
        @_admin_only
        def restart_engine():
            result = self.restart()
            return jsonify(result), (200 if result.get("success") else 400)

        # -- OTS plugin-framework config contract (Settings tab) ------------
        # GET/POST here are unrelated to federation.ini — they read/write the
        # app.config keys seeded from default_config.DefaultConfig (whether
        # the plugin runs at all, where federation.ini lives, log level).
        # OTS core's Plugin.tsx always renders this tab for every plugin.

        @bp.route("/config", methods=["GET"])
        @_admin_only
        def get_plugin_config():
            from ots_federation.default_config import DefaultConfig
            return jsonify({key: self._app.config.get(key) for key in dir(DefaultConfig) if key.isupper()})

        @bp.route("/config", methods=["POST"])
        @_admin_only
        def update_plugin_config():
            from ots_federation.default_config import DefaultConfig
            payload = request.get_json(silent=True) or {}
            result = DefaultConfig.validate(payload)
            if not result.get("success"):
                return jsonify(result), 400
            self._app.config.update(payload)
            return jsonify(result)

        # -- federation.ini admin: global [federation]/[federation_ssl] -----

        @bp.route("/peers", methods=["GET"])
        @_admin_only
        def list_peers():
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                return err
            try:
                return jsonify(ini_writer.read_all(fed_path))
            except ini_writer.IniError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400

        @bp.route("/global", methods=["PUT"])
        @_admin_only
        def update_global():
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                return err
            payload = request.get_json(silent=True) or {}
            try:
                ini_writer.update_global(
                    fed_path, payload.get("global", {}), payload.get("ssl", {})
                )
                return jsonify({"success": True, **ini_writer.read_all(fed_path)})
            except ini_writer.IniError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400

        # -- federation.ini admin: per-peer [federate:<name>] ---------------

        @bp.route("/peers", methods=["POST"])
        @_admin_only
        def create_peer():
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                return err
            payload = request.get_json(silent=True) or {}
            name = (payload.get("name") or "").strip()
            if not name:
                return jsonify({"success": False, "error": "'name' is required"}), 400
            try:
                ini_writer.upsert_peer(fed_path, name, payload, is_new=True)
                return jsonify({"success": True, **ini_writer.read_all(fed_path)})
            except ini_writer.IniError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400

        @bp.route("/peers/<name>", methods=["PUT"])
        @_admin_only
        def edit_peer(name: str):
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                return err
            payload = request.get_json(silent=True) or {}
            try:
                ini_writer.upsert_peer(fed_path, name, payload, is_new=False)
                return jsonify({"success": True, **ini_writer.read_all(fed_path)})
            except ini_writer.IniError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400

        @bp.route("/peers/<name>", methods=["DELETE"])
        @_admin_only
        def remove_peer(name: str):
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                return err
            try:
                ini_writer.delete_peer(fed_path, name)
                return jsonify({"success": True, **ini_writer.read_all(fed_path)})
            except ini_writer.IniError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400

        @bp.route("/peers/<name>/enable", methods=["POST"])
        @_admin_only
        def peer_enable(name: str):
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                return err
            payload = request.get_json(silent=True) or {}
            enabled = bool(payload.get("enabled", True))
            try:
                ini_writer.set_peer_enabled(fed_path, name, enabled)
                return jsonify({"success": True, **ini_writer.read_all(fed_path)})
            except ini_writer.IniError as exc:
                return jsonify({"success": False, "error": str(exc)}), 400

        # -- bundled Mantine/React UI (the OTS plugin-UI iframe convention) -
        # Built by OTS-UI-Plugin-Template's `npm run build`, outDir pointed at
        # ots_federation/ui/. See README's "Bundled plugin UI" section for the
        # build instructions. OTS core's web UI embeds this at
        # /api/plugins/ots-federation/ui inside an <iframe> on the plugin's
        # page (OpenTAKServer-UI src/pages/Plugin.tsx). Server-rendered plain
        # HTML — same convention as the CI-TRAP Reports plugin's admin page
        # — rather than a built JS bundle: no npm build step, no CDN
        # dependency, and no asset-serving path that can 404/mismatch.

        from ots_federation import admin_ui

        # flash() needs a secret key. OTS core always configures one via
        # Flask-Security; this is a no-op there. Only relevant standalone
        # (tests/dev) — never overwrite an existing key, that would
        # invalidate live sessions.
        if not self._app.config.get("SECRET_KEY"):
            self._app.config["SECRET_KEY"] = os.urandom(32)

        def _fed_cfg_path_for_ui() -> str:
            """Always returns a path (unlike _fed_cfg_path_or_404), since the
            admin page must render even before federation.ini exists — that's
            the whole point of the 'generate' form."""
            return self._fed_cfg_path or _get_default_fed_config_path(self._app)

        @bp.route("/ui", methods=["GET"])
        @_admin_only
        def ui_index():
            fed_path = _fed_cfg_path_for_ui()
            data = ini_writer.read_all(fed_path)
            return admin_ui.render_admin_page(
                name=self.name,
                version=self.metadata.get("version", "dev"),
                status=self.get_info(),
                data=data,
                fed_cfg_path=fed_path,
            )

        @bp.route("/ui/restart", methods=["POST"])
        @_admin_only
        def ui_restart():
            result = self.restart()
            if result.get("success"):
                admin_ui.flash("Engine restarted.", "success")
            else:
                admin_ui.flash(f"Restart failed: {result.get('error')}", "error")
            return redirect(url_for("federation_plugin.ui_index"))

        @bp.route("/ui/quickstart", methods=["POST"])
        @_admin_only
        def ui_quickstart():
            fed_path = _fed_cfg_path_for_ui()
            cert_dir = os.path.join(os.path.dirname(fed_path), "federation_certs")
            argv = [
                "--ini-path", fed_path,
                "--cert-dir", cert_dir,
                "--listen-port", request.form.get("listen_port", "9101"),
                "--accept-as", request.form.get("accept_as", "*:__ANON__"),
                "--share-as", request.form.get("share_as", "__ANON__:__ANON__"),
            ]
            if request.form.get("server_id"):
                argv += ["--server-id", request.form["server_id"]]
            if request.form.get("server_address"):
                argv += ["--server-address", request.form["server_address"]]
            if request.form.get("force"):
                argv.append("--force")

            proc = subprocess.run(
                [sys.executable, "-m", "ots_federation.quickstart", *argv],
                capture_output=True, text=True, timeout=60,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode == 0:
                admin_ui.flash(output or "Done.", "success")
            else:
                admin_ui.flash(output or f"quickstart exited {proc.returncode}", "error")
            return redirect(url_for("federation_plugin.ui_index"))

        @bp.route("/ui/export-bundle", methods=["POST"])
        @_admin_only
        def ui_export_bundle():
            fed_path = _fed_cfg_path_for_ui()
            cert_dir = os.path.join(os.path.dirname(fed_path), "federation_certs")
            export_dir = os.path.join(cert_dir, "export-bundle")
            proc = subprocess.run(
                [
                    sys.executable, "-m", "ots_federation.gen_fed_ca", "export",
                    "--cert-dir", cert_dir, "--out-dir", export_dir, "--zip",
                ],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode != 0:
                admin_ui.flash((proc.stdout or "") + (proc.stderr or ""), "error")
                return redirect(url_for("federation_plugin.ui_index"))

            zip_path = export_dir.rstrip(os.sep) + ".zip"
            if not os.path.exists(zip_path):
                admin_ui.flash("Export ran but the zip wasn't found — check the cert-dir has "
                                "output from a prior generate/quickstart.", "error")
                return redirect(url_for("federation_plugin.ui_index"))
            return send_file(zip_path, as_attachment=True, download_name="federation-peer-bundle.zip")

        @bp.route("/ui/global", methods=["POST"])
        @_admin_only
        def ui_global():
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                admin_ui.flash("federation.ini not found — generate it first.", "error")
                return redirect(url_for("federation_plugin.ui_index"))

            global_data = admin_ui.form_to_data(request.form, ini_writer.GLOBAL_FIELDS)
            ssl_data = admin_ui.form_to_data(request.form, ini_writer.SSL_FIELDS)
            admin_ui.apply_secret_field(request.form, "fed_key_pw", ssl_data)

            for key, dest_filename in (
                ("fed_ca_bundle", "fed-ca.crt"),
                ("fed_cert", "server-chain.crt"),
                ("fed_key", "server.key"),
            ):
                saved = admin_ui.save_uploaded_cert(
                    fed_path, request.files.get(f"{key}__file"), dest_filename,
                    is_key=(key == "fed_key"),
                )
                if saved:
                    ssl_data[key] = saved

            try:
                ini_writer.update_global(fed_path, global_data, ssl_data)
                admin_ui.flash("Global settings saved. Restart the engine to apply.", "success")
            except ini_writer.IniError as exc:
                admin_ui.flash(f"Couldn't save: {exc}", "error")
            return redirect(url_for("federation_plugin.ui_index"))

        def _save_peer_from_form(fed_path: str, name: str, *, is_new: bool):
            data = admin_ui.form_to_data(request.form, ini_writer.PEER_FIELDS)
            admin_ui.apply_secret_field(request.form, "connection_token", data)
            for key, dest_filename in (
                ("ca_cert", "peer-ca.crt"),
                ("client_cert", "client-chain.crt"),
                ("client_key", "client.key"),
            ):
                saved = admin_ui.save_uploaded_cert(
                    fed_path, request.files.get(f"{key}__file"), dest_filename,
                    peer_name=name, is_key=(key == "client_key"),
                )
                if saved:
                    data[key] = saved
            ini_writer.upsert_peer(fed_path, name, data, is_new=is_new)

        @bp.route("/ui/peers/new", methods=["POST"])
        @_admin_only
        def ui_peer_create():
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                admin_ui.flash("federation.ini not found — generate it first.", "error")
                return redirect(url_for("federation_plugin.ui_index"))
            name = (request.form.get("name") or "").strip()
            if not name:
                admin_ui.flash("Peer name is required.", "error")
                return redirect(url_for("federation_plugin.ui_index"))
            try:
                _save_peer_from_form(fed_path, name, is_new=True)
                admin_ui.flash(f"Peer '{name}' created. Restart the engine to apply.", "success")
            except ini_writer.IniError as exc:
                admin_ui.flash(f"Couldn't create peer: {exc}", "error")
            return redirect(url_for("federation_plugin.ui_index"))

        @bp.route("/ui/peers/<name>/edit", methods=["POST"])
        @_admin_only
        def ui_peer_edit(name: str):
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                admin_ui.flash("federation.ini not found.", "error")
                return redirect(url_for("federation_plugin.ui_index"))
            try:
                _save_peer_from_form(fed_path, name, is_new=False)
                admin_ui.flash(f"Peer '{name}' saved. Restart the engine to apply.", "success")
            except ini_writer.IniError as exc:
                admin_ui.flash(f"Couldn't save peer: {exc}", "error")
            return redirect(url_for("federation_plugin.ui_index"))

        @bp.route("/ui/peers/<name>/toggle", methods=["POST"])
        @_admin_only
        def ui_peer_toggle(name: str):
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                admin_ui.flash("federation.ini not found.", "error")
                return redirect(url_for("federation_plugin.ui_index"))
            enabled = request.form.get("enabled") == "1"
            try:
                ini_writer.set_peer_enabled(fed_path, name, enabled)
                admin_ui.flash(
                    f"Peer '{name}' {'enabled' if enabled else 'disabled'}. Restart the engine to apply.",
                    "success",
                )
            except ini_writer.IniError as exc:
                admin_ui.flash(f"Couldn't update peer: {exc}", "error")
            return redirect(url_for("federation_plugin.ui_index"))

        @bp.route("/ui/peers/<name>/delete", methods=["POST"])
        @_admin_only
        def ui_peer_delete(name: str):
            fed_path, err = self._fed_cfg_path_or_404()
            if err:
                admin_ui.flash("federation.ini not found.", "error")
                return redirect(url_for("federation_plugin.ui_index"))
            try:
                ini_writer.delete_peer(fed_path, name)
                admin_ui.flash(f"Peer '{name}' deleted. Restart the engine to apply.", "success")
            except ini_writer.IniError as exc:
                admin_ui.flash(f"Couldn't delete peer: {exc}", "error")
            return redirect(url_for("federation_plugin.ui_index"))

        self.blueprint = bp
