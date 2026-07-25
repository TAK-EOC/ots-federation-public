# ots_federation/default_config.py
# OTS plugin-framework config contract (docs.opentakserver.io/plugins.html).
# OTS core does not load this module itself — FederationPlugin.activate() seeds
# these defaults into app.config (see plugin.py). The web UI calls validate()
# on user-submitted config changes.
#
# Unlike the OTS plugin template, the federation engine's real configuration
# surface lives in federation.ini (peers, TLS material, group policy) — not in
# config.yml. These keys only control whether the plugin runs and where the
# INI lives; validate() therefore checks that the referenced INI exists and
# parses, and directs everything else to the INI file.

import configparser
import os
from dataclasses import dataclass


@dataclass
class DefaultConfig:
    # Loaded first; user overrides come from config.yml via app.config.
    # The DB Plugins table is the authoritative enable switch (PluginManager
    # passes it to activate()); this flag exists for config-surface parity
    # with the plugin-framework convention.
    OTS_FEDERATION_ENABLED = True

    # Path to federation.ini. Empty string means the engine falls back to
    # <OTS_DATA_FOLDER>/federation.ini (see plugin._get_default_fed_config_path).
    OTS_FEDERATION_CONFIG = ""

    # PY-31: runtime-tunable log level for the federation engine child process.
    # Change in config.yml (or the plugin config UI) and restart the plugin — or
    # send SIGHUP to the engine — to raise verbosity without editing code.
    OTS_FEDERATION_LOG_LEVEL = "INFO"

    @staticmethod
    def validate(config: dict) -> dict:
        """
        Validate user config input from the OTS web UI.

        Returns {"success": True, "error": ""} when valid, otherwise
        {"success": False, "error": "<message>"} — the shape the OTS
        plugin framework expects.
        """
        try:
            for key, value in config.items():
                if key not in DefaultConfig.__dict__.keys():
                    return {
                        "success": False,
                        "error": f"{key} is not a valid config key — peer, TLS, "
                                 "and group-policy settings belong in federation.ini",
                    }
                if key == "OTS_FEDERATION_ENABLED":
                    if type(value) is not bool:
                        return {
                            "success": False,
                            "error": f"{key} must be a boolean",
                        }
                elif key == "OTS_FEDERATION_LOG_LEVEL":
                    if str(value).upper() not in (
                        "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET",
                    ):
                        return {
                            "success": False,
                            "error": f"{key} must be a standard logging level name",
                        }
                elif key == "OTS_FEDERATION_CONFIG":
                    if type(value) is not str:
                        return {
                            "success": False,
                            "error": f"{key} must be a string path (or empty for "
                                     "the OTS_DATA_FOLDER default)",
                        }
                    if value:
                        if not os.path.isfile(value):
                            return {
                                "success": False,
                                "error": f"{key}: no federation config at {value}",
                            }
                        parser = configparser.ConfigParser()
                        try:
                            parser.read(value)
                        except configparser.Error as exc:
                            return {
                                "success": False,
                                "error": f"{key}: {value} is not valid INI: {exc}",
                            }
                        if not parser.has_section("federation"):
                            return {
                                "success": False,
                                "error": f"{key}: {value} has no [federation] section",
                            }

            return {"success": True, "error": ""}
        except BaseException as exc:  # noqa: BLE001 — framework contract: never raise
            return {"success": False, "error": str(exc)}
