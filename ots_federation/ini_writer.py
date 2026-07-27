# ots_federation/ini_writer.py
# Admin-UI config surface: reads and writes federation.ini for the /peers and
# /global routes in plugin.py.
#
# Deliberately SEPARATE from config.py's get_federation_config():
#   - config.py is the strict runtime loader used by the engine child process.
#     It raises on missing required fields and DROPS disabled peers entirely
#     (get_federation_config only returns peers where enabled=True).
#   - This module is a lenient reader/writer for the admin UI. It must be able
#     to display a disabled or half-configured peer (e.g. one the operator is
#     midway through editing) without raising, and it must preserve the
#     hand-written comments in federation.ini (quickstart.py emits a "minimal,
#     commented" file — a raw configparser round-trip would silently discard
#     every comment).
#
# Uses configupdater (comment/formatting-preserving INI editor) instead of
# stdlib configparser for all WRITE operations. Reads can use either; we use
# configupdater throughout so read and write share one code path.
#
# Secret handling:
#   - connection_token ([federate:<name>]) and fed_key_pw ([federation_ssl])
#     are never returned in full. read_all() masks them as "***" when set,
#     "" when unset.
#   - On write, a field is only changed if the caller explicitly supplies a
#     value for it. Sending "***" (the masked sentinel echoed back by a
#     round-trip GET→edit→PUT in a naive client) is treated as "leave
#     unchanged" specifically so the frontend never has to know the real
#     secret to safely re-submit a form. Sending "" clears it. Omitting the
#     key entirely also leaves it unchanged.

from __future__ import annotations

import os
import threading
from typing import Any, Optional

from configupdater import ConfigUpdater

_MASK = "***"

# Write operations mutate federation.ini on disk; serialize them so two
# concurrent admin-UI requests (or a request racing the watchdog reading the
# file) can't interleave. Does not protect against a second OTS process editing
# the same file — matches the existing single-writer assumption elsewhere in
# this plugin (quickstart.py, gen_fed_ca.py).
_write_lock = threading.Lock()


class IniError(Exception):
    """Raised for validation/IO failures the caller should show to the operator."""


# --- field schemas -----------------------------------------------------
# (key, kind, default, secret?) — kind is one of "str", "bool", "int".
# `key` is the INI key ots_federation actually reads (config.py); where
# config.py accepts an old/new alias pair, we always WRITE the new
# (friendly) name and read either.

PEER_FIELDS: list[tuple[str, str, Any, bool]] = [
    ("enabled", "bool", True, False),
    ("address", "str", "", False),
    ("port", "int", 9100, False),
    ("protocol", "str", "grpc", False),
    ("display_name", "str", "", False),
    ("notes", "str", "", False),
    ("fingerprint", "str", "", False),
    ("server_id", "str", "", False),
    ("ca_cert", "str", "", False),
    ("client_cert", "str", "", False),
    ("client_key", "str", "", False),
    ("max_hops", "int", -1, False),
    ("accept_as", "str", "*:", False),
    ("share_as", "str", "*:*", False),
    ("reconnect_interval", "int", 30, False),
    ("health_check_interval", "int", 10, False),
    ("protocol_version", "int", 2, False),
    ("filter", "str", "", False),
    ("max_frame_size", "int", 0, False),
    ("max_retries", "int", -1, False),
    ("unlimited_retries", "bool", True, False),
    ("fallback", "str", "", False),
    ("use_token", "bool", False, False),
    ("connection_token", "str", "", True),
    ("token_type", "str", "", False),
    ("share_alerts", "bool", True, False),
    ("archive", "bool", True, False),
    ("federated_group_mapping", "bool", True, False),
    ("automatic_group_mapping", "bool", False, False),
    ("use_group_hop_limiting", "bool", False, False),
    ("fallback_when_no_group_mappings", "bool", False, False),
    ("token_federate", "bool", False, False),
    ("token_expiration", "int", 0, False),
    ("inbound_group_mapping", "str", "", False),
    ("mission_federate_default", "bool", True, False),
]
PEER_REQUIRED = ("address", "display_name")
# The legacy alias each friendly key may already appear as in an existing
# file (config.py's _resolve_alias). We only ever WRITE the friendly name,
# but we must know the old name so an edit doesn't leave a stale old-key
# value that would out-precedence what we just wrote (old key wins only when
# new key is ALSO absent, per config.py — but a leftover old key is still
# confusing to an operator reading the file after an edit, so we remove it).
PEER_ALIASES = {"accept_as": "group_map_in", "share_as": "group_map_out"}

GLOBAL_FIELDS: list[tuple[str, str, Any, bool]] = [
    ("enabled", "bool", True, False),
    ("server_id", "str", "", False),
    ("server_name", "str", "", False),
    ("max_hops", "int", 3, False),
    ("listen_enabled", "bool", False, False),
    ("listen_ip", "str", "0.0.0.0", False),
    ("listen_port", "int", 9101, False),
    ("accept_as", "str", "", False),
    ("share_as", "str", "", False),
    ("allow_federated_delete", "bool", True, False),
    ("allow_mission_federation", "bool", True, False),
    ("allow_data_feed_federation", "bool", True, False),
    ("enable_mission_fed_disruption_tolerance", "bool", False, False),
    ("mission_fed_disruption_tolerance_recency_secs", "int", 43200, False),
    ("federate_only_public_missions", "bool", False, False),
    ("enable_data_pkg_file_filter", "bool", False, False),
    ("allow_duplicate", "bool", False, False),
    ("initialization_delay_secs", "int", 30, False),
    ("max_message_size_bytes", "int", 268435456, False),
    ("grpc_max_workers", "int", 64, False),
    ("rol_log_sink", "str", "", False),
    ("inject_cot_parser", "bool", False, False),
]
GLOBAL_REQUIRED = ("server_id",)
GLOBAL_ALIASES = {"accept_as": "default_group_map_in", "share_as": "default_group_map_out"}

SSL_FIELDS: list[tuple[str, str, Any, bool]] = [
    ("fed_ca_bundle", "str", "", False),
    ("fed_cert", "str", "", False),
    ("fed_key", "str", "", False),
    ("fed_key_pw", "str", "", True),
    ("fed_verify_hostname", "bool", True, False),
]


def _coerce_out(kind: str, raw: Optional[str], default: Any) -> Any:
    if raw is None:
        return default
    if kind == "bool":
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if kind == "int":
        try:
            return int(raw.strip())
        except ValueError:
            return default
    return raw


def _coerce_in(kind: str, value: Any) -> str:
    if kind == "bool":
        return "true" if bool(value) else "false"
    return str(value)


def _load(ini_path: str) -> ConfigUpdater:
    if not os.path.exists(ini_path):
        raise IniError(f"federation config not found at {ini_path}")
    cfg = ConfigUpdater()
    cfg.read(ini_path)
    return cfg


def _section_to_dict(
    cfg: ConfigUpdater,
    section: str,
    fields: list[tuple[str, str, Any, bool]],
    aliases: dict[str, str],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    has_section = cfg.has_section(section)
    for key, kind, default, secret in fields:
        raw = None
        if has_section:
            if cfg[section].get(key) is not None:
                raw = cfg[section][key].value
            elif key in aliases and cfg[section].get(aliases[key]) is not None:
                raw = cfg[section][aliases[key]].value
        value = _coerce_out(kind, raw, default)
        if secret:
            out[key] = _MASK if raw else ""
        else:
            out[key] = value
    return out


def read_all(ini_path: str) -> dict[str, Any]:
    """Return {"global": {...}, "ssl": {...}, "peers": [...]} for the admin UI.

    Includes disabled peers (unlike config.get_federation_config, which drops
    them) so the operator can see and re-enable them. Never raises for a
    malformed individual peer section — best-effort field extraction only;
    this is a display/edit surface, not the engine's runtime loader.
    """
    if not os.path.exists(ini_path):
        return {"global": {}, "ssl": {}, "peers": [], "exists": False}

    cfg = _load(ini_path)
    result: dict[str, Any] = {
        "exists": True,
        "global": _section_to_dict(cfg, "federation", GLOBAL_FIELDS, GLOBAL_ALIASES),
        "ssl": _section_to_dict(cfg, "federation_ssl", SSL_FIELDS, {}),
        "peers": [],
    }

    for section in cfg.sections():
        if not section.startswith("federate:"):
            continue
        peer = _section_to_dict(cfg, section, PEER_FIELDS, PEER_ALIASES)
        peer["name"] = section[len("federate:"):]
        result["peers"].append(peer)

    result["peers"].sort(key=lambda p: p["name"])
    return result


def _apply_fields(
    cfg: ConfigUpdater,
    section: str,
    fields: list[tuple[str, str, Any, bool]],
    aliases: dict[str, str],
    data: dict[str, Any],
) -> None:
    if not cfg.has_section(section):
        cfg.add_section(section)

    for key, kind, _default, secret in fields:
        if key not in data:
            continue  # not supplied — leave existing value untouched
        value = data[key]

        if secret:
            # "" -> keys present already? "" means clear; None/absent handled
            # by the `key not in data` check above. The masked sentinel means
            # "no change" (frontend echoes it back on a GET->PUT round trip).
            if value == _MASK:
                continue
            if value in (None, ""):
                if key in cfg[section]:
                    del cfg[section][key]
                continue
            cfg[section][key] = _coerce_in(kind, value)
            continue

        if value is None or value == "":
            if key in cfg[section]:
                del cfg[section][key]
            continue

        cfg[section][key] = _coerce_in(kind, value)
        # Remove a stale legacy-alias key so the file doesn't end up with both
        # (config.py would still resolve correctly — new key wins — but a
        # leftover old key reads as a bug to the next person editing the file).
        alias = aliases.get(key)
        if alias and alias in cfg[section]:
            del cfg[section][alias]


def upsert_peer(ini_path: str, name: str, data: dict[str, Any], *, is_new: bool) -> None:
    """Create or update a [federate:<name>] section. Preserves file comments."""
    if not name or "]" in name or "\n" in name:
        raise IniError("invalid peer name")

    with _write_lock:
        cfg = _load(ini_path)
        section = f"federate:{name}"

        if is_new and cfg.has_section(section):
            raise IniError(f"a peer named {name!r} already exists")
        if not is_new and not cfg.has_section(section):
            raise IniError(f"no peer named {name!r} exists")

        merged = dict(data)
        if is_new:
            for key, _kind, default, _secret in PEER_FIELDS:
                merged.setdefault(key, default)
            for req in PEER_REQUIRED:
                if not merged.get(req):
                    raise IniError(f"'{req}' is required")

        _apply_fields(cfg, section, PEER_FIELDS, PEER_ALIASES, merged)
        cfg.update_file()


def delete_peer(ini_path: str, name: str) -> None:
    with _write_lock:
        cfg = _load(ini_path)
        section = f"federate:{name}"
        if not cfg.has_section(section):
            raise IniError(f"no peer named {name!r} exists")
        cfg.remove_section(section)
        cfg.update_file()


def set_peer_enabled(ini_path: str, name: str, enabled: bool) -> None:
    upsert_peer(ini_path, name, {"enabled": enabled}, is_new=False)


def update_global(ini_path: str, data: dict[str, Any], ssl_data: Optional[dict[str, Any]] = None) -> None:
    with _write_lock:
        cfg = _load(ini_path)
        _apply_fields(cfg, "federation", GLOBAL_FIELDS, GLOBAL_ALIASES, data)
        if ssl_data:
            _apply_fields(cfg, "federation_ssl", SSL_FIELDS, {}, ssl_data)
        cfg.update_file()
