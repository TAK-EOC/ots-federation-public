# tests/test_admin_ui.py
# End-to-end tests for the server-rendered admin page (ots_federation/
# admin_ui.py + the /ui/* routes in plugin.py). Exercises real Flask form
# POSTs (not the JSON API) since that's what the actual browser page sends,
# and the quickstart/export-bundle tests run the REAL subprocess (python -m
# ots_federation.quickstart / gen_fed_ca) rather than mocking it, since the
# whole point of these buttons is generating real cert material.
#
# quickstart.py's _check_ots_environment() requires `import opentakserver`
# to succeed. A conftest fixture stubs a minimal opentakserver package onto
# sys.path / PYTHONPATH for the duration of these tests only, since a full
# opentakserver install isn't a reasonable test dependency for this repo.

import io
import os
import sys

import pytest
from flask import Flask

from ots_federation.default_config import DefaultConfig
from ots_federation.plugin import FederationPlugin


@pytest.fixture
def stub_opentakserver_on_path(tmp_path, monkeypatch):
    """Make `import opentakserver` succeed for the quickstart subprocess's
    environment check, without needing the real (heavy) package."""
    stub_root = tmp_path / "stub_pkgs"
    (stub_root / "opentakserver").mkdir(parents=True)
    (stub_root / "opentakserver" / "__init__.py").write_text("")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(stub_root) + os.pathsep + env.get("PYTHONPATH", "")
    monkeypatch.setenv("PYTHONPATH", env["PYTHONPATH"])
    return stub_root


@pytest.fixture
def client(tmp_path):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    plugin = FederationPlugin()
    plugin._app = app
    plugin._fed_cfg_path = str(tmp_path / "federation.ini")
    plugin.load_metadata()
    for key in dir(DefaultConfig):
        if key.isupper():
            app.config.setdefault(key, getattr(DefaultConfig, key))
    plugin._build_blueprint()
    app.register_blueprint(plugin.blueprint)
    return app.test_client(), tmp_path


BASE = "/api/plugins/ots-federation/ui"


def test_page_renders_generate_form_when_no_ini_exists(client):
    c, _ = client
    r = c.get(BASE)
    assert r.status_code == 200
    assert b"Generate certs" in r.data
    assert b"{{" not in r.data and b"}}" not in r.data  # no unrendered Jinja


def test_quickstart_button_generates_real_certs_and_ini(client, stub_opentakserver_on_path):
    c, tmp_path = client
    r = c.post(
        f"{BASE}/quickstart",
        data={
            "server_id": "test-server",
            "server_address": "test.example.com",
            "listen_port": "9101",
            "accept_as": "*:__ANON__",
            "share_as": "__ANON__:__ANON__",
        },
        follow_redirects=True,
    )
    assert r.status_code == 200
    ini_path = tmp_path / "federation.ini"
    certs_dir = tmp_path / "federation_certs"
    assert ini_path.exists()
    for fname in ("fed-ca.crt", "fed-ca.key", "server.crt", "server.key", "server-chain.crt"):
        assert (certs_dir / fname).exists(), fname
    assert b"Peers" in r.data  # page now shows the configured sections


def _run_quickstart(c, tmp_path):
    return c.post(
        f"{BASE}/quickstart",
        data={"server_id": "test-server", "server_address": "test.example.com"},
    )


def test_peer_create_edit_toggle_delete_full_cycle(client, stub_opentakserver_on_path):
    c, tmp_path = client
    _run_quickstart(c, tmp_path)

    r = c.post(
        f"{BASE}/peers/new",
        data={
            "name": "testpeer",
            "display_name": "Test Peer",
            "address": "10.0.0.5",
            "port": "9100",
            "protocol": "grpc",
            "enabled": "on",
            "accept_as": "*:Cyan",
            "share_as": "Cyan:Cyan",
            "client_cert__file": (io.BytesIO(b"FAKECERTDATA"), "whatever.crt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"testpeer" in r.data
    uploaded = tmp_path / "federation_certs" / "peers" / "testpeer" / "client-chain.crt"
    assert uploaded.exists()
    assert uploaded.read_bytes() == b"FAKECERTDATA"

    # Edit: change notes, leave connection_token blank+unchecked -> stays unset
    r = c.post(
        f"{BASE}/peers/testpeer/edit",
        data={
            "name": "testpeer", "display_name": "Test Peer", "address": "10.0.0.5",
            "port": "9100", "protocol": "grpc", "enabled": "on",
            "accept_as": "*:Cyan", "share_as": "Cyan:Cyan",
            "notes": "updated via form", "connection_token": "",
        },
        follow_redirects=True,
    )
    assert b"updated via form" in r.data

    # Toggle disable
    r = c.post(f"{BASE}/peers/testpeer/toggle", data={"enabled": "0"}, follow_redirects=True)
    assert r.status_code == 200

    # Delete, and confirm it's actually gone from the peers table (not just
    # absent because the flash message happens to not repeat the name)
    r = c.post(f"{BASE}/peers/testpeer/delete", follow_redirects=True)
    peers_section = r.data.decode().split("<h2>Peers</h2>")[1].split("Add peer")[0]
    assert "testpeer" not in peers_section


def test_global_settings_form_and_tls_file_upload(client, stub_opentakserver_on_path):
    c, tmp_path = client
    _run_quickstart(c, tmp_path)

    r = c.post(
        f"{BASE}/global",
        data={
            "enabled": "on", "server_id": "test-server", "server_name": "test-server",
            "max_hops": "3", "listen_enabled": "on", "listen_ip": "0.0.0.0", "listen_port": "9101",
            "accept_as": "*:__ANON__", "share_as": "__ANON__:__ANON__",
            "allow_federated_delete": "on", "allow_mission_federation": "on",
            "allow_data_feed_federation": "on",
            "mission_fed_disruption_tolerance_recency_secs": "43200",
            "initialization_delay_secs": "30", "max_message_size_bytes": "268435456",
            "grpc_max_workers": "64", "rol_log_sink": "",
            "fed_ca_bundle": str(tmp_path / "federation_certs" / "fed-ca.crt"),
            "fed_ca_bundle__file": (io.BytesIO(b"NEWCADATA"), "ca.crt"),
            "fed_cert": "", "fed_key": "", "fed_key_pw": "", "fed_verify_hostname": "on",
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert (tmp_path / "federation_certs" / "fed-ca.crt").read_bytes() == b"NEWCADATA"


def test_export_bundle_produces_downloadable_zip(client, stub_opentakserver_on_path):
    c, tmp_path = client
    _run_quickstart(c, tmp_path)
    r = c.post(f"{BASE}/export-bundle")
    assert r.status_code == 200
    assert r.content_type == "application/zip"
    assert len(r.data) > 100


def test_restart_route_does_not_crash_without_a_live_broker(client):
    c, _ = client
    r = c.post(f"{BASE}/restart", follow_redirects=True)
    assert r.status_code == 200
