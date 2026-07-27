# tests/test_ini_writer.py
# Covers ots_federation/ini_writer.py: the admin UI's read/write path for
# federation.ini. Separate from config.py's strict runtime-loader tests
# because this module has different guarantees (lenient reads, comment
# preservation, secret masking) that config.py doesn't need to provide.

import configparser
import shutil

import pytest

from ots_federation import config as strict_config
from ots_federation import ini_writer as w

EXAMPLE_INI = "ots_federation/examples/federation.ini"


@pytest.fixture
def ini_path(tmp_path):
    dest = tmp_path / "federation.ini"
    shutil.copy(EXAMPLE_INI, dest)
    return str(dest)


def test_read_all_missing_file(tmp_path):
    result = w.read_all(str(tmp_path / "does_not_exist.ini"))
    assert result == {"global": {}, "ssl": {}, "peers": [], "exists": False}


def test_read_all_lists_existing_peers(ini_path):
    data = w.read_all(ini_path)
    assert data["exists"] is True
    names = {p["name"] for p in data["peers"]}
    assert "tak-server-east" in names
    assert "taky-peer-minimal" in names


def test_create_peer_round_trips_through_strict_loader(ini_path):
    w.upsert_peer(
        ini_path,
        "roundtrip",
        {
            "address": "10.0.0.9",
            "port": 9100,
            "display_name": "Roundtrip Peer",
            "accept_as": "*:White",
            "share_as": "White:White",
        },
        is_new=True,
    )

    cp = configparser.ConfigParser()
    cp.read(ini_path)
    fc = strict_config.get_federation_config(cp)
    peer = next(p for p in fc.peers if p.name == "roundtrip")
    assert peer.address == "10.0.0.9"
    assert peer.group_map_in == "*:White"
    assert peer.group_map_out == "White:White"


def test_create_peer_requires_address_and_display_name(ini_path):
    with pytest.raises(w.IniError):
        w.upsert_peer(ini_path, "incomplete", {}, is_new=True)


def test_create_peer_rejects_duplicate_name(ini_path):
    with pytest.raises(w.IniError):
        w.upsert_peer(
            ini_path,
            "tak-server-east",
            {"address": "1.2.3.4", "display_name": "Dup"},
            is_new=True,
        )


def test_edit_peer_requires_existing_section(ini_path):
    with pytest.raises(w.IniError):
        w.upsert_peer(ini_path, "does-not-exist", {"notes": "x"}, is_new=False)


def test_secret_is_masked_on_read_and_not_clobbered_by_mask_sentinel(ini_path):
    w.upsert_peer(
        ini_path,
        "secretpeer",
        {"address": "10.0.0.1", "display_name": "Secret Peer", "connection_token": "topsecret"},
        is_new=True,
    )
    data = w.read_all(ini_path)
    peer = next(p for p in data["peers"] if p["name"] == "secretpeer")
    assert peer["connection_token"] == "***"

    # Echoing the mask sentinel back (as a naive edit-and-resubmit client
    # would) must NOT overwrite the real secret.
    w.upsert_peer(ini_path, "secretpeer", {"connection_token": "***", "notes": "updated"}, is_new=False)

    cp = configparser.ConfigParser()
    cp.read(ini_path)
    assert cp.get("federate:secretpeer", "connection_token") == "topsecret"


def test_empty_string_clears_secret(ini_path):
    w.upsert_peer(
        ini_path,
        "secretpeer2",
        {"address": "10.0.0.2", "display_name": "Secret Peer 2", "connection_token": "topsecret"},
        is_new=True,
    )
    w.upsert_peer(ini_path, "secretpeer2", {"connection_token": ""}, is_new=False)

    cp = configparser.ConfigParser()
    cp.read(ini_path)
    assert not cp.has_option("federate:secretpeer2", "connection_token")


def test_set_peer_enabled_toggles_flag_only(ini_path):
    w.set_peer_enabled(ini_path, "tak-server-east", False)
    data = w.read_all(ini_path)
    peer = next(p for p in data["peers"] if p["name"] == "tak-server-east")
    assert peer["enabled"] is False
    # Address etc. should be untouched.
    assert peer["address"]


def test_delete_peer_removes_section(ini_path):
    w.delete_peer(ini_path, "taky-peer-minimal")
    data = w.read_all(ini_path)
    names = {p["name"] for p in data["peers"]}
    assert "taky-peer-minimal" not in names


def test_delete_nonexistent_peer_raises(ini_path):
    with pytest.raises(w.IniError):
        w.delete_peer(ini_path, "does-not-exist")


def test_writes_preserve_all_comment_lines(ini_path):
    before = [
        line
        for line in open(ini_path).read().splitlines()
        if line.strip().startswith(("#", ";"))
    ]

    w.upsert_peer(
        ini_path,
        "commentcheck",
        {"address": "10.0.0.3", "display_name": "Comment Check"},
        is_new=True,
    )
    w.set_peer_enabled(ini_path, "commentcheck", False)
    w.delete_peer(ini_path, "commentcheck")
    w.update_global(ini_path, {"max_hops": 5}, {})

    after = [
        line
        for line in open(ini_path).read().splitlines()
        if line.strip().startswith(("#", ";"))
    ]
    assert before == after


def test_update_global_writes_friendly_alias_names(ini_path):
    w.update_global(ini_path, {"accept_as": "*:Cyan"}, {})
    cp = configparser.ConfigParser()
    cp.read(ini_path)
    assert cp.get("federation", "accept_as") == "*:Cyan"


def test_update_global_ssl_section(ini_path):
    w.update_global(ini_path, {}, {"fed_verify_hostname": False})
    data = w.read_all(ini_path)
    assert data["ssl"]["fed_verify_hostname"] is False
