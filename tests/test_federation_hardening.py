# tests/test_federation_hardening.py
# Ported from taky tests/test_federation_hardening.py into
# ots_federation plugin namespace..
# Adaptations vs. taky original:
#   - All taky.* imports → ots_federation.*
#   - _build_taky_version → _build_ots_version (uses importlib.metadata)
#   - _make_peer_config includes display_name="" (plugin field, not required
#     when constructing the dataclass directly; only enforced in _parse_peer_section)
#   - _minimal_fed_ini includes display_name in [federate:alpha] (required)
#   - allow_federated_delete DEFAULT conflict documented below:
#       taky-fed default: False (secure conservative)
#       plugin default: True  (matches CoreConfig allowFederatedDelete spec)
#     Tests that assert the config-level default are adapted to assert True;
#     the guard behaviour tests use explicit kwarg and are unaffected.
# Tests for the taky-fed hardening batch:
#   health_check_interval default 60s -> 10s
#   TakServerVersion populated in outbound Subscription
#   display_name + fallback_when_no_group_mappings config
#   allow_federated_delete config + inbound DELETE guard
#   ROL frame logging passthrough
#   per-group hop limit enforcement
#   ContactListEntry wired to LocalBus / OTS

import configparser
import io
import os
import queue
import tempfile
import unittest
from datetime import datetime as dt, timedelta
from unittest.mock import MagicMock, patch

from lxml import etree

from ots_federation import models
from ots_federation.codec import (
    FedMeta,
    decode_contact_entry,
    decode_federated_event,
    encode_federated_event,
    prepare_outbound_event,
    synthesize_contact_event,
)
from ots_federation.config import (
    FederatePeerConfig,
    FederationConfig,
    get_federation_config,
)
from ots_federation.groups import FederateGroupRegistry
from ots_federation.proto import fig_pb2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg_from_str(ini_text: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_file(io.StringIO(ini_text))
    return cfg


def _minimal_fed_ini(extra_fed_keys: str = "", peer_keys: str = "") -> str:
    """Minimal valid taky.conf with [federation] and one [federate:alpha] section.

    display_name is included in [federate:alpha] because it is REQUIRED by the
    plugin's _parse_peer_section (raises ConfigError when missing)..
    """
    return (
        "[federation]\nenabled = true\nserver_id = ots-test\n"
        f"{extra_fed_keys}\n"
        "[federate:alpha]\naddress = 10.0.0.1\ndisplay_name = Alpha\n"
        f"{peer_keys}\n"
    )


def _make_geo_proto(uid="test-uid", etype="a-f-G-U-C"):
    """Build a minimal FederatedEvent with a GeoEvent."""
    now_ms = int(dt.utcnow().timestamp() * 1000)
    geo = fig_pb2.GeoEvent(
        uid=uid, type=etype, coordSource="m-g",
        sendTime=now_ms, startTime=now_ms,
        staleTime=now_ms + 300_000,
    )
    return fig_pb2.FederatedEvent(event=geo)


def _make_delete_proto(uid="del-uid"):
    return _make_geo_proto(uid=uid, etype="t-x-d-d")


def _make_peer_config(**overrides):
    defaults = dict(
        name="alpha", enabled=True, address="127.0.0.1", port=9100,
        ca_cert="", client_cert="", client_key="",
        max_hops=3, reconnect_interval=1, health_check_interval=10,
        display_name="",  # plugin field; empty is fine for direct-construct
    )
    defaults.update(overrides)
    return FederatePeerConfig(**defaults)


def _make_simple_event(uid="evt-1", etype="a-f-G-U-C"):
    """Build a minimal models.Event (no detail)."""
    now = dt.utcnow()
    evt = models.Event(
        uid=uid, etype=etype, how="m-g",
        time=now, start=now, stale=now + timedelta(minutes=5),
    )
    evt.point = models.Point(lat=0, lon=0, hae=0, ce=9999999, le=9999999)
    return evt


def _make_takuser_event(uid="u1", group_name="White"):
    """Build a models.Event with a real TAKUser detail (group_name e.g. 'White').

    Option D : sets evt.local_acl_groups sidecar so prepare_outbound_event
    can apply per-group hop-limit and outbound group policy using the ACL cache
    sidecar rather than TAKUser.group (the Phase-1→D source swap).
    """
    from ots_federation.models.takuser import TAKUser
    now = dt.utcnow()
    evt = models.Event(
        uid=uid, etype="a-f-G-U-C", how="m-g",
        time=now, start=now, stale=now + timedelta(minutes=5),
    )
    evt.point = models.Point(lat=0, lon=0, hae=0, ce=9999999, le=9999999)

    detail_xml = (
        f'<detail>'
        f'<takv os="Android" version="4.10.0" device="Test" platform="ATAK-CIV"/>'
        f'<contact callsign="TestUser" endpoint="*:-1:stcp"/>'
        f'<uid Droid="TestUser"/>'
        f'<__group name="{group_name}" role="HQ"/>'
        f'</detail>'
    )
    detail_elm = etree.fromstring(detail_xml.encode())
    evt.detail = TAKUser.from_elm(detail_elm, uid=uid)
    #: ACL cache sidecar — set directly in tests to simulate a warm cache.
    evt.local_acl_groups = frozenset([group_name])
    return evt


# ---------------------------------------------------------------------------
# health_check_interval default 10s
# ---------------------------------------------------------------------------

class TestHealthCheckIntervalDefault(unittest.TestCase):
    """health_check_interval default was 60s, must now be 10s."""

    def test_dataclass_default_is_10(self):
        peer = _make_peer_config()
        self.assertEqual(peer.health_check_interval, 10)

    def test_config_parse_default_is_10(self):
        cfg = _cfg_from_str(_minimal_fed_ini())
        result = get_federation_config(cfg)
        self.assertEqual(result.peers[0].health_check_interval, 10)

    def test_config_parse_override_respected(self):
        cfg = _cfg_from_str(_minimal_fed_ini(peer_keys="health_check_interval = 30"))
        result = get_federation_config(cfg)
        self.assertEqual(result.peers[0].health_check_interval, 30)

    def test_dataclass_explicit_override(self):
        peer = _make_peer_config(health_check_interval=5)
        self.assertEqual(peer.health_check_interval, 5)


# ---------------------------------------------------------------------------
# TakServerVersion in Subscription
# ---------------------------------------------------------------------------

class TestTakServerVersionInSubscription(unittest.TestCase):
    """Outbound Subscription must carry TakServerVersion."""

    def test_build_ots_version_returns_proto(self):
        from ots_federation.client import _build_ots_version
        ver = _build_ots_version()
        self.assertIsInstance(ver, fig_pb2.TakServerVersion)

    def test_variant_is_ots_federation(self):
        from ots_federation.client import _build_ots_version
        ver = _build_ots_version()
        self.assertEqual(ver.variant, "ots-federation")

    def test_version_fields_are_ints(self):
        """major/minor/patch must be non-negative integers."""
        from ots_federation.client import _build_ots_version
        ver = _build_ots_version()
        self.assertGreaterEqual(ver.major, 0)
        self.assertGreaterEqual(ver.minor, 0)
        self.assertGreaterEqual(ver.patch, 0)

    def test_version_in_subscription(self):
        """FederateClient._build_subscription must include version field."""
        from ots_federation.client import FederateClient
        from ots_federation.bridge import FederationBridge
        bridge = FederationBridge()
        try:
            peer_cfg = _make_peer_config()
            client = FederateClient(
                peer_name="alpha", peer_config=peer_cfg,
                node_id="OTS-TEST", bridge=bridge,
            )
            sub = client._build_subscription()
            self.assertTrue(sub.HasField("version"))
            self.assertEqual(sub.version.variant, "ots-federation")
        finally:
            bridge.close()

    def test_fallback_on_bad_version_string(self):
        """_build_ots_version must not raise on uninstalled or bad version."""
        from ots_federation.client import _build_ots_version
        import importlib.metadata as _meta
        # Patch version to raise PackageNotFoundError
        with patch.object(_meta, "version", side_effect=_meta.PackageNotFoundError):
            ver = _build_ots_version()
        # Should not raise; major/minor/patch default to 0
        self.assertEqual(ver.major, 0)
        self.assertEqual(ver.variant, "ots-federation")


# ---------------------------------------------------------------------------
# display_name + fallback_when_no_group_mappings
# ---------------------------------------------------------------------------

class TestDisplayNameConfig(unittest.TestCase):
    """display_name in [federate:<name>] surfaces in outgoing Identity.

    Note: unlike taky-fed where display_name is optional (fallback to node_id)
    the plugin treats display_name as REQUIRED (ConfigError if absent in INI).
    When constructing FederatePeerConfig directly, display_name may be empty —
    _build_identity still falls back to node_id as designed.
    """

    def test_display_name_default_empty_on_direct_construct(self):
        peer = _make_peer_config()
        self.assertEqual(peer.display_name, "")

    def test_display_name_parsed_from_config(self):
        # Build the ini directly to avoid duplicate display_name in the template
        ini = (
            "[federation]\nenabled = true\nserver_id = ots-test\n"
            "[federate:alpha]\naddress = 10.0.0.1\ndisplay_name = Alpha Server\n"
        )
        cfg = _cfg_from_str(ini)
        result = get_federation_config(cfg)
        self.assertEqual(result.peers[0].display_name, "Alpha Server")

    def test_display_name_required_by_config_parser(self):
        """_parse_peer_section raises ConfigError when display_name is missing."""
        from ots_federation.config import ConfigError
        ini = (
            "[federation]\nenabled = true\nserver_id = ots-test\n"
            "[federate:nodisplay]\naddress = 10.0.0.2\n"
        )
        cfg = _cfg_from_str(ini)
        with self.assertRaises(ConfigError):
            get_federation_config(cfg)

    def test_display_name_used_in_identity_when_set(self):
        from ots_federation.client import FederateClient
        from ots_federation.bridge import FederationBridge
        bridge = FederationBridge()
        try:
            peer_cfg = _make_peer_config(display_name="My Alpha Peer")
            client = FederateClient(
                peer_name="alpha", peer_config=peer_cfg,
                node_id="OTS-NODE", bridge=bridge,
            )
            identity = client._build_identity()
            self.assertEqual(identity.name, "My Alpha Peer")
        finally:
            bridge.close()

    def test_identity_falls_back_to_node_id_when_display_name_empty(self):
        from ots_federation.client import FederateClient
        from ots_federation.bridge import FederationBridge
        bridge = FederationBridge()
        try:
            peer_cfg = _make_peer_config(display_name="")
            client = FederateClient(
                peer_name="alpha", peer_config=peer_cfg,
                node_id="OTS-NODE", bridge=bridge,
            )
            identity = client._build_identity()
            self.assertEqual(identity.name, "OTS-NODE")
        finally:
            bridge.close()


class TestFallbackWhenNoGroupMappings(unittest.TestCase):
    """fallback_when_no_group_mappings wires to registry.set_fallback_allow."""

    def test_default_is_false(self):
        peer = _make_peer_config()
        self.assertFalse(peer.fallback_when_no_group_mappings)

    def test_config_parse_true(self):
        cfg = _cfg_from_str(
            _minimal_fed_ini(peer_keys="fallback_when_no_group_mappings = true")
        )
        result = get_federation_config(cfg)
        self.assertTrue(result.peers[0].fallback_when_no_group_mappings)

    def test_fallback_wired_to_registry_in_manager(self):
        """When fallback=True, FederationManager sets fallback_allow on registry."""
        from ots_federation.manager import FederationManager
        peer_cfg = _make_peer_config(
            ca_cert="", client_cert="", client_key="",
            fallback_when_no_group_mappings=True,
        )
        fed_cfg = FederationConfig(
            enabled=True,
            server_id="OTS-LOCAL",
            server_name="Local",
            max_hops=3,
            peers=[peer_cfg],
        )
        mgr = FederationManager(fed_cfg)
        provisional_id = "127.0.0.1:9100"
        # _fallback_allow should be True for this provisional_id
        self.assertTrue(mgr.group_registry._fallback_allow.get(provisional_id, False))


# ---------------------------------------------------------------------------
# allow_federated_delete config + inbound guard
# ---------------------------------------------------------------------------

class TestAllowFederatedDeleteConfig(unittest.TestCase):
    """allow_federated_delete config and guard..

    DEFAULT CONFLICT:
      taky-fed:  default=False (secure conservative, matches TAK Server std)
      plugin:    default=True  (matches CoreConfig allowFederatedDelete spec)

    Plugin keeps default=True per parity work. The guard logic is fully
    implemented; operators must explicitly set allow_federated_delete=False in
    taky.conf to enforce the DELETE restriction.
    """

    def test_federation_config_default_true_plugin(self):
        """Plugin default is True (CoreConfig spec). See conflict note above."""
        fed_cfg = FederationConfig(enabled=True, server_id="X")
        self.assertTrue(fed_cfg.allow_federated_delete)  # plugin: True (conflict)

    def test_config_parse_default_true_plugin(self):
        """INI omitting allow_federated_delete → True (plugin default)."""
        cfg = _cfg_from_str(_minimal_fed_ini())
        result = get_federation_config(cfg)
        self.assertTrue(result.allow_federated_delete)  # plugin: True (conflict)

    def test_config_parse_explicit_false(self):
        cfg = _cfg_from_str(_minimal_fed_ini(extra_fed_keys="allow_federated_delete = false"))
        result = get_federation_config(cfg)
        self.assertFalse(result.allow_federated_delete)

    def test_config_parse_true(self):
        cfg = _cfg_from_str(_minimal_fed_ini(extra_fed_keys="allow_federated_delete = true"))
        result = get_federation_config(cfg)
        self.assertTrue(result.allow_federated_delete)


class TestFederatedDeleteInboundGuard(unittest.TestCase):
    """Inbound DELETE events dropped when allow_federated_delete=False."""

    def _make_client(self, allow_delete=False):
        from ots_federation.client import FederateClient
        from ots_federation.bridge import FederationBridge
        bridge = FederationBridge()
        peer_cfg = _make_peer_config()
        client = FederateClient(
            peer_name="alpha", peer_config=peer_cfg,
            node_id="OTS-NODE", bridge=bridge,
            allow_federated_delete=allow_delete,
        )
        return client, bridge

    def test_delete_event_dropped_when_not_allowed(self):
        client, bridge = self._make_client(allow_delete=False)
        try:
            proto = _make_delete_proto()
            client._handle_inbound(proto, decode_federated_event)
            # Bridge queue should be empty — event was dropped
            self.assertTrue(bridge.inbound_q.empty())
        finally:
            bridge.close()

    def test_delete_event_forwarded_when_allowed(self):
        client, bridge = self._make_client(allow_delete=True)
        try:
            proto = _make_delete_proto()
            client._handle_inbound(proto, decode_federated_event)
            # Bridge queue should have the event
            self.assertFalse(bridge.inbound_q.empty())
        finally:
            bridge.close()

    def test_non_delete_event_always_forwarded(self):
        client, bridge = self._make_client(allow_delete=False)
        try:
            proto = _make_geo_proto(etype="a-f-G-U-C")
            client._handle_inbound(proto, decode_federated_event)
            self.assertFalse(bridge.inbound_q.empty())
        finally:
            bridge.close()

    def test_client_constructor_accept_allow_federated_delete(self):
        """FederateClient constructor must accept allow_federated_delete kwarg."""
        from ots_federation.client import FederateClient
        from ots_federation.bridge import FederationBridge
        bridge = FederationBridge()
        try:
            client = FederateClient(
                peer_name="x", peer_config=_make_peer_config(),
                node_id="N", bridge=bridge, allow_federated_delete=True,
            )
            self.assertTrue(client.allow_federated_delete)
        finally:
            bridge.close()


# ---------------------------------------------------------------------------
# ROL frame logging passthrough
# ---------------------------------------------------------------------------

class TestROLFrameLogging(unittest.TestCase):
    """ServerROLStream logs program at INFO and optionally writes to sink."""

    def _make_servicer(self, sink_path=""):
        from ots_federation.fed_server import FederatedChannelServicer
        bridge_mock = MagicMock()
        manager_mock = MagicMock()
        return FederatedChannelServicer(
            server_id="SRV", server_name="Test", bridge=bridge_mock,
            manager=manager_mock, default_max_hops=3,
            rol_log_sink=sink_path,
        )

    def test_rol_log_sink_default_empty(self):
        cfg = FederationConfig(enabled=True, server_id="X")
        self.assertEqual(cfg.rol_log_sink, "")

    def test_config_parse_rol_sink(self):
        cfg = _cfg_from_str(_minimal_fed_ini(extra_fed_keys="rol_log_sink = /tmp/rol.bin"))
        result = get_federation_config(cfg)
        self.assertEqual(result.rol_log_sink, "/tmp/rol.bin")

    def test_serverrolstream_logs_at_info(self):
        """ServerROLStream must emit at least one INFO log per ROL frame."""
        servicer = self._make_servicer()
        rol = fig_pb2.ROL(program="test-program")
        ctx = MagicMock()
        ctx.peer.return_value = "127.0.0.1:12345"

        with self.assertLogs("FederatedChannelServicer", level="INFO") as cm:
            servicer.ServerROLStream(iter([rol]), ctx)

        self.assertTrue(any("test-program" in line for line in cm.output))

    def test_serverrolstream_writes_to_sink(self):
        """When sink configured, raw ROL bytes are appended with a 4-byte length prefix."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            sink_path = f.name
        try:
            servicer = self._make_servicer(sink_path=sink_path)
            rol = fig_pb2.ROL(program="my-program")
            ctx = MagicMock()
            ctx.peer.return_value = "127.0.0.1:12345"

            with self.assertLogs("FederatedChannelServicer", level="INFO"):
                servicer.ServerROLStream(iter([rol]), ctx)

            with open(sink_path, "rb") as f:
                data = f.read()
            # First 4 bytes = big-endian length
            self.assertGreater(len(data), 4)
            msg_len = int.from_bytes(data[:4], "big")
            raw_proto = data[4:4 + msg_len]
            decoded = fig_pb2.ROL()
            decoded.ParseFromString(raw_proto)
            self.assertEqual(decoded.program, "my-program")
        finally:
            os.unlink(sink_path)

    def test_serverrolstream_no_sink_no_write(self):
        """Without sink configured, no file writes should occur (no side effects)."""
        servicer = self._make_servicer(sink_path="")
        rol = fig_pb2.ROL(program="prog")
        ctx = MagicMock()
        ctx.peer.return_value = "127.0.0.1:12345"
        # Should not raise, no file creation
        with self.assertLogs("FederatedChannelServicer", level="INFO"):
            servicer.ServerROLStream(iter([rol]), ctx)


# ---------------------------------------------------------------------------
# per-group hop limits enforcement
# ---------------------------------------------------------------------------

class TestPerGroupHopLimits(unittest.TestCase):
    """FederateGroupHopLimits enforced in prepare_outbound_event."""

    def test_group_hop_limits_extracted_from_proto(self):
        """decode_federated_event extracts FederateGroupHopLimits into FedMeta."""
        now_ms = int(dt.utcnow().timestamp() * 1000)
        geo = fig_pb2.GeoEvent(
            uid="x", type="a-f-G-U-C", coordSource="m-g",
            sendTime=now_ms, startTime=now_ms, staleTime=now_ms + 300_000,
        )
        limits = fig_pb2.FederateGroupHopLimits(
            useFederateGroupHopLimits=True,
        )
        lim = limits.limits.add()
        lim.groupName = "White"
        lim.maxHops = 2
        lim.currentHops = 2

        proto = fig_pb2.FederatedEvent(event=geo, federateGroupHopLimits=limits)
        evt, fed_meta = decode_federated_event(proto)
        self.assertIsNotNone(fed_meta.group_hop_limits)
        self.assertTrue(fed_meta.group_hop_limits.useFederateGroupHopLimits)

    def test_group_hop_limits_not_set_when_use_flag_false(self):
        """FedMeta.group_hop_limits is None when useFederateGroupHopLimits=False."""
        now_ms = int(dt.utcnow().timestamp() * 1000)
        geo = fig_pb2.GeoEvent(
            uid="x", type="a-f-G-U-C", coordSource="m-g",
            sendTime=now_ms, startTime=now_ms, staleTime=now_ms + 300_000,
        )
        limits = fig_pb2.FederateGroupHopLimits(useFederateGroupHopLimits=False)
        lim = limits.limits.add()
        lim.groupName = "White"
        lim.maxHops = 2
        lim.currentHops = 2
        proto = fig_pb2.FederatedEvent(event=geo, federateGroupHopLimits=limits)
        _, fed_meta = decode_federated_event(proto)
        self.assertIsNone(fed_meta.group_hop_limits)

    def test_per_group_limit_drops_event_at_limit(self):
        """prepare_outbound_event drops events when per-group hops exhausted."""
        evt = _make_takuser_event(uid="u1", group_name="White")

        limits = fig_pb2.FederateGroupHopLimits(useFederateGroupHopLimits=True)
        lim = limits.limits.add()
        lim.groupName = "White"
        lim.maxHops = 2
        lim.currentHops = 2  # at limit — should drop
        fed_meta = FedMeta(
            seen_server_ids=["other-node"],
            current_hops=1,
            max_hops=10,
            group_hop_limits=limits,
        )
        evt.fed_meta = fed_meta

        result = prepare_outbound_event(evt, node_id="NODE", default_max_hops=10)
        self.assertIsNone(result)

    def test_per_group_limit_passes_event_below_limit(self):
        """prepare_outbound_event forwards events when per-group hops not exhausted."""
        # A plain event without TAKUser detail — group check is bypassed
        # so the event passes through on the global hop check alone.
        evt = _make_simple_event(uid="u2")

        limits = fig_pb2.FederateGroupHopLimits(useFederateGroupHopLimits=True)
        lim = limits.limits.add()
        lim.groupName = "White"
        lim.maxHops = 5
        lim.currentHops = 2  # below limit — would pass even if group matched
        fed_meta = FedMeta(
            seen_server_ids=["other-node"],
            current_hops=1,
            max_hops=10,
            group_hop_limits=limits,
        )
        evt.fed_meta = fed_meta

        result = prepare_outbound_event(evt, node_id="NODE", default_max_hops=10)
        # Non-TAKUser event bypasses group check → should encode and return proto
        self.assertIsNotNone(result)

    def test_group_hop_limits_propagated_through_encode(self):
        """encode_federated_event propagates group_hop_limits from FedMeta."""
        evt = _make_simple_event()
        limits = fig_pb2.FederateGroupHopLimits(useFederateGroupHopLimits=True)
        lim = limits.limits.add()
        lim.groupName = "Cyan"
        lim.maxHops = 3
        lim.currentHops = 1
        fed_meta = FedMeta(
            seen_server_ids=["node-a"],
            current_hops=1,
            max_hops=5,
            group_hop_limits=limits,
        )
        proto = encode_federated_event(evt, fed_meta)
        self.assertTrue(proto.federateGroupHopLimits.useFederateGroupHopLimits)
        self.assertEqual(proto.federateGroupHopLimits.limits[0].groupName, "Cyan")

    def test_group_hop_limits_not_propagated_when_absent(self):
        """encode_federated_event with no group_hop_limits leaves field empty."""
        evt = _make_simple_event()
        fed_meta = FedMeta(seen_server_ids=["node-a"], current_hops=1, max_hops=5)
        proto = encode_federated_event(evt, fed_meta)
        # useFederateGroupHopLimits defaults to False when not set
        self.assertFalse(proto.federateGroupHopLimits.useFederateGroupHopLimits)


# ---------------------------------------------------------------------------
# ContactListEntry wired to LocalBus / OTS
# ---------------------------------------------------------------------------

class TestContactListEntrySynthesis(unittest.TestCase):
    """synthesize_contact_event generates CoT events from ContactListEntry."""

    def _make_contact(self, op, uid="contact-uid-1", callsign="Alpha"):
        return fig_pb2.ContactListEntry(
            operation=op,
            uid=uid,
            callsign=callsign,
            phone="+15551234567",
        )

    def test_create_generates_event(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("CREATE"))
        evt = synthesize_contact_event(contact)
        self.assertIsNotNone(evt)
        self.assertEqual(evt.uid, "contact-uid-1")
        self.assertEqual(evt.etype, "a-f-G-U-C")

    def test_update_generates_event(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("UPDATE"))
        evt = synthesize_contact_event(contact)
        self.assertIsNotNone(evt)

    def test_delete_generates_tombstone(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("DELETE"))
        evt = synthesize_contact_event(contact)
        self.assertIsNotNone(evt)
        # Tombstone: stale must be in the past
        self.assertLess(evt.stale, dt.utcnow())

    def test_create_stale_in_future(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("CREATE"))
        evt = synthesize_contact_event(contact)
        self.assertGreater(evt.stale, dt.utcnow())

    def test_read_returns_none(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("READ"))
        evt = synthesize_contact_event(contact)
        self.assertIsNone(evt)

    def test_invalid_returns_none(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("INVALID"))
        evt = synthesize_contact_event(contact)
        self.assertIsNone(evt)

    def test_missing_uid_returns_none(self):
        contact = fig_pb2.ContactListEntry(
            operation=fig_pb2.CRUD.Value("CREATE"), uid="", callsign="X"
        )
        evt = synthesize_contact_event(contact)
        self.assertIsNone(evt)

    def test_detail_has_contact_element(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("CREATE"), callsign="Bravo")
        evt = synthesize_contact_event(contact)
        self.assertIsNotNone(evt.detail)
        detail_elm = evt.detail.as_element
        contact_elm = detail_elm.find("contact")
        self.assertIsNotNone(contact_elm)
        self.assertEqual(contact_elm.get("callsign"), "Bravo")

    def test_detail_has_uid_droid_element(self):
        contact = self._make_contact(fig_pb2.CRUD.Value("CREATE"), callsign="Charlie")
        evt = synthesize_contact_event(contact)
        detail_elm = evt.detail.as_element
        uid_elm = detail_elm.find("uid")
        self.assertIsNotNone(uid_elm)
        self.assertEqual(uid_elm.get("Droid"), "Charlie")

    def test_phone_in_contact_element(self):
        contact = fig_pb2.ContactListEntry(
            operation=fig_pb2.CRUD.Value("CREATE"),
            uid="ph-uid", callsign="Foxtrot", phone="+15559876543",
        )
        evt = synthesize_contact_event(contact)
        detail_elm = evt.detail.as_element
        contact_elm = detail_elm.find("contact")
        self.assertEqual(contact_elm.get("phone"), "+15559876543")


class TestContactListEntryInboundRouting(unittest.TestCase):
    """FederateClient._handle_inbound routes ContactListEntry events via bridge.

    In the plugin, synthesized contact CoT events are injected via
    bridge.enqueue → LocalBus → OTS, the same path as regular inbound events.
    """

    def _make_contact_proto(self, op=1, uid="c-uid", callsign="Delta"):
        return fig_pb2.FederatedEvent(
            contact=fig_pb2.ContactListEntry(
                operation=op, uid=uid, callsign=callsign,
            )
        )

    def _make_client(self):
        from ots_federation.client import FederateClient
        from ots_federation.bridge import FederationBridge
        bridge = FederationBridge()
        client = FederateClient(
            peer_name="alpha", peer_config=_make_peer_config(),
            node_id="OTS-NODE", bridge=bridge,
        )
        return client, bridge

    def test_create_contact_enqueued_to_bridge(self):
        client, bridge = self._make_client()
        try:
            proto = self._make_contact_proto(op=1)  # CREATE
            client._handle_inbound(proto, decode_federated_event)
            self.assertFalse(bridge.inbound_q.empty())
            _, evt = bridge.inbound_q.get_nowait()
            self.assertEqual(evt.uid, "c-uid")
            self.assertEqual(evt.etype, "a-f-G-U-C")
        finally:
            bridge.close()

    def test_update_contact_enqueued_to_bridge(self):
        client, bridge = self._make_client()
        try:
            proto = self._make_contact_proto(op=3)  # UPDATE
            client._handle_inbound(proto, decode_federated_event)
            self.assertFalse(bridge.inbound_q.empty())
        finally:
            bridge.close()

    def test_delete_contact_generates_tombstone(self):
        client, bridge = self._make_client()
        try:
            proto = self._make_contact_proto(op=4)  # DELETE
            client._handle_inbound(proto, decode_federated_event)
            self.assertFalse(bridge.inbound_q.empty())
            _, evt = bridge.inbound_q.get_nowait()
            self.assertLess(evt.stale, dt.utcnow())
        finally:
            bridge.close()

    def test_read_contact_not_enqueued(self):
        client, bridge = self._make_client()
        try:
            proto = self._make_contact_proto(op=2)  # READ
            client._handle_inbound(proto, decode_federated_event)
            self.assertTrue(bridge.inbound_q.empty())
        finally:
            bridge.close()

    def test_geo_event_with_no_contact_unaffected(self):
        """Plain GeoEvent handling is not broken by contact routing code."""
        client, bridge = self._make_client()
        try:
            proto = _make_geo_proto(uid="geo-1", etype="a-f-G-U-C")
            client._handle_inbound(proto, decode_federated_event)
            self.assertFalse(bridge.inbound_q.empty())
            _, evt = bridge.inbound_q.get_nowait()
            self.assertEqual(evt.uid, "geo-1")
        finally:
            bridge.close()


if __name__ == "__main__":
    unittest.main()
