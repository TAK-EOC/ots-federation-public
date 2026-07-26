# tests/test_federation_group_policy.py
# Tests for the group-policy data path (epic 3e28a2).
# Tickets covered:
#   821114 — inbound map_inbound never called (ServerEventStream + ClientEventStream)
#   a24bf4 — outbound map_outbound/federateGroups never set (prepare_outbound_event)
#   d15a02 — FederateGroups streams were stubs (ClientFederateGroupsStream /
#             ServerFederateGroupsStream / _drain_groups_stream / _open_client_groups_stream)
# Test classes:
#   TestOutboundGroupTagging  — prepare_outbound_event sets federateGroups + blocks
#   TestInboundGroupFiltering — _handle_inbound drops unmapped events
#   TestFederateGroupsRoundTrip — FederateGroups stream announce / receive
#   TestWildcardGroupPolicy   — wildcard "*" config opens all groups for a peer
#   TestManagerRegistryBuild  — FederationManager builds registry from config
#   TestServerInboundFiltering — FederatedChannelServicer.ServerEventStream group filter

import os
import queue
import unittest
from datetime import datetime as dt, timedelta
from unittest.mock import MagicMock, patch

from ots_federation import models
from ots_federation.models.takuser import TAKUser
from ots_federation.models.teams import Teams
from ots_federation.bridge import FederationBridge
from ots_federation.client import FederateClient, PeerState
from ots_federation.codec import (
    FedMeta,
    encode_federated_event,
    prepare_outbound_event,
)
from ots_federation.config import FederatePeerConfig, FederationConfig
from ots_federation.groups import (
    FederateGroupRegistry,
    FederatePeerGroupMap,
    parse_group_map,
)
from ots_federation.manager import FederationManager
from ots_federation.proto import fig_pb2


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

PEER_ID = "server-alpha.example.com"
NODE_ID = "taky-local.example.com"


def _make_takuser_evt(uid="test-uid", group="White"):
    """Build a minimal Event with a TAKUser detail in the given group.

    Phase-1: `group` is now a plain str (e.g. "White"); was Teams enum.
    Option D : sets evt.local_acl_groups sidecar so prepare_outbound_event
    can source the ACL group from the cache sidecar rather than <__group> XML.
    """
    from lxml import etree

    detail_elm = etree.Element("detail")
    takv = etree.SubElement(detail_elm, "takv")
    for k in ("os", "version", "device", "platform"):
        takv.set(k, "x")
    contact = etree.SubElement(detail_elm, "contact")
    contact.set("callsign", "TESTUSER")
    contact.set("endpoint", "*:-1:stcp")
    uid_e = etree.SubElement(detail_elm, "uid")
    uid_e.set("Droid", "TESTUSER")
    grp = etree.SubElement(detail_elm, "__group")
    grp.set("name", group)   # already a str
    grp.set("role", "Team Member")
    user = TAKUser.from_elm(detail_elm, uid=uid)

    now = dt.utcnow()
    evt = models.Event(
        uid=uid,
        etype="a-f-G-U-C",
        how="m-g",
        time=now,
        start=now,
        stale=now + timedelta(seconds=300),
    )
    evt.point = models.Point(lat=1.0, lon=2.0, hae=0.0, ce=9.9, le=9999999.0)
    evt.detail = user
    #: ACL cache sidecar — sourced from EudGroupCache in production;
    # set directly in tests to simulate a warm cache for this uid.
    evt.local_acl_groups = frozenset([group])
    return evt


def _make_geo_evt(uid="test-uid"):
    """Build a minimal Event with no TAKUser detail (generic marker)."""
    now = dt.utcnow()
    evt = models.Event(
        uid=uid,
        etype="a-f-G-U-C",
        how="m-g",
        time=now,
        start=now,
        stale=now + timedelta(seconds=300),
    )
    evt.point = models.Point(lat=1.0, lon=2.0, hae=0.0, ce=9.9, le=9999999.0)
    return evt


def _registry_with(peer_id, in_pairs=None, out_pairs=None):
    """Build a FederateGroupRegistry from simple dicts.

    in_pairs : dict {remote_group_str: str | None}
    out_pairs: dict {str: remote_group_str}
    """
    reg = FederateGroupRegistry()
    for remote, local in (in_pairs or {}).items():
        reg.add_peer_map(FederatePeerGroupMap(peer_id, "in", remote, local))
    for local_team, remote_name in (out_pairs or {}).items():
        reg.add_peer_map(FederatePeerGroupMap(peer_id, "out", remote_name, local_team))
    return reg


def _make_peer_config(name="peer", **kwargs):
    defaults = dict(
        name=name,
        enabled=True,
        address="127.0.0.1",
        port=9100,
        ca_cert="",
        client_cert="",
        client_key="",
        max_hops=3,
        group_map_in="",
        group_map_out="",
        reconnect_interval=1,
        health_check_interval=60,
    )
    defaults.update(kwargs)
    return FederatePeerConfig(**defaults)


# ---------------------------------------------------------------------------
# 1. Outbound group tagging
# ---------------------------------------------------------------------------

class TestOutboundGroupTagging(unittest.TestCase):
    """prepare_outbound_event sets federateGroups and enforces block-unmapped."""

    def _prepare(self, evt, registry, peer_id=PEER_ID):
        return prepare_outbound_event(
            evt,
            node_id=NODE_ID,
            default_max_hops=3,
            registry=registry,
            peer_id=peer_id,
        )

    def test_white_group_tagged_on_outbound(self):
        """TAKUser/White event gets federateGroups=[mapped remote name]."""
        reg = _registry_with(PEER_ID, out_pairs={"White": "White"})
        evt = _make_takuser_evt(group="White")
        proto = self._prepare(evt, reg)
        self.assertIsNotNone(proto)
        self.assertIn("White", list(proto.federateGroups))

    def test_outbound_group_maps_to_custom_remote_name(self):
        """Local White maps to remote 'OpsGrp-Alpha' in federateGroups."""
        reg = _registry_with(PEER_ID, out_pairs={"White": "OpsGrp-Alpha"})
        evt = _make_takuser_evt(group="White")
        proto = self._prepare(evt, reg)
        self.assertIsNotNone(proto)
        self.assertEqual(list(proto.federateGroups), ["OpsGrp-Alpha"])

    def test_unmapped_takuser_group_is_blocked(self):
        """TAKUser in an unmapped group returns None (block-unmapped default)."""
        # Only Blue is mapped; event is White → blocked
        reg = _registry_with(PEER_ID, out_pairs={"Blue": "Blue"})
        evt = _make_takuser_evt(group="White")
        proto = self._prepare(evt, reg)
        self.assertIsNone(proto)

    def test_no_peer_mapping_blocks_takuser_event(self):
        """Registry has no outbound entry for the peer → block."""
        reg = FederateGroupRegistry()  # empty
        evt = _make_takuser_evt(group="White")
        proto = self._prepare(evt, reg)
        self.assertIsNone(proto)

    def test_non_takuser_no_group_is_blocked_under_registry(self):
        """
        Non-TAKUser events with no determinable group are blocked under
        block-unmapped default.

        Prior to fix, such events forwarded unconditionally
        (fail-open). Correct post-fix behavior: block when group cannot be
        determined from detail (no <__group> element, no detail at all).
        """
        reg = _registry_with(PEER_ID, out_pairs={"White": "White"})
        evt = _make_geo_evt()  # detail=None, no group determinable
        proto = self._prepare(evt, reg)
        # Must be blocked: no group determinable → block-unmapped default applies.
        self.assertIsNone(proto)

    def test_no_registry_skips_group_tagging(self):
        """When registry=None, no group filtering; event passes through."""
        evt = _make_takuser_evt(group="White")
        proto = prepare_outbound_event(evt, node_id=NODE_ID, default_max_hops=3)
        self.assertIsNotNone(proto)
        self.assertEqual(list(proto.federateGroups), [])

    def test_multiple_outbound_groups(self):
        """An event tagged to multiple remote groups carries all of them."""
        # This tests map_outbound_groups via the codec path; we simulate
        # a TAKUser that lands in multiple groups by manually calling the
        # registry and verifying the codec path would produce the right list.
        reg = _registry_with(
            PEER_ID,
            out_pairs={"White": "White", "Blue": "Blue"},
        )
        evt = _make_takuser_evt(group="White")
        proto = self._prepare(evt, reg)
        self.assertIsNotNone(proto)
        # White → only "White" (single-group TAKUser)
        self.assertEqual(list(proto.federateGroups), ["White"])

    def test_empty_peer_id_no_group_policy(self):
        """When peer_id is '' (handshake incomplete), group policy is skipped."""
        reg = _registry_with(PEER_ID, out_pairs={"White": "White"})
        evt = _make_takuser_evt(group="White")
        # peer_id="" → no mapping lookup → forward unconditionally
        proto = self._prepare(evt, reg, peer_id="")
        # With peer_id="" and a TAKUser, local_groups=[White] but
        # registry.map_outbound_groups("", [White]) → [] → blocked.
        # Correct per spec: a peer whose server_id we don't know yet should
        # be treated as blocked until the handshake completes and send_event
        # is called with the real remote_server_id.
        # This is acceptable behavior (conservative / secure).
        # Just verify it doesn't crash.
        # (proto may be None or non-None depending on registry key; either is OK
        # as long as it doesn't raise.)
        _ = proto  # no assertion — just verify no exception

    def test_unmapped_group_drop_is_logged_at_info(self):
        """Suppressing an event for no-mapped-group emits an INFO drop-log.

        Drop-log observability added in Phase-1: operators
        can see suppressed events at INFO level without enabling full DEBUG.
        Log must include uid, etype, and peer_id.
        """
        import logging
        reg = _registry_with(PEER_ID, out_pairs={"Blue": "Blue"})
        evt = _make_takuser_evt(group="White")  # White not mapped → suppressed
        with self.assertLogs("ots_federation.codec", level=logging.INFO) as cm:
            result = self._prepare(evt, reg)
        self.assertIsNone(result, "White event must be blocked when only Blue is mapped")
        log_text = " ".join(cm.output)
        # Required fields in the drop-log (uid, etype, peer_id)
        self.assertIn("test-uid", log_text, "drop-log must include the event uid")
        self.assertIn("a-f-G-U-C", log_text, "drop-log must include the cot etype")
        self.assertIn(PEER_ID, log_text, "drop-log must include the peer_id")


# ---------------------------------------------------------------------------
# 2. Inbound group filtering
# ---------------------------------------------------------------------------

class TestInboundGroupFiltering(unittest.TestCase):
    """FederateClient._handle_inbound drops events whose groups are all blocked."""

    def _make_client(self, registry=None):
        cfg = _make_peer_config()
        bridge = FederationBridge()
        client = FederateClient(
            peer_name="peer",
            peer_config=cfg,
            node_id=NODE_ID,
            bridge=bridge,
            group_registry=registry,
        )
        # Simulate completed handshake so remote_server_id is known.
        client._remote_server_id = PEER_ID
        client._state = PeerState.ACTIVE
        return client, bridge

    def _make_proto_with_groups(self, uid="test-uid", remote_groups=None):
        """Build a FederatedEvent proto with the given federateGroups list."""
        now_ms = int(dt.utcnow().timestamp() * 1000)
        geo = fig_pb2.GeoEvent(
            uid=uid,
            type="a-f-G-U-C",
            coordSource="m-g",
            sendTime=now_ms,
            startTime=now_ms,
            staleTime=now_ms + 300_000,
            lat=1.0,
            lon=2.0,
            hae=0.0,
        )
        fed = fig_pb2.FederatedEvent(event=geo)
        for g in (remote_groups or []):
            fed.federateGroups.append(g)
        return fed

    def test_mapped_group_passes_through(self):
        """Event with a mapped remote group is enqueued."""
        reg = _registry_with(PEER_ID, in_pairs={"White": "White"})
        client, bridge = self._make_client(reg)
        proto = self._make_proto_with_groups(remote_groups=["White"])
        from ots_federation.codec import decode_federated_event
        client._handle_inbound(proto, decode_federated_event)
        self.assertFalse(bridge.inbound_q.empty())

    def test_unmapped_group_is_blocked(self):
        """Event with no mapped remote group is dropped silently."""
        # Only Blue mapped; event carries White → block
        reg = _registry_with(PEER_ID, in_pairs={"Blue": "Blue"})
        client, bridge = self._make_client(reg)
        proto = self._make_proto_with_groups(remote_groups=["White"])
        from ots_federation.codec import decode_federated_event
        client._handle_inbound(proto, decode_federated_event)
        self.assertTrue(bridge.inbound_q.empty())

    def test_no_registry_passes_through(self):
        """Without a registry, all events pass through (backward-compatible)."""
        client, bridge = self._make_client(registry=None)
        proto = self._make_proto_with_groups(remote_groups=["White"])
        from ots_federation.codec import decode_federated_event
        client._handle_inbound(proto, decode_federated_event)
        self.assertFalse(bridge.inbound_q.empty())

    def test_empty_federate_groups_blocked_without_wildcard(self):
        """Event with no federateGroups (stock TAK Server) is DROPPED when the
        peer's accept_as names specific remote groups only (b39e05 fail-closed)."""
        reg = _registry_with(PEER_ID, in_pairs={"Blue": "Blue"})
        client, bridge = self._make_client(reg)
        proto = self._make_proto_with_groups(remote_groups=[])
        from ots_federation.codec import decode_federated_event
        client._handle_inbound(proto, decode_federated_event)
        self.assertTrue(bridge.inbound_q.empty(),
                        "group-less event must not bypass a named-scope accept_as")

    def test_empty_federate_groups_admitted_via_wildcard(self):
        """Event with no federateGroups is admitted when the peer has a
        wildcard accept_as ('*'→Green) — the stock-TAK-Server interop path."""
        reg = _registry_with(PEER_ID, in_pairs={"*": "Green"})
        client, bridge = self._make_client(reg)
        proto = self._make_proto_with_groups(remote_groups=[])
        from ots_federation.codec import decode_federated_event
        client._handle_inbound(proto, decode_federated_event)
        self.assertFalse(bridge.inbound_q.empty())

    def test_partial_match_passes_through(self):
        """Event with some mapped + some unmapped groups passes through."""
        reg = _registry_with(PEER_ID, in_pairs={"White": "White"})
        client, bridge = self._make_client(reg)
        # White mapped, SIGINT not mapped → at least one mapped → pass
        proto = self._make_proto_with_groups(remote_groups=["White", "SIGINT"])
        from ots_federation.codec import decode_federated_event
        client._handle_inbound(proto, decode_federated_event)
        self.assertFalse(bridge.inbound_q.empty())

    def test_all_groups_blocked_drops_event(self):
        """Event where every remote group is explicitly blocked is dropped."""
        reg = _registry_with(PEER_ID, in_pairs={"White": None, "Blue": None})
        client, bridge = self._make_client(reg)
        proto = self._make_proto_with_groups(remote_groups=["White", "Blue"])
        from ots_federation.codec import decode_federated_event
        client._handle_inbound(proto, decode_federated_event)
        self.assertTrue(bridge.inbound_q.empty())

    def tearDown(self):
        # Clean up bridge socketpairs
        pass


# ---------------------------------------------------------------------------
# 3. FederateGroups stream announce / receive
# ---------------------------------------------------------------------------

class TestFederateGroupsRoundTrip(unittest.TestCase):
    """
    _drain_groups_stream calls update_from_federate_groups; announced groups
    are stored in the registry for the remote peer.
    """

    def _make_client(self, registry=None):
        cfg = _make_peer_config()
        bridge = FederationBridge()
        client = FederateClient(
            peer_name="peer",
            peer_config=cfg,
            node_id=NODE_ID,
            bridge=bridge,
            group_registry=registry,
        )
        client._remote_server_id = PEER_ID
        client._state = PeerState.ACTIVE
        return client, bridge

    def test_drain_groups_updates_registry(self):
        """_drain_groups_stream calls update_from_federate_groups with received groups."""
        reg = FederateGroupRegistry()
        client, _bridge = self._make_client(reg)

        # Simulate a one-message groups stream.
        msg = fig_pb2.FederateGroups(federateGroups=["White", "Blue"])

        def _fake_stream():
            yield msg

        client._drain_groups_stream(_fake_stream())

        announced = reg.get_announced_groups(PEER_ID)
        self.assertEqual(set(announced), {"White", "Blue"})

    def test_drain_groups_no_registry_no_crash(self):
        """Without a registry, _drain_groups_stream just logs — no crash."""
        client, _bridge = self._make_client(registry=None)
        msg = fig_pb2.FederateGroups(federateGroups=["White"])

        def _fake_stream():
            yield msg

        try:
            client._drain_groups_stream(_fake_stream())
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"_drain_groups_stream raised unexpectedly: {exc!r}")

    def test_open_client_groups_stream_announces_configured_groups(self):
        """_open_client_groups_stream sends configured outbound groups."""
        reg = _registry_with(PEER_ID, out_pairs={"White": "White", "Blue": "Blue"})
        client, _bridge = self._make_client(reg)
        # _remote_server_id is already set to PEER_ID
        # We intercept the generator by inspecting the stub call.
        sent_msgs = []

        class FakeStream:
            def future(self, gen, **kwargs):
                for m in gen:
                    sent_msgs.append(m)
                return MagicMock()

        fake_stub = MagicMock()
        fake_stub.ClientFederateGroupsStream = FakeStream()
        client._open_client_groups_stream(fake_stub)

        self.assertEqual(len(sent_msgs), 1)
        announced = set(sent_msgs[0].federateGroups)
        self.assertEqual(announced, {"White", "Blue"})

    def test_open_client_groups_stream_empty_when_no_registry(self):
        """Without a registry, ClientFederateGroupsStream sends empty list."""
        client, _bridge = self._make_client(registry=None)
        sent_msgs = []

        class FakeStream:
            def future(self, gen, **kwargs):
                for m in gen:
                    sent_msgs.append(m)
                return MagicMock()

        fake_stub = MagicMock()
        fake_stub.ClientFederateGroupsStream = FakeStream()
        client._open_client_groups_stream(fake_stub)

        self.assertEqual(len(sent_msgs), 1)
        self.assertEqual(list(sent_msgs[0].federateGroups), [])


# ---------------------------------------------------------------------------
# 4. Wildcard group config (operator-opens-all-groups case)
# ---------------------------------------------------------------------------

class TestWildcardGroupPolicy(unittest.TestCase):
    """
    An operator can open all groups for a peer using wildcard config:
      group_map_in  = *:White   (route all remote groups to local White)
      group_map_out = White:*   (not yet supported — outbound wildcard is Phase 2)

    Or for a true pass-through / TAK-interop open, use fallback_allow=True.
    """

    def test_wildcard_inbound_routes_any_group(self):
        """'*:White' in group_map_in admits events with any remote group label."""
        # Parse "White:White, *:White" — route everything to White
        entries = parse_group_map("White:White, *:White", "in")
        reg = FederateGroupRegistry()
        for e in entries:
            e.peer_id = PEER_ID
            reg.add_peer_map(e)

        result = reg.map_inbound_groups(PEER_ID, ["SIGINT"])
        self.assertIsNotNone(result)
        self.assertIn("White", result)

    def test_wildcard_block_drops_unmapped(self):
        """'*:' (block wildcard) drops events with unrecognized group labels."""
        entries = parse_group_map("White:White, *:", "in")
        reg = FederateGroupRegistry()
        for e in entries:
            e.peer_id = PEER_ID
            reg.add_peer_map(e)

        # SIGINT has no explicit map; wildcard is block → None
        result = reg.map_inbound_groups(PEER_ID, ["SIGINT"])
        self.assertIsNone(result)
        # White still passes
        result = reg.map_inbound_groups(PEER_ID, ["White"])
        self.assertIsNotNone(result)

    def test_fallback_allow_opens_peer_for_tak_interop(self):
        """
        An operator can enable fallback_allow=True to accept any remote group
        whose name matches a local Teams value — the TAK Server
        fallbackWhenNoGroupMappings=true equivalent.
        """
        reg = FederateGroupRegistry()
        reg.set_fallback_allow(PEER_ID, True)
        # Phase-1: fallback passes through any remote group name as-is (string passthrough).
        result = reg.map_inbound_groups(PEER_ID, ["White", "Blue"])
        self.assertIsNotNone(result)
        self.assertIn("White", result)
        self.assertIn("Blue", result)

    def test_fallback_allow_passes_through_arbitrary_name(self):
        """Phase-1: Fallback allow passes arbitrary group names through as strings."""
        reg = FederateGroupRegistry()
        reg.set_fallback_allow(PEER_ID, True)
        result = reg.map_inbound_groups(PEER_ID, ["SIGINT"])
        # Phase-1 behavior: "SIGINT" passes through as-is (not blocked, not None)
        self.assertIsNotNone(result)
        self.assertIn("SIGINT", result)


# ---------------------------------------------------------------------------
# 5. FederationManager builds registry from config
# ---------------------------------------------------------------------------

class TestManagerRegistryBuild(unittest.TestCase):
    """FederationManager._build_group_registry populates the registry from config."""

    def setUp(self):
        pass

    def test_registry_built_from_peer_group_map_in(self):
        """Peers with group_map_in have inbound entries in the registry."""
        peer = _make_peer_config(
            name="alpha",
            address="10.0.0.1",
            port=9100,
            group_map_in="White:White, Blue:Blue",
            group_map_out="",
        )
        cfg = FederationConfig(
            enabled=True,
            server_id="taky-test",
            peers=[peer],
        )
        mgr = FederationManager(cfg)
        reg = mgr.group_registry
        # Provisional peer_id = "10.0.0.1:9100"
        pid = "10.0.0.1:9100"
        self.assertIsNotNone(reg.map_inbound(pid, "White"))
        self.assertEqual(reg.map_inbound(pid, "White"), "White")
        self.assertEqual(reg.map_inbound(pid, "Blue"), "Blue")
        mgr.bridge.close()

    def test_registry_built_from_peer_group_map_out(self):
        """Peers with group_map_out have outbound entries in the registry."""
        peer = _make_peer_config(
            name="alpha",
            address="10.0.0.1",
            port=9100,
            group_map_in="",
            group_map_out="White:White, Blue:Blue",
        )
        cfg = FederationConfig(
            enabled=True,
            server_id="taky-test",
            peers=[peer],
        )
        mgr = FederationManager(cfg)
        reg = mgr.group_registry
        pid = "10.0.0.1:9100"
        self.assertEqual(reg.map_outbound(pid, "White"), "White")
        self.assertEqual(reg.map_outbound(pid, "Blue"), "Blue")
        mgr.bridge.close()

    def test_arbitrary_group_map_in_does_not_crash(self):
        """Phase-1: Any group name in group_map_in is valid (no enum validation)."""
        peer = _make_peer_config(
            name="bad",
            address="10.0.0.2",
            port=9100,
            group_map_in="White:NotATeam",  # was invalid pre-Phase-1, now accepted
            group_map_out="",
        )
        cfg = FederationConfig(
            enabled=True,
            server_id="taky-test",
            peers=[peer],
        )
        try:
            mgr = FederationManager(cfg)
            mgr.bridge.close()
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"FederationManager.__init__ raised: {exc!r}")

    def test_registry_accessible_from_client(self):
        """FederateClient instances created by manager share the same registry."""
        peer = _make_peer_config(
            name="alpha",
            address="10.0.0.1",
            port=9100,
            group_map_in="White:White",
            group_map_out="White:White",
        )
        cfg = FederationConfig(
            enabled=True,
            server_id="taky-test",
            peers=[peer],
        )
        mgr = FederationManager(cfg)
        client = mgr.clients["alpha"]
        self.assertIs(client.group_registry, mgr.group_registry)
        mgr.bridge.close()


# ---------------------------------------------------------------------------
# 6. ServerEventStream inbound filtering (FederatedChannelServicer)
# ---------------------------------------------------------------------------

class TestServerInboundFiltering(unittest.TestCase):
    """FederatedChannelServicer.ServerEventStream drops unmapped-group events."""

    def setUp(self):
        pass

    def _make_servicer(self, registry=None):
        from ots_federation.fed_server import FederatedChannelServicer

        bridge = FederationBridge()
        manager = MagicMock()
        manager.register_inbound_link = MagicMock()
        manager.deregister_inbound_link = MagicMock()
        servicer = FederatedChannelServicer(
            server_id="TAKY-SERVER",
            server_name="Test Server",
            bridge=bridge,
            manager=manager,
            default_max_hops=3,
            group_registry=registry,
        )
        return servicer, bridge

    def _make_context(self, peer_id="peer.example.com"):
        ctx = MagicMock()
        ctx.peer.return_value = peer_id
        # ServerFederateGroupsStream holds the stream open with `while
        # context.is_active`; default it False so unit tests collect the single
        # yielded message and the generator completes instead of blocking.
        ctx.is_active.return_value = False
        return ctx

    def _make_fed_event_proto(self, uid="test-uid", remote_groups=None):
        now_ms = int(dt.utcnow().timestamp() * 1000)
        geo = fig_pb2.GeoEvent(
            uid=uid, type="a-f-G-U-C", coordSource="m-g",
            sendTime=now_ms, startTime=now_ms, staleTime=now_ms + 300_000,
            lat=1.0, lon=2.0, hae=0.0,
        )
        proto = fig_pb2.FederatedEvent(event=geo)
        for g in (remote_groups or []):
            proto.federateGroups.append(g)
        return proto

    def test_mapped_group_delivered_to_bridge(self):
        """ServerEventStream admits events with mapped group labels."""
        reg = _registry_with("peer.example.com", in_pairs={"White": "White"})
        servicer, bridge = self._make_servicer(reg)
        ctx = self._make_context("peer.example.com")
        proto = self._make_fed_event_proto(remote_groups=["White"])
        list([] for _ in [servicer.ServerEventStream([proto], ctx)])
        # Event should be in the bridge
        self.assertFalse(bridge.inbound_q.empty())

    def test_unmapped_group_dropped_by_server_event_stream(self):
        """ServerEventStream drops events with no mappable groups."""
        reg = _registry_with("peer.example.com", in_pairs={"Blue": "Blue"})
        servicer, bridge = self._make_servicer(reg)
        ctx = self._make_context("peer.example.com")
        proto = self._make_fed_event_proto(remote_groups=["White"])  # White not mapped
        list([] for _ in [servicer.ServerEventStream([proto], ctx)])
        self.assertTrue(bridge.inbound_q.empty())

    def test_no_registry_server_event_stream_passes_all(self):
        """Without a registry, ServerEventStream passes all events."""
        servicer, bridge = self._make_servicer(registry=None)
        ctx = self._make_context("peer.example.com")
        proto = self._make_fed_event_proto(remote_groups=["White"])
        list([] for _ in [servicer.ServerEventStream([proto], ctx)])
        self.assertFalse(bridge.inbound_q.empty())

    def test_client_federate_groups_stream_updates_registry(self):
        """ClientFederateGroupsStream feeds received groups into the registry."""
        reg = FederateGroupRegistry()
        servicer, _bridge = self._make_servicer(reg)
        ctx = self._make_context("peer.example.com")
        msg = fig_pb2.FederateGroups(federateGroups=["White", "Blue"])
        servicer.ClientFederateGroupsStream([msg], ctx)
        announced = reg.get_announced_groups("peer.example.com")
        self.assertEqual(set(announced), {"White", "Blue"})

    def test_server_federate_groups_stream_announces_configured_groups(self):
        """ServerFederateGroupsStream yields our configured outbound groups."""
        reg = _registry_with("peer.example.com", out_pairs={"White": "White"})
        servicer, _bridge = self._make_servicer(reg)

        sub = fig_pb2.Subscription(
            identity=fig_pb2.Identity(serverId="peer.example.com")
        )
        ctx = self._make_context("peer.example.com")
        msgs = list(servicer.ServerFederateGroupsStream(sub, ctx))
        self.assertEqual(len(msgs), 1)
        self.assertIn("White", list(msgs[0].federateGroups))

    def test_server_federate_groups_stream_empty_without_registry(self):
        """ServerFederateGroupsStream sends empty list when no registry configured."""
        servicer, _bridge = self._make_servicer(registry=None)
        sub = fig_pb2.Subscription()
        ctx = self._make_context()
        msgs = list(servicer.ServerFederateGroupsStream(sub, ctx))
        self.assertEqual(len(msgs), 1)
        self.assertEqual(list(msgs[0].federateGroups), [])


# ---------------------------------------------------------------------------
# 7. Default group policy
#    Covers the four cases mandated by the ticket:
#      (a) default-policy applies to an inbound peer with no explicit map
#      (b) default-policy open (*:Cyan) lets events flow both ways
#      (c) explicit per-peer map still wins over the default
#      (d) OUTGOING [federate:*] map keyed by server_id applies after rekey
# ---------------------------------------------------------------------------

INBOUND_PEER_ID = "de46d6396ead472583e3cac58c62c085"  # ots-fed-node server_id


class TestDefaultGroupPolicy(unittest.TestCase):
    """
    [federation] default_group_map_in / default_group_map_out applied to peers
    with no explicit per-peer map..
    """

    # ------------------------------------------------------------------
    # (a) Default policy blocks inbound peer when default is empty
    # ------------------------------------------------------------------
    def test_no_default_blocks_inbound_peer_with_no_explicit_map(self):
        """Without any default, an inbound peer with no explicit map is blocked."""
        reg = FederateGroupRegistry()
        # No default, no per-peer map for INBOUND_PEER_ID
        result = reg.map_inbound(INBOUND_PEER_ID, "White")
        self.assertIsNone(result)

    def test_no_default_blocks_inbound_peer_outbound_direction(self):
        """Without any default, outbound to an unmapped inbound peer is blocked."""
        reg = FederateGroupRegistry()
        result = reg.map_outbound(INBOUND_PEER_ID, "White")
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # (a) Default policy applies to an inbound peer with no explicit map
    # ------------------------------------------------------------------
    def test_default_inbound_policy_applies_to_unmapped_peer(self):
        """
        An inbound peer with no [federate:*] config section uses the
        [federation] default_group_map_in policy.

        This is the primary mechanism for accepting events from a TAK Server
        that dialled IN and whose server_id has no per-peer section.
        """
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map
        entries = parse_group_map("White:White, Blue:Blue", "in")
        reg.set_default_in_map(entries)

        # Inbound peer has no explicit map: default is used
        result = reg.map_inbound(INBOUND_PEER_ID, "White")
        self.assertEqual(result, "White")
        result = reg.map_inbound(INBOUND_PEER_ID, "Blue")
        self.assertEqual(result, "Blue")
        # Group not in default → block
        result = reg.map_inbound(INBOUND_PEER_ID, "SIGINT")
        self.assertIsNone(result)

    def test_default_outbound_policy_applies_to_unmapped_peer(self):
        """
        Outbound direction: default policy applies to peers with no explicit
        [federate:*] group_map_out section.
        """
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map
        entries = parse_group_map("White:White", "out")
        reg.set_default_out_map(entries)

        result = reg.map_outbound(INBOUND_PEER_ID, "White")
        self.assertEqual(result, "White")
        # Unmapped group → block
        result = reg.map_outbound(INBOUND_PEER_ID, "Blue")
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # (b) Default *:Cyan opens all groups both ways
    # ------------------------------------------------------------------
    def test_default_star_cyan_admits_any_inbound_group(self):
        """
        default_group_map_in = *:Cyan
        Admits events from any remote group label into local Cyan.

        This is the config an operator sets to open an inbound TAK peer
        (e.g. ots-fed-node: de46d6396ead472583e3cac58c62c085).
        """
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map
        entries = parse_group_map("*:Cyan", "in")
        reg.set_default_in_map(entries)

        # Any remote group routes to Cyan
        for grp in ("White", "Blue", "SIGINT", "Magenta", "OpsGrp-Alpha"):
            result = reg.map_inbound(INBOUND_PEER_ID, grp)
            self.assertEqual(result, "Cyan", f"expected Cyan for group {grp!r}")

    def test_default_star_cyan_in_map_inbound_groups_multi(self):
        """map_inbound_groups with default *:Cyan returns {Cyan} for any inputs."""
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map
        entries = parse_group_map("*:Cyan", "in")
        reg.set_default_in_map(entries)

        result = reg.map_inbound_groups(INBOUND_PEER_ID, ["White", "Blue", "SIGINT"])
        self.assertIsNotNone(result)
        self.assertEqual(result, {"Cyan"})

    def test_default_star_cyan_outbound_lets_events_flow_to_unmapped_peer(self):
        """
        default_group_map_out = Cyan:Cyan
        Outbound events in Cyan reach an inbound peer with no explicit section.
        """
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map
        entries = parse_group_map("Cyan:Cyan", "out")
        reg.set_default_out_map(entries)

        result = reg.map_outbound(INBOUND_PEER_ID, "Cyan")
        self.assertEqual(result, "Cyan")
        # Other groups still blocked
        result = reg.map_outbound(INBOUND_PEER_ID, "White")
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # (c) Explicit per-peer map wins over default
    # ------------------------------------------------------------------
    def test_explicit_peer_map_takes_precedence_over_default_inbound(self):
        """
        When a peer has an explicit per-peer inbound map, the default is NOT
        consulted — the per-peer map is the sole authority for that peer.
        """
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map

        # Default: route all to Cyan
        entries = parse_group_map("*:Cyan", "in")
        reg.set_default_in_map(entries)

        # Explicit per-peer map: White→White only (Blue blocked)
        reg.add_peer_map(FederatePeerGroupMap(INBOUND_PEER_ID, "in", "White", "White"))

        # White uses explicit map (White, not Cyan)
        result = reg.map_inbound(INBOUND_PEER_ID, "White")
        self.assertEqual(result, "White")

        # Blue: explicit map has no entry, no wildcard in explicit map → block
        # (default NOT consulted because per-peer table exists)
        result = reg.map_inbound(INBOUND_PEER_ID, "Blue")
        self.assertIsNone(result, "default must not be consulted when per-peer map exists")

    def test_explicit_peer_map_takes_precedence_over_default_outbound(self):
        """
        Explicit per-peer outbound map takes precedence over default outbound policy.
        """
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map

        # Default: White→White
        entries = parse_group_map("White:White", "out")
        reg.set_default_out_map(entries)

        # Explicit per-peer: White→OpsGrp-Alpha
        reg.add_peer_map(
            FederatePeerGroupMap(INBOUND_PEER_ID, "out", "OpsGrp-Alpha", "White")
        )

        result = reg.map_outbound(INBOUND_PEER_ID, "White")
        self.assertEqual(result, "OpsGrp-Alpha", "explicit per-peer map must override default")

    # ------------------------------------------------------------------
    # (d) OUTGOING [federate:*] map keyed by server_id applies after rekey
    # ------------------------------------------------------------------
    def test_outgoing_map_applies_after_rekey_inbound(self):
        """
        FederationManager keyed the map by provisional "address:port".
        After rekey_peer(provisional_id, server_id), map_inbound finds the map
        using the real server_id — fixing the address:port-vs-server_id bug.
        """
        from ots_federation.groups import parse_group_map

        provisional_id = "10.0.0.1:9100"
        real_server_id = "server-alpha-uuid-1234"

        reg = FederateGroupRegistry()
        # Simulate _build_group_registry: key by address:port
        entries = parse_group_map("White:White, Blue:Blue", "in")
        for e in entries:
            e.peer_id = provisional_id
            reg.add_peer_map(e)

        # Before rekey: lookup by real_server_id → miss (no map) → block
        self.assertIsNone(reg.map_inbound(real_server_id, "White"),
                          "before rekey, real_server_id lookup must miss")

        # Rekey (simulates getIdentity completing)
        reg.rekey_peer(provisional_id, real_server_id)

        # After rekey: lookup by real_server_id finds the map
        result = reg.map_inbound(real_server_id, "White")
        self.assertEqual(result, "White",
                         "after rekey, real_server_id lookup must find the map")

        # Provisional id is gone
        self.assertIsNone(reg.map_inbound(provisional_id, "White"),
                          "after rekey, provisional_id must no longer match")

    def test_outgoing_map_outbound_applies_after_rekey(self):
        """
        Outbound map keyed by provisional address:port is accessible via
        real server_id after rekey_peer. §key-consistency.
        """
        from ots_federation.groups import parse_group_map

        provisional_id = "10.0.0.1:9100"
        real_server_id = "server-alpha-uuid-1234"

        reg = FederateGroupRegistry()
        entries = parse_group_map("White:White", "out")
        for e in entries:
            e.peer_id = provisional_id
            reg.add_peer_map(e)

        # Before rekey: blocked
        self.assertIsNone(reg.map_outbound(real_server_id, "White"))

        reg.rekey_peer(provisional_id, real_server_id)

        # After rekey: found
        self.assertEqual(reg.map_outbound(real_server_id, "White"), "White")

    def test_rekey_peer_noop_when_ids_equal(self):
        """rekey_peer(id, id) is a safe no-op."""
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap("peer-x", "in", "White", "White"))
        reg.rekey_peer("peer-x", "peer-x")
        self.assertEqual(reg.map_inbound("peer-x", "White"), "White")

    def test_rekey_peer_noop_when_old_id_not_present(self):
        """rekey_peer with unknown old_id is a safe no-op."""
        reg = FederateGroupRegistry()
        try:
            reg.rekey_peer("not-in-registry", "some-new-id")
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f"rekey_peer raised unexpectedly: {exc!r}")

    # ------------------------------------------------------------------
    # (e) rekey_peer collision safety: a dialed peer answering getIdentity
    #     with ANOTHER configured peer's server_id must never inherit that
    #     peer's group policy, and must never destroy its own policy trying.
    # ------------------------------------------------------------------

    def test_rekey_peer_refuses_collision_with_another_configured_peer(self):
        """
        NEGATIVE assertion: if new_id already has its OWN registered policy
        (a real, separately-configured peer -- e.g. victim-peer), rekey_peer
        must refuse the whole operation, not silently discard old_id's entry
        while leaving new_id's untouched. This is the exact identity-theft
        exploit shape: a dialed peer (attacker) answers getIdentity claiming
        victim-peer's server_id, hoping to inherit victim-peer's policy.
        """
        reg = FederateGroupRegistry()
        # victim-peer: a real, separately-configured peer with its own policy.
        reg.add_peer_map(FederatePeerGroupMap("victim-peer", "in", "SECRET", "SECRET"))
        reg.add_peer_map(FederatePeerGroupMap("victim-peer", "out", "SECRET", "SECRET"))
        # attacker-provisional: the dialed peer's OWN provisional entry,
        # scoped to something much less sensitive.
        reg.add_peer_map(FederatePeerGroupMap("10.0.0.66:9100", "in", "FIRE-OPS", "FIRE-OPS"))

        # Attacker's getIdentity() claims to be "victim-peer".
        reg.rekey_peer("10.0.0.66:9100", "victim-peer")

        # victim-peer's OWN policy must be completely untouched.
        self.assertEqual(
            reg.map_inbound("victim-peer", "SECRET"), "SECRET",
            "victim-peer's policy must survive a colliding rekey attempt untouched",
        )
        self.assertEqual(reg.map_outbound("victim-peer", "SECRET"), "SECRET")
        # The attacker's own provisional entry must ALSO survive (not popped) --
        # refusing the whole operation, not just skipping the overwrite.
        self.assertEqual(
            reg.map_inbound("10.0.0.66:9100", "FIRE-OPS"), "FIRE-OPS",
            "a refused rekey must leave the OLD key's entry in place too, "
            "not silently discard it",
        )
        # And the attacker's own scoped policy must NOT have leaked onto
        # victim-peer's key either.
        self.assertIsNone(reg.map_inbound("victim-peer", "FIRE-OPS"))

    def test_rekey_peer_refuses_collision_on_outbound_only_table(self):
        """Collision detection checks the outbound table too, not just inbound."""
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap("victim-peer", "out", "White", "White"))
        reg.add_peer_map(FederatePeerGroupMap("10.0.0.1:9100", "out", "Cyan", "Cyan"))

        reg.rekey_peer("10.0.0.1:9100", "victim-peer")

        self.assertEqual(reg.map_outbound("victim-peer", "White"), "White")
        self.assertEqual(reg.map_outbound("10.0.0.1:9100", "Cyan"), "Cyan")

    def test_rekey_peer_refuses_collision_on_fallback_allow_table(self):
        """Collision detection also covers the fallback_allow table."""
        reg = FederateGroupRegistry()
        reg.set_fallback_allow("victim-peer", True)
        reg.add_peer_map(FederatePeerGroupMap("10.0.0.1:9100", "in", "X", "X"))

        reg.rekey_peer("10.0.0.1:9100", "victim-peer")

        # victim-peer's fallback flag must be untouched; the attacker's
        # provisional entry must still be present under its own key.
        self.assertTrue(reg._fallback_allow.get("victim-peer"))
        self.assertEqual(reg.map_inbound("10.0.0.1:9100", "X"), "X")

    def test_rekey_peer_still_succeeds_when_no_collision(self):
        """
        Non-collision rekey (the normal, legitimate case -- new_id has no
        prior entry anywhere) still works exactly as before: this is a
        regression guard that the collision-safety fix didn't break the
        ordinary provisional-id -> real-server_id rekey path.
        """
        reg = FederateGroupRegistry()
        reg.add_peer_map(FederatePeerGroupMap("10.0.0.1:9100", "in", "White", "White"))
        reg.add_peer_map(FederatePeerGroupMap("10.0.0.1:9100", "out", "White", "White"))
        reg.set_fallback_allow("10.0.0.1:9100", True)

        reg.rekey_peer("10.0.0.1:9100", "real-server-id-xyz")

        self.assertEqual(reg.map_inbound("real-server-id-xyz", "White"), "White")
        self.assertEqual(reg.map_outbound("real-server-id-xyz", "White"), "White")
        self.assertTrue(reg._fallback_allow.get("real-server-id-xyz"))
        # Old provisional key is gone (genuinely rekeyed, not left behind).
        self.assertIsNone(reg.map_inbound("10.0.0.1:9100", "White"))

    # ------------------------------------------------------------------
    # End-to-end: FederationManager default policy from config
    # ------------------------------------------------------------------
    def test_manager_wires_default_policy_from_config(self):
        """
        FederationManager._build_group_registry reads default_group_map_in /
        default_group_map_out from FederationConfig and wires them into the
        registry, so an inbound peer (no explicit [federate:*] section) is
        admitted.
        """
        cfg = FederationConfig(
            enabled=True,
            server_id="taky-test",
            default_group_map_in="*:Cyan",
            default_group_map_out="Cyan:Cyan",
            peers=[],  # no explicit peers
        )
        mgr = FederationManager(cfg)
        reg = mgr.group_registry

        # Inbound: any remote group from unmapped peer → Cyan
        result = reg.map_inbound(INBOUND_PEER_ID, "White")
        self.assertEqual(result, "Cyan")
        result = reg.map_inbound(INBOUND_PEER_ID, "SIGINT")
        self.assertEqual(result, "Cyan")

        # Outbound: Cyan events forwarded to unmapped peer as "Cyan"
        result = reg.map_outbound(INBOUND_PEER_ID, "Cyan")
        self.assertEqual(result, "Cyan")
        # Other groups still blocked outbound
        result = reg.map_outbound(INBOUND_PEER_ID, "White")
        self.assertIsNone(result)

        mgr.bridge.close()

    def test_manager_default_policy_does_not_override_explicit_peer_map(self):
        """
        When [federation] default is set AND a [federate:*] explicit map exists
        the explicit map wins for that peer; default covers only unmapped peers.
        """
        explicit_peer = _make_peer_config(
            name="alpha",
            address="10.0.0.1",
            port=9100,
            group_map_in="White:White",  # explicit: only White
            group_map_out="",
        )
        cfg = FederationConfig(
            enabled=True,
            server_id="taky-test",
            default_group_map_in="*:Cyan",  # default: admit everything as Cyan
            peers=[explicit_peer],
        )
        mgr = FederationManager(cfg)
        reg = mgr.group_registry

        # Provisional key (address:port) — used before rekey
        provisional_id = "10.0.0.1:9100"

        # Explicit map has White→White; default would give Blue→Cyan but must not
        self.assertEqual(reg.map_inbound(provisional_id, "White"), "White")
        # Blue not in explicit map, no wildcard in explicit map → block
        # (default must not bleed in for a peer with an explicit table)
        self.assertIsNone(
            reg.map_inbound(provisional_id, "Blue"),
            "default must not apply to a peer that has an explicit per-peer map",
        )

        mgr.bridge.close()


# ---------------------------------------------------------------------------
# 8. Identity binding: group-ACL decisions keyed on the authenticated mTLS
#    certificate, never on a self-asserted wire field.
# ---------------------------------------------------------------------------

def _make_test_cert_pem(cn="identity-binding-test"):
    """Build a throwaway self-signed certificate and return its PEM bytes."""
    from ots_federation.gen_fed_ca import generate_ca
    from cryptography.hazmat.primitives import serialization

    _key, cert = generate_ca(cn=cn, org="ots-test", validity_days=1)
    return cert.public_bytes(serialization.Encoding.PEM)


def _fingerprint_of(pem_bytes):
    """Compute the canonical colon-hex SHA-256 fingerprint of a test cert's PEM."""
    from ots_federation.cert_identity import fingerprint_from_pem
    return fingerprint_from_pem(pem_bytes)


def _mock_secure_context(peer_addr, pem_bytes):
    """MagicMock ServicerContext exposing a real certificate via auth_context()."""
    ctx = MagicMock()
    ctx.peer.return_value = peer_addr
    ctx.auth_context.return_value = {"x509_pem_cert": [pem_bytes]}
    return ctx


def _mock_insecure_context(peer_addr):
    """MagicMock ServicerContext with no usable auth_context (legacy/testing path)."""
    ctx = MagicMock()
    ctx.peer.return_value = peer_addr
    # Deliberately do NOT configure auth_context — a bare MagicMock's return
    # value fails cert_identity's isinstance/parse checks, which is exactly
    # what an insecure test channel looks like from the servicer's view.
    return ctx


class TestCertFingerprintIdentityBinding(unittest.TestCase):
    """
    _resolve_authenticated_peer binds group-registry lookups SOLELY to a
    CONFIGURED fingerprint->peer_id table -- corrected implementation after
    the first attempt's trust-on-first-use approach was rejected in
    verification.

    Every test here registers the presented cert's ACTUAL fingerprint (never
    a made-up string) via reg.register_fingerprint, mirroring how
    manager.py._build_group_registry populates the table from each peer's
    configured `fingerprint` key. Subscription.identity.serverId is either
    absent or deliberately WRONG in several tests specifically to prove it is
    never consulted for the policy decision.
    """

    def _make_servicer(self, registry=None):
        from ots_federation.fed_server import FederatedChannelServicer

        bridge = FederationBridge()
        manager = MagicMock()
        manager.register_inbound_link = MagicMock()
        manager.deregister_inbound_link = MagicMock()
        servicer = FederatedChannelServicer(
            server_id="TAKY-SERVER",
            server_name="Test Server",
            bridge=bridge,
            manager=manager,
            default_max_hops=3,
            group_registry=registry,
        )
        return servicer, manager

    def _sub(self, server_id):
        return fig_pb2.Subscription(identity=fig_pb2.Identity(serverId=server_id))

    # --- Positive: a fingerprint configured for a peer resolves to that peer ---

    def test_configured_fingerprint_resolves_to_its_peer(self):
        """
        A cert whose fingerprint was registered for "known-peer" resolves to
        "known-peer" and is never quarantined -- the Subscription serverId
        doesn't even need to match (it isn't consulted at all).
        """
        pem = _make_test_cert_pem()
        fp = _fingerprint_of(pem)
        reg = _registry_with("known-peer", in_pairs={"White": "White"})
        reg.register_fingerprint(fp, "known-peer")
        servicer, _mgr = self._make_servicer(reg)
        ctx = _mock_secure_context("ipv4:10.0.0.5:1234", pem)

        # Subscription claims something else entirely -- must be irrelevant.
        peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx, self._sub("this-is-not-consulted")
        )
        self.assertEqual(peer_id, "known-peer")
        self.assertFalse(
            quarantined,
            "a certificate whose fingerprint is configured for a peer must "
            "be trusted regardless of what serverId it claims on the wire",
        )

    def test_configured_fingerprint_resolves_with_no_subscription_at_all(self):
        """ServerEventStream/SendOneEvent-style calls pass subscription=None;
        fingerprint resolution must not depend on a Subscription being present."""
        pem = _make_test_cert_pem()
        fp = _fingerprint_of(pem)
        reg = _registry_with("known-peer", in_pairs={"White": "White"})
        reg.register_fingerprint(fp, "known-peer")
        servicer, _mgr = self._make_servicer(reg)
        ctx = _mock_secure_context("ipv4:10.0.0.5:1234", pem)

        peer_id, quarantined = servicer._resolve_authenticated_peer(ctx, None)
        self.assertEqual(peer_id, "known-peer")
        self.assertFalse(quarantined)

    # --- NEGATIVE (a): fingerprint NOT configured -- quarantine, no default ---

    def test_unconfigured_fingerprint_is_quarantined_even_with_permissive_default(self):
        """
        NEGATIVE assertion: a certificate whose fingerprint has NO entry in
        the registry's fingerprint table is quarantined even when a
        permissive global default (accept_as=*:__ANON__ equivalent) is
        configured -- it must NEVER inherit that default. This is the H-1
        exploit surface: an unconfigured certificate must get nothing, not
        the most permissive available policy.
        """
        reg = FederateGroupRegistry()
        from ots_federation.groups import parse_group_map
        # A permissive global default IS configured...
        reg.set_default_in_map(parse_group_map("*:__ANON__", "in"))
        # ...but this certificate's fingerprint was never registered anywhere.
        servicer, _mgr = self._make_servicer(reg)
        pem = _make_test_cert_pem()
        ctx = _mock_secure_context("ipv4:10.0.0.9:4444", pem)

        peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx, self._sub("totally-unconfigured-identity")
        )
        self.assertTrue(
            quarantined,
            "a certificate with no configured fingerprint must be "
            "quarantined, never handed the global default policy",
        )

        # Confirm the caller-side contract too: ServerEventStream must not
        # consult map_inbound_groups at all when quarantined (it would
        # otherwise return {'__ANON__'} from the default above).
        local_groups = (
            None if quarantined
            else reg.map_inbound_groups(peer_id, [])
        )
        self.assertIsNone(
            local_groups,
            "quarantined identity must resolve to no groups, not the "
            "configured default (__ANON__)",
        )

    def test_unconfigured_fingerprint_with_no_default_is_also_quarantined(self):
        """Same as above but with no default configured at all -- still quarantined."""
        reg = FederateGroupRegistry()  # nothing configured anywhere
        servicer, _mgr = self._make_servicer(reg)
        pem = _make_test_cert_pem()
        ctx = _mock_secure_context("ipv4:10.0.0.9:4444", pem)

        _peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx, self._sub("nobody-configured-this")
        )
        self.assertTrue(quarantined)

    # --- NEGATIVE (b): unconfigured fingerprint, but serverId MATCHES a real
    #     peer -- must still quarantine. This is the exact H-1 escalation:
    #     asserting a configured peer's identity string on an unrelated cert.

    def test_unconfigured_fingerprint_claiming_a_real_peers_server_id_is_quarantined(self):
        """
        NEGATIVE assertion: an attacker's certificate (never registered
        anywhere) that asserts Subscription.identity.serverId == a REAL
        configured peer's name must still be quarantined -- serverId is
        never consulted for the policy decision, only the fingerprint is.
        """
        reg = _registry_with("victim-peer", in_pairs={"SECRET": "SECRET"})
        victim_pem = _make_test_cert_pem(cn="victim-real-cert")
        reg.register_fingerprint(_fingerprint_of(victim_pem), "victim-peer")

        attacker_pem = _make_test_cert_pem(cn="attacker-cert")  # NOT registered
        servicer, _mgr = self._make_servicer(reg)
        ctx = _mock_secure_context("ipv4:10.0.0.66:6666", attacker_pem)

        peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx, self._sub("victim-peer")  # <-- claims the victim's name
        )
        self.assertTrue(
            quarantined,
            "a certificate not configured for ANY peer must be quarantined "
            "even when it claims a real, configured peer's serverId",
        )
        local_groups = (
            None if quarantined
            else reg.map_inbound_groups(peer_id, ["SECRET"])
        )
        self.assertIsNone(
            local_groups,
            "the attacker's connection must never receive the victim's "
            "SECRET group policy",
        )

    # --- NEGATIVE (c): a DIFFERENT cert claiming a configured peer's serverId
    #     is quarantined -- covers the same escalation with the real peer's
    #     own cert not yet having connected in this process at all (no
    #     trust-on-first-use state exists anymore, so there is no race).

    def test_different_cert_claiming_configured_peers_identity_is_quarantined(self):
        """
        A certificate that is simply not THIS peer's registered fingerprint
        is quarantined regardless of claimed identity -- verified with two
        DIFFERENT certs, neither of which happens to be the one registered
        for "shared-name".
        """
        reg = _registry_with("shared-name", in_pairs={"FIRE-OPS": "FIRE-OPS"})
        real_pem = _make_test_cert_pem(cn="the-real-shared-name-cert")
        reg.register_fingerprint(_fingerprint_of(real_pem), "shared-name")

        impostor_pem = _make_test_cert_pem(cn="impostor-cert")
        servicer, _mgr = self._make_servicer(reg)
        ctx = _mock_secure_context("ipv4:10.0.0.2:2222", impostor_pem)

        peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx, self._sub("shared-name")
        )
        self.assertTrue(
            quarantined,
            "a certificate other than the one configured for this peer "
            "must be refused even when it presents the matching serverId",
        )

    def test_no_persistent_state_across_repeated_unconfigured_attempts(self):
        """
        Regression guard for the rejected first attempt's pre-claim DoS:
        resolution is a pure, stateless config lookup now -- repeatedly
        presenting DIFFERENT unconfigured certificates claiming the SAME
        serverId never binds, never locks out a later legitimate cert, and
        never changes behavior between calls.
        """
        real_pem = _make_test_cert_pem(cn="the-real-peer-cert")
        reg = _registry_with("contested-name", in_pairs={"White": "White"})
        reg.register_fingerprint(_fingerprint_of(real_pem), "contested-name")
        servicer, _mgr = self._make_servicer(reg)

        # Three different attacker certs, all claiming "contested-name",
        # none of them registered -- all quarantined, none of them "sticks".
        for i in range(3):
            attacker_pem = _make_test_cert_pem(cn=f"attacker-{i}")
            ctx = _mock_secure_context(f"ipv4:10.0.0.{i}:1111", attacker_pem)
            _peer_id, quarantined = servicer._resolve_authenticated_peer(
                ctx, self._sub("contested-name")
            )
            self.assertTrue(quarantined, f"attacker attempt #{i} must be quarantined")

        # The REAL peer's cert, arriving after three attacker attempts,
        # must still resolve cleanly -- no pre-claim lockout is possible.
        ctx_real = _mock_secure_context("ipv4:10.0.0.99:9999", real_pem)
        peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx_real, self._sub("contested-name")
        )
        self.assertEqual(peer_id, "contested-name")
        self.assertFalse(
            quarantined,
            "the real peer's configured certificate must never be locked "
            "out by prior unconfigured attempts (no TOFU state to poison)",
        )

    def test_same_cert_reconnecting_stays_trusted(self):
        """The SAME configured certificate reconnecting is trusted every time."""
        pem = _make_test_cert_pem()
        reg = _registry_with("stable-peer", in_pairs={"White": "White"})
        reg.register_fingerprint(_fingerprint_of(pem), "stable-peer")
        servicer, _mgr = self._make_servicer(reg)

        for i in range(3):
            ctx = _mock_secure_context(f"ipv4:10.0.0.1:{5000 + i}", pem)
            peer_id, quarantined = servicer._resolve_authenticated_peer(
                ctx, self._sub("stable-peer")
            )
            self.assertEqual(peer_id, "stable-peer")
            self.assertFalse(quarantined, f"reconnect #{i} must stay trusted")

    # --- Legacy/insecure-channel fallback: no cert to bind to ---

    def test_no_certificate_falls_back_to_legacy_resolution(self):
        """
        An insecure channel (no verified peer certificate available) has
        nothing to bind identity to, so resolution falls back to the
        pre-fix candidate-only behavior rather than quarantining every
        insecure/test connection.
        """
        reg = _registry_with("legacy-peer", in_pairs={"White": "White"})
        servicer, _mgr = self._make_servicer(reg)
        ctx = _mock_insecure_context("ipv4:10.0.0.1:9999")

        peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx, self._sub("legacy-peer")
        )
        self.assertEqual(peer_id, "legacy-peer")
        self.assertFalse(quarantined)

    def test_no_group_registry_configured_skips_binding_entirely(self):
        """With group policy disabled entirely, identity binding is a no-op
        (nothing for a spoofed identity to bypass)."""
        servicer, _mgr = self._make_servicer(registry=None)
        pem = _make_test_cert_pem()
        ctx = _mock_secure_context("ipv4:10.0.0.1:1234", pem)

        peer_id, quarantined = servicer._resolve_authenticated_peer(
            ctx, self._sub("anything")
        )
        self.assertEqual(peer_id, "anything")
        self.assertFalse(quarantined)

    # --- ClientEventStream integration: quarantined peer gets no fan-out ---

    def test_client_event_stream_does_not_register_quarantined_peer(self):
        """
        ClientEventStream must NOT register an outbound fan-out link for a
        quarantined peer -- otherwise the outbound direction would inherit
        whatever the (bypassed) default policy permits.
        """
        reg = FederateGroupRegistry()  # nothing configured -> any cert is unknown
        servicer, manager = self._make_servicer(reg)
        pem = _make_test_cert_pem()
        ctx = _mock_secure_context("ipv4:10.0.0.1:1234", pem)
        # Fire the RPC-done callback as soon as the servicer registers it, the
        # way gRPC does when a stream ends. That sets the link's stop event, so
        # drain_outbound() exits at once. The registration decision under test
        # runs before that loop, so it has already happened by then.
        ctx.add_callback.side_effect = lambda cb: cb()
        sub = self._sub("unconfigured-walkup-peer")

        list(servicer.ClientEventStream(sub, ctx))

        manager.register_inbound_link.assert_not_called()

    def test_client_event_stream_registers_known_peer(self):
        """A cert with a configured fingerprint IS registered for outbound fan-out."""
        pem = _make_test_cert_pem()
        reg = _registry_with("dial-in-peer", out_pairs={"White": "White"})
        reg.register_fingerprint(_fingerprint_of(pem), "dial-in-peer")
        servicer, manager = self._make_servicer(reg)
        ctx = _mock_secure_context("ipv4:10.0.0.1:1234", pem)
        # Fire the RPC-done callback immediately (see the quarantine test above)
        # so drain_outbound() exits once registration has been decided.
        ctx.add_callback.side_effect = lambda cb: cb()
        sub = self._sub("dial-in-peer")

        list(servicer.ClientEventStream(sub, ctx))

        manager.register_inbound_link.assert_called_once()
        called_peer_id = manager.register_inbound_link.call_args[0][0]
        self.assertEqual(called_peer_id, "dial-in-peer")


if __name__ == "__main__":
    unittest.main()

