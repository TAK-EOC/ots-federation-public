# tests/test_federation_integration.py
# Adapted from taky test_federation_integration.py (taky-federation branch).
# Changes vs. taky original:
#   - Removed COTRouter + taky.config dependencies.
#   - Uses RouterFakeBus (ots_federation.bus) instead of COTRouter:
#     RouterFakeBus.inject(src, evt) queues events locally AND calls
#     manager.on_outbound(src, evt), reproducing the COTRouter chain.
#   - FakeLocalSrc replaces UnittestTAKClient (no TAKClient dependency).
#   - All imports updated from taky.cot.* → ots_federation.*.
# Tests still cover the same semantics:
#   (a) inbound FederatedEvent from peer A is delivered to the bus (local delivery)
#   (b) it is NOT echoed back to peer A (src-skip in on_outbound)
#   (c) an event whose provenance already contains our node_id is dropped
#   (d) a locally-originated event is forwarded with fresh provenance

import queue
import unittest
from datetime import datetime as dt, timedelta

from ots_federation.bridge import FederationBridge
from ots_federation.bus import RouterFakeBus
from ots_federation.client import FederateClient, PeerState
from ots_federation.codec import FedMeta, encode_federated_event
from ots_federation.config import FederatePeerConfig, FederationConfig
from ots_federation.manager import FederationManager
from ots_federation.models import Event
from ots_federation.proto import fig_pb2

from tests import FakeLocalSrc


def _make_peer_config(name, **kwargs):
    defaults = dict(
        name=name,
        enabled=True,
        address="127.0.0.1",
        port=9100,
        ca_cert="",
        client_cert="",
        client_key="",
        max_hops=3,
        reconnect_interval=1,
        health_check_interval=60,
    )
    defaults.update(kwargs)
    return FederatePeerConfig(**defaults)


def _make_fed_config(peers, server_id="TAKY-LOCAL"):
    return FederationConfig(
        enabled=True,
        server_id=server_id,
        server_name="Local Test Server",
        max_hops=3,
        peers=peers,
    )


def _make_geo_event_proto(uid="fed-uid-1", provenance=None, max_hops=3, current_hops=1):
    """Build a real FederatedEvent proto with a GeoEvent payload."""
    now_ms = int(dt.utcnow().timestamp() * 1000)
    geo = fig_pb2.GeoEvent(
        uid=uid,
        type="a-f-G-U-C",
        coordSource="m-g",
        sendTime=now_ms,
        startTime=now_ms,
        staleTime=now_ms + 300_000,
        lat=1.234,
        lon=-3.14,
        hae=0.0,
        ce=9.9,
        le=9999999.0,
    )
    fed = fig_pb2.FederatedEvent(event=geo)
    for sid in (provenance or []):
        fed.federateProvenance.append(
            fig_pb2.FederateProvenance(federationServerId=sid)
        )
    fed.federateHops.CopyFrom(
        fig_pb2.FederateHops(maxHops=max_hops, currentHops=current_hops)
    )
    return fed


class FederationIntegrationTest(unittest.TestCase):
    """
    Real FederationManager + real bridge + real codec; only gRPC is faked.

    RouterFakeBus replaces COTRouter: deliver + on_outbound fan-out in one step.
    """

    def setUp(self):
        # Two federate peers: A is the inbound source, B is a downstream peer.
        self.peer_a_cfg = _make_peer_config("peer-a")
        self.peer_b_cfg = _make_peer_config("peer-b")
        self.cfg = _make_fed_config([self.peer_a_cfg, self.peer_b_cfg])

        self.mgr = FederationManager(self.cfg)

        # RouterFakeBus: delivers events locally + triggers federation fan-out.
        self.bus = RouterFakeBus(self.mgr)

        self.peer_a = self.mgr.clients["peer-a"]
        self.peer_b = self.mgr.clients["peer-b"]
        # Both peers ACTIVE so send_event proceeds (no real gRPC channel).
        self.peer_a._state = PeerState.ACTIVE
        self.peer_b._state = PeerState.ACTIVE

        # A fake local source (replaces UnittestTAKClient / COTRouter client).
        self.local = FakeLocalSrc()

    def tearDown(self):
        self.mgr.bridge.close()

    def _inject_inbound(self, proto, peer):
        """
        Push an inbound FederatedEvent through the real inbound path:
        peer._handle_inbound (real decode + fed_meta sidecar + bridge.enqueue)
        then drain the bridge into the bus. Mirrors the gRPC side-thread.
        """
        from ots_federation.codec import decode_federated_event

        peer._handle_inbound(proto, decode_federated_event)
        self.mgr.bridge.drain(self.bus)

    def test_inbound_delivered_to_bus(self):
        """
        (a) An inbound FederatedEvent from peer A must be delivered to the bus
        (local event delivery equivalent to COTRouter.broadcast to local clients).
        """
        proto = _make_geo_event_proto(uid="from-peer-a", provenance=["PEER-A-ID"])
        self._inject_inbound(proto, self.peer_a)

        src, evt = self.bus.events.get_nowait()
        self.assertEqual(evt.uid, "from-peer-a")
        # The codec attaches fed_meta as the §5 sidecar attribute.
        self.assertTrue(hasattr(evt, "fed_meta"))
        self.assertEqual(evt.fed_meta.seen_server_ids, ["PEER-A-ID"])

    def test_inbound_not_echoed_to_source_peer(self):
        """
        (b) The inbound event from peer A must NOT be echoed back to peer A
        (on_outbound src-skip), but SHOULD be forwarded to peer B.
        """
        proto = _make_geo_event_proto(uid="no-echo", provenance=["PEER-A-ID"])
        self._inject_inbound(proto, self.peer_a)

        # Bus received it (local delivery).
        _src, evt = self.bus.events.get_nowait()
        self.assertEqual(evt.uid, "no-echo")

        # Peer A must NOT have anything queued for send-back (src-skip).
        self.assertTrue(self.peer_a._outbound_q.empty())

        # Peer B SHOULD have received it for forwarding.
        self.assertFalse(self.peer_b._outbound_q.empty())
        fwd_proto = self.peer_b._outbound_q.get_nowait()
        self.assertEqual(fwd_proto.event.uid, "no-echo")
        # Our node_id was appended to provenance on the forward hop.
        prov_ids = [p.federationServerId for p in fwd_proto.federateProvenance]
        self.assertIn("TAKY-LOCAL", prov_ids)
        self.assertIn("PEER-A-ID", prov_ids)

    def test_loop_prevention_own_id_in_provenance(self):
        """
        (c) An event whose provenance chain already contains OUR node_id must
        be dropped before forwarding to another peer (loop prevention).
        """
        proto = _make_geo_event_proto(
            uid="looped",
            provenance=["PEER-A-ID", "TAKY-LOCAL"],
            current_hops=2,
        )
        self._inject_inbound(proto, self.peer_a)

        # Still delivered locally (local delivery is independent of loop guard).
        _src, evt = self.bus.events.get_nowait()
        self.assertEqual(evt.uid, "looped")

        # Peer A: src-skip → nothing.
        self.assertTrue(self.peer_a._outbound_q.empty())

        # Peer B: loop prevention drops it because TAKY-LOCAL is already in
        # the provenance chain — nothing enqueued for forwarding.
        self.assertTrue(self.peer_b._outbound_q.empty())

    def test_local_origin_event_forwarded_with_fresh_provenance(self):
        """
        (d) A locally-originated event (no fed_meta) must be forwarded to all
        active peers with hops=1 and our own provenance stamped.
        """
        now = dt.utcnow()
        evt = Event(
            uid="local-origin",
            etype="a-f-G-U-C",
            how="m-g",
            time=now,
            start=now,
            stale=now + timedelta(seconds=300),
        )
        # Originate from local src: trigger on_outbound fan-out directly.
        self.mgr.on_outbound(self.local, evt)

        for peer in (self.peer_a, self.peer_b):
            self.assertFalse(peer._outbound_q.empty())
            fwd = peer._outbound_q.get_nowait()
            self.assertEqual(fwd.event.uid, "local-origin")
            self.assertEqual(fwd.federateHops.currentHops, 1)
            prov_ids = [p.federationServerId for p in fwd.federateProvenance]
            self.assertEqual(prov_ids, ["TAKY-LOCAL"])


if __name__ == "__main__":
    unittest.main()
