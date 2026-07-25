# ots_federation/bus.py
# LocalBus protocol: the seam between the federation engine (bridge, client
# fed_server) and the application layer (OTS REST/socket client, or a test double).
# In taky, the equivalent seam was COTRouter.route(src, evt) — called by
# bridge.drain for each inbound federated event, routing it to local ATAK
# clients and triggering the outbound federation fan-out.
# In ots_federation:
#   - bridge.drain(bus)  →  bus.inject(src, evt)  for each queued event.
#   - The OTS bridge (implemented separately) wraps this to forward events to
#     OTS via REST API, CoT-over-TCP socket, or another transport.
#   - For testing, FakeLocalBus records (src, evt) pairs for assertion.
# The OTS bridge is expected to call manager.on_outbound(src, evt) inside its
# inject implementation so federation peers get their outbound fan-out
# mirroring COTRouter's behavior. See RouterFakeBus in the test suite for a
# complete example that covers both local delivery and federation fan-out.

import queue
from typing import Any, FrozenSet, Optional, Protocol, runtime_checkable


@runtime_checkable
class LocalBus(Protocol):
    """
    Minimal event bus protocol.

    The federation engine's bridge calls inject(src, evt, local_groups=...) for
    each inbound FederatedEvent decoded from a peer gRPC stream. The OTS bridge
    implements this to forward events to OpenTAKServer.

    Parameters
    ----------
    src : any
        The federate peer client or inbound peer link that delivered the event.
        Passed through so the OTS bridge or router can implement src-skip
        (avoid echoing the event back to its origin peer) when calling
        FederationManager.on_outbound.
    evt : models.Event
        Decoded CoT event. The fed_meta sidecar is attached as evt.fed_meta by
        the transport layer (FederateClient._handle_inbound /
        FederatedChannelServicer.ServerEventStream) before calling inject.
    local_groups : frozenset[str] | None
        Mapped local OTS ACL group names for targeted groups-exchange delivery
        (Option D-D-forks-resolved). None = no group
        mapping available; implementations fall back to cot_parser publish.
    """

    def inject(self, src: Any, evt: Any, local_groups: Optional[FrozenSet[str]] = None) -> None: ...


class FakeLocalBus:
    """
    Test double for LocalBus.

    Records (src, evt) pairs in a queue.Queue for assertion in unit tests.
    Does NOT call manager.on_outbound — use RouterFakeBus for integration
    tests that need federation fan-out behaviour.
    """

    def __init__(self):
        self.events: queue.Queue = queue.Queue()

    def inject(self, src: Any, evt: Any, local_groups: Optional[FrozenSet[str]] = None) -> None:
        self.events.put((src, evt))


class RouterFakeBus:
    """
    Integration-test double that mimics COTRouter's role.

    Stores events locally (for assertion) AND calls manager.on_outbound(src, evt)
    so that federation fan-out to other active peers is triggered. This mirrors
    the COTRouter.broadcast → fed_broker.on_outbound chain that the
    taky integration tests relied on.

    Parameters
    ----------
    manager : FederationManager
        The FederationManager instance to call on_outbound against.
    """

    def __init__(self, manager):
        self.manager = manager
        self.events: queue.Queue = queue.Queue()

    def inject(self, src: Any, evt: Any, local_groups: Optional[FrozenSet[str]] = None) -> None:
        # Local delivery first (analogous to router.broadcast sending to local clients).
        self.events.put((src, evt))
        # Federation fan-out (analogous to router calling fed_broker.on_outbound).
        self.manager.on_outbound(src, evt)
