# tests/__init__.py
# Shared test fixtures for the ots_federation test suite.
# Adapted from taky tests/__init__.py (taky-federation branch, commit e12a2af).
# Replaces:
#   - UnittestTAKClient (taky TAKClient subclass) → FakeLocalSrc (plain object)
#   - COTRouter dependency removed entirely
# The RouterFakeBus (in ots_federation.bus) replaces both the COTRouter role
# (local delivery) and the fed_broker.on_outbound trigger.

import queue

from ots_federation.bus import FakeLocalBus, RouterFakeBus  # noqa: F401 (re-exported)


class FakeLocalSrc:
    """
    Fake source object that mimics the interface surface FederationManager
    expects on a non-peer source (i.e. a local ATAK client or OTS bridge).

    Used in integration tests to call manager.on_outbound(src, evt) where
    src is not one of the federate peer clients.

    Attributes
    ----------
    remote_server_id : None
        Not a federate peer, so no remote ID.
    user : None
        No user object (matches FederateClient.user = None convention).
    events : queue.Queue
        Events delivered to this fake local source via a RouterFakeBus.
    """

    def __init__(self):
        self.remote_server_id = None
        self.user = None
        self.events: queue.Queue = queue.Queue()
