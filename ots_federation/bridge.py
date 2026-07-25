# ots_federation/bridge.py
# Adapted from taky.cot.federation.bridge (taky-federation branch, commit e12a2af).
# MIT License — copyright Tim K (tkuester). Adaptation: replaced COTRouter with
# LocalBus protocol (see bus.py).
#            wakeup fd).
# Problem:
#   The application event loop may be select/asyncio/anything. gRPC callbacks
#   fire on grpcio's internal thread pool. Without a bridge, there is no safe
#   way for the gRPC thread to deliver a decoded event to the main loop.
# Solution:
#   1. A os.socketpair creates two connected AF_UNIX sockets (rx_fd, tx_fd).
#   2. rx_fd is registered with the application event loop (select, epoll, etc.).
#   3. When a gRPC thread decodes a FederatedEvent, it:
#      a. Puts (src, evt) on inbound_q (thread-safe).
#      b. Writes one byte to tx_fd to wake the event loop.
#   4. The event loop detects rx_fd as readable, reads the wakeup byte(s), and
#      drains inbound_q — calling bus.inject(src, evt) for each item.
# Seam change vs. taky:
#   taky:           drain(router)  →  router.route(federate_client, evt)
#   ots_federation: drain(bus)     →  bus.inject(src, evt)
# The OTS bridge (implemented separately) implements LocalBus.inject to forward
# events to OpenTAKServer and call manager.on_outbound for federation fan-out.

import logging
import queue
import socket


class FederationBridge:
    """
    Socketpair-based wakeup bridge between gRPC side-threads and the application
    event loop.

    The event loop must:
        1. Add bridge.rx_fd to its read-set (select/epoll/etc.).
        2. On rx_fd readable: call bridge.drain(bus) to deliver pending events.

    The gRPC side-thread must:
        1. Call bridge.enqueue(src, evt) for each decoded inbound event.

    Parameters
    ----------
    (none — bridge is created once at FederationManager start)

    Attributes
    ----------
    rx_fd : socket.socket
        The readable end of the wakeup socketpair. Register with event loop.
    tx_fd : socket.socket
        The writable end. Written by gRPC side-threads.
    inbound_q : queue.Queue
        Thread-safe queue holding (src, models.Event) tuples.
    """

    def __init__(self):
        self.lgr = logging.getLogger(self.__class__.__name__)
        self.inbound_q = queue.Queue()
        self.rx_fd, self.tx_fd = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.rx_fd.setblocking(False)
        self.tx_fd.setblocking(False)
        self.lgr.debug(
            "FederationBridge created: rx_fd=%d tx_fd=%d",
            self.rx_fd.fileno(),
            self.tx_fd.fileno(),
        )

    def enqueue(self, src, evt):
        """
        Enqueue a decoded inbound event and wake the event loop.

        Called from gRPC side-thread. Thread-safe.

        Parameters
        ----------
        src : FederateClient | _InboundPeerLink
            The peer that delivered the event (passed as src to bus.inject).
        evt : models.Event
            Decoded CoT event with fed_meta sidecar attached.
        """
        self.inbound_q.put((src, evt))
        try:
            self.tx_fd.send(b"\x01")
        except (OSError, socket.error) as exc:
            self.lgr.debug("Bridge tx_fd write failed (shutdown?): %s", exc)

    def drain(self, bus):
        """
        Drain inbound_q and deliver all pending events to the bus.

        Reads wakeup byte(s) from rx_fd (non-blocking), then pops all items
        from inbound_q, calling bus.inject(src, evt) for each.

        Parameters
        ----------
        bus : LocalBus
            The application event bus (OTS bridge, RouterFakeBus, FakeLocalBus, etc.)
            that receives inbound federated events.
        """
        # Drain all pending wakeup bytes.
        try:
            while True:
                data = self.rx_fd.recv(4096)
                if not data:
                    break
        except BlockingIOError:
            pass
        except (OSError, socket.error) as exc:
            self.lgr.warning("Bridge rx_fd read error: %s", exc)
            return

        while True:
            try:
                src, evt = self.inbound_q.get_nowait()
            except queue.Empty:
                break
            try:
                # Pass inbound_local_groups sidecar (set by FederateClient /
                # FederationServer._handle_inbound after map_inbound_groups) so
                # inject can publish to the OTS groups exchange for targeted
                # delivery to SSL-grouped EUDs (-D).
                local_groups = getattr(evt, "inbound_local_groups", None)
                bus.inject(src, evt, local_groups=local_groups)
            except Exception as exc:  # pylint: disable=broad-except
                self.lgr.error(
                    "Error injecting federated event from %s: %s",
                    src,
                    exc,
                    exc_info=exc,
                )

    def close(self):
        """Close the socketpair. Called at server shutdown."""
        for fd in (self.rx_fd, self.tx_fd):
            try:
                fd.close()
            except OSError:
                pass
        self.lgr.debug("FederationBridge closed")
