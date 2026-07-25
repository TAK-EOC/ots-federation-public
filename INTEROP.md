# Interoperability

`ots-federation` implements the standard TAK **federation v2** protocol
(FIG — Federated Intel Gateway — gRPC service, mutual-TLS). This document
lists the specific peer versions verified against and what "verified" means
for each.

## Verified peer versions

| Peer | Version | Notes |
|---|---|---|
| **TAK Server** | `5.4-RELEASE-17` (official Docker distribution) | Federation protocol v2 (gRPC), stock `federation.jar` FIG negotiator, default port `9001` |
| **OpenTAKServer** | `1.7.11` | via this plugin, OTS-to-OTS federation |
| **taky** | `0.11.x` (federation-enabled build) | requires the federation feature flag enabled at build/config time |
| **ATAK** | `5.6` | end-user client devices connecting to a federated server; federation is transparent to the client |

All federation, regardless of peer type, negotiates over the **FIG (Federated
Intel Gateway) v2 protocol** — a gRPC service, not the legacy v1 TCP/XML
transport. `ots-federation`'s own listener defaults to TCP `9101`; stock TAK
Server's federation input defaults to `9001`. Either side's port is
configurable — match whatever the peer admin's config actually uses.

**Stock TAK Server callers:** a `<federate>` entry with no `<inboundGroup>`
and no `<outboundGroup>` negotiates the FIG handshake successfully but
exchanges **zero traffic in either direction** — this fails silently (no
error in the TAK Server log) and is the most common first-federation mistake.
Add at least one of each before expecting any CoT to cross the link.

## Runtime

| Component | Version(s) |
|---|---|
| Python | 3.10 – 3.14 |
| grpcio | 1.81.1 |
| protobuf | 6.33.x |

## What was verified, and against which peer

Coverage is not uniform across peers — stated per pairing rather than as a
blanket claim:

- **Control plane, OTS ↔ stock TAK Server 5.4**: proven. FIG v2 handshake
  succeeds using the leaf+CA **chain certificate** TAK Server's negotiator
  requires (a bare leaf certificate is not sufficient against stock TAK
  Server).
- **Data plane, OTS ↔ stock TAK Server 5.4**: all CoT payload classes this
  plugin builds for — PLI, marker, route, CASEVAC/other, group-broadcast
  chat, directed chat — confirmed in both directions, observed from the
  receiving server's own event store (not a synthetic test client's
  receipt; see the interop test plan for why that distinction matters).
- **OTS ↔ taky (federation build)**: PLI confirmed via a real,
  group-enrolled client over a sustained multi-day period. The other
  payload classes travel the same encode/transport path but have not been
  separately exercised against a taky peer the way they have against TAK
  Server, so treat that coverage as narrower until it is.
- **Group mapping**: the wildcard `accept_as = *:<group>` path was
  verified against stock TAK Server, which by default does not annotate
  group membership on outbound federated events (`federatedGroupMapping`
  disabled is the common configuration) — the wildcard was confirmed to
  accept these unannotated events rather than silently dropping them.

Multi-peer link stability and loop prevention (provenance + hop limits) are
exercised by this project's own unit test suite, not by the real-peer
interop testing summarized above; they are not separately claimed as
interop-verified here.

## What "verified" means here

Verification was functional/interoperability testing against the specific
peer versions above: CoT events were originated on one server, observed
arriving (or correctly not arriving, for negative/group-policy cases) on
the peer, using each server's own authoritative event store as the source
of truth. It is not a conformance or security audit of the peer software
itself, and it does not cover peer versions outside the table above.

## Known scope boundary

`ots-federation` federates events between a server and its directly
configured peers (direct link, both directions) — that is what this
document verifies. Re-forwarding an event received from one peer out to a
*different* peer ("hub" / transitive federation) is a distinct capability,
gated by its own configuration flag, and is **not demonstrated working**.
Current understanding is that it is blocked by a fail-closed
group-membership cache lookup for uids that never had a local
registration. If your deployment needs hub/passthrough, treat it as
unverified and test it directly before relying on it.
