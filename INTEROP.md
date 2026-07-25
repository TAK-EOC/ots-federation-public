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

## What was verified

- **Bidirectional CoT event federation** — PLI, markers, and GeoChat
  messages federate correctly in both directions between `ots-federation`
  and each peer type listed above.
- **Mutual-CA handshake with stock TAK Server**, including the
  leaf+CA **chain certificate** TAK Server's FIG negotiator requires
  (a bare leaf certificate is not sufficient against stock TAK Server;
  the chain must be presented).
- **Group mapping**, including the group-less case: stock TAK Server does
  not annotate group membership on outbound federated events by default
  (`federatedGroupMapping` disabled is the common configuration), so
  `ots-federation`'s wildcard `accept_as` mapping (`*:<group>`) was
  verified to accept these unannotated inbound events rather than
  silently dropping them.
- **Multi-peer link stability** — concurrent federation links to more
  than one peer type held without cross-talk or link flapping.
- **Loop prevention** — provenance tracking and hop-limit enforcement
  were verified to stop a re-federated event from cycling back through
  a link it already traversed, across a multi-server mesh.

## What "verified" means here

Verification was functional/interoperability testing against the specific
peer versions above: CoT events were originated on one server, observed
arriving (or correctly not arriving, for negative/group-policy cases) on
the peer, using each server's own authoritative event store as the source
of truth. It is not a conformance or security audit of the peer software
itself, and it does not cover peer versions outside the table above.

## Known scope boundary

`ots-federation` federates events between a server and its directly
configured peers (direct link, both directions). Re-forwarding an event
received from one peer out to a *different* peer ("hub" / transitive
federation) is a distinct capability, controlled independently, and is
outside the scope of what this document verifies.
