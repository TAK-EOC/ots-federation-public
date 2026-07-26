# Security

## Trust model

Federation is a peering relationship between servers whose operators already trust each
other. Each side runs its own certificate authority, exchanges the CA certificate out of
band, and adds the other's CA to its federation trust bundle. There is no central
authority and no directory of peers. A peer you have added can send you events and can
receive whatever your group configuration shares with it.

Federate only with peers you trust to run their own server honestly. Group scope limits
what a peer can reach. It does not make a hostile peer safe.

The federation trust bundle is separate from the trust bundle your TAK clients
authenticate against. A stolen client certificate does not grant federation access.

## What scope enforcement guarantees

Group policy resolves from the certificate the peer presents on the TLS transport, in
both directions:

- An inbound connection is matched by the client certificate it presents during the
  handshake.
- An outbound dial is matched by the certificate the dialed server presents.

In each case the engine takes the SHA-256 fingerprint of that certificate and looks it up
in the `fingerprint` value configured on a peer section. Nothing the peer says about
itself selects policy. The server identity a peer reports over the wire gets recorded for
logging and never chooses a group map.

A certificate whose fingerprint you have not configured receives no policy at all. It
does not fall back to a default group map, and it does not get registered to receive
events. An outbound dial to a server presenting an unconfigured certificate is refused
before any application call goes out.

`fingerprint` is therefore required in both directions. A peer section without one
exchanges nothing, in either direction, no matter what else is configured on it. Set it
to the value `ots-fed-certs export` prints. If the peer's client and server certificates
are separate leaves, list both, comma separated.

Group mapping denies by default. A group with no mapping gets dropped rather than passed
through. Directed messages addressed to a callsign go through the same group
reachability check as broadcast traffic, so addressing someone by name does not get
around the group map.

## Loop prevention

Two controls, in order of importance.

The provenance chain is the primary one. Every event carries the list of servers that
have already relayed it, and a server drops any event that already carries its own
identity. That stops a cycle whatever the hop counters say.

The hop clamp is secondary. Each event carries a hop budget. A received budget that is
absent, zero, or negative resolves to the local `max_hops` setting. A peer can lower the
budget below yours; it cannot raise it. This bounds how far a single event travels and
limits amplification if provenance were stripped in transit.

A peer can strip provenance from events it originates. The hop clamp bounds the result.

## Limits

Federation Hub is not supported. The engine speaks direct server-to-server federation
with mutual certificates. The hub token-exchange calls exist so that a hub-aware peer
does not drop the connection on an unimplemented method, and they return empty. There is
no token-based authentication path.

Transit between peers is off by default. Your server does not relay one peer's traffic to
another peer unless you turn that on. Read the passthrough patterns in the example
configuration before enabling it, because it changes which operators can see each other's
data.

Certificate revocation is not checked. Retire a compromised peer by removing its
fingerprint from your configuration.

Callsign and group resolution reads your group database. If that database is unreachable,
directed delivery fails closed and the traffic is dropped.

## Reporting a vulnerability

Report security issues to takeoc@proton.me. Please do not open a public issue for an
unpatched vulnerability.
