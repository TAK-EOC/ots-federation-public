# Interop Test Plan

A repeatable methodology for validating `ots-federation` against a peer
server type, in both directions, across all supported CoT payload types —
and for distinguishing **local delivery of federated events** (peer → your
server → your own clients) from **hub / passthrough** (peer A → your
server → peer B), which is a separate capability with its own trust and
implementation considerations.

This is the methodology used to produce the results summarized in
[`INTEROP.md`](../INTEROP.md). Use it as a template for validating a new
peer version, or for revalidating after a config or dependency change.

## Server / peer topology (template)

| Role | Example label | Fed listener | Notes |
|---|---|---|---|
| Device under test | `server-a` | `:9101` | `ots-federation`-enabled OpenTAKServer |
| Peer — taky | `server-b` | `:9101` | federation-enabled taky build |
| Peer — stock TAK Server | `server-c` | `:9001` (v2) | official Docker distribution |
| Peer — second OTS/taky node | `server-d` | `:9101` | for multi-peer / mesh cases |

Substitute your own hostnames/addresses for `server-a`..`server-d`. Each
server keeps its own federation key; peers exchange only public CA
certificates (see the README "Peering" section). Federating with stock
TAK Server additionally requires presenting the **leaf+CA chain**
certificate to its FIG negotiator — a bare leaf certificate is rejected.

## Test client naming convention

```
client-<N>_<peer-label><M>
```

- `<peer-label>` — which peer server the client connects to (e.g. `a`,
  `b`, `c`, `d` for the table above).
- `<N>` client index, `<M>` server index (supports more than one instance
  of a given peer type).
- Use a CN charset valid as an OTS username (letters/numbers/underscores/
  periods) so the same CN can enroll cleanly on the OTS side.

Example: `client-1_a1` is the first test client enrolled against
`server-a`.

## Observation method — server-side truth, not synthetic-client receipt

A synthetic, raw-socket test client only *receives* an event if it is a
member of the group the federation link maps traffic into. A freshly
minted certificate with no group assignment is **groupless**: it receives
nothing, and its own outbound events don't federate either. Relying on a
groupless synthetic client's receipt (or non-receipt) as the pass/fail
signal produces false negatives.

**Authoritative observation is the receiving server's own event store**,
not a synthetic client:

- OpenTAKServer: query the CoT table directly (e.g. `select uid from cot
  where uid ~ '<test-tag>'`).
- taky: the taky container's event store / logs.
- TAK Server: `cot_router` (positions/markers/routes), `cot_router_chat`
  (chat), `fed_event` (federation log) in the CoreConfig-configured
  database.

A properly group-enrolled real client (not synthetic) is a valid
secondary observer.

## Payload matrix

Run each payload type in each enabled direction for each server pair:

| # | Payload | CoT type | Notes |
|---|---|---|---|
| 1 | PLI | `a-f-G-U-C` | position/location update |
| 2 | marker | `a-u-G` | point marker |
| 3 | route | `b-m-r` | route/line |
| 4 | other / CASEVAC | `b-r-f-h-c` | represents the "other" detail-heavy CoT class |
| 5 | group broadcast chat | `b-t-f` | GeoChat, broadcast |
| 6 | directed chat (DM) | `b-t-f` | GeoChat, directed |

Directions run **both ways** for every enabled server pair — a payload
verified `server-a → server-b` is not assumed to also work
`server-b → server-a`; test it explicitly.

## Two capability classes — keep them separate

**Class A — local delivery of federated events** (peer → your server →
your server's own clients). This is the baseline federation contract:
an event that arrives over a federation link reaches locally connected
clients through the normal local-delivery group mechanism.

**Class B — hub / passthrough** (peer A → your server → peer B).
Re-forwarding an event that arrived *from* one peer back out to a
*different* peer. This is a distinct capability from Class A, gated by
its own configuration switch, and has its own failure modes around group
cache population for non-local UIDs. Treat "hub" as a topology/trust
decision (transitive federation exposes peer A's traffic to peer B) —
confirm it is an intentional design choice before enabling it, and test
it as a separate scenario from Class A.

## Group-policy test cases

For each peer, verify group mapping behavior explicitly rather than
assuming it:

1. **Wildcard accept path** — a peer that does not annotate group
   membership on the wire (the common stock TAK Server configuration,
   `federatedGroupMapping` disabled) must still be accepted via a
   wildcard `accept_as = *:<group>` mapping. Verify the event is not
   silently dropped.
2. **Explicit group mapping** — a peer that does annotate group
   membership maps into the configured local group, and only that group.
3. **Fail-closed on no match** — an event whose annotated group matches
   no configured mapping is dropped, not forwarded to a default group.
4. **share_as outbound restriction** — only events whose local group is
   in the configured `share_as` outbound mapping reach a given peer link.

## Multi-peer / link-stability checks

With links to more than one peer type active concurrently:

- Confirm no cross-talk — an event destined for peer A's group mapping
  does not leak to peer B's link.
- Hold links open over an extended period and confirm no flapping,
  leaked file descriptors, or growing memory on either the federation
  process or its peers.
- Restart one peer link and confirm the others are unaffected and the
  restarted link recovers without a full server restart.

## Loop-prevention checks

- Originate an event on `server-a`, let it federate out to `server-b`,
  and confirm `server-b` does not re-forward it back to `server-a`
  (provenance-based loop prevention).
- In a 3+ server mesh, confirm hop-limit enforcement stops an event from
  cycling indefinitely even if provenance tracking alone were bypassed.

## Reporting results

For each (peer version, payload, direction, group-policy case) tuple,
record: pass/fail, the authoritative observation used (server-side query,
not synthetic-client receipt), and any deviation from expected group
mapping. Roll the summary into `INTEROP.md` once a peer version has been
fully exercised against this matrix.
