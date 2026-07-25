# ots-federation

TAK **federation v2** for [OpenTAKServer](https://github.com/brian7704/OpenTAKServer)
Is a plugin that lets an OTS instance exchange CoT traffic
server-to-server with stock **TAK Server**, **taky**, and other OTS instances
over the standard FIG v2 gRPC federation protocol.

- Bidirectional event federation (PLI, markers, GeoChat) over mutual-TLS gRPC
- Interoperates with stock TAK Server 5.x federation (v2 protocol)
- Group-based access control per peer: `accept_as` / `share_as` mappings,
  fail-closed by default
- Loop prevention (provenance + hop limits) for multi-server meshes
- Runs as a supervised child process — no OpenTAKServer core changes

## Requirements

- OpenTAKServer ≥ 1.7, < 2.0
- Python 3.10 – 3.14 (install the wheel matching your OTS venv's
  `python -V`)

## Install

Via the OpenTAKServer web UI: **Plugins → Upload** the wheel file.

Or directly into the OTS virtualenv:

```bash
/path/to/ots/venv/bin/pip install ots_federation-<version>-<pytag>-none-any.whl
```

Then restart OpenTAKServer. The plugin registers itself; no core
configuration changes are required to load it.

## Quick start

```bash
/path/to/ots/venv/bin/ots-federation-quickstart
```

One idempotent command that:

1. generates a federation CA and a SAN-correct server certificate
   (plus the leaf+CA chain certificate TAK Server interop requires),
2. writes a minimal, commented `federation.ini` (listener on port 9101,
   documented group-policy defaults),
3. emits a **peer exchange bundle** to hand to the admin of the server you
   want to federate with,
4. prints the restart instruction.

It refuses to overwrite existing configuration or certificates unless you
pass `--force`. Re-running it is safe.

## Peering (mutual-CA exchange)

No private keys ever change hands. To federate with another server:

```bash
/path/to/ots/venv/bin/ots-fed-certs export --out ./peer-bundle
```

Send the resulting bundle to the remote admin. It contains your federation
CA certificate, ready-to-fill configuration stanzas for their side (both
ots-federation INI format and stock TAK Server `CoreConfig.xml` format),
and step-by-step instructions. They send you their CA certificate back;
append it to your `fed_ca_bundle` file and restart.

**Federating with a stock TAK Server?** Two rules the bundle's templates
already encode, worth knowing because both fail silently:

- The `<federate>` entry on the TAK Server **must** have at least one
  `<inboundGroup>` and one `<outboundGroup>` — a federate with no groups
  exchanges no traffic in either direction.
- The federate `id` is the SHA-256 fingerprint of the certificate your
  server actually presents (the leaf certificate when using a chain).

## Configuration

The full commented reference lives in the packaged example:
`ots_federation/examples/federation.ini`. The essentials:

```ini
[federation]
enabled = true
server_id = tak-fed.example.com     ; your federation identity
listen_enabled = true
listen_port = 9101
accept_as = *:FedIn                 ; map inbound events into local group
share_as = FedOut:FedOut            ; local groups allowed outbound

[federation_ssl]
fed_ca_bundle = /path/to/fed-ca-bundle.pem
fed_cert = /path/to/server-chain.crt
fed_key = /path/to/server.key

[federate:peer-name]
enabled = true
address = tak-peer.example.com
port = 9101
accept_as = *:FedIn
share_as = FedOut:FedOut
```

Group policy is fail-closed: events that match no mapping are dropped, not
forwarded. A wildcard (`*:<group>`) is required to accept events from peers
that do not annotate group membership on the wire.

## Interoperability & testing

See [`INTEROP.md`](INTEROP.md) for the specific peer versions verified
against, and [`docs/interop-test-plan.md`](docs/interop-test-plan.md) for
the interop test methodology (scenario matrix, payload types, direction
coverage, group-policy cases, link-stability checks).

## License

MIT — see [LICENSE](LICENSE).
