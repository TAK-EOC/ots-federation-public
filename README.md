# ots-federation

TAK **federation v2** for [OpenTAKServer](https://github.com/brian7704/OpenTAKServer) —
a plugin that lets an OTS instance exchange CoT traffic
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

## Admin UI

[#admin-ui](#admin-ui)

Once installed, the plugin registers itself under OTS's standard plugin
routes at `/api/plugins/ots-federation/*`, which gets you a **Settings**
tab for free in OTS's own web UI (whether the plugin runs at all, where
`federation.ini` lives, log level — the `OTS_FEDERATION_*` keys in
`default_config.py`) and a **UI** tab showing this plugin's own admin page
in an iframe, per
[docs.opentakserver.io/plugins.html](https://docs.opentakserver.io/plugins.html).

The admin page itself is plain server-rendered HTML — inline CSS, a little
inline vanilla JS for `confirm()` dialogs only, no build step, no CDN
dependency — same convention as the CI-TRAP Reports plugin's admin page.
(An earlier version of this used the officially-documented Mantine/React
iframe convention instead; that build is no longer used here in favor of
something with a much smaller failure surface to debug against a live
server.) It covers:

- **Engine status** — running/stopped, pid, uptime, auto-restart count, and
  a **Restart engine** button that stops and respawns the engine child
  process so on-disk `federation.ini` edits take effect.
- **Generate federation.ini + certs** — shown when no `federation.ini`
  exists yet. Runs the equivalent of `ots-federation-quickstart` (CA +
  server/client identity certs + a minimal `federation.ini`) from the
  browser instead of SSH, writing into `federation_certs/` next to
  `federation.ini`.
- **Peers** — every `[federate:<name>]` section (including disabled ones,
  unlike the engine's own strict loader, which drops disabled peers), with
  an inline enable/disable button, and add/edit/delete forms covering every
  documented peer field (address, `accept_as`/`share_as` group mapping,
  retry/health tuning, legacy token auth) plus **file upload fields** for
  each peer's `ca_cert`/`client_cert`/`client_key` — upload the file and the
  corresponding federation.ini path is set for you.
- **Global federation settings** — the `[federation]` and
  `[federation_ssl]` sections: server identity, inbound listener, default
  group policy, CoreConfig parity knobs, and file upload fields for
  `fed_ca_bundle`/`fed_cert`/`fed_key`.
- **Peer-exchange bundle** — a button that re-runs `ots-fed-certs export
  --zip` against the current cert material and serves the resulting bundle
  as a direct download, ready to hand to the remote admin per the Peering
  section above.

Uploaded files are saved under `federation_certs/` (global material) or
`federation_certs/peers/<name>/` (per-peer material), next to
`federation.ini`; uploaded private keys are written with mode `0600`.

All routes require an OTS administrator session (`@roles_accepted` — the
iframe runs same-origin, so the existing OTS session cookie carries over;
no separate login). A JSON REST API also exists under the same prefix
(`GET/POST /peers`, `PUT /global`, `POST /restart`, etc.) for scripting —
the HTML page and the JSON API both write through the same
`ini_writer.py`, so they stay consistent with each other.

**Edits write to `federation.ini`, not the running engine.** The engine
child process only reads `federation.ini` at startup. Any peer or global
change made through the UI is written immediately (via
[`configupdater`](https://configupdater.readthedocs.io/), which preserves
the file's hand-written comments — a plain `configparser` round-trip would
silently discard them), but won't take effect until you hit **Restart
engine**.

Secrets (`connection_token`, `fed_key_pw`) are never round-tripped into the
page: the field is always rendered blank with a separate "clear this
value" checkbox — leaving both alone keeps the existing secret unchanged,
typing a new value sets it, and checking "clear" removes it.

## Interoperability & testing

See [`INTEROP.md`](INTEROP.md) for the specific peer versions verified
against, and [`docs/interop-test-plan.md`](docs/interop-test-plan.md) for
the interop test methodology (scenario matrix, payload types, direction
coverage, group-policy cases, link-stability checks).

## Security

See [`docs/SECURITY.md`](docs/SECURITY.md) for the trust model, what group
scope enforcement guarantees, and how to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).
