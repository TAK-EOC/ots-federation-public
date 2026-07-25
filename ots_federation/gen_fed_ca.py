#!/usr/bin/env python3
# ots_federation/gen_fed_ca.py
# Generate a standalone federation CA + server identity cert + client identity cert
# for taky federation mTLS.
# This CA is SEPARATE from taky's ATAK client CA ([ssl] section). It signs only
# federation peer certificates and must never be used to sign ATAK device client certs.
# Key material output:
#   <out_dir>/fed-ca.key         — CA private key  (mode 0600)  — KEEP IN secrets/
#   <out_dir>/fed-ca.crt         — CA certificate  (public; distribute to all peers)
#   <out_dir>/server.key         — Server identity private key (mode 0600)
#   <out_dir>/server.crt         — Server identity leaf certificate (single cert)
#   <out_dir>/server-chain.crt   — Server identity chain: leaf + CA concatenated (leaf first)
#   <out_dir>/client.key         — Client identity private key (mode 0600)
#   <out_dir>/client.crt         — Client identity leaf certificate (single cert)
#   <out_dir>/client-chain.crt   — Client identity chain: leaf + CA concatenated (leaf first)
# TAK SERVER INTEROP NOTE (TAK Server 5.4 FIG negotiator):
#   TAK Server's FIG negotiator hardcodes peerCertificates[1] when validating the
#   federate peer's TLS handshake — it requires the peer to send a 2-cert chain
#   (leaf cert + signing CA cert) rather than just the leaf. If only the leaf is
#   sent, TAK Server throws an ArrayIndexOutOfBoundsException during FIG negotiation.
#   For TAK Server interop, set fed_cert (and per-peer client_cert) to point at the
#   *-chain.crt files, NOT the bare *.crt files:
#   [federation_ssl]
#   fed_ca_bundle = /path/to/fed-ca.crt
#   fed_cert      = /path/to/server-chain.crt    # <-- chain file for TAK Server interop
#   fed_key       = /path/to/server.key
#   fed_key_pw    =
#   The bare *.crt files are preserved for back-compat (taky-to-taky federation works
#   with either; only the TAK Server FIG negotiator requires the chain).
# Usage:
#   python3 -m ots_federation.gen_fed_ca --help
#   ots-fed-certs --out-dir /path/to/output \
#       --ca-cn federation-ca --server-cn server-01 --client-cn client-01
# Security notes:
#   - Private keys are written with mode 0600 and should be stored in secrets/.
#   - Never commit private key files to git.
#   - CA cert (fed-ca.crt) is public material; distribute to all federate peers.
#   - CA private key (fed-ca.key) stays on the issuing host only.
#   - EC P-256 keys are used for all material (preferred by).
# Per-peer [federate:<name>] sections may override ca_cert/client_cert/client_key
# for peer-specific cert material.

import argparse
import datetime
import ipaddress
import os
import sys
import textwrap
import xml.etree.ElementTree as ET
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def _make_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate an EC P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def _write_private_key(path: str, key: ec.EllipticCurvePrivateKey, password: bytes = None) -> None:
    """Write a private key in PEM format with mode 0600."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )
    # Open with mode 0600 — private keys only.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    except Exception:
        os.close(fd)
        raise


def _write_cert(path: str, cert: x509.Certificate) -> None:
    """Write a certificate in PEM format with mode 0644."""
    pem = cert.public_bytes(serialization.Encoding.PEM)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    except Exception:
        os.close(fd)
        raise


def _write_cert_chain(
    path: str, leaf_cert: x509.Certificate, ca_cert: x509.Certificate
) -> None:
    """
    Write a PEM certificate chain file (leaf cert followed by CA cert) with mode 0644.

    The leaf-first ordering is required by TLS stack conventions (RFC 5246 §7.4.2)
    and specifically by TAK Server 5.4's FIG negotiator, which reads peerCertificates[1]
    (the CA cert) during federation handshake. Sending only the leaf causes an
    ArrayIndexOutOfBoundsException in TAK Server's FIG negotiation code.

    Parameters
    ----------
    path : str
        Filesystem path to write the chain file.
    leaf_cert : x509.Certificate
        The end-entity (leaf) certificate — written first.
    ca_cert : x509.Certificate
        The signing CA certificate — written second.
    """
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(leaf_pem)
            f.write(ca_pem)
    except Exception:
        os.close(fd)
        raise


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def generate_ca(
    cn: str,
    org: str,
    validity_days: int,
) -> tuple:
    """
    Generate a self-signed federation CA key + certificate.

    Parameters
    ----------
    cn : str
        Common Name for the CA certificate (e.g. "taky-federation-ca").
    org : str
        Organization name embedded in the CA certificate.
    validity_days : int
        CA validity in days from now.

    Returns
    -------
    (ca_key, ca_cert) : tuple of (EllipticCurvePrivateKey, x509.Certificate)
    """
    ca_key = _make_ec_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])
    now = _utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def generate_peer_cert(
    cn: str,
    org: str,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    validity_days: int,
    san_dns: list = None,
    san_ip: list = None,
    is_server: bool = True,
) -> tuple:
    """
    Generate a federation peer certificate signed by the federation CA.

    Parameters
    ----------
    cn : str
        Common Name for the peer certificate (e.g. "taky-server-01").
    org : str
        Organization name.
    ca_key : EllipticCurvePrivateKey
        Federation CA private key for signing.
    ca_cert : x509.Certificate
        Federation CA certificate for issuer linkage.
    validity_days : int
        Certificate validity in days from now.
    san_dns : list of str, optional
        DNS Subject Alternative Names (e.g. ["taky.example.com"]).
    san_ip : list of str, optional
        IP Address SANs (e.g. ["203.0.113.10"]).
    is_server : bool
        True = serverAuth EKU; False = clientAuth EKU. Both are added if
        both modes may be needed (e.g., a peer acting as both client and
        server), but the primary EKU is set first.

    Returns
    -------
    (peer_key, peer_cert) : tuple of (EllipticCurvePrivateKey, x509.Certificate)
    """
    peer_key = _make_ec_key()
    now = _utcnow()

    san_names = []
    for dns in (san_dns or []):
        san_names.append(x509.DNSName(dns))
    for ip in (san_ip or []):
        san_names.append(x509.IPAddress(ipaddress.ip_address(ip)))

    # Always include CN as a DNS SAN to support check_hostname=True.
    if not san_names:
        san_names.append(x509.DNSName(cn))

    # Extended Key Usage: include both server and client auth because taky peers
    # act as both gRPC client (outbound) and gRPC server (Phase 2 inbound).
    # grpcio validates EKU on the server cert for client connections.
    ekus = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(peer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(ekus),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(peer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    peer_cert = builder.sign(ca_key, hashes.SHA256())
    return peer_key, peer_cert


def cmd_generate(argv, prog="ots-fed-certs generate"):
    """
    Implements the `generate` subcommand — unchanged behavior from the original
    (pre-subcommand) `ots-fed-certs` CLI. See main() for subcommand dispatch and
    the back-compat shim that routes bare (no-subcommand) invocations here.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Generate a standalone federation CA, server cert, and client cert "
            "for taky federation mTLS. "
            "Private keys are written with mode 0600. "
            "Store fed-ca.key in secrets/ and never commit it."
        )
    )
    parser.add_argument(
        "--out-dir",
        default=".",
        help="Directory to write generated files (default: current directory)",
    )
    parser.add_argument(
        "--ca-cn",
        default="taky-federation-ca",
        help="Common Name for the federation CA (default: taky-federation-ca)",
    )
    parser.add_argument(
        "--server-cn",
        default="taky-server",
        help="Common Name for the server identity cert (default: taky-server)",
    )
    parser.add_argument(
        "--client-cn",
        default="taky-client",
        help="Common Name for the client identity cert (default: taky-client)",
    )
    parser.add_argument(
        "--org",
        default="field-services",
        help="Organization name embedded in all certs (default: field-services)",
    )
    parser.add_argument(
        "--ca-days",
        type=int,
        default=1825,
        help="CA validity in days (default: 1825 = 5 years)",
    )
    parser.add_argument(
        "--cert-days",
        type=int,
        default=365,
        help="Peer cert validity in days (default: 365 = 1 year)",
    )
    parser.add_argument(
        "--server-san-dns",
        action="append",
        default=[],
        metavar="DNS",
        help="DNS SAN for server cert (may be repeated). Default: same as --server-cn.",
    )
    parser.add_argument(
        "--server-san-ip",
        action="append",
        default=[],
        metavar="IP",
        help="IP Address SAN for server cert (may be repeated).",
    )
    parser.add_argument(
        "--client-san-dns",
        action="append",
        default=[],
        metavar="DNS",
        help="DNS SAN for client cert (may be repeated). Default: same as --client-cn.",
    )
    parser.add_argument(
        "--key-password",
        default=None,
        help="Password to encrypt private keys (default: unencrypted). "
             "Set via --key-password=<pw>. Avoid shell history for sensitive passwords.",
    )

    args = parser.parse_args(argv)
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    key_pw = args.key_password.encode("utf-8") if args.key_password else None

    print(f"[gen_fed_ca] Writing to: {out_dir}")
    print("[gen_fed_ca] Chain files (*-chain.crt) required for TAK Server 5.4 FIG interop.")

    # 1. Federation CA
    print("[gen_fed_ca] Generating federation CA key + certificate ...")
    ca_key, ca_cert = generate_ca(
        cn=args.ca_cn,
        org=args.org,
        validity_days=args.ca_days,
    )
    _write_private_key(os.path.join(out_dir, "fed-ca.key"), ca_key, password=key_pw)
    _write_cert(os.path.join(out_dir, "fed-ca.crt"), ca_cert)
    print(f"  fed-ca.key  (0600) — KEEP IN secrets/, never commit")
    print(f"  fed-ca.crt  (0644) — distribute to all federate peers out-of-band")

    # 2. Server identity cert
    print("[gen_fed_ca] Generating server identity cert ...")
    server_key, server_cert = generate_peer_cert(
        cn=args.server_cn,
        org=args.org,
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=args.cert_days,
        san_dns=args.server_san_dns or None,
        san_ip=args.server_san_ip or None,
        is_server=True,
    )
    _write_private_key(os.path.join(out_dir, "server.key"), server_key, password=key_pw)
    _write_cert(os.path.join(out_dir, "server.crt"), server_cert)
    _write_cert_chain(os.path.join(out_dir, "server-chain.crt"), server_cert, ca_cert)
    print(f"  server.key        (0600)")
    print(f"  server.crt        (0644) — leaf cert only (back-compat)")
    print(f"  server-chain.crt  (0644) — leaf + CA chain (required for TAK Server interop)")

    # 3. Client identity cert (used for outbound mTLS — fed_cert/fed_key in [federation_ssl])
    print("[gen_fed_ca] Generating client identity cert ...")
    client_key, client_cert = generate_peer_cert(
        cn=args.client_cn,
        org=args.org,
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=args.cert_days,
        san_dns=args.client_san_dns or None,
        san_ip=None,
        is_server=False,
    )
    _write_private_key(os.path.join(out_dir, "client.key"), client_key, password=key_pw)
    _write_cert(os.path.join(out_dir, "client.crt"), client_cert)
    _write_cert_chain(os.path.join(out_dir, "client-chain.crt"), client_cert, ca_cert)
    print(f"  client.key        (0600)")
    print(f"  client.crt        (0644) — leaf cert only (back-compat)")
    print(f"  client-chain.crt  (0644) — leaf + CA chain (required for TAK Server interop)")

    print()
    print("[gen_fed_ca] TAK Server interop: use *-chain.crt files for fed_cert.")
    print("[gen_fed_ca] TAK Server 5.4 FIG negotiator reads peerCertificates[1] (the CA)")
    print("[gen_fed_ca] during FIG negotiation — sending only the leaf causes an AIOOBE.")
    print()
    print("[gen_fed_ca] Example [federation_ssl] config (TAK Server interop):")
    print(f"  [federation_ssl]")
    print(f"  fed_ca_bundle = {os.path.join(out_dir, 'fed-ca.crt')}")
    print(f"  fed_cert      = {os.path.join(out_dir, 'server-chain.crt')}  # <-- chain file")
    print(f"  fed_key       = {os.path.join(out_dir, 'server.key')}")
    print(f"  fed_key_pw    =")
    print()
    print("[gen_fed_ca] WARNING: store fed-ca.key in secrets/ per workspace convention.")
    print("[gen_fed_ca] WARNING: never commit private key files to git.")
    return 0


# ---------------------------------------------------------------------------
# export subcommand — mutual-CA peer-exchange bundle
# ---------------------------------------------------------------------------
# No private key material is ever written by this subcommand. The bundle
# carries ONLY our fed-CA certificate (public) plus filled-in config-stanza
# templates and a README. The remote admin returns their own CA cert; no
# signing traffic or key material crosses hosts in either direction.

_EXPORT_INI_TEMPLATE = """\
# --- ots-federation.ini peer stanza for federating with "{server_id}" ---
# Generated by 'ots-fed-certs export' (mutual-CA exchange).
# Add this section to YOUR federation.ini, then point ca_cert at the
# fed-ca.crt included in this bundle (or your merged multi-CA bundle file —
# see README.md step 1).
[federate:{server_id}]
address = {address}
display_name = {server_id}
port = {listen_port}
protocol = grpc
# ca_cert: path where you saved fed-ca.crt from this bundle.
ca_cert = /path/to/fed-ca.crt
# accept_as / share_as: TIGHTEN to your real ACL group names before going
# live — the wildcards below are permissive placeholders, not a
# recommendation. See README.qmd "CoT Events Not Exchanged" for semantics.
accept_as = *:
share_as = *:*
"""

_EXPORT_README_TEMPLATE = """\
---
title: "Federation peer-exchange bundle — {server_id}"
date: "{date}"
---

# Federation peer-exchange bundle — {server_id}

Generated by `ots-fed-certs export` (mutual-CA exchange — no
private keys ever move; each side keeps and controls its own CA).

**This bundle contains no private key material anywhere.** Only our
federation CA certificate (public) and filled-in config templates.

## Our federation identity

- server_id / federate name: `{server_id}`
- address: `{address}`
- listen_port: `{listen_port}`
- leaf certificate fingerprint (SHA-256, colon-hex): `{fingerprint}`

## What's in this bundle

- `fed-ca.crt` — our federation CA certificate (public). Add it to your trust
  store so you can verify our identity cert during the mTLS handshake.
- `ots-federation-federate-stanza.ini` — a `[federate:{server_id}]` section to
  add to YOUR `federation.ini` if you also run ots-federation / taky.
- `takserver-federate-stanza.xml` — a `<federate>` element to add inside your
  CoreConfig.xml `<federation>` block if you run stock TAK Server.

## Steps

1. **Trust our CA.** Copy `fed-ca.crt` from this bundle into your federation
   trust store:
   - ots-federation / taky: point `ca_cert` (per-peer, set in the INI stanza
     below) or `[federation_ssl] fed_ca_bundle` (global) at this file — or
     append it to an existing multi-CA bundle:
     `cat fed-ca.crt >> /path/to/your/fed-ca-bundle.crt` (grpcio and Python's
     `ssl.SSLContext.load_verify_locations` both accept multi-cert PEM
     bundles natively; no code change needed — validated live 2026-07-24).
   - Stock TAK Server: import into your CoreConfig `<tls>` `truststoreFile`.

2. **Add the federate entry.**
   - ots-federation: paste `ots-federation-federate-stanza.ini` into your
     `federation.ini`, fill in `ca_cert` with the path from step 1, and
     tighten `accept_as` / `share_as` to your real ACL groups.
   - Stock TAK Server: paste `takserver-federate-stanza.xml` inside your
     CoreConfig.xml `<federation>` element. **The `<inboundGroup>` /
     `<outboundGroup>` children are REQUIRED** — a `<federate>` entry without
     them exchanges nothing in either direction (this is what broke ticket
     2a74dd; do not strip them). The `id` attribute is already filled in as
     the SHA-256 fingerprint of the leaf certificate we present during the
     handshake (`{fingerprint}`) — TAK Server's FIG negotiator uses it to
     match our inbound connection to this entry.
   - Chain-cert note: if your TAK Server FIG negotiator logs an
     `ArrayIndexOutOfBoundsException`, you're being sent a bare leaf cert
     instead of a leaf+CA chain. `ots-fed-certs generate` already handles
     this on our side (`server-chain.crt` / `client-chain.crt`); the `id`
     above stays the LEAF fingerprint either way (peerCertificates[0]).

3. **Send us your CA cert.** Export your own federation CA certificate
   (public only — never your private key) and send it back to us. We add it
   to our trust bundle the same way:
   `cat their-fed-ca.crt >> /path/to/our/fed-ca-bundle.crt`.

4. **Restart / reload** federation on both sides once the CA exchange and
   federate entries are in place.

No private keys crossed a host boundary at any point in this exchange.
"""


def _leaf_fingerprint_sha256_colon_hex(cert: x509.Certificate) -> str:
    """
    Return the SHA-256 fingerprint of a certificate as colon-separated
    uppercase hex (e.g. "AA:BB:CC:...").

    This is the value a stock TAK Server CoreConfig <federate id="..."> entry
    must carry for us: the fingerprint of the LEAF certificate we actually
    present during the mTLS handshake. With chain certs (leaf + CA, required
    for TAK Server FIG interop — see the module docstring's chain-cert quirk),
    that is peerCertificates[0], i.e. still the leaf, not the CA.
    """
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def _build_federate_coreconfig_xml(fingerprint: str, server_id: str, address: str, listen_port: int) -> str:
    """
    Build the stock TAK Server CoreConfig <federate> stanza as an XML string.

    Built via xml.etree.ElementTree (never string-formatted markup, PY-5) so
    server_id/address are safely escaped even though they originate from
    operator-controlled local input (cert CN / CLI flags), not a network peer.
    """
    federate = ET.Element(
        "federate",
        {
            "id": fingerprint,
            "displayName": server_id,
            "address": address,
            "port": str(listen_port),
        },
    )
    inbound = ET.SubElement(federate, "inboundGroup")
    inbound.text = "__ANON__"
    outbound = ET.SubElement(federate, "outboundGroup")
    outbound.text = "__ANON__"
    ET.indent(federate, space="    ")
    return ET.tostring(federate, encoding="unicode")


def cmd_export(argv, prog="ots-fed-certs export"):
    """
    Implements the `export` subcommand: emit a mutual-CA peer-exchange bundle
    (mutual-CA exchange) from a prior `generate` output. NEVER includes private keys.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Emit a peer-exchange bundle for mutual-CA federation hand-out "
            "(mutual-CA exchange: no private keys ever move). Reads a prior 'generate' "
            "output and produces our public fed-CA cert, filled-in config "
            "stanza templates (ots-federation INI + stock TAK CoreConfig XML), "
            "and a README with the exchange steps."
        ),
    )
    parser.add_argument(
        "--cert-dir",
        default=".",
        help="Directory containing a prior 'generate' output (fed-ca.crt, "
             "server.crt). Default: current directory.",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Directory to write the export bundle (default: <cert-dir>/export-bundle).",
    )
    parser.add_argument(
        "--server-id",
        default=None,
        help="Our server_id / federate section name for the templates "
             "(default: read from the server cert's Common Name).",
    )
    parser.add_argument(
        "--our-address",
        default="<FILL_IN_OUR_REACHABLE_ADDRESS_OR_HOSTNAME>",
        help="Our reachable hostname/IP to embed in the templates "
             "(default: a placeholder the remote admin must fill in).",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=9101,
        help="Our federation inbound listen_port (default: 9101).",
    )
    parser.add_argument(
        "--zip",
        action="store_true",
        help="Also produce a <out-dir>.zip archive of the bundle.",
    )
    args = parser.parse_args(argv)

    cert_dir = os.path.abspath(args.cert_dir)
    ca_crt_path = os.path.join(cert_dir, "fed-ca.crt")
    server_crt_path = os.path.join(cert_dir, "server.crt")

    if not os.path.isfile(ca_crt_path):
        print(
            f"[ots-fed-certs export] ERROR: {ca_crt_path} not found. "
            f"Run 'ots-fed-certs generate --out-dir {cert_dir}' first.",
            file=sys.stderr,
        )
        return 1
    if not os.path.isfile(server_crt_path):
        print(
            f"[ots-fed-certs export] ERROR: {server_crt_path} not found. "
            f"Run 'ots-fed-certs generate --out-dir {cert_dir}' first.",
            file=sys.stderr,
        )
        return 1

    with open(ca_crt_path, "rb") as f:
        ca_pem = f.read()
    with open(server_crt_path, "rb") as f:
        server_leaf_cert = x509.load_pem_x509_certificate(f.read())

    server_id = args.server_id
    if not server_id:
        cn_attrs = server_leaf_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        server_id = cn_attrs[0].value if cn_attrs else "ots-federation-peer"

    fingerprint = _leaf_fingerprint_sha256_colon_hex(server_leaf_cert)

    out_dir = os.path.abspath(args.out_dir) if args.out_dir else os.path.join(cert_dir, "export-bundle")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[ots-fed-certs export] Writing peer-exchange bundle to: {out_dir}")

    # 1. Public fed-CA cert only — never a key.
    bundle_ca_path = os.path.join(out_dir, "fed-ca.crt")
    fd = os.open(bundle_ca_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(ca_pem)
    except Exception:
        os.close(fd)
        raise
    print("  fed-ca.crt                        — our federation CA (public only)")

    # 2. ots-federation INI stanza template.
    ini_stanza = _EXPORT_INI_TEMPLATE.format(
        server_id=server_id, address=args.our_address, listen_port=args.listen_port
    )
    ini_path = os.path.join(out_dir, "ots-federation-federate-stanza.ini")
    with open(ini_path, "w") as f:
        f.write(ini_stanza)
    print("  ots-federation-federate-stanza.ini — [federate:*] INI stanza template")

    # 3. Stock TAK CoreConfig <federate> XML stanza template.
    federate_xml = _build_federate_coreconfig_xml(
        fingerprint, server_id, args.our_address, args.listen_port
    )
    xml_header = (
        "<!-- Stock TAK Server CoreConfig <federate> stanza for "
        f"\"{server_id}\" -->\n"
        "<!-- Generated by 'ots-fed-certs export' (mutual-CA exchange). -->\n"
        "<!-- Add this inside CoreConfig.xml's <federation> element.           -->\n"
        "<!-- inboundGroup/outboundGroup are REQUIRED — a federate entry       -->\n"
        "<!-- without them exchanges nothing in either direction. id = SHA-256 -->\n"
        "<!-- fingerprint of the LEAF cert we present (see README.md).        -->\n"
    )
    coreconfig_path = os.path.join(out_dir, "takserver-federate-stanza.xml")
    with open(coreconfig_path, "w") as f:
        f.write(xml_header + federate_xml + "\n")
    print("  takserver-federate-stanza.xml      — stock TAK CoreConfig <federate> stanza")

    # 4. README with exchange steps.
    readme = _EXPORT_README_TEMPLATE.format(
        server_id=server_id,
        address=args.our_address,
        listen_port=args.listen_port,
        fingerprint=fingerprint,
        date=_utcnow().date().isoformat(),
    )
    readme_path = os.path.join(out_dir, "README.md")
    with open(readme_path, "w") as f:
        f.write(readme)
    print("  README.md                          — exchange steps for the remote admin")

    if args.zip:
        zip_path = out_dir.rstrip(os.sep) + ".zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fname in sorted(os.listdir(out_dir)):
                zf.write(os.path.join(out_dir, fname), arcname=fname)
        print(f"  {os.path.basename(zip_path)}                — zip archive of the above")

    print()
    print(f"[ots-fed-certs export] Federate id (leaf cert fingerprint): {fingerprint}")
    print("[ots-fed-certs export] No private key material was written to this bundle.")
    return 0


# ---------------------------------------------------------------------------
# apply subcommand — fleet cert lifecycle, OUR side only
# ---------------------------------------------------------------------------
# apply NEVER writes into /opt/fleet/ansible/ (repo-claim lock applies
# to that tree). It only stages a plaintext secrets file locally and prints
# the exact sops/ansible commands for a human to run. Var names below
# (ots_fed_ca_crt / ots_fed_server_cert / ots_fed_server_key) match
# project_roles/ots_server/tasks/ssl.yml on the ansible repo's main branch —
# do not rename without updating that role too.

_ANSIBLE_TREE_ROOT = "/opt/fleet/ansible"


def cmd_apply(argv, prog="ots-fed-certs apply"):
    """
    Implements the `apply` subcommand: package a prior 'generate' output for
    OUR fleet into a plaintext sops-staging file, and print the exact
    sops-encrypt + ansible-role-var steps. Never writes into the ansible tree.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Package a prior 'generate' output for OUR fleet: emit a "
            "plaintext secrets-staging file with the exact keys the ansible "
            "ots_server role expects, plus the sops/ansible commands to run "
            "yourself. NEVER writes into the ansible tree."
        ),
    )
    parser.add_argument(
        "--cert-dir",
        default=".",
        help="Directory containing a prior 'generate' output. Default: current directory.",
    )
    parser.add_argument(
        "--host",
        required=True,
        help="Fleet hostname this cert material is for (e.g. ots-fed-node) — "
             "used for the staging subdirectory and the printed instructions.",
    )
    parser.add_argument(
        "--out-dir",
        default="./sops-staging",
        help="Local staging directory (default: ./sops-staging). Must NOT be "
             "inside the ansible tree.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing staging file.",
    )
    args = parser.parse_args(argv)

    out_dir_abs = os.path.abspath(args.out_dir)
    ansible_root_abs = os.path.abspath(_ANSIBLE_TREE_ROOT)
    if out_dir_abs == ansible_root_abs or out_dir_abs.startswith(ansible_root_abs + os.sep):
        print(
            f"[ots-fed-certs apply] ERROR: --out-dir must not be inside {ansible_root_abs} "
            "(repo-claim lock applies to that tree; apply only stages files locally).",
            file=sys.stderr,
        )
        return 1

    cert_dir = os.path.abspath(args.cert_dir)
    ca_path = os.path.join(cert_dir, "fed-ca.crt")
    chain_path = os.path.join(cert_dir, "server-chain.crt")
    leaf_path = os.path.join(cert_dir, "server.crt")
    key_path = os.path.join(cert_dir, "server.key")

    if not os.path.isfile(ca_path) or not os.path.isfile(key_path):
        print(
            f"[ots-fed-certs apply] ERROR: generate output not found in {cert_dir}. "
            f"Run 'ots-fed-certs generate --out-dir {cert_dir}' first.",
            file=sys.stderr,
        )
        return 1

    if os.path.isfile(chain_path):
        cert_path = chain_path
        cert_source_note = "server-chain.crt (leaf+CA — safe for both taky and TAK Server peers)"
    elif os.path.isfile(leaf_path):
        cert_path = leaf_path
        cert_source_note = "server.crt (bare leaf — NOT TAK Server FIG-interop safe; regenerate for server-chain.crt)"
        print(
            f"[ots-fed-certs apply] WARNING: {chain_path} not found; falling back to bare leaf cert.",
            file=sys.stderr,
        )
    else:
        print(
            f"[ots-fed-certs apply] ERROR: neither server-chain.crt nor server.crt found in {cert_dir}.",
            file=sys.stderr,
        )
        return 1

    host_dir = os.path.join(out_dir_abs, args.host)
    staging_path = os.path.join(host_dir, "ots-federation.plaintext.yml")

    if os.path.exists(staging_path) and not args.force:
        print(
            f"[ots-fed-certs apply] ERROR: {staging_path} already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1

    os.makedirs(host_dir, exist_ok=True)

    with open(ca_path) as f:
        ca_pem = f.read()
    with open(cert_path) as f:
        cert_pem = f.read()
    with open(key_path) as f:
        key_pem = f.read()

    staging_yaml = (
        "# PLAINTEXT staging file — NOT sops-encrypted. Generated by 'ots-fed-certs apply'.\n"
        f"# Source cert material: {cert_dir} ({cert_source_note}).\n"
        "# Encrypt this with sops BEFORE it ever reaches the ansible tree, then delete it.\n"
        "# Key names below match project_roles/ots_server/tasks/ssl.yml on the ansible\n"
        "# repo's main branch — do not rename.\n"
        f"ots_fed_ca_crt: |\n{textwrap.indent(ca_pem, '  ')}\n"
        f"ots_fed_server_cert: |\n{textwrap.indent(cert_pem, '  ')}\n"
        f"ots_fed_server_key: |\n{textwrap.indent(key_pem, '  ')}\n"
    )

    # Contains private key material — restrictive from creation (PY-12).
    # O_EXCL unless --force (existence was already gated above); --force
    # needs O_TRUNC to actually overwrite, since O_EXCL always fails on an
    # existing path regardless of TRUNC.
    open_flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if args.force else os.O_EXCL)
    fd = os.open(staging_path, open_flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(staging_yaml)
    except Exception:
        os.close(fd)
        raise

    print("[ots-fed-certs apply] Wrote plaintext secrets staging file (mode 0600):")
    print(f"  {staging_path}")
    print()
    print("[ots-fed-certs apply] NEXT STEPS (run these yourself — apply never writes")
    print("into the ansible tree; the repo-claim lock applies there):")
    print(f"  1. sops --encrypt --age <recipient> {staging_path} \\")
    print(f"       > {_ANSIBLE_TREE_ROOT}/node_secrets/{args.host}/ots-federation.sops.yml")
    print(f"  2. rm {staging_path}   # never leave plaintext key material on disk")
    print("  3. Set/confirm role vars for this host (project_roles/ots_server/defaults/main.yml,")
    print("     ansible repo main branch): ots_server_federation_server_id,")
    print("     ots_server_federation_server_name, ots_server_federation_listen_port,")
    print("     ots_server_federation_accept_as, ots_server_federation_share_as,")
    print("     ots_server_federation_peers (list of {name, display_name, address, port,")
    print("     accept_as, share_as} per remote peer).")
    print(f"  4. Re-run the ots_server role against {args.host} (tags: ots, ssl, federation).")
    return 0


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------

_SUBCOMMANDS = {
    "generate": cmd_generate,
    "export": cmd_export,
    "apply": cmd_apply,
}


def main(argv=None):
    """
    Dispatch to generate|export|apply subcommands.

    Back-compat: a bare invocation with no recognized subcommand as argv[0]
    (including the original flat-flag shape, e.g. `ots-fed-certs --out-dir ...`,
    and a zero-arg invocation) is treated as `generate`, after printing a
    one-line deprecation notice on stderr. This keeps every existing script
    and operator muscle-memory working unchanged after the export/apply
    subcommands were added (2026-07-24).
    """
    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] in _SUBCOMMANDS:
        return _SUBCOMMANDS[argv[0]](argv[1:])

    print(
        "[ots-fed-certs] DEPRECATION: bare invocation without a subcommand is "
        "deprecated; use 'ots-fed-certs generate ...' explicitly. "
        "Continuing as 'generate'.",
        file=sys.stderr,
    )
    return cmd_generate(argv, prog="ots-fed-certs")


if __name__ == "__main__":
    sys.exit(main())
