# ots_federation/cert_identity.py
# Shared helper: resolve a federation peer's identity from the AUTHENTICATED
# mTLS certificate it presented on the transport, never from a wire-supplied
# or self-asserted field.
#
# Why this module exists: the fed_server.py servicer, the outbound client
# (client.py), and gen_fed_ca.py's `export` subcommand all need the exact
# same value — the SHA-256 fingerprint of a certificate, formatted as
# colon-separated uppercase hex — and it must be computed the same way
# everywhere so a peer's config-side identity (the fingerprint gen_fed_ca.py
# prints for a CoreConfig <federate id="..."> entry) always matches the
# identity the servicer resolves for that same certificate at runtime. One
# implementation, reused, per the workspace's security-relevant-helpers-once
# convention.
#
# Group-ACL and outbound-share decisions key on this fingerprint, not on
# Subscription.identity.serverId or a raw TCP peer address — both of which
# the connecting peer controls and can set to whatever it likes.

import base64
import json
import logging
import re
from typing import Optional, Set

from cryptography import x509
from cryptography.hazmat.primitives import hashes

log = logging.getLogger(__name__)

# SHA-256 digest = 32 bytes = 32 colon-separated 2-hex-digit groups.
_FINGERPRINT_RE = re.compile(r"^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$")


class FingerprintFormatError(ValueError):
    """Raised when a configured fingerprint string is not valid colon-hex SHA-256."""


def normalize_fingerprint_colon_hex(raw: str) -> str:
    """
    Normalize an operator-supplied SHA-256 fingerprint string to the same
    canonical form ``leaf_fingerprint_sha256_colon_hex`` produces: colon
    separated, upper-case hex, e.g. ``"AA:BB:CC:...:11"``.

    Accepts case-insensitive input (operators paste fingerprints from many
    tools that print lower-case hex) and surrounding whitespace, so a config
    value always compares equal to the value computed at runtime from the
    actual mTLS peer certificate — that equality is the entire point of the
    fingerprint-keyed identity binding this helper supports.

    Parameters
    ----------
    raw : str
        The raw ``fingerprint = ...`` config value.

    Returns
    -------
    str
        Canonical upper-case colon-hex form.

    Raises
    ------
    FingerprintFormatError
        If *raw* is not 32 colon-separated hex byte pairs (a SHA-256 digest).
        Deliberately fails loudly at config-load time rather than silently
        accepting a malformed value that could never match a real
        certificate — a fingerprint that never matches only ever quarantines
        (fails closed), but a config typo an operator can't see is a support
        headache worth catching immediately.
    """
    candidate = (raw or "").strip().upper()
    if not _FINGERPRINT_RE.match(candidate):
        raise FingerprintFormatError(
            f"invalid SHA-256 fingerprint {raw!r}: expected 32 colon-separated "
            "hex byte pairs, e.g. 'AA:BB:CC:...:11' (see cert_identity.py "
            "leaf_fingerprint_sha256_colon_hex for the canonical format)"
        )
    return candidate

# gRPC's C-core SSL auth context carries the peer's PEM-encoded leaf
# certificate under this property name (GRPC_X509_PEM_CERT_PROPERTY_NAME in
# grpc's ssl_transport_security.h) once the TLS handshake has completed and
# the peer presented a certificate. It is populated by the transport layer
# itself, before any application-level message is read — a peer cannot
# influence what appears here short of presenting a different certificate.
_AUTH_CONTEXT_PEM_CERT_KEY = "x509_pem_cert"


def leaf_fingerprint_sha256_colon_hex(cert: "x509.Certificate") -> str:
    """
    Return the SHA-256 fingerprint of *cert* as colon-separated uppercase hex
    (e.g. "AA:BB:CC:..."). This is the canonical fingerprint format used
    throughout federation identity binding and in the CoreConfig
    <federate id="..."> value gen_fed_ca.py's `export` subcommand prints for
    TAK Server interop.
    """
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def fingerprint_from_pem(pem_bytes: bytes) -> str:
    """Parse a PEM-encoded certificate and return its SHA-256 fingerprint."""
    cert = x509.load_pem_x509_certificate(pem_bytes)
    return leaf_fingerprint_sha256_colon_hex(cert)


def peer_fingerprint_from_grpc_context(context) -> Optional[str]:
    """
    Extract the AUTHENTICATED peer's leaf-certificate SHA-256 fingerprint
    from a grpc.ServicerContext, via ``context.auth_context()['x509_pem_cert']``.

    Returns None when the transport carries no verified peer certificate to
    bind to — an insecure channel (testing only; FederationServer logs a
    separate warning when it starts one), a context that doesn't expose
    auth_context in the expected shape, or any parse failure. Callers MUST
    treat None as "identity not cryptographically established" and must
    never substitute a self-asserted or address-derived string in its place
    for an ACL decision — that substitution is exactly the defect this
    module closes.
    """
    try:
        auth_ctx = context.auth_context()
    except Exception:  # pylint: disable=broad-except
        return None

    try:
        pem_list = auth_ctx.get(_AUTH_CONTEXT_PEM_CERT_KEY)
    except Exception:  # pylint: disable=broad-except
        return None

    if not pem_list:
        return None

    pem_bytes = pem_list[0]
    if not isinstance(pem_bytes, (bytes, bytearray)):
        return None

    try:
        return fingerprint_from_pem(bytes(pem_bytes))
    except Exception as exc:  # pylint: disable=broad-except
        log.warning(
            "cert_identity: failed to parse peer certificate from auth_context: %s",
            exc,
        )
        return None


def _channelz_target_matches(channelz_target: str, dialed_target: str) -> bool:
    """
    True when a channelz channel's reported target refers to *dialed_target*.

    channelz canonicalizes a scheme-less dial target like "10.0.0.1:9100"
    to "dns:///10.0.0.1:9100"; accept both the exact string and any
    scheme-prefixed form ending in "/<dialed_target>".
    """
    if not channelz_target or not dialed_target:
        return False
    return channelz_target == dialed_target or channelz_target.endswith(
        "/" + dialed_target
    )


def observed_server_cert_fingerprints_for_target(dialed_target: str) -> Set[str]:
    """
    Return the SHA-256 fingerprints of the certificates the DIALED SERVER
    actually presented on every live, TLS-secured client transport this
    process currently holds to *dialed_target* — observed via gRPC channelz
    socket introspection.

    Why channelz: grpcio's Python CLIENT side (verified empirically on the
    pinned grpcio, 1.81.1) exposes neither an auth_context on client call
    objects (cygrpc.auth_context requires the server-side cygrpc.Call type;
    client calls are SegregatedCall/IntegratedCall and are rejected with a
    TypeError) nor any custom TLS verification callback at channel
    construction (no TlsChannelCredentials / ServerAuthorizationCheckCallback
    equivalent on the public or cygrpc surface). Channelz, enabled per
    channel with the ("grpc.enable_channelz", 1) channel option, DOES expose
    each live client socket's security.tls.remoteCertificate — the PEM
    certificate presented by the remote endpoint during the TLS handshake of
    the very transport the channel's RPCs run on. Reading it is therefore an
    observation of the actual session's peer certificate (no separate probe
    connection, no TOCTOU against a different handshake), which is the same
    property TAK Server gets from its protocol-negotiator cert-chain callback
    (TakFigClient.java:1268-1311).

    Channelz state is process-global, so results are filtered to channels
    whose target matches *dialed_target*. All live sockets across all
    matching channels/subchannels are collected: callers enforcing an
    identity pin must treat anything other than exactly one distinct
    fingerprint that resolves to a configured peer as a refusal.

    FAIL-CLOSED CONTRACT: any error — channelz unavailable, private-API
    shape change, JSON/base64/PEM parse failure, insecure (non-TLS)
    transport — yields fewer (possibly zero) fingerprints, never a made-up
    one. Callers MUST refuse the session when the result is empty; they must
    never substitute a wire-supplied or address-derived identity in place of
    an observed certificate.

    Parameters
    ----------
    dialed_target : str
        The exact target string passed to grpc.secure_channel
        (e.g. "10.0.0.1:9100").

    Returns
    -------
    Set[str]
        Normalized (upper-case colon-hex) SHA-256 fingerprints; empty when
        nothing observable.
    """
    fingerprints: Set[str] = set()
    try:
        # Private grpcio surface (same calls the grpcio-channelz service
        # package wraps). Imported lazily so this module stays importable
        # if the surface ever moves — failure means "nothing observable",
        # which fails closed at every caller.
        from grpc._cython import cygrpc  # pylint: disable=import-outside-toplevel
    except Exception:  # pylint: disable=broad-except
        log.warning(
            "cert_identity: grpc channelz surface unavailable; cannot observe "
            "dialed server certificates (sessions requiring identity "
            "verification will be refused)"
        )
        return fingerprints

    start_id = 0
    for _ in range(1000):  # hard bound; channelz pages are never this many
        try:
            page = json.loads(cygrpc.channelz_get_top_channels(start_id))
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("cert_identity: channelz_get_top_channels failed: %s", exc)
            break
        channels = page.get("channel", [])
        for channel in channels:
            target = channel.get("data", {}).get("target", "")
            if not _channelz_target_matches(target, dialed_target):
                continue
            for sub_ref in channel.get("subchannelRef", []):
                fingerprints |= _subchannel_remote_cert_fingerprints(
                    cygrpc, sub_ref.get("subchannelId")
                )
        if page.get("end") or not channels:
            break
        try:
            start_id = (
                max(int(c["ref"]["channelId"]) for c in channels) + 1
            )
        except Exception:  # pylint: disable=broad-except
            break
    return fingerprints


def _subchannel_remote_cert_fingerprints(cygrpc, subchannel_id) -> Set[str]:
    """Collect remote-cert fingerprints from every socket of one subchannel."""
    fingerprints: Set[str] = set()
    if subchannel_id is None:
        return fingerprints
    try:
        sub = json.loads(cygrpc.channelz_get_subchannel(int(subchannel_id)))
    except Exception:  # pylint: disable=broad-except
        return fingerprints
    for sock_ref in sub.get("subchannel", {}).get("socketRef", []):
        sock_id = sock_ref.get("socketId")
        if sock_id is None:
            continue
        try:
            sock = json.loads(cygrpc.channelz_get_socket(int(sock_id)))
        except Exception:  # pylint: disable=broad-except
            continue
        tls = sock.get("socket", {}).get("security", {}).get("tls", {})
        remote_cert_b64 = tls.get("remoteCertificate")
        if not remote_cert_b64:
            # Insecure or half-open socket: nothing to observe. Never
            # substitute anything — absence fails closed at the caller.
            continue
        try:
            pem_bytes = base64.b64decode(remote_cert_b64)
            fingerprints.add(fingerprint_from_pem(pem_bytes))
        except Exception as exc:  # pylint: disable=broad-except
            log.warning(
                "cert_identity: failed to parse channelz remote certificate: %s",
                exc,
            )
    return fingerprints
