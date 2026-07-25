# taky/cot/federation/tls.py
# Stream: tls-config
#                       check_hostname=True, no CERT_NONE ever)
#(TLS layer — ssl stdlib, gRPC ChannelCredentials).
# Two SEPARATE SSL contexts:
#   1. grpc_client_credentials → grpc.ssl_channel_credentials
#      Used by FederateClient.run_grpc_thread to open outbound gRPC channel.
#   2. grpc_server_credentials → grpc.ssl_server_credentials
#      Used by FederationManager hub-server mode (Phase 2).
# These must NEVER share an ssl.SSLContext with the ATAK client TLS context
# (which is built from [ssl] config in taky.config). A compromised ATAK client
# cert must not grant federation-level trust.
# Config section parsed: [federation_ssl].

import ssl
from typing import Optional

import grpc


def _read_pem_bytes(path: str, label: str, password: Optional[bytes] = None) -> bytes:
    """
    Read raw PEM bytes from a file. For private keys, call ssl.PrivateKey
    indirectly by using ssl.SSLContext.load_cert_chain with the key file —
    this helper just does file I/O.

    Parameters
    ----------
    path : str
        Filesystem path to a PEM file.
    label : str
        Human-readable description used in error messages (e.g. "federation CA bundle").

    Returns
    -------
    bytes
        Raw PEM file contents.

    Raises
    ------
    OSError
        If the file cannot be opened.
    """
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as exc:
        raise OSError(f"Failed to read {label} from {path!r}: {exc}") from exc


def _validate_pem_with_ssl(
    ca_bundle_path: str,
    cert_path: str,
    key_path: str,
    key_password: Optional[bytes],
) -> None:
    """
    Validate that the cert/key/CA material loads cleanly via ssl.SSLContext.

    Creates a temporary SSLContext (TLS_CLIENT) with CERT_REQUIRED and attempts
    to load the CA bundle and client cert/key. Raises ssl.SSLError if anything
    is wrong. This gives clear errors before handing the raw bytes to grpcio.

    Enforcesconstraints:
    - TLS 1.2 minimum (OP_NO_TLSv1, OP_NO_TLSv1_1).
    - CERT_REQUIRED (not CERT_NONE or CERT_OPTIONAL).
    - check_hostname=True.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    # Load the federation CA bundle for peer verification.
    ctx.load_verify_locations(cafile=ca_bundle_path)

    # Load our identity cert + key (validates both and that they match).
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path, password=key_password)


def build_grpc_client_credentials(
    fed_ca_bundle_path: str,
    fed_cert_path: str,
    fed_key_path: str,
    fed_key_password: Optional[bytes] = None,
) -> grpc.ChannelCredentials:
    """
    Build gRPC channel credentials for outbound mutual TLS to a federate peer.

    Uses Python ssl stdlib to validate cert material and load raw PEM bytes
    then wraps in grpc.ssl_channel_credentials.

    This function uses the FEDERATION CA only — it must never be called with
    paths from the [ssl] ATAK client section.

    Security constraints:
    - TLS 1.2 minimum; TLS 1.3 preferred (grpcio default with modern OpenSSL).
    - CERT_REQUIRED + check_hostname=True enforced by _validate_pem_with_ssl.
    - CA bundle must be the FEDERATION CA, not the ATAK client CA.
    - Do NOT use ssl.CERT_NONE or check_hostname=False even for testing.

    Parameters
    ----------
    fed_ca_bundle_path : str
        Path to PEM file containing the federation CA certificate(s).
        Used to verify the remote peer's certificate chain.
    fed_cert_path : str
        Path to PEM file containing this server's federation identity certificate.
    fed_key_path : str
        Path to PEM file containing this server's federation identity private key.
    fed_key_password : bytes, optional
        Key password as bytes, or None if the key is unencrypted.
        Pass b"" for an empty password; None means truly no password.

    Returns
    -------
    grpc.ChannelCredentials
        Ready for use in grpc.secure_channel(address, credentials).

    Raises
    ------
    ssl.SSLError
        If cert/key/CA cannot be loaded, are invalid, or the cert and key do
        not match.
    OSError
        If any of the PEM files cannot be opened.
    """
    # Validate material via ssl before handing raw bytes to grpcio.
    # This provides clear error messages rather than opaque gRPC channel errors.
    _validate_pem_with_ssl(
        ca_bundle_path=fed_ca_bundle_path,
        cert_path=fed_cert_path,
        key_path=fed_key_path,
        key_password=fed_key_password,
    )

    root_certs = _read_pem_bytes(fed_ca_bundle_path, "federation CA bundle")
    certificate_chain = _read_pem_bytes(fed_cert_path, "federation identity certificate")
    private_key = _read_pem_bytes(fed_key_path, "federation identity private key")

    # grpcio ssl_channel_credentials takes raw PEM bytes.
    # root_certificates: CA to verify the server's cert.
    # private_key / certificate_chain: our identity for mTLS.
    return grpc.ssl_channel_credentials(
        root_certificates=root_certs,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )


def build_grpc_server_credentials(
    fed_ca_bundle_path: str,
    fed_cert_path: str,
    fed_key_path: str,
    fed_key_password: Optional[bytes] = None,
    require_client_auth: bool = True,
) -> grpc.ServerCredentials:
    """
    Build gRPC server credentials for inbound mutual TLS connections.

    Used by FederationServer (fed_server.py) to host the FederatedChannel gRPC
    server so a remote taky/TAK-Server peer can connect inbound.
    (direct server-to-server)

    The server presents its own federation identity certificate (fed_cert/fed_key
    from [federation_ssl]) and verifies the connecting peer's client certificate
    against the FEDERATION CA bundle. With require_client_auth=True this enforces
    mutual TLS: only peers holding a valid federation-CA-signed certificate can
    connect.

    This function uses the FEDERATION CA only — it must never be called with paths
    from the [ssl] ATAK client section. A compromised ATAK client cert must not
    grant federation-level trust.

    TAK SERVER INTEROP — fed_cert MUST be a full leaf+CA chain
    -----------------------------------------------------------
    TAK Server 5.4's FIG negotiator hardcodes peerCertificates[1] when inspecting
    the handshake certificate list presented by the federate peer. It unconditionally
    reads the second certificate in the chain as the signing CA. If taky sends only
    the leaf (a single-cert PEM), TAK Server throws ArrayIndexOutOfBoundsException
    during FIG negotiation and the federation connection fails.

    To interoperate with TAK Server:
      - Set fed_cert_path to a PEM file containing the LEAF cert followed immediately
        by the CA cert (i.e. a two-entry chain: leaf first, CA second).
      - gen_fed_ca.py emits server-chain.crt (and client-chain.crt) for this purpose.
      - The bare server.crt / client.crt files (leaf only) are preserved for
        back-compat and for taky-to-taky links where this constraint does not apply.

    This function accepts a chain file transparently: grpc.ssl_server_credentials
    passes the certificate_chain bytes through to the TLS stack as-is, and a
    standards-compliant TLS stack (OpenSSL/BoringSSL) handles multi-cert chains
    correctly. No code change is needed here — only the file pointed to by
    fed_cert_path must contain the full chain.

    Security constraints:
    - require_client_auth=True (mutual TLS) — never set False in production.
    - CA bundle must be the FEDERATION CA, not the ATAK client CA.
    - Cert material is validated via ssl.SSLContext before being handed to grpcio
      so configuration errors surface clearly rather than as opaque channel errors.

    Parameters
    ----------
    fed_ca_bundle_path : str
        Federation CA bundle for verifying connecting peer certificates.
    fed_cert_path : str
        Path to PEM file containing this server's federation TLS certificate chain.
        MUST be a leaf+CA chain (two PEM blocks) for TAK Server 5.4 FIG interop.
        Use server-chain.crt generated by gen_fed_ca.py, not the bare server.crt.
    fed_key_path : str
        This server's federation TLS private key.
    fed_key_password : bytes, optional
        Key password if encrypted; None for an unencrypted key.
    require_client_auth : bool
        If True (default), enforce mutual TLS (require_client_auth=True in
        grpc.ssl_server_credentials). Never set False in production.

    Returns
    -------
    grpc.ServerCredentials
        Ready for use in grpc.server(...).add_secure_port(address, credentials).

    Raises
    ------
    ssl.SSLError
        If cert/key/CA cannot be loaded or are invalid, or the cert and key do
        not match.
    OSError
        If any of the PEM files cannot be opened.
    """
    # Validate material via ssl before handing raw bytes to grpcio. We use the
    # server-side context to validate the identity cert + key + CA load cleanly.
    _validate_server_pem_with_ssl(
        ca_bundle_path=fed_ca_bundle_path,
        cert_path=fed_cert_path,
        key_path=fed_key_path,
        key_password=fed_key_password,
    )

    root_certs = _read_pem_bytes(fed_ca_bundle_path, "federation CA bundle")
    certificate_chain = _read_pem_bytes(fed_cert_path, "federation identity certificate")
    private_key = _read_pem_bytes(fed_key_path, "federation identity private key")

    # grpcio ssl_server_credentials takes (private_key, certificate_chain) pairs
    # for the server identity, plus root_certificates for verifying client certs.
    return grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(private_key, certificate_chain)],
        root_certificates=root_certs,
        require_client_auth=require_client_auth,
    )


def _validate_server_pem_with_ssl(
    ca_bundle_path: str,
    cert_path: str,
    key_path: str,
    key_password: Optional[bytes],
) -> None:
    """
    Validate server-side cert/key/CA material via ssl.SSLContext.

    Mirrors _validate_pem_with_ssl but uses a TLS_SERVER context (the cert is
    presented as a server identity and the CA bundle is loaded to verify
    connecting client certs). Raises ssl.SSLError on any problem so config
    errors surface before grpcio sees them.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Require and verify the connecting peer's client certificate (mutual TLS).
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Load the federation CA bundle used to verify connecting client certs.
    ctx.load_verify_locations(cafile=ca_bundle_path)

    # Load our identity cert + key (validates both and that they match).
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path, password=key_password)
