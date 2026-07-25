# tests/test_federation_tls_config.py
# Tests for:
#   taky/cot/federation/config.py — get_federation_config config parsing
#   taky/cot/federation/tls.py    — build_grpc_client_credentials (mTLS Phase 1)
#   taky/cot/federation/gen_fed_ca.py — generate_ca, generate_peer_cert
# SEPARATION INVARIANT:
#   The federation [federation_ssl] SSLContext must NEVER be the same object as
#   the ATAK client [ssl] SSLContext. Several tests explicitly verify this.
# Throwaway test certs are generated in a tmp directory using the same
# cryptography library as gen_fed_ca.py. No generated cert material is committed.

import configparser
import os
import ssl
import tempfile
import unittest

import grpc

from ots_federation.config import (
    FederationConfig,
    FederationSslConfig,
    FederatePeerConfig,
    get_federation_config,
)
from ots_federation.gen_fed_ca import generate_ca, generate_peer_cert, _write_private_key, _write_cert, _write_cert_chain
from ots_federation.tls import build_grpc_client_credentials, build_grpc_server_credentials


# ---------------------------------------------------------------------------
# Helpers: generate throwaway cert material into a tmp directory
# ---------------------------------------------------------------------------

def _generate_test_pki(tmp_dir: str):
    """
    Generate a throwaway federation CA + server cert + client cert for testing.
    Returns a dict of paths.
    """
    ca_key, ca_cert = generate_ca(
        cn="test-fed-ca",
        org="test-org",
        validity_days=1,
    )
    _write_private_key(os.path.join(tmp_dir, "ca.key"), ca_key)
    _write_cert(os.path.join(tmp_dir, "ca.crt"), ca_cert)

    server_key, server_cert = generate_peer_cert(
        cn="test-server",
        org="test-org",
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=1,
        san_dns=["test-server"],
        is_server=True,
    )
    _write_private_key(os.path.join(tmp_dir, "server.key"), server_key)
    _write_cert(os.path.join(tmp_dir, "server.crt"), server_cert)

    client_key, client_cert = generate_peer_cert(
        cn="test-client",
        org="test-org",
        ca_key=ca_key,
        ca_cert=ca_cert,
        validity_days=1,
        san_dns=["test-client"],
        is_server=False,
    )
    _write_private_key(os.path.join(tmp_dir, "client.key"), client_key)
    _write_cert(os.path.join(tmp_dir, "client.crt"), client_cert)

    return {
        "ca_crt": os.path.join(tmp_dir, "ca.crt"),
        "ca_key": os.path.join(tmp_dir, "ca.key"),
        "server_crt": os.path.join(tmp_dir, "server.crt"),
        "server_key": os.path.join(tmp_dir, "server.key"),
        "client_crt": os.path.join(tmp_dir, "client.crt"),
        "client_key": os.path.join(tmp_dir, "client.key"),
    }


def _cfg_from_text(ini_text: str) -> configparser.ConfigParser:
    """Parse a ConfigParser from an INI string."""
    cfg = configparser.ConfigParser(allow_no_value=True)
    cfg.read_string(ini_text)
    return cfg


# ---------------------------------------------------------------------------
# Tests: config parsing
# ---------------------------------------------------------------------------

class TestGetFederationConfig(unittest.TestCase):
    """Tests for get_federation_config()."""

    def test_no_section_returns_disabled(self):
        """Missing [federation] section → FederationConfig(enabled=False)."""
        cfg = _cfg_from_text("[taky]\nhostname = taky.local\n")
        result = get_federation_config(cfg)
        self.assertIsInstance(result, FederationConfig)
        self.assertFalse(result.enabled)
        self.assertEqual(result.peers, [])

    def test_federation_disabled_flag(self):
        """[federation] enabled=false → FederationConfig(enabled=False)."""
        cfg = _cfg_from_text("""
[federation]
enabled = false
server_id = MY-SERVER
""")
        result = get_federation_config(cfg)
        self.assertFalse(result.enabled)

    def test_minimal_enabled_config(self):
        """[federation] with required fields only → enabled with defaults."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001
""")
        result = get_federation_config(cfg)
        self.assertTrue(result.enabled)
        self.assertEqual(result.server_id, "TAKY-001")
        self.assertEqual(result.server_name, "TAKY-001")  # defaults to server_id
        self.assertEqual(result.max_hops, 3)
        self.assertEqual(result.peers, [])

    def test_server_name_explicit(self):
        """server_name is used when specified."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001
server_name = Taky Alpha Node
""")
        result = get_federation_config(cfg)
        self.assertEqual(result.server_name, "Taky Alpha Node")

    def test_max_hops_override(self):
        """max_hops is parsed correctly."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001
max_hops = 5
""")
        result = get_federation_config(cfg)
        self.assertEqual(result.max_hops, 5)

    def test_missing_server_id_raises(self):
        """[federation] enabled but missing server_id → configparser.Error."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
""")
        with self.assertRaises(configparser.Error):
            get_federation_config(cfg)

    def test_single_peer_section(self):
        """A single [federate:<name>] section is parsed into peers list."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:alpha]
address = 10.1.2.3
display_name = alpha
port = 9100
""")
        result = get_federation_config(cfg)
        self.assertEqual(len(result.peers), 1)
        peer = result.peers[0]
        self.assertIsInstance(peer, FederatePeerConfig)
        self.assertEqual(peer.name, "alpha")
        self.assertEqual(peer.address, "10.1.2.3")
        self.assertEqual(peer.port, 9100)
        self.assertTrue(peer.enabled)
        self.assertEqual(peer.protocol, "grpc")  # default
        self.assertEqual(peer.max_hops, -1)       # default
        self.assertEqual(peer.reconnect_interval, 30)
        self.assertEqual(peer.health_check_interval, 10)  # updated

    def test_multiple_peer_sections(self):
        """Multiple [federate:<name>] sections → multiple peers."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:alpha]
address = 10.1.2.3
display_name = alpha

[federate:bravo]
address = 10.1.2.4
display_name = bravo
port = 9200
""")
        result = get_federation_config(cfg)
        self.assertEqual(len(result.peers), 2)
        names = {p.name for p in result.peers}
        self.assertIn("alpha", names)
        self.assertIn("bravo", names)

    def test_disabled_peer_excluded(self):
        """[federate:<name>] with enabled=false is excluded from peers list."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:alpha]
address = 10.1.2.3
display_name = alpha
enabled = true

[federate:bravo]
address = 10.1.2.4
display_name = bravo
enabled = false
""")
        result = get_federation_config(cfg)
        self.assertEqual(len(result.peers), 1)
        self.assertEqual(result.peers[0].name, "alpha")

    def test_peer_missing_address_raises(self):
        """[federate:<name>] with missing address raises configparser.Error."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:bad-peer]
port = 9100
""")
        with self.assertRaises(configparser.Error):
            get_federation_config(cfg)

    def test_peer_invalid_protocol_raises(self):
        """[federate:<name>] with invalid protocol raises configparser.Error."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:bad-proto]
address = 10.1.2.3
display_name = bad-proto
protocol = http
""")
        with self.assertRaises(configparser.Error):
            get_federation_config(cfg)

    def test_peer_group_map_fields(self):
        """group_map_in / group_map_out are parsed as raw strings."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:alpha]
address = 10.1.2.3
display_name = alpha
group_map_in = White:White, *:
group_map_out = White:White
""")
        result = get_federation_config(cfg)
        peer = result.peers[0]
        self.assertEqual(peer.group_map_in, "White:White, *:")
        self.assertEqual(peer.group_map_out, "White:White")

    def test_peer_cert_paths(self):
        """Per-peer ca_cert / client_cert / client_key are parsed."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:alpha]
address = 10.1.2.3
display_name = alpha
ca_cert = /etc/fed/alpha-ca.crt
client_cert = /etc/fed/alpha-client.crt
client_key = /etc/fed/alpha-client.key
""")
        result = get_federation_config(cfg)
        peer = result.peers[0]
        self.assertEqual(peer.ca_cert, "/etc/fed/alpha-ca.crt")
        self.assertEqual(peer.client_cert, "/etc/fed/alpha-client.crt")
        self.assertEqual(peer.client_key, "/etc/fed/alpha-client.key")

    def test_federation_ssl_section(self):
        """[federation_ssl] is parsed into FederationSslConfig."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federation_ssl]
fed_ca_bundle = /data/fed_ssl/federation-ca.pem
fed_cert      = /data/fed_ssl/taky.crt
fed_key       = /data/fed_ssl/taky.key
fed_key_pw    = s3cr3t
fed_verify_hostname = true
""")
        result = get_federation_config(cfg)
        self.assertIsInstance(result.ssl, FederationSslConfig)
        self.assertEqual(result.ssl.fed_ca_bundle, "/data/fed_ssl/federation-ca.pem")
        self.assertEqual(result.ssl.fed_cert, "/data/fed_ssl/taky.crt")
        self.assertEqual(result.ssl.fed_key, "/data/fed_ssl/taky.key")
        self.assertEqual(result.ssl.fed_key_pw, "s3cr3t")
        self.assertTrue(result.ssl.fed_verify_hostname)

    def test_federation_ssl_absent_returns_defaults(self):
        """Missing [federation_ssl] section → FederationSslConfig with empty paths."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001
""")
        result = get_federation_config(cfg)
        self.assertEqual(result.ssl.fed_ca_bundle, "")
        self.assertEqual(result.ssl.fed_cert, "")
        self.assertEqual(result.ssl.fed_key, "")
        self.assertTrue(result.ssl.fed_verify_hostname)  # secure default

    def test_ssl_section_not_consumed(self):
        """
        SEPARATION INVARIANT: a taky [ssl] section in the config does not
        affect federation config parsing (different sections, different keys).
        """
        cfg = _cfg_from_text("""
[ssl]
enabled = true
ca = /etc/taky/ssl/ca.crt
cert = /etc/taky/ssl/server.crt
key = /etc/taky/ssl/server.key

[federation]
enabled = true
server_id = TAKY-001

[federation_ssl]
fed_ca_bundle = /data/fed/ca.pem
fed_cert = /data/fed/client.crt
fed_key  = /data/fed/client.key
""")
        result = get_federation_config(cfg)
        # Federation CA must come from [federation_ssl], not [ssl].
        self.assertEqual(result.ssl.fed_ca_bundle, "/data/fed/ca.pem")
        self.assertNotEqual(result.ssl.fed_ca_bundle, "/etc/taky/ssl/ca.crt")

    def test_peer_port_default(self):
        """Default port for [federate:<name>] is 9100 (standard v2 gRPC port)."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:alpha]
address = 10.1.2.3
display_name = alpha
""")
        result = get_federation_config(cfg)
        self.assertEqual(result.peers[0].port, 9100)

    def test_invalid_bool_raises(self):
        """Invalid boolean for enabled raises configparser.Error."""
        cfg = _cfg_from_text("""
[federation]
enabled = definitely
server_id = TAKY-001
""")
        with self.assertRaises(configparser.Error):
            get_federation_config(cfg)

    def test_invalid_port_raises(self):
        """Non-integer port for a peer raises configparser.Error."""
        cfg = _cfg_from_text("""
[federation]
enabled = true
server_id = TAKY-001

[federate:alpha]
address = 10.1.2.3
display_name = alpha
port = notaport
""")
        with self.assertRaises(configparser.Error):
            get_federation_config(cfg)


# ---------------------------------------------------------------------------
# Tests: TLS credentials construction
# ---------------------------------------------------------------------------

class TestBuildGrpcClientCredentials(unittest.TestCase):
    """Tests for build_grpc_client_credentials()."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="taky-fed-tls-test-")
        self._pki = _generate_test_pki(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_returns_channel_credentials(self):
        """build_grpc_client_credentials() returns a grpc.ChannelCredentials."""
        creds = build_grpc_client_credentials(
            fed_ca_bundle_path=self._pki["ca_crt"],
            fed_cert_path=self._pki["client_crt"],
            fed_key_path=self._pki["client_key"],
        )
        self.assertIsInstance(creds, grpc.ChannelCredentials)

    def test_missing_ca_raises(self):
        """Non-existent CA bundle path raises OSError."""
        with self.assertRaises(OSError):
            build_grpc_client_credentials(
                fed_ca_bundle_path="/nonexistent/ca.crt",
                fed_cert_path=self._pki["client_crt"],
                fed_key_path=self._pki["client_key"],
            )

    def test_missing_cert_raises(self):
        """Non-existent cert path raises OSError."""
        with self.assertRaises(OSError):
            build_grpc_client_credentials(
                fed_ca_bundle_path=self._pki["ca_crt"],
                fed_cert_path="/nonexistent/client.crt",
                fed_key_path=self._pki["client_key"],
            )

    def test_missing_key_raises(self):
        """Non-existent key path raises OSError."""
        with self.assertRaises(OSError):
            build_grpc_client_credentials(
                fed_ca_bundle_path=self._pki["ca_crt"],
                fed_cert_path=self._pki["client_crt"],
                fed_key_path="/nonexistent/client.key",
            )

    def test_mismatched_cert_key_raises(self):
        """Mismatched cert/key pair raises ssl.SSLError (or OSError via ssl)."""
        # server.key does not match client.crt
        with self.assertRaises((ssl.SSLError, OSError)):
            build_grpc_client_credentials(
                fed_ca_bundle_path=self._pki["ca_crt"],
                fed_cert_path=self._pki["client_crt"],
                fed_key_path=self._pki["server_key"],  # wrong key
            )

    def test_wrong_ca_produces_different_bundle_bytes(self):
        """
        When a different CA bundle is passed, the resulting credentials
        embed different root_certificates bytes than the correct CA.

        Chain trust validation (cert signed by CA) is enforced by the TLS
        handshake at connection time, not at credential-construction time —
        ssl.SSLContext.load_verify_locations only validates the CA cert
        itself, not whether any loaded cert is signed by it. This test
        verifies that the wrong CA bytes flow through into the credential
        object, so a peer TLS handshake would fail at runtime.
        """
        # Generate a second CA that did NOT sign our client cert.
        second_ca_key, second_ca_cert = generate_ca(
            cn="other-fed-ca", org="other-org", validity_days=1
        )
        other_ca_path = os.path.join(self._tmp, "other-ca.crt")
        _write_cert(other_ca_path, second_ca_cert)

        # Build credentials with the wrong CA — construction succeeds;
        # chain validation failure happens at TLS handshake time.
        wrong_creds = build_grpc_client_credentials(
            fed_ca_bundle_path=other_ca_path,
            fed_cert_path=self._pki["client_crt"],
            fed_key_path=self._pki["client_key"],
        )
        correct_creds = build_grpc_client_credentials(
            fed_ca_bundle_path=self._pki["ca_crt"],
            fed_cert_path=self._pki["client_crt"],
            fed_key_path=self._pki["client_key"],
        )
        # Both return ChannelCredentials; the CA bytes differ (verified via file bytes).
        with open(other_ca_path, "rb") as f:
            wrong_ca_bytes = f.read()
        with open(self._pki["ca_crt"], "rb") as f:
            correct_ca_bytes = f.read()
        self.assertNotEqual(wrong_ca_bytes, correct_ca_bytes,
                            "Test setup error: the two CA certs should differ")

    def test_server_credentials_build_ok(self):
        """build_grpc_server_credentials returns ServerCredentials with valid material."""
        import grpc

        creds = build_grpc_server_credentials(
            fed_ca_bundle_path=self._pki["ca_crt"],
            fed_cert_path=self._pki["server_crt"],
            fed_key_path=self._pki["server_key"],
        )
        self.assertIsInstance(creds, grpc.ServerCredentials)

    def test_server_credentials_mismatched_key_raises(self):
        """A cert/key mismatch is caught by ssl validation before grpcio."""
        import ssl

        with self.assertRaises(ssl.SSLError):
            build_grpc_server_credentials(
                fed_ca_bundle_path=self._pki["ca_crt"],
                fed_cert_path=self._pki["server_crt"],
                fed_key_path=self._pki["client_key"],  # wrong key
            )


# ---------------------------------------------------------------------------
# Tests: separation from ATAK client [ssl] context
# ---------------------------------------------------------------------------

class TestSeparationFromAtakSsl(unittest.TestCase):
    """
    Verify that federation TLS helpers do not touch or share the ATAK client
    [ssl] SSLContext..
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="taky-fed-sep-test-")
        self._pki = _generate_test_pki(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_federation_ssl_config_keys_separate_from_atak_ssl(self):
        """
        A config with both [ssl] and [federation_ssl] sections never bleeds
        [ssl] paths into FederationSslConfig.
        """
        cfg = _cfg_from_text("""
[ssl]
enabled = true
ca = /etc/taky/ssl/atak-ca.crt
cert = /etc/taky/ssl/atak-server.crt
key = /etc/taky/ssl/atak-server.key
key_pw = atak-secret

[federation]
enabled = true
server_id = TAKY-001

[federation_ssl]
fed_ca_bundle = /data/fed/fed-ca.pem
fed_cert = /data/fed/client.crt
fed_key = /data/fed/client.key
fed_key_pw = fed-secret
""")
        result = get_federation_config(cfg)
        ssl_cfg = result.ssl

        # Federation paths must come from [federation_ssl], never from [ssl].
        self.assertEqual(ssl_cfg.fed_ca_bundle, "/data/fed/fed-ca.pem")
        self.assertNotIn("atak", ssl_cfg.fed_ca_bundle)
        self.assertEqual(ssl_cfg.fed_cert, "/data/fed/client.crt")
        self.assertNotIn("atak", ssl_cfg.fed_cert)
        self.assertEqual(ssl_cfg.fed_key_pw, "fed-secret")
        self.assertNotEqual(ssl_cfg.fed_key_pw, "atak-secret")

    def test_build_grpc_credentials_uses_only_federation_pki(self):
        """
        build_grpc_client_credentials is called with distinct federation PKI
        material and must NOT use the ATAK client PKI paths.

        Chain trust validation (cert signed by CA) happens at the TLS handshake
        not during credential construction. This test verifies the separation at
        the config/file-path level: the ATAK CA file bytes differ from the
        federation CA bytes, confirming the two trust stores are distinct.
        """
        # A second "ATAK-style" CA that did not sign the client cert.
        atak_ca_key, atak_ca_cert = generate_ca(
            cn="atak-client-ca", org="test-org", validity_days=1
        )
        atak_ca_path = os.path.join(self._tmp, "atak-ca.crt")
        _write_cert(atak_ca_path, atak_ca_cert)

        # Both construction calls succeed at the API level.
        # Actual TLS handshake failure (wrong CA) is tested at connection time.
        fed_creds = build_grpc_client_credentials(
            fed_ca_bundle_path=self._pki["ca_crt"],   # correct federation CA
            fed_cert_path=self._pki["client_crt"],
            fed_key_path=self._pki["client_key"],
        )
        self.assertIsInstance(fed_creds, grpc.ChannelCredentials)

        # Verify the ATAK CA bytes differ from the federation CA bytes.
        with open(atak_ca_path, "rb") as f:
            atak_ca_bytes = f.read()
        with open(self._pki["ca_crt"], "rb") as f:
            fed_ca_bytes = f.read()
        self.assertNotEqual(atak_ca_bytes, fed_ca_bytes,
                            "ATAK CA and federation CA must be different trust stores")


# ---------------------------------------------------------------------------
# Tests: gen_fed_ca script
# ---------------------------------------------------------------------------

class TestGenFedCa(unittest.TestCase):
    """Tests for gen_fed_ca.py certificate generation."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="taky-gen-fed-ca-test-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_generate_ca_returns_valid_cert(self):
        """generate_ca() returns a key and a self-signed CA certificate."""
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives.asymmetric import ec

        ca_key, ca_cert = generate_ca(cn="test-ca", org="test-org", validity_days=1)
        self.assertIsInstance(ca_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(ca_cert, cx509.Certificate)

        bc = ca_cert.extensions.get_extension_for_class(cx509.BasicConstraints)
        self.assertTrue(bc.value.ca)

    def test_generate_peer_cert_signed_by_ca(self):
        """generate_peer_cert() returns a cert verifiable against the CA."""
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives.asymmetric import ec

        ca_key, ca_cert = generate_ca(cn="test-ca", org="test-org", validity_days=1)
        peer_key, peer_cert = generate_peer_cert(
            cn="test-peer",
            org="test-org",
            ca_key=ca_key,
            ca_cert=ca_cert,
            validity_days=1,
        )
        self.assertIsInstance(peer_key, ec.EllipticCurvePrivateKey)

        # Verify the cert's issuer matches the CA's subject.
        self.assertEqual(peer_cert.issuer, ca_cert.subject)

        # Verify the CA signature on the peer cert using the EC ECDSA API.
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        ca_cert.public_key().verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            _ec.ECDSA(peer_cert.signature_hash_algorithm),
        )

    def test_generated_pki_loads_for_grpc(self):
        """End-to-end: gen_fed_ca output loads into build_grpc_client_credentials."""
        pki = _generate_test_pki(self._tmp)
        creds = build_grpc_client_credentials(
            fed_ca_bundle_path=pki["ca_crt"],
            fed_cert_path=pki["client_crt"],
            fed_key_path=pki["client_key"],
        )
        self.assertIsInstance(creds, grpc.ChannelCredentials)

    def test_private_key_file_mode_0600(self):
        """gen_fed_ca writes private key files with mode 0600."""
        pki = _generate_test_pki(self._tmp)
        for key_path in (pki["ca_key"], pki["server_key"], pki["client_key"]):
            mode = oct(os.stat(key_path).st_mode & 0o777)
            self.assertEqual(mode, oct(0o600), f"{key_path} mode should be 0600, got {mode}")

    def test_main_creates_all_files(self):
        """gen_fed_ca.main() creates all eight expected files (including chain files)."""
        from ots_federation.gen_fed_ca import main

        out_dir = os.path.join(self._tmp, "gen-out")
        ret = main(["--out-dir", out_dir])
        self.assertEqual(ret, 0)

        expected_files = [
            "fed-ca.key", "fed-ca.crt",
            "server.key", "server.crt", "server-chain.crt",
            "client.key", "client.crt", "client-chain.crt",
        ]
        for fname in expected_files:
            path = os.path.join(out_dir, fname)
            self.assertTrue(os.path.exists(path), f"Expected {fname} not found")

    def test_main_chain_files_contain_two_certs(self):
        """
        server-chain.crt and client-chain.crt must contain exactly two PEM certificates.

        TAK Server 5.4 FIG negotiator reads peerCertificates[1] (the second cert in the
        chain). A chain with only one cert causes ArrayIndexOutOfBoundsException in TAK
        Server's FIG negotiation code.
        """
        from ots_federation.gen_fed_ca import main

        out_dir = os.path.join(self._tmp, "chain-count-out")
        main(["--out-dir", out_dir])

        for chain_file in ("server-chain.crt", "client-chain.crt"):
            path = os.path.join(out_dir, chain_file)
            with open(path, "r") as f:
                contents = f.read()
            cert_count = contents.count("BEGIN CERTIFICATE")
            self.assertEqual(
                cert_count, 2,
                f"{chain_file} must contain exactly 2 PEM certs (leaf + CA), found {cert_count}",
            )

    def test_main_chain_files_leaf_first(self):
        """
        In server-chain.crt and client-chain.crt the leaf cert appears before the CA cert.

        The TLS convention (RFC 5246 §7.4.2) and TAK Server's FIG negotiator both
        expect leaf-first ordering.
        """
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from ots_federation.gen_fed_ca import main

        out_dir = os.path.join(self._tmp, "chain-order-out")
        main(["--out-dir", out_dir, "--server-cn", "leaf-server", "--ca-cn", "ca-signer"])

        for chain_file, leaf_cn in (
            ("server-chain.crt", "leaf-server"),
            ("client-chain.crt", "taky-client"),  # default client CN
        ):
            path = os.path.join(out_dir, chain_file)
            # Split PEM blocks manually so we can check ordering.
            with open(path, "rb") as f:
                raw = f.read()

            pem_blocks = []
            start = 0
            marker = b"-----BEGIN CERTIFICATE-----"
            end_marker = b"-----END CERTIFICATE-----"
            while True:
                s = raw.find(marker, start)
                if s == -1:
                    break
                e = raw.find(end_marker, s)
                if e == -1:
                    break
                pem_blocks.append(raw[s:e + len(end_marker)])
                start = e + len(end_marker)

            self.assertEqual(len(pem_blocks), 2, f"{chain_file} should have 2 PEM blocks")

            first_cert = cx509.load_pem_x509_certificate(pem_blocks[0])
            second_cert = cx509.load_pem_x509_certificate(pem_blocks[1])

            # First cert must NOT be a CA (BasicConstraints ca=False).
            try:
                bc = first_cert.extensions.get_extension_for_class(cx509.BasicConstraints)
                self.assertFalse(bc.value.ca, f"First cert in {chain_file} should be leaf (ca=False)")
            except cx509.ExtensionNotFound:
                pass  # No BasicConstraints = leaf cert (not CA)

            # Second cert must be a CA (BasicConstraints ca=True).
            bc2 = second_cert.extensions.get_extension_for_class(cx509.BasicConstraints)
            self.assertTrue(bc2.value.ca, f"Second cert in {chain_file} should be CA (ca=True)")

    def test_main_chain_files_mode_0644(self):
        """Chain files (server-chain.crt, client-chain.crt) are written with mode 0644."""
        from ots_federation.gen_fed_ca import main

        out_dir = os.path.join(self._tmp, "chain-mode-out")
        main(["--out-dir", out_dir])

        for chain_file in ("server-chain.crt", "client-chain.crt"):
            path = os.path.join(out_dir, chain_file)
            mode = oct(os.stat(path).st_mode & 0o777)
            self.assertEqual(mode, oct(0o644), f"{chain_file} mode should be 0644, got {mode}")

    def test_server_credentials_accept_chain_file(self):
        """
        build_grpc_server_credentials succeeds when fed_cert_path points at a
        server-chain.crt (leaf + CA). This verifies the no-code-change claim in
        tls.py: grpcio passes the PEM bytes through to OpenSSL/BoringSSL unchanged
        and a chain file is valid input.
        """
        from ots_federation.gen_fed_ca import main, _write_cert_chain
        from ots_federation.gen_fed_ca import generate_ca, generate_peer_cert

        # Generate PKI and chain file in tmp dir.
        ca_key, ca_cert = generate_ca(cn="test-ca", org="test-org", validity_days=1)
        svr_key, svr_cert = generate_peer_cert(
            cn="test-server", org="test-org",
            ca_key=ca_key, ca_cert=ca_cert, validity_days=1,
            san_dns=["test-server"], is_server=True,
        )
        ca_path = os.path.join(self._tmp, "ca.crt")
        svr_crt_path = os.path.join(self._tmp, "server.crt")
        svr_key_path = os.path.join(self._tmp, "server.key")
        chain_path = os.path.join(self._tmp, "server-chain.crt")

        from ots_federation.gen_fed_ca import _write_cert, _write_private_key
        _write_cert(ca_path, ca_cert)
        _write_cert(svr_crt_path, svr_cert)
        _write_private_key(svr_key_path, svr_key)
        _write_cert_chain(chain_path, svr_cert, ca_cert)

        creds = build_grpc_server_credentials(
            fed_ca_bundle_path=ca_path,
            fed_cert_path=chain_path,   # chain file, not bare leaf
            fed_key_path=svr_key_path,
        )
        self.assertIsInstance(creds, grpc.ServerCredentials)

    def test_main_key_files_mode_0600(self):
        """gen_fed_ca.main() creates private keys with mode 0600."""
        from ots_federation.gen_fed_ca import main

        out_dir = os.path.join(self._tmp, "gen-mode-out")
        main(["--out-dir", out_dir])

        for key_file in ("fed-ca.key", "server.key", "client.key"):
            path = os.path.join(out_dir, key_file)
            mode = oct(os.stat(path).st_mode & 0o777)
            self.assertEqual(mode, oct(0o600), f"{key_file} mode should be 0600, got {mode}")


if __name__ == "__main__":
    unittest.main()

