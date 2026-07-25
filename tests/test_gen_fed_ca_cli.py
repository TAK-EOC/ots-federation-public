# tests/test_gen_fed_ca_cli.py
# Tests for the generate|export|apply subcommand CLI shape added to
# ots_federation/gen_fed_ca.py.
# Sibling to tests/test_federation_tls_config.py's TestGenFedCa class, which
# covers generate's certificate-material behavior and is left unchanged.

import os
import re
import shutil
import tempfile
import unittest
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ots_federation.gen_fed_ca import (
    _leaf_fingerprint_sha256_colon_hex,
    cmd_apply,
    cmd_export,
    cmd_generate,
    main,
)


def _colon_hex_fingerprint(cert: x509.Certificate) -> str:
    """Independent reference implementation used to cross-check the CLI's fingerprint."""
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join("%02X" % b for b in digest)


class TestSubcommandDispatch(unittest.TestCase):
    """main() dispatches to generate|export|apply and keeps back-compat."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ots-fed-cli-dispatch-")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_generate_subcommand_creates_files(self):
        out_dir = os.path.join(self._tmp, "gen")
        ret = main(["generate", "--out-dir", out_dir])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "fed-ca.crt")))

    def test_bare_invocation_back_compat_behaves_as_generate(self):
        """A bare `ots-fed-certs <old flags>` invocation (no subcommand token)
        must behave exactly like `generate <old flags>` — this is the explicit
        back-compat contract for existing scripts/muscle memory."""
        out_dir = os.path.join(self._tmp, "back-compat")
        ret = main(["--out-dir", out_dir, "--server-cn", "legacy-server"])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "fed-ca.crt")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "server-chain.crt")))

    def test_bare_invocation_emits_deprecation_notice_on_stderr(self):
        import contextlib
        import io

        out_dir = os.path.join(self._tmp, "deprecation")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            ret = main(["--out-dir", out_dir])
        self.assertEqual(ret, 0)
        self.assertIn("DEPRECATION", stderr.getvalue())
        self.assertIn("generate", stderr.getvalue())

    def test_zero_arg_invocation_back_compat(self):
        """Bare zero-arg invocation (old default: generate into cwd) still dispatches
        to generate rather than erroring — exercised via explicit --out-dir to avoid
        writing into the real cwd."""
        out_dir = os.path.join(self._tmp, "zero-arg")
        os.makedirs(out_dir, exist_ok=True)
        cwd = os.getcwd()
        try:
            os.chdir(out_dir)
            ret = main([])
        finally:
            os.chdir(cwd)
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "fed-ca.crt")))

    def test_export_subcommand_dispatches(self):
        cert_dir = os.path.join(self._tmp, "certs")
        cmd_generate(["--out-dir", cert_dir])
        export_dir = os.path.join(self._tmp, "bundle")
        ret = main(["export", "--cert-dir", cert_dir, "--out-dir", export_dir])
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(os.path.join(export_dir, "fed-ca.crt")))

    def test_apply_subcommand_dispatches(self):
        cert_dir = os.path.join(self._tmp, "certs")
        cmd_generate(["--out-dir", cert_dir])
        staging_dir = os.path.join(self._tmp, "staging")
        ret = main(["apply", "--cert-dir", cert_dir, "--host", "test-host", "--out-dir", staging_dir])
        self.assertEqual(ret, 0)
        self.assertTrue(
            os.path.exists(os.path.join(staging_dir, "test-host", "ots-federation.plaintext.yml"))
        )


class TestExportBundle(unittest.TestCase):
    """Tests for `ots-fed-certs export` — mutual-CA peer-exchange bundle."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ots-fed-cli-export-")
        self.cert_dir = os.path.join(self._tmp, "certs")
        cmd_generate(["--out-dir", self.cert_dir, "--server-cn", "export-test-server"])

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_export_without_generate_first_fails_cleanly(self):
        empty_dir = os.path.join(self._tmp, "empty")
        os.makedirs(empty_dir)
        ret = cmd_export(["--cert-dir", empty_dir])
        self.assertEqual(ret, 1)

    def test_export_produces_exact_file_set(self):
        out_dir = os.path.join(self._tmp, "bundle")
        ret = cmd_export(["--cert-dir", self.cert_dir, "--out-dir", out_dir])
        self.assertEqual(ret, 0)
        expected = {
            "fed-ca.crt",
            "ots-federation-federate-stanza.ini",
            "takserver-federate-stanza.xml",
            "README.md",
        }
        self.assertEqual(set(os.listdir(out_dir)), expected)

    def test_export_bundle_contains_no_private_key_material(self):
        """Hard requirement: no private keys anywhere in the export bundle."""
        out_dir = os.path.join(self._tmp, "bundle-no-keys")
        cmd_export(["--cert-dir", self.cert_dir, "--out-dir", out_dir])

        for fname in os.listdir(out_dir):
            # No file named like a key.
            self.assertFalse(fname.endswith(".key"), f"unexpected key file in bundle: {fname}")
            path = os.path.join(out_dir, fname)
            with open(path, "rb") as f:
                contents = f.read()
            self.assertNotIn(b"PRIVATE KEY", contents, f"private key material found in {fname}")

    def test_coreconfig_stanza_has_inbound_and_outbound_group(self):
        """A <federate> entry without inboundGroup/outboundGroup
        children exchanges nothing. The export template must always include both."""
        out_dir = os.path.join(self._tmp, "bundle-groups")
        cmd_export(["--cert-dir", self.cert_dir, "--out-dir", out_dir])
        xml_path = os.path.join(out_dir, "takserver-federate-stanza.xml")
        with open(xml_path) as f:
            xml_text = f.read()
        self.assertIn("<inboundGroup>", xml_text)
        self.assertIn("<outboundGroup>", xml_text)
        self.assertIn("<federate ", xml_text)

    def test_coreconfig_stanza_id_matches_leaf_fingerprint(self):
        """The <federate id="..."> value must be the SHA-256 colon-hex fingerprint
        of the actual leaf cert (server.crt) produced by the preceding generate."""
        out_dir = os.path.join(self._tmp, "bundle-fingerprint")
        cmd_export(["--cert-dir", self.cert_dir, "--out-dir", out_dir])

        with open(os.path.join(self.cert_dir, "server.crt"), "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read())
        expected_fingerprint = _colon_hex_fingerprint(leaf_cert)

        xml_path = os.path.join(out_dir, "takserver-federate-stanza.xml")
        with open(xml_path) as f:
            xml_text = f.read()
        match = re.search(r'id="([0-9A-F:]+)"', xml_text)
        self.assertIsNotNone(match, "no id=\"...\" attribute found in CoreConfig stanza")
        self.assertEqual(match.group(1), expected_fingerprint)

        readme_path = os.path.join(out_dir, "README.md")
        with open(readme_path) as f:
            readme_text = f.read()
        self.assertIn(expected_fingerprint, readme_text)

    def test_leaf_fingerprint_helper_matches_reference(self):
        with open(os.path.join(self.cert_dir, "server.crt"), "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read())
        self.assertEqual(
            _leaf_fingerprint_sha256_colon_hex(leaf_cert),
            _colon_hex_fingerprint(leaf_cert),
        )

    def test_ini_stanza_uses_server_id_and_address(self):
        out_dir = os.path.join(self._tmp, "bundle-ini")
        cmd_export(
            ["--cert-dir", self.cert_dir, "--out-dir", out_dir, "--our-address", "203.0.113.10", "--listen-port", "9101"]
        )
        ini_path = os.path.join(out_dir, "ots-federation-federate-stanza.ini")
        with open(ini_path) as f:
            ini_text = f.read()
        self.assertIn("[federate:export-test-server]", ini_text)
        self.assertIn("address = 203.0.113.10", ini_text)
        self.assertIn("port = 9101", ini_text)

    def test_server_id_defaults_from_cert_cn(self):
        out_dir = os.path.join(self._tmp, "bundle-default-id")
        cmd_export(["--cert-dir", self.cert_dir, "--out-dir", out_dir])
        ini_path = os.path.join(out_dir, "ots-federation-federate-stanza.ini")
        with open(ini_path) as f:
            self.assertIn("[federate:export-test-server]", f.read())

    def test_zip_flag_produces_archive_with_same_contents(self):
        out_dir = os.path.join(self._tmp, "bundle-zip")
        cmd_export(["--cert-dir", self.cert_dir, "--out-dir", out_dir, "--zip"])
        zip_path = out_dir + ".zip"
        self.assertTrue(os.path.exists(zip_path))
        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
        self.assertEqual(
            names,
            {"fed-ca.crt", "ots-federation-federate-stanza.ini", "takserver-federate-stanza.xml", "README.md"},
        )

    def test_ca_cert_in_bundle_matches_source(self):
        out_dir = os.path.join(self._tmp, "bundle-ca-match")
        cmd_export(["--cert-dir", self.cert_dir, "--out-dir", out_dir])
        with open(os.path.join(self.cert_dir, "fed-ca.crt"), "rb") as f:
            source_ca = f.read()
        with open(os.path.join(out_dir, "fed-ca.crt"), "rb") as f:
            bundle_ca = f.read()
        self.assertEqual(source_ca, bundle_ca)


class TestApplyLeg(unittest.TestCase):
    """Tests for `ots-fed-certs apply` — OUR fleet cert staging."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ots-fed-cli-apply-")
        self.cert_dir = os.path.join(self._tmp, "certs")
        cmd_generate(["--out-dir", self.cert_dir, "--server-cn", "apply-test-server"])

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_apply_without_generate_first_fails_cleanly(self):
        empty_dir = os.path.join(self._tmp, "empty")
        os.makedirs(empty_dir)
        staging_dir = os.path.join(self._tmp, "staging")
        ret = cmd_apply(["--cert-dir", empty_dir, "--host", "test-host", "--out-dir", staging_dir])
        self.assertEqual(ret, 1)
        self.assertFalse(os.path.exists(staging_dir))

    def test_apply_writes_only_under_out_dir(self):
        """Hard constraint: apply must write only under its own --out-dir."""
        staging_dir = os.path.join(self._tmp, "staging")
        before = set()
        for root, _dirs, files in os.walk(self._tmp):
            for fname in files:
                before.add(os.path.join(root, fname))

        ret = cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", staging_dir])
        self.assertEqual(ret, 0)

        after = set()
        for root, _dirs, files in os.walk(self._tmp):
            for fname in files:
                after.add(os.path.join(root, fname))

        new_files = after - before
        self.assertTrue(new_files, "apply did not write any new files")
        for path in new_files:
            self.assertTrue(
                path.startswith(os.path.abspath(staging_dir) + os.sep),
                f"apply wrote outside --out-dir: {path}",
            )

    def test_apply_refuses_out_dir_inside_ansible_tree(self):
        """Repo-claim lock: apply must never write into /opt/fleet/ansible."""
        ansible_target = "/opt/fleet/ansible/node_secrets/test-host-should-not-exist"
        ret = cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", ansible_target])
        self.assertEqual(ret, 1)
        self.assertFalse(
            os.path.exists(ansible_target),
            "apply must not create anything inside the ansible tree",
        )

    def test_apply_staging_file_has_expected_sops_var_names(self):
        """Var names must match project_roles/ots_server/tasks/ssl.yml on the
        ansible repo's main branch: ots_fed_ca_crt / ots_fed_server_cert /
        ots_fed_server_key. Renaming these silently breaks the real role."""
        staging_dir = os.path.join(self._tmp, "staging")
        cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", staging_dir])
        staging_path = os.path.join(staging_dir, "test-host", "ots-federation.plaintext.yml")
        with open(staging_path) as f:
            content = f.read()
        for key in ("ots_fed_ca_crt:", "ots_fed_server_cert:", "ots_fed_server_key:"):
            self.assertIn(key, content)

    def test_apply_staging_file_mode_0600(self):
        staging_dir = os.path.join(self._tmp, "staging")
        cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", staging_dir])
        staging_path = os.path.join(staging_dir, "test-host", "ots-federation.plaintext.yml")
        mode = oct(os.stat(staging_path).st_mode & 0o777)
        self.assertEqual(mode, oct(0o600))

    def test_apply_refuses_to_clobber_without_force(self):
        staging_dir = os.path.join(self._tmp, "staging")
        ret1 = cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", staging_dir])
        self.assertEqual(ret1, 0)
        ret2 = cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", staging_dir])
        self.assertEqual(ret2, 1)

    def test_apply_force_overwrites(self):
        staging_dir = os.path.join(self._tmp, "staging")
        cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", staging_dir])
        ret = cmd_apply(["--cert-dir", self.cert_dir, "--host", "test-host", "--out-dir", staging_dir, "--force"])
        self.assertEqual(ret, 0)

    def test_apply_falls_back_to_bare_leaf_when_chain_missing(self):
        cert_dir_no_chain = os.path.join(self._tmp, "certs-no-chain")
        cmd_generate(["--out-dir", cert_dir_no_chain, "--server-cn", "no-chain-server"])
        os.remove(os.path.join(cert_dir_no_chain, "server-chain.crt"))

        staging_dir = os.path.join(self._tmp, "staging-no-chain")
        ret = cmd_apply(["--cert-dir", cert_dir_no_chain, "--host", "test-host", "--out-dir", staging_dir])
        self.assertEqual(ret, 0)

        staging_path = os.path.join(staging_dir, "test-host", "ots-federation.plaintext.yml")
        with open(staging_path) as f:
            content = f.read()
        with open(os.path.join(cert_dir_no_chain, "server.crt")) as f:
            leaf_pem = f.read()
        self.assertIn(leaf_pem.strip().splitlines()[0], content)


if __name__ == "__main__":
    unittest.main()
