# tests/test_quickstart.py
# Tests for ots_federation/quickstart.py — the ots-federation-quickstart
# console script.
# Follows the tmp_path-based cert/config test pattern used in
# tests/test_federation_tls_config.py and tests/test_gen_fed_ca_cli.py.
#
# This dev venv does not have `opentakserver` installed (it is an OTS-venv-only
# runtime dependency, not a dev/test dependency of this repo), so
# _check_ots_environment() genuinely returns False here — that fact is used
# directly by TestOtsEnvironmentCheck instead of being mocked. All other test
# classes patch _check_ots_environment to True to exercise the rest of the
# workflow, matching what a real OTS venv (with opentakserver importable)
# would see.

import os
import shutil
import tempfile
import unittest
from unittest import mock

from ots_federation import quickstart


class TestOtsEnvironmentCheck(unittest.TestCase):
    """`ots-federation-quickstart` prints the pip line when the plugin's
    hard dependency (opentakserver) isn't importable in this interpreter."""

    def test_check_ots_environment_false_when_opentakserver_absent(self):
        # Genuinely true in this dev venv (opentakserver is an OTS-venv-only
        # runtime dep) — no mocking needed for this assertion.
        self.assertFalse(quickstart._check_ots_environment())

    def test_main_exits_nonzero_and_prints_pip_line_when_env_check_fails(self):
        import contextlib
        import io

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            ret = quickstart.main(["--cert-dir", "/nonexistent/should-not-be-touched"])
        self.assertEqual(ret, 1)
        output = stderr.getvalue()
        self.assertIn("opentakserver", output)
        self.assertIn("pip install", output)
        self.assertFalse(os.path.exists("/nonexistent/should-not-be-touched"))

    def test_check_ots_environment_true_when_module_present(self):
        with mock.patch.dict("sys.modules", {"opentakserver": mock.MagicMock()}):
            self.assertTrue(quickstart._check_ots_environment())


class TestQuickstartWorkflow(unittest.TestCase):
    """End-to-end quickstart behavior with the OTS env check patched True
    (simulating a real OTS venv where opentakserver is importable)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ots-quickstart-test-")
        self.cert_dir = os.path.join(self._tmp, "fed_ssl")
        self.ini_path = os.path.join(self._tmp, "config", "federation.ini")
        self._env_patcher = mock.patch.object(quickstart, "_check_ots_environment", return_value=True)
        self._env_patcher.start()

    def tearDown(self):
        self._env_patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, extra_args=None, force=False):
        args = [
            "--cert-dir", self.cert_dir,
            "--ini-path", self.ini_path,
            "--server-id", "quickstart-test",
            "--server-address", "203.0.113.11",
        ]
        if force:
            args.append("--force")
        if extra_args:
            args.extend(extra_args)
        return quickstart.main(args)

    def test_first_run_creates_certs_ini_and_export_bundle(self):
        ret = self._run()
        self.assertEqual(ret, 0)
        for fname in ("fed-ca.crt", "fed-ca.key", "server.crt", "server-chain.crt", "server.key"):
            self.assertTrue(os.path.exists(os.path.join(self.cert_dir, fname)), fname)
        self.assertTrue(os.path.exists(self.ini_path))
        export_dir = os.path.join(self.cert_dir, "export-bundle")
        self.assertTrue(os.path.exists(os.path.join(export_dir, "fed-ca.crt")))
        self.assertTrue(os.path.exists(os.path.join(export_dir, "README.md")))

    def test_second_run_without_force_exits_nonzero_and_writes_nothing(self):
        ret1 = self._run()
        self.assertEqual(ret1, 0)

        # Snapshot state after first run.
        before = {}
        for root, _dirs, files in os.walk(self._tmp):
            for fname in files:
                path = os.path.join(root, fname)
                before[path] = os.path.getmtime(path)

        ret2 = self._run()
        self.assertEqual(ret2, 1)

        after = {}
        for root, _dirs, files in os.walk(self._tmp):
            for fname in files:
                path = os.path.join(root, fname)
                after[path] = os.path.getmtime(path)

        self.assertEqual(before, after, "second run without --force modified files on disk")

    def test_second_run_with_force_overwrites(self):
        ret1 = self._run()
        self.assertEqual(ret1, 0)
        ret2 = self._run(force=True)
        self.assertEqual(ret2, 0)

    def test_federation_ini_matches_minimal_required_fields(self):
        self._run()
        with open(self.ini_path) as f:
            ini_text = f.read()
        self.assertIn("[federation]", ini_text)
        self.assertIn("enabled = true", ini_text)
        self.assertIn("server_id = quickstart-test", ini_text)
        self.assertIn("listen_port = 9101", ini_text)
        self.assertIn("[federation_ssl]", ini_text)
        self.assertIn(f"fed_ca_bundle = {os.path.abspath(self.cert_dir)}/fed-ca.crt", ini_text)
        self.assertIn(f"fed_cert = {os.path.abspath(self.cert_dir)}/server-chain.crt", ini_text)
        self.assertIn(f"fed_key = {os.path.abspath(self.cert_dir)}/server.key", ini_text)

    def test_federation_ini_wildcard_defaults_and_security_note(self):
        self._run()
        with open(self.ini_path) as f:
            ini_text = f.read()
        self.assertIn("accept_as = *:__ANON__", ini_text)
        self.assertIn("share_as = __ANON__:__ANON__", ini_text)
        self.assertIn("SECURITY NOTE", ini_text)

    def test_federation_ini_is_parseable_by_get_federation_config(self):
        """The written file must actually parse via the library's own config loader."""
        import configparser

        from ots_federation.config import get_federation_config

        self._run()
        cfg = configparser.ConfigParser(allow_no_value=True)
        cfg.read(self.ini_path)
        result = get_federation_config(cfg)
        self.assertTrue(result.enabled)
        self.assertEqual(result.server_id, "quickstart-test")
        self.assertEqual(result.listen_port, 9101)
        self.assertEqual(result.ssl.fed_ca_bundle, os.path.join(os.path.abspath(self.cert_dir), "fed-ca.crt"))

    def test_custom_accept_as_share_as_overrides(self):
        ret = self._run(extra_args=["--accept-as", "*:Cyan", "--share-as", "Cyan:Cyan"])
        self.assertEqual(ret, 0)
        with open(self.ini_path) as f:
            ini_text = f.read()
        self.assertIn("accept_as = *:Cyan", ini_text)
        self.assertIn("share_as = Cyan:Cyan", ini_text)

    def test_prints_restart_instruction(self):
        import contextlib
        import io

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self._run()
        output = stdout.getvalue()
        self.assertIn("systemctl restart opentakserver", output)

    def test_default_paths_match_fleet_convention(self):
        self.assertEqual(quickstart.DEFAULT_CERT_DIR, "/opt/ots/fed_ssl")
        self.assertEqual(quickstart.DEFAULT_INI_PATH, "/opt/ots/config/federation.ini")
        self.assertEqual(quickstart.DEFAULT_LISTEN_PORT, 9101)

    def test_server_id_defaults_to_hostname_when_omitted(self):
        import socket

        ret = quickstart.main(["--cert-dir", self.cert_dir, "--ini-path", self.ini_path])
        self.assertEqual(ret, 0)
        with open(self.ini_path) as f:
            ini_text = f.read()
        self.assertIn(f"server_id = {socket.gethostname()}", ini_text)


class TestExistingOutputsDetection(unittest.TestCase):
    """_existing_outputs() is the pure function backing the clobber guard."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ots-quickstart-detect-")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_empty_dirs_report_no_hits(self):
        cert_dir = os.path.join(self._tmp, "certs")
        ini_path = os.path.join(self._tmp, "federation.ini")
        export_dir = os.path.join(self._tmp, "export")
        os.makedirs(cert_dir)
        hits = quickstart._existing_outputs(cert_dir, ini_path, export_dir)
        self.assertEqual(hits, [])

    def test_existing_cert_file_reported(self):
        cert_dir = os.path.join(self._tmp, "certs")
        os.makedirs(cert_dir)
        with open(os.path.join(cert_dir, "fed-ca.crt"), "w") as f:
            f.write("placeholder")
        ini_path = os.path.join(self._tmp, "federation.ini")
        export_dir = os.path.join(self._tmp, "export")
        hits = quickstart._existing_outputs(cert_dir, ini_path, export_dir)
        self.assertIn(os.path.join(cert_dir, "fed-ca.crt"), hits)

    def test_existing_ini_reported(self):
        cert_dir = os.path.join(self._tmp, "certs")
        os.makedirs(cert_dir)
        ini_path = os.path.join(self._tmp, "federation.ini")
        with open(ini_path, "w") as f:
            f.write("[federation]\n")
        export_dir = os.path.join(self._tmp, "export")
        hits = quickstart._existing_outputs(cert_dir, ini_path, export_dir)
        self.assertIn(ini_path, hits)

    def test_nonempty_export_dir_reported(self):
        cert_dir = os.path.join(self._tmp, "certs")
        os.makedirs(cert_dir)
        ini_path = os.path.join(self._tmp, "federation.ini")
        export_dir = os.path.join(self._tmp, "export")
        os.makedirs(export_dir)
        with open(os.path.join(export_dir, "README.md"), "w") as f:
            f.write("x")
        hits = quickstart._existing_outputs(cert_dir, ini_path, export_dir)
        self.assertIn(export_dir, hits)

    def test_empty_export_dir_not_reported(self):
        cert_dir = os.path.join(self._tmp, "certs")
        os.makedirs(cert_dir)
        ini_path = os.path.join(self._tmp, "federation.ini")
        export_dir = os.path.join(self._tmp, "export")
        os.makedirs(export_dir)
        hits = quickstart._existing_outputs(cert_dir, ini_path, export_dir)
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
