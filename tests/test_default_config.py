# Tests for the OTS plugin-framework config contract (default_config.py).

import pytest

from ots_federation.default_config import DefaultConfig


class TestDefaultConfigValidate:
    def test_empty_config_is_valid(self):
        assert DefaultConfig.validate({}) == {"success": True, "error": ""}

    def test_defaults_are_valid(self):
        result = DefaultConfig.validate(
            {
                "OTS_FEDERATION_ENABLED": DefaultConfig.OTS_FEDERATION_ENABLED,
                "OTS_FEDERATION_CONFIG": DefaultConfig.OTS_FEDERATION_CONFIG,
            }
        )
        assert result["success"] is True

    def test_unknown_key_rejected(self):
        result = DefaultConfig.validate({"OTS_FEDERATION_BOGUS": 1})
        assert result["success"] is False
        assert "not a valid config key" in result["error"]

    def test_enabled_must_be_bool(self):
        result = DefaultConfig.validate({"OTS_FEDERATION_ENABLED": "yes"})
        assert result["success"] is False

    def test_config_must_be_str(self):
        result = DefaultConfig.validate({"OTS_FEDERATION_CONFIG": 42})
        assert result["success"] is False

    def test_config_missing_file_rejected(self, tmp_path):
        result = DefaultConfig.validate(
            {"OTS_FEDERATION_CONFIG": str(tmp_path / "nope.ini")}
        )
        assert result["success"] is False
        assert "no federation config" in result["error"]

    def test_config_invalid_ini_rejected(self, tmp_path):
        bad = tmp_path / "federation.ini"
        bad.write_text("[federation\nbroken")
        result = DefaultConfig.validate({"OTS_FEDERATION_CONFIG": str(bad)})
        assert result["success"] is False

    def test_config_without_federation_section_rejected(self, tmp_path):
        ini = tmp_path / "federation.ini"
        ini.write_text("[other]\nkey = value\n")
        result = DefaultConfig.validate({"OTS_FEDERATION_CONFIG": str(ini)})
        assert result["success"] is False
        assert "[federation] section" in result["error"]

    def test_valid_ini_accepted(self, tmp_path):
        ini = tmp_path / "federation.ini"
        ini.write_text("[federation]\nenabled = true\nserver_id = TEST\n")
        result = DefaultConfig.validate({"OTS_FEDERATION_CONFIG": str(ini)})
        assert result == {"success": True, "error": ""}


class TestLoadDefaultConfig:
    def test_setdefault_preserves_operator_overrides(self):
        # plugin.py imports flask at module level; it only runs inside the
        # OTS venv, so skip where flask is absent (engine-only test envs).
        pytest.importorskip("flask")
        from ots_federation.plugin import FederationPlugin

        class FakeApp:
            config = {"OTS_FEDERATION_CONFIG": "/etc/custom/federation.ini"}

        plugin = FederationPlugin()
        plugin._load_default_config(FakeApp())

        assert FakeApp.config["OTS_FEDERATION_CONFIG"] == "/etc/custom/federation.ini"
        assert FakeApp.config["OTS_FEDERATION_ENABLED"] is True
        assert plugin._config["OTS_FEDERATION_CONFIG"] == "/etc/custom/federation.ini"
