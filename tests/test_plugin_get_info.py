# tests/test_plugin_get_info.py
# OTS core's web UI builds every plugin nav link and enable/disable POST
# directly off `plugin.distro` from GET /api/plugins (confirmed against
# OpenTAKServer-UI's Navbar.tsx and ServerPluginManager.tsx, both of which do
# `plugin.distro` with no fallback). If get_info() omits "distro", the
# frontend receives `undefined`, builds a link to `/plugin?name=undefined`,
# and Enable/Disable becomes `app.plugin_manager.plugins["undefined"]` ->
# KeyError. Caught in the wild on a real OTS server (2026-07-26) — this test
# exists so it can't silently regress again.

import pytest

from ots_federation.plugin import DISTRO, FederationPlugin


def test_get_info_includes_distro_before_activation():
    """distro must be present even before activate()/load_metadata() run,
    since OTS's web UI can fetch /api/plugins immediately on page load."""
    plugin = FederationPlugin()
    info = plugin.get_info()
    assert info["distro"] == DISTRO
    assert info["name"]


def test_get_info_includes_distro_after_load_metadata():
    plugin = FederationPlugin()
    plugin.load_metadata()
    info = plugin.get_info()
    assert info["distro"] == DISTRO


def test_load_metadata_includes_project_url_as_a_list():
    """OTS core's own web UI (Plugin.tsx About tab) does
    `about?.project_url.forEach(...)` with NO null-check on project_url
    itself -- only on `about`. A metadata dict missing this key entirely
    (or where it's undefined) throws inside OTS core's own JS and blanks
    the whole plugin detail page, including the UI iframe tab. Caught in
    the wild on a real OTS server (2026-07-26) via a browser console
    export. This test locks in that project_url is always at least an
    empty list, never absent/undefined, from both the found-package and
    package-not-found code paths."""
    plugin = FederationPlugin()
    meta = plugin.load_metadata()
    assert isinstance(meta.get("project_url"), list)


def test_load_metadata_project_url_populated_from_installed_package():
    """Requires this package itself to be installed (pip install -e .) so
    importlib.metadata can find it -- confirms [project.urls] in
    pyproject.toml actually reaches the metadata dict, not just the
    not-found fallback."""
    plugin = FederationPlugin()
    meta = plugin.load_metadata()
    if meta["version"] == "dev":
        pytest.skip("package not installed in this environment (importlib.metadata can't find it)")
    assert len(meta["project_url"]) > 0
    assert any(url.startswith("Repository") for url in meta["project_url"])
