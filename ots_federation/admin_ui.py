# ots_federation/admin_ui.py
# Plain server-rendered HTML admin page for the federation plugin —
# same convention as the CI-TRAP Reports plugin's admin page: one
# self-contained page, inline CSS, a little inline vanilla JS for
# confirm() dialogs only. No npm build step, no CDN dependency, no JS
# bundle/asset-serving path to go wrong. Replaces the earlier Mantine/
# React iframe UI (ots-federation-ui repo), which is no longer used.
#
# Uses plain <form> POSTs (not fetch/JSON) with the redirect-after-post
# pattern (flash message, then 303 back to /ui) so the page works with
# JS entirely disabled, and a page refresh never resubmits a form.
#
# File uploads (TLS cert/key material) are saved under
# <federation.ini's directory>/federation_certs/ — global material directly
# there, per-peer material under federation_certs/peers/<name>/ — and the
# corresponding federation.ini path field is updated to point at the saved
# file. Uploaded private keys are written with mode 0600.

from __future__ import annotations

import os
from typing import Any, Optional

from flask import (
    Response,
    flash,
    get_flashed_messages,
    redirect,
    render_template_string,
    request,
    send_file,
    url_for,
)
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from ots_federation import ini_writer
from ots_federation.ini_writer import GLOBAL_FIELDS, PEER_FIELDS, SSL_FIELDS

_KEY_FILE_MODE = 0o600


# --- form <-> ini_writer data-dict glue -------------------------------

def form_to_data(
    form,
    field_defs: list[tuple[str, str, Any, bool]],
    *,
    include_all_bools: bool = True,
) -> dict[str, Any]:
    """
    Convert a submitted <form> into the dict shape ini_writer.upsert_peer /
    update_global expect, honoring the same "key not in dict => leave
    unchanged" contract ini_writer._apply_fields relies on.

    - bool fields: HTML only submits a checkbox when checked, so absence
      normally means False. Since this page's forms always render every
      field (a full-page edit, not a partial patch), a bool field is always
      included as True/False — never omitted — unless include_all_bools is
      explicitly turned off (not currently used, kept for future partial
      forms).
    - int fields: blank => omit (leave unchanged / use default on create).
    - str fields: always included verbatim (including "", which
      ini_writer treats as "clear this key").
    - secret fields: NEVER read from the plain `key` input directly (that
      input is always left blank in the rendered page — the real secret is
      never round-tripped into the page). Handled by the caller via
      `{key}__value` / `{key}__clear`, see peer/global route handlers.
    """
    data: dict[str, Any] = {}
    for key, kind, _default, secret in field_defs:
        if secret:
            continue  # caller handles secret fields separately
        if kind == "bool":
            if include_all_bools:
                data[key] = key in form
        elif kind == "int":
            raw = (form.get(key) or "").strip()
            if raw != "":
                try:
                    data[key] = int(raw)
                except ValueError:
                    pass  # leave unchanged rather than 500 on a stray non-numeric value
        else:
            data[key] = form.get(key, "")
    return data


def apply_secret_field(form, key: str, data: dict[str, Any]) -> None:
    """
    Secret fields (connection_token, fed_key_pw) get two form inputs:
    `{key}` (always rendered blank) and `{key}__clear` (a checkbox).
    - `{key}__clear` checked -> data[key] = "" (clears it)
    - `{key}` non-blank      -> data[key] = <value> (sets it)
    - neither                -> key omitted entirely (leaves it unchanged)
    """
    if form.get(f"{key}__clear"):
        data[key] = ""
    else:
        value = form.get(key, "")
        if value:
            data[key] = value


# --- file upload handling ---------------------------------------------

def _certs_dir(fed_cfg_path: str, peer_name: Optional[str] = None) -> str:
    base = os.path.join(os.path.dirname(os.path.abspath(fed_cfg_path)), "federation_certs")
    if peer_name:
        base = os.path.join(base, "peers", peer_name)
    os.makedirs(base, exist_ok=True)
    return base


def save_uploaded_cert(
    fed_cfg_path: str,
    file: Optional[FileStorage],
    dest_filename: str,
    *,
    peer_name: Optional[str] = None,
    is_key: bool = False,
) -> Optional[str]:
    """
    Save an uploaded cert/key file under federation_certs/[peers/<name>/],
    named `dest_filename` (so re-uploading the same slot overwrites cleanly
    rather than accumulating stale files under the client's original
    filename). Returns the absolute path written, or None if no file was
    submitted.
    """
    if file is None or not file.filename:
        return None
    directory = _certs_dir(fed_cfg_path, peer_name)
    safe_name = secure_filename(dest_filename)
    path = os.path.join(directory, safe_name)
    file.save(path)
    if is_key:
        os.chmod(path, _KEY_FILE_MODE)
    return path


# --- page rendering ------------------------------------------------------

_PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ots-federation admin</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 1000px; margin: 2rem auto; padding: 0 1rem; line-height: 1.4; }
  h1 { margin-bottom: 0.25rem; }
  h2 { margin-top: 2.5rem; border-bottom: 1px solid #8884; padding-bottom: 0.25rem; }
  .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 1rem; font-size: 0.85rem; font-weight: 600; color: #fff; }
  .badge.running { background: #2e9e44; }
  .badge.stopped { background: #777; }
  .badge.exited { background: #c0392b; }
  .flash { padding: 0.75rem 1rem; border-radius: 6px; margin: 1rem 0; white-space: pre-wrap; font-family: inherit; }
  .flash.success { background: #d9f5df; border: 1px solid #2e9e44; }
  .flash.error { background: #fadada; border: 1px solid #c0392b; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid #8884; vertical-align: top; }
  fieldset { border: 1px solid #8884; border-radius: 6px; margin-bottom: 1rem; }
  legend { font-weight: 600; padding: 0 0.4rem; }
  label { display: block; margin: 0.5rem 0 0.15rem; font-size: 0.9rem; }
  input[type=text], input[type=number], input[type=password], select { width: 100%; max-width: 480px; padding: 0.35rem 0.5rem; box-sizing: border-box; }
  input[type=checkbox] { margin-right: 0.4rem; }
  .help { font-size: 0.8rem; opacity: 0.7; margin: 0.1rem 0 0.4rem; }
  .row { display: flex; gap: 2rem; flex-wrap: wrap; }
  .row > div { flex: 1; min-width: 260px; }
  button, .button { background: #2563eb; color: #fff; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.95rem; }
  button.secondary { background: #6b7280; }
  button.danger { background: #c0392b; }
  button:hover { opacity: 0.9; }
  details { margin: 0.5rem 0; }
  summary { cursor: pointer; font-weight: 600; }
  pre { background: #0002; padding: 0.75rem; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; }
  .inline-form { display: inline; }
</style>
</head>
<body>

<h1>Federation admin</h1>
<p style="opacity:0.7">{{ name }} v{{ version }}</p>

{% for category, message in flashes %}
  <div class="flash {{ category }}">{{ message }}</div>
{% endfor %}

<h2>Engine</h2>
<p>
  Status:
  <span class="badge {{ 'running' if status.status == 'running' else ('stopped' if status.status == 'stopped' else 'exited') }}">{{ status.status }}</span>
  {% if status.pid %} &middot; pid {{ status.pid }}{% endif %}
  {% if status.uptime_secs is not none %} &middot; up {{ status.uptime_secs }}s{% endif %}
  {% if status.restart_count %} &middot; {{ status.restart_count }} auto-restart(s){% endif %}
</p>
<form method="post" action="{{ url_for('federation_plugin.ui_restart') }}" class="inline-form" onsubmit="return confirm('Restart the federation engine now? Active peer connections will drop and reconnect.');">
  <button type="submit">Restart engine</button>
</form>

{% if not exists %}
<h2>Generate federation.ini + certs</h2>
<p>No federation.ini found at <code>{{ fed_cfg_path }}</code> yet. Fill this in once to generate a federation CA,
server/client identity certs, and a minimal federation.ini (equivalent to running <code>ots-federation-quickstart</code> by hand).</p>
<form method="post" action="{{ url_for('federation_plugin.ui_quickstart') }}">
  <div class="row">
    <div>
      <label>Server ID</label>
      <input type="text" name="server_id" placeholder="(default: hostname)">
      <label>Server address (for cert SAN + peer bundle)</label>
      <input type="text" name="server_address" placeholder="(default: local FQDN)">
      <label>Listen port</label>
      <input type="number" name="listen_port" value="9101">
    </div>
    <div>
      <label>Default accept_as</label>
      <input type="text" name="accept_as" value="*:__ANON__">
      <label>Default share_as</label>
      <input type="text" name="share_as" value="__ANON__:__ANON__">
      <label><input type="checkbox" name="force"> Overwrite existing output (--force)</label>
    </div>
  </div>
  <p class="help">Certs and federation.ini are written to {{ fed_cfg_path }} and its sibling federation_certs/ directory.</p>
  <button type="submit">Generate certs + federation.ini</button>
</form>
{% endif %}

{% if exists %}
<h2>Peers</h2>
<table>
<thead><tr><th>Name</th><th>Address</th><th>Accept as / Share as</th><th>Enabled</th><th></th></tr></thead>
<tbody>
{% for p in peers %}
  <tr>
    <td><strong>{{ p.display_name or p.name }}</strong><br><span class="help">{{ p.name }}</span></td>
    <td>{{ p.address }}:{{ p.port }} <span class="help">({{ p.protocol }})</span></td>
    <td class="help">in: {{ p.accept_as }}<br>out: {{ p.share_as }}</td>
    <td>
      <form method="post" action="{{ url_for('federation_plugin.ui_peer_toggle', name=p.name) }}" class="inline-form">
        <input type="hidden" name="enabled" value="{{ '0' if p.enabled else '1' }}">
        <button type="submit" class="secondary">{{ 'Disable' if p.enabled else 'Enable' }}</button>
      </form>
    </td>
    <td>
      <form method="post" action="{{ url_for('federation_plugin.ui_peer_delete', name=p.name) }}" class="inline-form" onsubmit="return confirm('Delete peer {{ p.name }}? This removes its [federate:{{ p.name }}] section.');">
        <button type="submit" class="danger">Delete</button>
      </form>
    </td>
  </tr>
  <tr>
    <td colspan="5" style="border-bottom: 2px solid #8888; padding-top:0;">
      <details>
        <summary>Edit {{ p.name }}</summary>
        {{ peer_form(p, is_new=False) }}
      </details>
    </td>
  </tr>
{% endfor %}
</tbody>
</table>

<details>
<summary><strong>Add peer</strong></summary>
{{ peer_form(None, is_new=True) }}
</details>

<h2>Global federation settings</h2>
<form method="post" action="{{ url_for('federation_plugin.ui_global') }}" enctype="multipart/form-data">
  <fieldset>
    <legend>Identity &amp; listener</legend>
    <div class="row">
      <div>
        <label><input type="checkbox" name="enabled" {{ 'checked' if global_settings.enabled }}> Federation enabled</label>
        <label>Server ID</label>
        <input type="text" name="server_id" value="{{ global_settings.server_id }}">
        <label>Server name</label>
        <input type="text" name="server_name" value="{{ global_settings.server_name }}">
        <label>Global max hops</label>
        <input type="number" name="max_hops" value="{{ global_settings.max_hops }}">
      </div>
      <div>
        <label><input type="checkbox" name="listen_enabled" {{ 'checked' if global_settings.listen_enabled }}> Listen for inbound peers</label>
        <label>Listen IP</label>
        <input type="text" name="listen_ip" value="{{ global_settings.listen_ip }}">
        <label>Listen port</label>
        <input type="number" name="listen_port" value="{{ global_settings.listen_port }}">
      </div>
    </div>
  </fieldset>

  <fieldset>
    <legend>Default group policy</legend>
    <div class="row">
      <div>
        <label>Default accept_as</label>
        <input type="text" name="accept_as" value="{{ global_settings.accept_as }}">
        <p class="help">Applied to any peer with no accept_as of its own. Empty = block all.</p>
      </div>
      <div>
        <label>Default share_as</label>
        <input type="text" name="share_as" value="{{ global_settings.share_as }}">
        <p class="help">Applied to any peer with no share_as of its own. Empty = block all.</p>
      </div>
    </div>
  </fieldset>

  <fieldset>
    <legend>CoreConfig parity</legend>
    <div class="row">
      <div>
        <label><input type="checkbox" name="allow_federated_delete" {{ 'checked' if global_settings.allow_federated_delete }}> Allow federated delete</label>
        <label><input type="checkbox" name="allow_mission_federation" {{ 'checked' if global_settings.allow_mission_federation }}> Allow mission federation</label>
        <label><input type="checkbox" name="allow_data_feed_federation" {{ 'checked' if global_settings.allow_data_feed_federation }}> Allow data feed federation</label>
        <label><input type="checkbox" name="enable_mission_fed_disruption_tolerance" {{ 'checked' if global_settings.enable_mission_fed_disruption_tolerance }}> Mission disruption tolerance</label>
        <label>Disruption tolerance recency (s)</label>
        <input type="number" name="mission_fed_disruption_tolerance_recency_secs" value="{{ global_settings.mission_fed_disruption_tolerance_recency_secs }}">
        <label><input type="checkbox" name="federate_only_public_missions" {{ 'checked' if global_settings.federate_only_public_missions }}> Federate only public missions</label>
      </div>
      <div>
        <label><input type="checkbox" name="enable_data_pkg_file_filter" {{ 'checked' if global_settings.enable_data_pkg_file_filter }}> Enable data package/mission file filter</label>
        <label><input type="checkbox" name="allow_duplicate" {{ 'checked' if global_settings.allow_duplicate }}> Allow duplicate</label>
        <label>Initialization delay (s)</label>
        <input type="number" name="initialization_delay_secs" value="{{ global_settings.initialization_delay_secs }}">
        <label>Max message size (bytes)</label>
        <input type="number" name="max_message_size_bytes" value="{{ global_settings.max_message_size_bytes }}">
        <label>gRPC max workers</label>
        <input type="number" name="grpc_max_workers" value="{{ global_settings.grpc_max_workers }}">
        <label>ROL log sink path</label>
        <input type="text" name="rol_log_sink" value="{{ global_settings.rol_log_sink }}">
        <label><input type="checkbox" name="inject_cot_parser" {{ 'checked' if global_settings.inject_cot_parser }}> Inject into cot_parser exchange</label>
      </div>
    </div>
  </fieldset>

  <fieldset>
    <legend>TLS material</legend>
    <div class="row">
      <div>
        <label>Federation CA bundle path</label>
        <input type="text" name="fed_ca_bundle" value="{{ ssl.fed_ca_bundle }}">
        <label>...or upload a new CA bundle file</label>
        <input type="file" name="fed_ca_bundle__file">

        <label>Server identity cert path</label>
        <input type="text" name="fed_cert" value="{{ ssl.fed_cert }}">
        <label>...or upload a new cert file</label>
        <input type="file" name="fed_cert__file">

        <label>Server identity key path</label>
        <input type="text" name="fed_key" value="{{ ssl.fed_key }}">
        <label>...or upload a new key file</label>
        <input type="file" name="fed_key__file">
      </div>
      <div>
        <label>Key password</label>
        <input type="password" name="fed_key_pw" placeholder="(leave blank to keep unchanged)">
        <label><input type="checkbox" name="fed_key_pw__clear"> Clear key password</label>
        <label><input type="checkbox" name="fed_verify_hostname" {{ 'checked' if ssl.fed_verify_hostname }}> Verify peer hostname</label>
      </div>
    </div>
  </fieldset>

  <button type="submit">Save global settings</button>
</form>

<h2>Peer-exchange bundle</h2>
<p class="help">Re-emits the mutual-CA exchange bundle from the current cert material (no private keys) as a downloadable zip — hand it to the remote admin per the README's peering steps.</p>
<form method="post" action="{{ url_for('federation_plugin.ui_export_bundle') }}">
  <button type="submit">Generate + download peer-exchange bundle</button>
</form>
{% if export_output %}
<pre>{{ export_output }}</pre>
{% endif %}

{% endif %}

</body>
</html>
"""

# The peer add/edit form is rendered via a Python macro-like helper (not
# Jinja2 macros, to keep this a single flat template string) — built as an
# HTML fragment and injected via the `peer_form` callable passed into the
# template context (Jinja2 supports callables in context).


def _render_peer_form_html(peer: Optional[dict], is_new: bool, endpoint_new: str, endpoint_edit_tmpl: str) -> str:
    def v(key, default=""):
        return (peer or {}).get(key, default)

    action = endpoint_new if is_new else endpoint_edit_tmpl.replace("__NAME__", v("name"))
    name_field = (
        '<label>Section name (cannot be changed after creation)</label>'
        '<input type="text" name="name" required>'
        if is_new
        else f'<input type="hidden" name="name" value="{v("name")}">'
    )

    def text(key, label, help_text=""):
        return (
            f'<label>{label}</label><input type="text" name="{key}" value="{v(key)}">'
            + (f'<p class="help">{help_text}</p>' if help_text else "")
        )

    def number(key, label, default=0):
        return f'<label>{label}</label><input type="number" name="{key}" value="{v(key, default)}">'

    def checkbox(key, label, default=False):
        checked = "checked" if (v(key, default) and v(key, default) not in (False, "false", "0")) else ""
        return f'<label><input type="checkbox" name="{key}" {checked}> {label}</label>'

    def select(key, label, options, default=""):
        opts = "".join(
            f'<option value="{o}" {"selected" if v(key, default) == o else ""}>{o}</option>' for o in options
        )
        return f'<label>{label}</label><select name="{key}">{opts}</select>'

    def secret(key, label):
        return (
            f'<label>{label}</label><input type="password" name="{key}" placeholder="(leave blank to keep unchanged)">'
            f'<label><input type="checkbox" name="{key}__clear"> Clear this value</label>'
        )

    def cert_field(key, label, is_key=False):
        return (
            text(key, label)
            + f'<label>...or upload a new file</label><input type="file" name="{key}__file">'
        )

    html = f"""
<form method="post" action="{action}" enctype="multipart/form-data">
  {name_field}
  <fieldset><legend>Basic</legend>
    <div class="row"><div>
      {text('display_name', 'Display name', 'CoreConfig displayName — required.')}
      {text('address', 'Address', 'Hostname or IP to dial. Required.')}
      {number('port', 'Port', 9100)}
      {select('protocol', 'Protocol', ['grpc', 'v1fig'], 'grpc')}
      {checkbox('enabled', 'Enabled', True)}
      {text('notes', 'Notes')}
    </div></div>
  </fieldset>
  <fieldset><legend>Identity &amp; TLS</legend>
    <div class="row"><div>
      {text('fingerprint', 'Certificate fingerprint(s)', 'SHA-256 fingerprint(s) this peer authenticates with. ots-fed-certs export prints this.')}
      {text('server_id', 'Expected server_id')}
      {cert_field('ca_cert', 'Peer CA cert path')}
      {cert_field('client_cert', 'Our client cert path')}
      {cert_field('client_key', 'Our client key path', is_key=True)}
    </div></div>
  </fieldset>
  <fieldset><legend>Group mapping</legend>
    <div class="row"><div>
      {text('accept_as', 'Accept as (inbound)', '"Remote:Local, *:Local"')}
      {text('share_as', 'Share as (outbound)', '"Local:Remote"')}
      {text('inbound_group_mapping', 'Inbound group mapping (advanced)')}
      {checkbox('federated_group_mapping', 'Federated group mapping', True)}
      {checkbox('automatic_group_mapping', 'Automatic group mapping')}
      {checkbox('use_group_hop_limiting', 'Use group hop limiting')}
      {checkbox('fallback_when_no_group_mappings', 'Fallback when no group mappings')}
      {number('max_hops', 'Max hops', -1)}
    </div></div>
  </fieldset>
  <fieldset><legend>Retry &amp; health</legend>
    <div class="row"><div>
      {number('reconnect_interval', 'Reconnect interval (s)', 30)}
      {number('health_check_interval', 'Health check interval (s)', 10)}
      {number('max_retries', 'Max retries', -1)}
      {checkbox('unlimited_retries', 'Unlimited retries', True)}
      {text('fallback', 'Fallback address')}
      {number('protocol_version', 'Protocol version', 2)}
      {text('filter', 'Filter (XPath/CoT expression)')}
      {number('max_frame_size', 'Max frame size (bytes)', 0)}
    </div></div>
  </fieldset>
  <fieldset><legend>Sharing &amp; archival</legend>
    <div class="row"><div>
      {checkbox('share_alerts', 'Share alerts', True)}
      {checkbox('archive', 'Archive', True)}
      {checkbox('mission_federate_default', 'Mission federate (default)', True)}
    </div></div>
  </fieldset>
  <fieldset><legend>Legacy token auth</legend>
    <div class="row"><div>
      {checkbox('use_token', 'Use token')}
      {secret('connection_token', 'Connection token')}
      {text('token_type', 'Token type')}
      {checkbox('token_federate', 'Token federate')}
      {number('token_expiration', 'Token expiration', 0)}
    </div></div>
  </fieldset>
  <button type="submit">{'Add peer' if is_new else 'Save peer'}</button>
</form>
"""
    return html


def render_admin_page(*, name, version, status, data, fed_cfg_path, quickstart_output=None, export_output=None):
    """Render the full admin page. `data` is ini_writer.read_all()'s output."""
    from markupsafe import Markup

    def peer_form(peer, is_new):
        return Markup(
            _render_peer_form_html(
                peer,
                is_new,
                endpoint_new=url_for("federation_plugin.ui_peer_create"),
                endpoint_edit_tmpl=url_for("federation_plugin.ui_peer_edit", name="__NAME__"),
            )
        )

    flashes = get_flashed_messages(with_categories=True)

    return render_template_string(
        _PAGE_TEMPLATE,
        name=name,
        version=version,
        status=status,
        exists=data.get("exists", False),
        peers=data.get("peers", []),
        global_settings=data.get("global", {}),
        ssl=data.get("ssl", {}),
        fed_cfg_path=fed_cfg_path,
        flashes=flashes,
        peer_form=peer_form,
        quickstart_output=quickstart_output,
        export_output=export_output,
    )
