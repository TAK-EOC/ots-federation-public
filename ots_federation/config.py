# taky/cot/federation/config.py
# Stream: tls-config / stream:fedconfig
# Parses the new federation ini sections from taky.conf via configparser.
# taky.config.load_config already uses configparser.ConfigParser; federation
# sections are parsed AFTER the existing sections.
# New sections:
#   [federation]       — global switch, server identity, max_hops
#   [federate:<name>]  — one entry per peer (multiple allowed)
#   [federation_ssl]   — federation CA and identity cert paths
# get_federation_config(app_config) returns a FederationConfig instance.
# Returns FederationConfig(enabled=False, ...) if [federation] is absent or disabled.
# Key-name aliases:
#   accept_as  = friendlier alias for group_map_in  (inbound: "REMOTE:LOCAL, *:LOCAL")
#   share_as   = friendlier alias for group_map_out (outbound: "LOCAL:REMOTE")
# Applies to BOTH [federation] (global default) and [federate:<name>] (per-peer).
# Precedence rule: if both old and new key are present, the new alias (accept_as /
# share_as) wins; a warning is logged so the operator knows the old key was ignored.
# CoreConfig <federation> to INI key mapping:
# ====================================================================
# GLOBAL SECTION [federation]:
#   allow_federated_delete              → allowFederatedDelete (bool, default True)
#   allow_mission_federation            → allowMissionFederation (bool, default True)
#   allow_data_feed_federation          → allowDataFeedFederation (bool, default True)
#   enable_mission_fed_disruption_tolerance → enableMissionFederationDisruptionTolerance (bool)
#   mission_fed_disruption_tolerance_recency_secs → missionFederationDisruptionToleranceRecencySeconds (int, default 43200)
#   federate_only_public_missions       → federateOnlyPublicMissions (bool, default False)
#   enable_data_pkg_file_filter         → enableDataPackageAndMissionFileFilter (bool, default False)
#   allow_duplicate                     → allowDuplicate (bool, default False)
#   initialization_delay_secs           → initializationDelaySeconds (int, default 30)
#   max_message_size_bytes              → maxMessageSizeBytes (int, default 268435456)
# PER-PEER SECTION [federate:<name>]:
#   display_name                        → displayName (str, MUST - error if missing)
#   protocol_version                    → protocolVersion (int, default 2)
#   filter                              → filter (str, default None)
#   max_frame_size                      → maxFrameSize (int, default None)
#   max_retries                         → maxRetries (int, default -1)
#   unlimited_retries                   → unlimitedRetries (bool, default True)
#   fallback                            → fallback (str, default None)
#   use_token                           → useToken (bool, default False)
#   connection_token                    → connectionToken (str, default None - SECRET)
#   token_type                          → tokenType (str, default None)
#   notes                               → notes (str, default None)
#   share_alerts                        → shareAlerts (bool, default True)
#   archive                             → archive (bool, default True)
#   federated_group_mapping             → federatedGroupMapping (bool, default True)
#   automatic_group_mapping             → automaticGroupMapping (bool, default False)
#   use_group_hop_limiting              → useGroupHopLimiting (bool, default False)
#   fallback_when_no_group_mappings     → fallbackWhenNoGroupMappings (bool, default False)
#   token_federate                      → tokenFederate (bool, default False)
#   token_expiration                    → tokenExpiration (int, default None)
#   inbound_group_mapping               → inboundGroupMapping (str, default None)
#   mission_federate_default            → missionFederateDefault (bool, default True)

import configparser
import logging
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when a required config field is missing or invalid."""
    pass


@dataclass
class FederatePeerConfig:
    """
    Parsed configuration for a single [federate:<name>] section.

    Attributes
    ----------
    name : str
        Section name (the <name> part of [federate:<name>]).
    enabled : bool
    address : str
    port : int
        Default 9100 (v2 gRPC).(port table).
    protocol : str
        "grpc" (default) or "v1fig" (legacy). Only "grpc" implemented in Phase 1.
    ca_cert : str
        Path to per-peer CA cert PEM for verifying THIS peer's certificate.
        Distinct from [federation_ssl] fed_ca_bundle (which is the global default).
    client_cert : str
        Path to this server's client cert for mTLS to this peer.
    client_key : str
        Path to this server's client key for mTLS to this peer.
    max_hops : int
        Per-peer hop limit override. -1 = unlimited.
    group_map_in : str
        Raw config string "remote:local, *:" — parsed by groups.py.
        Friendly alias in taky.conf: ``accept_as``.  Controls WHAT WE LET IN
        (LHS = remote group or '*') and WHAT WE FLAG INBOUND DATA AS (RHS =
        local Teams group).  accept_as wins over group_map_in when both present.
    group_map_out : str
        Raw config string "local:remote" — parsed by groups.py.
        Friendly alias in taky.conf: ``share_as``.  Controls WHAT TO SHARE
        (LHS = local Teams group; unlisted groups are NOT shared) and WHAT GROUP
        WE SHARE AS (RHS = remote group name tag on outbound events).
        share_as wins over group_map_out when both present.
    reconnect_interval : int
        Seconds between reconnect attempts (base; exponential back-off caps at 5min).
    health_check_interval : int
        Seconds between HealthCheck RPCs..
    """

    name: str
    enabled: bool
    address: str
    port: int = 9100
    protocol: str = "grpc"
    ca_cert: str = ""
    client_cert: str = ""
    client_key: str = ""
    max_hops: int = -1
    group_map_in: str = "*:"
    group_map_out: str = "*:*"
    reconnect_interval: int = 30
    health_check_interval: int = 10
    # Default is 10s: lower than the original 60s so a monitoring peer doesn't
    # flag the link as stale (hub clientTimeoutTime=15s, clientRefreshTime=5s).
    # 10s is a conservative choice between the standard 3s and the old 60s;
    # it co-exists with the gRPC-level keepalive (keepalive_time_ms=30000 in
    # fed_server.py / client.py) which handles NAT-idle-link death separately
    #. Operators needing sub-10s cadence can lower via
    # health_check_interval in [federate:<name>]..
    server_id: str = ""
    # Optional: the expected federation server_id this peer will claim when it
    # connects inbound (subscription.identity.serverId).  When set, the group
    # registry is also keyed under this string so an inbound-only peer (one we
    # never dial outbound) is matched to this stanza's accept_as/share_as
    # policy instead of falling through to the global [federation] defaults.
    # Absent (empty string) = current behavior (keyed by address:port only,
    # rekeyed to real server_id only when our FederateClient dials outbound).
    # Shortcut-1 Option-1A.
    fingerprint: str = ""
    # SHA-256 fingerprint(s) (colon-hex, case-insensitive on input, normalized
    # to upper-case at parse time; comma-separated when the peer uses distinct
    # client and server certificates) of the certificate(s) THIS peer
    # authenticates with. This is the ONLY value group-ACL resolution keys
    # peer identity on — in BOTH directions, binding federation ACL
    # decisions to the authenticated cert identity rather than anything
    # self-asserted. It is never inferred and never defaults:
    #   - An INBOUND connection whose presented client certificate's
    #     fingerprint does not match a configured peer's `fingerprint` here
    #     is quarantined (empty policy, no fallthrough to [federation]
    #     defaults), even if the wire-supplied Subscription.identity.serverId
    #     matches this peer's declared server_id or name.
    #   - An OUTBOUND dial whose remote end presents a server certificate
    #     with a fingerprint not configured for any peer is REFUSED (no
    #     session, no policy), regardless of what getIdentity() reports.
    #     When this peer's TLS server certificate differs from its client
    #     certificate (gen_fed_ca issues separate leaf certs), list BOTH
    #     fingerprints, comma-separated.
    # `ots-fed-certs export` prints the exact value(s) to paste here (see
    # gen_fed_ca.py's export bundle templates).
    # Absent (empty string) = this peer can never be matched by fingerprint;
    # inbound connections are quarantined and outbound dials refused until
    # the operator sets this.
    # CoreConfig parity knobs
    display_name: str = ""  # displayName → MUST be present, error if missing
    protocol_version: int = 2  # protocolVersion
    filter: Optional[str] = None  # filter (XPath/CoT expression)
    max_frame_size: Optional[int] = None  # maxFrameSize
    max_retries: int = -1  # maxRetries (-1 = unlimited)
    unlimited_retries: bool = True  # unlimitedRetries
    fallback: Optional[str] = None  # fallback (secondary address)
    use_token: bool = False  # useToken
    connection_token: Optional[str] = None  # connectionToken (SECRET - no default)
    token_type: Optional[str] = None  # tokenType
    notes: Optional[str] = None  # notes
    share_alerts: bool = True  # shareAlerts
    archive: bool = True  # archive
    federated_group_mapping: bool = True  # federatedGroupMapping
    automatic_group_mapping: bool = False  # automaticGroupMapping
    use_group_hop_limiting: bool = False  # useGroupHopLimiting
    fallback_when_no_group_mappings: bool = False  # fallbackWhenNoGroupMappings
    token_federate: bool = False  # tokenFederate
    token_expiration: Optional[int] = None  # tokenExpiration
    inbound_group_mapping: Optional[str] = None  # inboundGroupMapping
    mission_federate_default: bool = True  # missionFederateDefault


@dataclass
class FederationSslConfig:
    """
    Parsed [federation_ssl] section.

    Attributes
    ----------
    fed_ca_bundle : str
        Path to the global federation CA bundle (PEM, may be multi-cert chain).
    fed_cert : str
        Path to this server's federation identity certificate.
    fed_key : str
        Path to this server's federation identity private key.
    fed_key_pw : str
        Key password (empty = unencrypted).
    fed_verify_hostname : bool
        Verify remote peer CN matches address. Default True.
    """

    fed_ca_bundle: str = ""
    fed_cert: str = ""
    fed_key: str = ""
    fed_key_pw: str = ""
    fed_verify_hostname: bool = True


@dataclass
class FederationConfig:
    """
    Top-level parsed federation configuration.

    Attributes
    ----------
    enabled : bool
        Global federation switch from [federation] enabled.
    server_id : str
        Stable server identity (used in FederateProvenance).
    server_name : str
        Human-readable server name (used in Identity.name).
    max_hops : int
        Global default hop limit. -1 = unlimited. Per-peer can override.
    listen_enabled : bool
        If True, run the inbound FederatedChannel gRPC server so a remote peer
        can connect to US (taky↔taky inbound side). Default False — zero
        regression when omitted.(direct server-to-server).
    listen_ip : str
        Bind address for the inbound server. Default "0.0.0.0".
    listen_port : int
        Bind port for the inbound server. Default 9101.
        (9100 is the outbound dial default; the inbound listener uses a distinct
        default so a single host can both dial and listen without a clash.)
    default_group_map_in : str
        Default inbound group policy applied to ANY peer (inbound OR outgoing)
        that has no explicit [federate:*] group_map_in configured.  Same syntax
        as the per-peer key: "Remote:Local, *:Local" comma-separated pairs.
        Empty string (default) = block all — the secure conservative default is
        preserved when this key is absent from [federation].  Set to "*:Cyan"
        to admit all groups from unmapped peers into the local Cyan group, or
        "*:White" for White, etc.  This is the primary knob for opening an
        inbound TAK Server peer that has no [federate:*] section.
        Friendly alias in taky.conf: ``accept_as``.
    default_group_map_out : str
        Default outbound group policy applied to any peer lacking an explicit
        [federate:*] group_map_out.  Same "Local:Remote" syntax.  Empty =
        block (do not forward events outbound to unmapped peers).
        Friendly alias in taky.conf: ``share_as``.
    peers : List[FederatePeerConfig]
        One entry per enabled [federate:<name>] section.
    ssl : FederationSslConfig
        Parsed [federation_ssl] section. fed_cert/fed_key double as the inbound
        server's identity certificate; fed_ca_bundle is the client-cert
        verification root for inbound mTLS.
    """

    enabled: bool = False
    server_id: str = ""
    server_name: str = ""
    max_hops: int = 3
    listen_enabled: bool = False
    listen_ip: str = "0.0.0.0"
    listen_port: int = 9101
    default_group_map_in: str = ""
    default_group_map_out: str = ""
    peers: List[FederatePeerConfig] = field(default_factory=list)
    ssl: FederationSslConfig = field(default_factory=FederationSslConfig)
    # CoreConfig parity knobs
    allow_federated_delete: bool = True  # allowFederatedDelete
    # NOTE: default True matches CoreConfig spec (allowFederatedDelete=true).
    # taky-fed hardening uses default=False as the secure
    # conservative default. Conflict documented in — the guard
    # logic is implemented; operators must explicitly set allow_federated_delete=False
    # in taky.conf to enable the security restriction.
    allow_mission_federation: bool = True  # allowMissionFederation
    allow_data_feed_federation: bool = True  # allowDataFeedFederation
    enable_mission_fed_disruption_tolerance: bool = False  # enableMissionFederationDisruptionTolerance
    mission_fed_disruption_tolerance_recency_secs: int = 43200  # missionFederationDisruptionToleranceRecencySeconds
    federate_only_public_missions: bool = False  # federateOnlyPublicMissions
    enable_data_pkg_file_filter: bool = False  # enableDataPackageAndMissionFileFilter
    allow_duplicate: bool = False  # allowDuplicate
    initialization_delay_secs: int = 30  # initializationDelaySeconds
    max_message_size_bytes: int = 268435456  # maxMessageSizeBytes
    # gRPC inbound server thread pool size. The sync gRPC server dedicates ONE
    # thread per active RPC, and each federate peer holds ~4 long-lived streaming
    # RPCs (ServerEventStream, ClientEventStream, both groups streams). Too small
    # a pool starves unary calls (HealthCheck) → UNAVAILABLE → the peer flaps.
    # Budget ~6 threads/peer + headroom; default 64 handles ~10 peers.
    grpc_max_workers: int = 64
    rol_log_sink: str = ""
    # Filesystem path to append raw ROL frame bytes to (one proto-serialized ROL
    # per append, preceded by a 4-byte big-endian length prefix). Empty string =
    # logging only (no file sink)..
    inject_cot_parser: bool = False
    # Option D inbound delivery (-D-forks-resolved):
    # When False (default): inbound federated events are published ONLY to the OTS
    # 'groups' topic exchange (routing-key <local_group>.OUT for each mapped local
    # group). SSL-grouped EUDs receive the event; __ANON__ EUDs do NOT (no over-share).
    # When True: ALSO publish to the cot_parser exchange for OTS DB persistence
    # accepting the __ANON__ side-delivery that cot_parser.route_cot causes when
    # user_id=None is injected.


def _get_str(cfg: configparser.ConfigParser, section: str, key: str, fallback: str = "") -> str:
    """Return a string value from a configparser section, with a fallback."""
    return cfg.get(section, key, fallback=fallback) or fallback


def _get_bool(cfg: configparser.ConfigParser, section: str, key: str, fallback: bool = False) -> bool:
    """Return a boolean value from a configparser section, with a fallback."""
    try:
        return cfg.getboolean(section, key, fallback=fallback)
    except ValueError as exc:
        raise configparser.Error(
            f"[{section}] {key}: expected boolean, got {cfg.get(section, key)!r}"
        ) from exc


def _get_int(cfg: configparser.ConfigParser, section: str, key: str, fallback: int = 0) -> int:
    """Return an integer value from a configparser section, with a fallback."""
    try:
        return cfg.getint(section, key, fallback=fallback)
    except ValueError as exc:
        raise configparser.Error(
            f"[{section}] {key}: expected integer, got {cfg.get(section, key)!r}"
        ) from exc


def _resolve_alias(
    cfg: configparser.ConfigParser,
    section: str,
    new_key: str,
    old_key: str,
    fallback: str = "",
) -> str:
    """
    Read a config key that has a preferred (new) name and a legacy (old) alias.

    Precedence: new_key wins over old_key.  When both are present, old_key is
    silently ignored and a warning is logged so operators know which key is
    authoritative.  When neither is present, ``fallback`` is returned.

     — accept_as / share_as friendlier aliases.

    Parameters
    ----------
    cfg : configparser.ConfigParser
    section : str
        INI section name, e.g. ``"federation"`` or ``"federate:foo"``.
    new_key : str
        The preferred key name (e.g. ``"accept_as"``).
    old_key : str
        The legacy key name (e.g. ``"default_group_map_in"``).
    fallback : str
        Value to use when neither key is present.
    """
    has_new = cfg.has_option(section, new_key)
    has_old = cfg.has_option(section, old_key)

    if has_new and has_old:
        log.warning(
            "[%s] both '%s' and '%s' are set; '%s' takes precedence — "
            "remove '%s' to silence this warning",
            section, new_key, old_key, new_key, old_key,
        )
        return _get_str(cfg, section, new_key, fallback=fallback)

    if has_new:
        return _get_str(cfg, section, new_key, fallback=fallback)

    if has_old:
        return _get_str(cfg, section, old_key, fallback=fallback)

    return fallback


def _parse_federation_ssl(cfg: configparser.ConfigParser) -> FederationSslConfig:
    """
    Parse the [federation_ssl] section. Returns empty FederationSslConfig if absent.

    
    """
    if not cfg.has_section("federation_ssl"):
        return FederationSslConfig()

    sec = "federation_ssl"
    return FederationSslConfig(
        fed_ca_bundle=_get_str(cfg, sec, "fed_ca_bundle"),
        fed_cert=_get_str(cfg, sec, "fed_cert"),
        fed_key=_get_str(cfg, sec, "fed_key"),
        fed_key_pw=_get_str(cfg, sec, "fed_key_pw", fallback=""),
        fed_verify_hostname=_get_bool(cfg, sec, "fed_verify_hostname", fallback=True),
    )


def _parse_peer_section(cfg: configparser.ConfigParser, section: str) -> FederatePeerConfig:
    """
    Parse a single [federate:<name>] section into a FederatePeerConfig.

    Required fields: address, display_name.
    All others have documented defaults per

    Raises
    ------
    ConfigError
        If a required field is missing (address, display_name).
    configparser.Error
        If a field value is invalid (e.g., bad integer or boolean format).
    """
    peer_name = section[len("federate:"):]

    address = _get_str(cfg, section, "address")
    if not address:
        raise configparser.Error(
            f"[{section}] missing required field 'address'"
        )

    protocol = _get_str(cfg, section, "protocol", fallback="grpc")
    if protocol not in ("grpc", "v1fig"):
        raise configparser.Error(
            f"[{section}] protocol must be 'grpc' or 'v1fig', got {protocol!r}"
        )

    # accept_as / share_as are the preferred operator-facing names.
    # group_map_in / group_map_out remain accepted as legacy aliases.
    # When both are present in the same section, the new key wins and a warning
    # is logged.  The resolved string is identical in format — only the name differs.
    group_map_in = _resolve_alias(
        cfg, section, "accept_as", "group_map_in", fallback="*:"
    )
    group_map_out = _resolve_alias(
        cfg, section, "share_as", "group_map_out", fallback="*:*"
    )

    # displayName is MUST per spec — error if missing
    display_name = _get_str(cfg, section, "display_name")
    if not display_name:
        raise ConfigError(
            f"[{section}] missing required field 'display_name' (CoreConfig displayName)"
        )

    # connectionToken: return None if absent (SECRET, never a default string)
    connection_token = cfg.get(section, "connection_token", fallback=None)

    # fingerprint: the ONLY value peer identity binding resolves against, in
    # both directions (never the wire-supplied serverId). Accepts a
    # comma-separated list because a peer's client and server TLS certificates
    # may be distinct leaves (gen_fed_ca issues both): inbound resolves the
    # peer's CLIENT cert, outbound the peer's SERVER cert. Normalize
    # case/whitespace here so every downstream comparison is against the
    # canonical upper-case colon-hex form; a malformed value fails config
    # load immediately rather than silently never matching at runtime.
    raw_fingerprint = _get_str(cfg, section, "fingerprint")
    if raw_fingerprint:
        from ots_federation.cert_identity import (  # pylint: disable=import-outside-toplevel
            FingerprintFormatError,
            normalize_fingerprint_colon_hex,
        )
        normalized_parts = []
        for part in raw_fingerprint.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                normalized_parts.append(normalize_fingerprint_colon_hex(part))
            except FingerprintFormatError as exc:
                raise configparser.Error(f"[{section}] {exc}") from exc
        fingerprint = ",".join(normalized_parts)
    else:
        fingerprint = ""

    return FederatePeerConfig(
        name=peer_name,
        enabled=_get_bool(cfg, section, "enabled", fallback=True),
        address=address,
        port=_get_int(cfg, section, "port", fallback=9100),
        protocol=protocol,
        ca_cert=_get_str(cfg, section, "ca_cert"),
        client_cert=_get_str(cfg, section, "client_cert"),
        client_key=_get_str(cfg, section, "client_key"),
        max_hops=_get_int(cfg, section, "max_hops", fallback=-1),
        group_map_in=group_map_in,
        group_map_out=group_map_out,
        reconnect_interval=_get_int(cfg, section, "reconnect_interval", fallback=30),
        health_check_interval=_get_int(cfg, section, "health_check_interval", fallback=10),
        server_id=_get_str(cfg, section, "server_id"),
        fingerprint=fingerprint,
        # CoreConfig parity knobs
        display_name=display_name,
        protocol_version=_get_int(cfg, section, "protocol_version", fallback=2),
        filter=_get_str(cfg, section, "filter") or None,
        max_frame_size=_get_int(cfg, section, "max_frame_size", fallback=0) or None,
        max_retries=_get_int(cfg, section, "max_retries", fallback=-1),
        unlimited_retries=_get_bool(cfg, section, "unlimited_retries", fallback=True),
        fallback=_get_str(cfg, section, "fallback") or None,
        use_token=_get_bool(cfg, section, "use_token", fallback=False),
        connection_token=connection_token,
        token_type=_get_str(cfg, section, "token_type") or None,
        notes=_get_str(cfg, section, "notes") or None,
        share_alerts=_get_bool(cfg, section, "share_alerts", fallback=True),
        archive=_get_bool(cfg, section, "archive", fallback=True),
        federated_group_mapping=_get_bool(cfg, section, "federated_group_mapping", fallback=True),
        automatic_group_mapping=_get_bool(cfg, section, "automatic_group_mapping", fallback=False),
        use_group_hop_limiting=_get_bool(cfg, section, "use_group_hop_limiting", fallback=False),
        fallback_when_no_group_mappings=_get_bool(cfg, section, "fallback_when_no_group_mappings", fallback=False),
        token_federate=_get_bool(cfg, section, "token_federate", fallback=False),
        token_expiration=_get_int(cfg, section, "token_expiration", fallback=0) or None,
        inbound_group_mapping=_get_str(cfg, section, "inbound_group_mapping") or None,
        mission_federate_default=_get_bool(cfg, section, "mission_federate_default", fallback=True),
    )


def get_federation_config(app_cfg: configparser.ConfigParser) -> FederationConfig:
    """
    Parse federation configuration from a taky configparser instance.

    Called from COTServer (or FederationManager.__init__) after taky.config
    has loaded taky.conf.

    Peer sections are identified by the prefix "federate:" in the section name.
    Missing or disabled [federation] section returns FederationConfig(enabled=False).

    Parameters
    ----------
    app_cfg : configparser.ConfigParser
        The already-loaded taky application config. Same object as taky.config.app_config.

    Returns
    -------
    FederationConfig
        Fully populated config object; peers list may be empty if none are configured.

    Raises
    ------
    configparser.Error
        If a required key is missing from an enabled peer section, or a field
        value is invalid.
    """
    # [federation] section absent → federation disabled; short-circuit.
    if not app_cfg.has_section("federation"):
        return FederationConfig(enabled=False)

    fed_enabled = _get_bool(app_cfg, "federation", "enabled", fallback=True)
    if not fed_enabled:
        return FederationConfig(enabled=False)

    server_id = _get_str(app_cfg, "federation", "server_id")
    if not server_id:
        raise configparser.Error(
            "[federation] missing required field 'server_id'"
        )

    server_name = _get_str(app_cfg, "federation", "server_name", fallback=server_id)
    max_hops = _get_int(app_cfg, "federation", "max_hops", fallback=3)
    grpc_max_workers = _get_int(app_cfg, "federation", "grpc_max_workers", fallback=64)

    # Inbound listener (taky↔taky server side). Disabled by default so existing
    # outbound-only deployments are byte-identical.
    listen_enabled = _get_bool(app_cfg, "federation", "listen_enabled", fallback=False)
    listen_ip = _get_str(app_cfg, "federation", "listen_ip", fallback="0.0.0.0")
    listen_port = _get_int(app_cfg, "federation", "listen_port", fallback=9101)

    # Default group policy applied to any peer that has no explicit [federate:*]
    # group map configured — covers both inbound (TAK Server dials IN) and
    # outgoing peers whose config omits the per-peer group_map_* keys.
    # Empty string = block (conservative default unchanged)..
    # accept_as / share_as are the preferred operator-facing key names.
    # default_group_map_in / default_group_map_out remain accepted as legacy aliases.
    # When both are present, the new alias wins and a warning is logged.
    default_group_map_in = _resolve_alias(
        app_cfg, "federation", "accept_as", "default_group_map_in", fallback=""
    )
    default_group_map_out = _resolve_alias(
        app_cfg, "federation", "share_as", "default_group_map_out", fallback=""
    )

    # Collect all [federate:<name>] sections.
    peers: List[FederatePeerConfig] = []
    for section in app_cfg.sections():
        if not section.startswith("federate:"):
            continue
        peer = _parse_peer_section(app_cfg, section)
        # Only include enabled peers.
        if peer.enabled:
            peers.append(peer)

    ssl_cfg = _parse_federation_ssl(app_cfg)

    # CoreConfig parity knobs (global section)
    allow_federated_delete = _get_bool(app_cfg, "federation", "allow_federated_delete", fallback=True)
    allow_mission_federation = _get_bool(app_cfg, "federation", "allow_mission_federation", fallback=True)
    allow_data_feed_federation = _get_bool(app_cfg, "federation", "allow_data_feed_federation", fallback=True)
    enable_mission_fed_disruption_tolerance = _get_bool(app_cfg, "federation", "enable_mission_fed_disruption_tolerance", fallback=False)
    mission_fed_disruption_tolerance_recency_secs = _get_int(app_cfg, "federation", "mission_fed_disruption_tolerance_recency_secs", fallback=43200)
    federate_only_public_missions = _get_bool(app_cfg, "federation", "federate_only_public_missions", fallback=False)
    enable_data_pkg_file_filter = _get_bool(app_cfg, "federation", "enable_data_pkg_file_filter", fallback=False)
    allow_duplicate = _get_bool(app_cfg, "federation", "allow_duplicate", fallback=False)
    initialization_delay_secs = _get_int(app_cfg, "federation", "initialization_delay_secs", fallback=30)
    max_message_size_bytes = _get_int(app_cfg, "federation", "max_message_size_bytes", fallback=268435456)
    rol_log_sink = _get_str(app_cfg, "federation", "rol_log_sink", fallback="")
    inject_cot_parser = _get_bool(app_cfg, "federation", "inject_cot_parser", fallback=False)

    return FederationConfig(
        enabled=True,
        server_id=server_id,
        server_name=server_name,
        max_hops=max_hops,
        listen_enabled=listen_enabled,
        listen_ip=listen_ip,
        listen_port=listen_port,
        default_group_map_in=default_group_map_in,
        default_group_map_out=default_group_map_out,
        peers=peers,
        ssl=ssl_cfg,
        # CoreConfig parity knobs (global section)
        allow_federated_delete=allow_federated_delete,
        allow_mission_federation=allow_mission_federation,
        allow_data_feed_federation=allow_data_feed_federation,
        enable_mission_fed_disruption_tolerance=enable_mission_fed_disruption_tolerance,
        mission_fed_disruption_tolerance_recency_secs=mission_fed_disruption_tolerance_recency_secs,
        federate_only_public_missions=federate_only_public_missions,
        enable_data_pkg_file_filter=enable_data_pkg_file_filter,
        allow_duplicate=allow_duplicate,
        initialization_delay_secs=initialization_delay_secs,
        max_message_size_bytes=max_message_size_bytes,
        rol_log_sink=rol_log_sink,
        inject_cot_parser=inject_cot_parser,
        grpc_max_workers=grpc_max_workers,
    )
