"""
Snort 3 Rule Option Catalogue & Component Specification.
Derived from snort3_complete_rule_documentation.txt (Snort 3 Rule Writing Guide).

Provides authoritative catalogues of:
- Supported Rule Actions (alert, block, drop, log, pass, react, rewrite)
- Protocols (tcp, udp, icmp, ip) and Application Services (http, ssl, dns, etc.)
- Direction Operators (->, <>)
- Variables ($HOME_NET, $EXTERNAL_NET, $HTTP_PORTS, etc.)
- Classtypes & Priorities
- Flow Arguments (to_server, to_client, established, stateless, etc.)
- Sticky Buffers (http_uri, http_header, http_client_body, file_data, etc.)
- Payload Detection Options & Modifiers (content, fast_pattern, nocase, offset, depth, within, distance, pcre, isdataat)
"""

from typing import Dict, List, Set, Any, Optional, Tuple
import re

# ── 1. Actions (docs.snort.org/rules/headers/actions) ───────────────────────────
VALID_ACTIONS: Set[str] = {
    "alert", "block", "drop", "log", "pass", "react", "reject", "rewrite"
}

# ── 1.1 Rule Types (docs.snort.org/rules/headers/new_header_types) ────────────
VALID_RULE_TYPES: Set[str] = {
    "traditional", "service", "file", "file_id"
}

# ── 2. Protocols & Services (docs.snort.org/rules/headers/protocols) ───────────
VALID_PROTOCOLS: Set[str] = {
    "tcp", "udp", "icmp", "ip"
}

VALID_SERVICE_HEADERS: Set[str] = {
    "http", "http2", "http3", "ssl", "tls", "dns", "ftp", "ftp-data",
    "smtp", "imap", "pop3", "ssh", "telnet", "dcerpc", "smb", "file",
    "modbus", "dnp3", "cip", "iec104", "sip", "snmp", "ntp"
}

VALID_DIRECTIONS: Set[str] = {
    "->", "<>"
}

# ── 3. Variables & Ports (docs.snort.org/rules/headers/ip_addresses) ───────────
VALID_IP_VARIABLES: Set[str] = {
    "$HOME_NET", "$EXTERNAL_NET", "$DNS_SERVERS", "$SMTP_SERVERS",
    "$HTTP_SERVERS", "$SQL_SERVERS", "$TELNET_SERVERS", "$SSH_SERVERS",
    "$FTP_SERVERS", "$SIP_SERVERS", "any"
}

VALID_PORT_VARIABLES: Set[str] = {
    "$HTTP_PORTS", "$SHELLCODE_PORTS", "$ORACLE_PORTS", "$SSH_PORTS",
    "$FTP_PORTS", "$SIP_PORTS", "$FILE_DATA_PORTS", "any"
}

# Explicitly invalid variables in standard Snort defaults that LLMs commonly hallucinate
FORBIDDEN_VARIABLES: Dict[str, str] = {
    "$HTTPS_PORTS": "Snort 3 does not define $HTTPS_PORTS in snort_defaults.lua. Use '443' or 'any'.",
    "$WEB_PORTS": "Snort 3 standard variable is $HTTP_PORTS.",
    "$C2_PORTS": "Custom undeclared variable. Use literal ports or 'any'.",
    "$INTERNAL_NET": "Standard Snort variable is $HOME_NET."
}

# ── 3.1 Rule Message Naming Conventions (docs.snort.org/rules/options/general/msg)
VALID_MSG_PREFIXES: Set[str] = {
    "MALWARE-CNC", "MALWARE-OTHER", "MALWARE-BACKDOOR",
    "SERVER-WEBAPP", "SERVER-OTHER", "SERVER-ORACLE", "SERVER-MYSQL", "SERVER-APACHE",
    "OS-WINDOWS", "OS-LINUX", "OS-SOLARIS", "OS-OTHER",
    "PROTOCOL-DNS", "PROTOCOL-ICMP", "PROTOCOL-VOIP", "PROTOCOL-SNMP", "PROTOCOL-TELNET", "PROTOCOL-FTP",
    "FILE-IDENTIFY", "FILE-OTHER", "FILE-EXECUTABLE", "FILE-PDF", "FILE-OFFICE", "FILE-IMAGE",
    "INDICATOR-COMPROMISE", "INDICATOR-OBFUSCATION", "INDICATOR-SHELLCODE",
    "EXPLOIT-KIT", "BROWSER-OTHER", "BROWSER-IE", "BROWSER-CHROME", "BROWSER-FIREFOX",
    "NETBIOS", "SQL", "POLICY-OTHER",
    # Common alternate prefixes observed in standard rulesets
    "MALWARE", "EXPLOIT", "TROJAN", "SCAN", "ET", "GPL"
}

FORBIDDEN_COMPROMISE_CLAIMS: Set[str] = {
    "system compromised", "host infected", "successful breach",
    "data stolen", "credentials stolen", "root access gained",
    "successful exploit", "host compromised"
}

# ── 4. Classtypes (docs.snort.org/rules/options/general/classtype) ─────────────
VALID_CLASSTYPES: Dict[str, int] = {
    "attempted-admin": 1,
    "attempted-user": 1,
    "shellcode-detect": 1,
    "successful-admin": 1,
    "successful-user": 1,
    "trojan-activity": 1,
    "malware-cnc": 1,
    "client-side-exploit": 1,
    "unsuccessful-user": 1,
    "web-application-attack": 1,
    "attempted-dos": 2,
    "attempted-recon": 2,
    "bad-unknown": 2,
    "default-login-attempt": 2,
    "denial-of-service": 2,
    "misc-attack": 2,
    "non-standard-protocol": 2,
    "rpc-portmap-decode": 2,
    "successful-dos": 2,
    "successful-recon-largescale": 2,
    "successful-recon-limited": 2,
    "suspicious-filename-detect": 2,
    "suspicious-login": 2,
    "system-call-detect": 2,
    "unusual-client-port-connection": 2,
    "web-application-activity": 2,
    "icmp-event": 3,
    "misc-activity": 3,
    "network-scan": 3,
    "not-suspicious": 3,
    "protocol-command-decode": 3,
    "string-detect": 3,
    "unknown": 3,
    "tcp-connection": 4
}

# ── 5. Flow Options (docs.snort.org/rules/options/non_payload/flow) ────────────
VALID_FLOW_DIRECTIONS: Set[str] = {
    "to_server", "to_client", "from_client", "from_server"
}

VALID_FLOW_STATES: Set[str] = {
    "established", "not_established", "stateless"
}

VALID_FLOW_STREAM_OPTIONS: Set[str] = {
    "only_stream", "no_stream"
}

VALID_FLOW_FRAG_OPTIONS: Set[str] = {
    "only_frag", "no_frag"
}

# ── 6. Sticky Buffers (docs.snort.org/rules/options/payload) ───────────────────
VALID_GENERAL_BUFFERS: Set[str] = {
    "pkt_data", "raw_data", "file_data", "js_data", "vba_data", "base64_data"
}

VALID_HTTP_BUFFERS: Set[str] = {
    "http_uri", "http_raw_uri", "http_header", "http_raw_header",
    "http_client_body", "http_raw_body", "http_param", "http_method",
    "http_version", "http_stat_code", "http_stat_msg", "http_cookie",
    "http_raw_cookie", "http_trailer", "http_raw_trailer", "http_true_ip",
    "http_raw_request", "http_raw_status"
}

VALID_STICKY_BUFFERS: Set[str] = VALID_GENERAL_BUFFERS | VALID_HTTP_BUFFERS | {
    # Service and protocol buffers (Note: dns_query is NOT supported in Snort 3 core; use wire format on UDP/53)
    "ssl_state", "tls_sni", "sip_header", "sip_body",
    "dce_stub_data", "modbus_data", "ber_data"
}

# ── 6.1 Protocol-Specific Options Catalogue ──────────────────────────────────
PROTOCOL_OPTIONS_CATALOGUE: Dict[str, Set[str]] = {
    "http": VALID_HTTP_BUFFERS | {
        "http_version", "http_method", "http_stat_code", "http_stat_msg",
        "bufferlen"
    },
    "ssl": {"ssl_state", "ssl_version", "tls_sni"},
    "tls": {"ssl_state", "ssl_version", "tls_sni"},
    "dns": set(),
    "sip": {"sip_method", "sip_stat_code", "sip_header", "sip_body"},
    "dcerpc": {"dce_iface", "dce_opnum", "dce_stub_data"},
    "modbus": {"modbus_func", "modbus_unit", "modbus_data"},
    "dnp3": {"dnp3_func", "dnp3_ind", "dnp3_obj", "dnp3_data"},
    "cip": {"cip_service", "cip_class", "cip_attribute", "cip_instance"},
    "iec104": {"iec104_asdu", "iec104_type"},
    "mms": {"mms_func", "mms_data"},
    "s7commplus": {"s7commplus_func", "s7commplus_data"}
}

# ── 7. Modifiers & Detection Options (docs.snort.org/rules/options/payload) ────
VALID_CONTENT_MODIFIERS: Set[str] = {
    "nocase", "fast_pattern", "offset", "depth", "distance", "within",
    "width", "endian"
}

VALID_NUMERIC_BINARY_OPTIONS: Set[str] = {
    "byte_test", "byte_extract", "byte_math", "byte_jump",
    "dsize", "bufferlen", "isdataat", "ber_data", "ber_skip"
}

# ── Helper Validation Functions ───────────────────────────────────────────────

def is_valid_action(action: str) -> bool:
    return action.lower().strip() in VALID_ACTIONS

def is_valid_rule_type(rule_type: str) -> bool:
    return rule_type.lower().strip() in VALID_RULE_TYPES

def is_valid_direction(direction: str) -> bool:
    return direction.strip() in VALID_DIRECTIONS

def is_valid_protocol_or_service(proto_or_service: str) -> bool:
    val = proto_or_service.lower().strip()
    return val in VALID_PROTOCOLS or val in VALID_SERVICE_HEADERS

def is_valid_classtype(classtype: str) -> bool:
    return classtype.lower().strip() in VALID_CLASSTYPES

def get_classtype_priority(classtype: str) -> Optional[int]:
    return VALID_CLASSTYPES.get(classtype.lower().strip())

def is_valid_ip_token(token: str) -> bool:
    token = token.strip()
    if token in VALID_IP_VARIABLES or token == "any":
        return True
    if token.startswith("!") and token[1:] in VALID_IP_VARIABLES:
        return True
    if token in FORBIDDEN_VARIABLES:
        return False
    # Validate CIDR or single IP
    ip_pattern = r"^!?(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$"
    if re.match(ip_pattern, token):
        return True
    # IP list e.g. [192.168.1.0/24,10.0.0.0/8]
    if token.startswith("[") and token.endswith("]"):
        return True
    return False

def is_valid_port_token(token: str) -> bool:
    token = token.strip()
    if token in VALID_PORT_VARIABLES or token == "any":
        return True
    if token in FORBIDDEN_VARIABLES:
        return False
    # Port number or range e.g. 80, 8080, 1024:65535, :1024, 1024:
    port_pattern = r"^!?(?:\d{1,5}(?::\d{1,5})?|:\d{1,5}|\d{1,5}:)$"
    if re.match(port_pattern, token):
        return True
    if token.startswith("[") and token.endswith("]"):
        return True
    return False

def validate_flow_args(args: List[str]) -> Tuple[bool, List[str]]:
    """Validate a list of flow option arguments for Snort 3."""
    errors = []
    seen_dirs = 0
    seen_states = 0
    seen_streams = 0
    seen_frags = 0

    for a in args:
        a_clean = a.lower().strip()
        if a_clean in VALID_FLOW_DIRECTIONS:
            seen_dirs += 1
        elif a_clean in VALID_FLOW_STATES:
            seen_states += 1
        elif a_clean in VALID_FLOW_STREAM_OPTIONS:
            seen_streams += 1
        elif a_clean in VALID_FLOW_FRAG_OPTIONS:
            seen_frags += 1
        else:
            errors.append(f"Invalid flow argument '{a}'. Must be valid Snort 3 flow property.")

    if seen_dirs > 1:
        errors.append("Conflicting flow directions specified (e.g. both to_server and to_client).")
    if seen_states > 1:
        errors.append("Conflicting flow states specified (e.g. both established and stateless).")
    if seen_streams > 1:
        errors.append("Conflicting stream reassembly options specified (e.g. both only_stream and no_stream).")
    if seen_frags > 1:
        errors.append("Conflicting fragment options specified (e.g. both only_frag and no_frag).")

    return (len(errors) == 0, errors)

def validate_direction_consistency(flow_dir: str, communication_direction: str) -> Tuple[bool, Optional[str]]:
    """
    Ensure the flow direction aligns with the communication direction.
    - to_server / from_client aligns with inbound_exploit or outbound_c2 (client -> server)
    - to_client / from_server aligns with server_response (server -> client)
    """
    flow_dir = flow_dir.lower().strip()
    comm_dir = communication_direction.lower().strip()

    if comm_dir in ["inbound_exploit", "outbound_c2", "client_request", "to_server"]:
        if flow_dir in ["to_client", "from_server"]:
            return False, f"Inconsistency: communication direction is '{comm_dir}' (client->server), but flow is set to '{flow_dir}' (server->client)."
    elif comm_dir in ["server_response", "c2_response", "to_client"]:
        if flow_dir in ["to_server", "from_client"]:
            return False, f"Inconsistency: communication direction is '{comm_dir}' (server->client), but flow is set to '{flow_dir}' (client->server)."

    return True, None

def is_valid_buffer(buf_name: str) -> bool:
    """Check if a buffer name is a recognized Snort 3 sticky buffer."""
    return buf_name.lower().strip() in VALID_STICKY_BUFFERS

def is_valid_content_modifier(mod_name: str) -> bool:
    """Check if a modifier name is a recognized Snort 3 content modifier."""
    return mod_name.lower().strip() in VALID_CONTENT_MODIFIERS

def load_protocol_catalogue(protocol: str) -> Set[str]:
    """Retrieve protocol-specific options catalogue for a given protocol or service name."""
    proto_clean = protocol.lower().strip()
    return PROTOCOL_OPTIONS_CATALOGUE.get(proto_clean, set())

# ── Re-export formal 9-field Option Specification Schema ──────────────────────
from snort_pipeline.option_catalogue import (
    OptionSpec,
    SNORT3_OPTION_CATALOGUE,
    get_option_spec,
    get_stage_catalogue,
    format_stage_catalogue_for_llm,
    list_options_by_category
)
