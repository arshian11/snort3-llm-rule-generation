"""
Snort 3 Stage 5 — Detection Generation Engine.
Grounded in snort3_complete_rule_documentation.txt (Payload & Inspection Options).

Implements the five detection sub-stages:
5.1 Sub-stage A: Buffer selection (sticky buffers: http_uri, http_client_body, file_data, pkt_data, etc.)
5.2 Sub-stage B: Content and pattern matching (content, fast_pattern, nocase, pcre, regex, encoding)
5.3 Sub-stage C: Position and relationship constraints (offset, depth, distance, within, isdataat, bufferlen)
5.4 Sub-stage D: Numeric, binary and structured-data inspection (byte_extract, byte_test, byte_math, byte_jump, dsize, ber_*)
5.5 Sub-stage E: Protocol-specific detection (HTTP, SSL/TLS, DCE/RPC, SIP, Modbus, DNP3, CIP, IEC104, etc.)
Followed by DetectionValidator & DetectionGenerator orchestrator with LLM self-healing retry loop.
"""

from typing import Dict, List, Set, Any, Optional, Tuple, Union
import re
import json

from snort_pipeline.snort3_catalogue import (
    VALID_STICKY_BUFFERS,
    VALID_GENERAL_BUFFERS,
    VALID_HTTP_BUFFERS,
    VALID_CONTENT_MODIFIERS,
    VALID_NUMERIC_BINARY_OPTIONS,
    PROTOCOL_OPTIONS_CATALOGUE,
    is_valid_buffer,
    load_protocol_catalogue
)
from snort_pipeline.rule_state import (
    RuleState,
    DetectionHypothesis,
    RuleHeaderAST,
    RuleOptionAST,
    ConstructionState,
    ValidationResult,
    StageResult
)
from snort_pipeline.option_catalogue import (
    format_stage_catalogue_for_llm,
    check_deprecated_snort2_option
)
from snort_pipeline.snort2_to_snort3_migration import (
    DELETED_PCRE_MODIFIERS,
    Snort2CompatibilityValidator
)
from snort_pipeline.protocol_constants import (
    ProtocolConstantFilter,
    DEFAULT_FILTER,
    encode_dns_wire_format,
    is_domain_name,
    calculate_shannon_entropy
)
from snort_pipeline.llm_engine import LLMClient

# Forbidden LLM hallucination placeholders and pseudo-keywords
FORBIDDEN_PLACEHOLDERS: Set[str] = {
    "malicious_artifact", "observed_pattern", "suspicious_payload",
    "attack_signature", "malicious_payload", "distinctive_c2_pattern",
    "malicious-c2-beacon.domain", "placeholder", "test_payload",
    "sample_payload", "example_payload", "dummy_payload",
    "tcp_flags:syn", "tcp_flags:ack", "icmp type 8", "icmp type 0"
}

# ─────────────────────────────────────────────────────────────────────────────
# 5.1 SUB-STAGE A: BUFFER SELECTION
# ─────────────────────────────────────────────────────────────────────────────

def select_detection_buffer(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None,
    data_element: Optional[str] = None
) -> Optional[str]:
    """
    Select appropriate Snort 3 sticky buffer following the sequence:
    Hypothesis -> Application Protocol -> Data Element -> Direction -> Suitable Buffer.

    Returns the buffer name (e.g. 'http_uri', 'http_client_body', 'file_data', 'pkt_data')
    or None if default packet data inspection (pkt_data) is intended.
    """
    h_type = header.header_type if header else "traditional"
    if h_type in ["file", "file_id"]:
        return "file_data"

    proto = ""
    app_proto = (hypothesis.target_protocol or "").lower().strip()
    if header and header.header_type == "service":
        proto = (header.service or header.protocol or "").lower().strip()
    elif app_proto and app_proto not in ["tcp", "ip"]:
        proto = app_proto
    elif header and header.protocol:
        proto = header.protocol.lower().strip()
    else:
        proto = app_proto

    # Normalize proto
    if proto in ["https", "tls", "ssl"]:
        proto = "ssl"
    elif proto in ["http", "http2", "http3", "web"]:
        proto = "http"
    elif header and header.header_type == "traditional" and str(header.dest_port) in ["$HTTP_PORTS", "80", "8080"]:
        proto = "http"
    elif proto in ["dns"] or (header and str(header.dest_port) in ["53", "$DNS_PORTS"]):
        proto = "dns"

    # Identify relevant data element from argument or hypothesis invariants
    elem = (data_element or "").lower().strip()
    if not elem and hypothesis.invariant_indicators:
        first_inv = hypothesis.invariant_indicators[0]
        if isinstance(first_inv, dict):
            elem = first_inv.get("type", "").lower().strip()

    comm_dir = (hypothesis.communication_direction or "").lower().strip()

    # 1. HTTP Buffers
    if proto == "http":
        if any(k in elem for k in ["uri", "url", "path", "query", "endpoint"]):
            return "http_uri"
        elif any(k in elem for k in ["header", "user_agent", "host", "referer"]):
            return "http_header"
        elif "cookie" in elem:
            return "http_cookie"
        elif any(k in elem for k in ["client_body", "post_data", "request_body", "json_payload", "xml"]):
            return "http_client_body"
        elif any(k in elem for k in ["response_body", "download", "file", "dropper", "exe", "pe"]):
            # In Snort 3, HTTP response body / file download is inspected via file_data
            return "file_data"
        elif "method" in elem:
            return "http_method"
        elif any(k in elem for k in ["status", "stat_code"]):
            return "http_stat_code"
        elif "true_ip" in elem:
            return "http_true_ip"

        # Direction-based fallback for HTTP
        if comm_dir in ["server_response", "c2_response"]:
            return "file_data"
        return "http_uri"

    # 2. SSL/TLS Buffers
    elif proto in ["ssl", "tls"]:
        if "sni" in elem or "domain" in elem:
            return "tls_sni"
        return "ssl_state"

    # 3. DNS Buffers: Snort 3 core has no dns_query keyword. DNS matches against raw UDP packet data using wire format.
    elif proto == "dns" or any(k in elem for k in ["dns", "domain", "query", "hostname"]):
        return None

    # 4. SIP Buffers
    elif proto == "sip":
        if "body" in elem:
            return "sip_body"
        return "sip_header"

    # 5. File / generic payload
    if any(k in elem for k in ["file", "dropper", "macro", "vba"]):
        return "file_data"
    elif "base64" in elem:
        return "base64_data"
    elif "js" in elem or "javascript" in elem:
        return "js_data"

    # Default buffer is pkt_data
    return "pkt_data"


# ─────────────────────────────────────────────────────────────────────────────
# 5.2 SUB-STAGE B: CONTENT AND PATTERN MATCHING
# ─────────────────────────────────────────────────────────────────────────────

def generate_content_match(
    pattern: str,
    is_hex: bool = False,
    is_negated: bool = False,
    fast_pattern: bool = False,
    nocase: bool = False
) -> RuleOptionAST:
    """
    Construct a primary Snort 3 content pattern matching AST node.
    Supports text patterns, binary hex patterns (|4D 5A|), and modifiers.
    """
    clean_pat = str(pattern).strip()

    # Normalize HTTP header format e.g. "User-Agent:value" -> "User-Agent: value"
    if re.match(r'^[A-Za-z0-9_-]+:[^\s/]', clean_pat) and not clean_pat.startswith("http"):
        clean_pat = re.sub(r'^([A-Za-z0-9_-]+):([^\s])', r'\1: \2', clean_pat)

    # Format hex bytes if requested and not already formatted with pipes
    if is_hex and not (clean_pat.startswith("|") and clean_pat.endswith("|")):
        # Ensure clean hex tokens
        hex_tokens = re.findall(r"[0-9a-fA-F]{2}", clean_pat)
        if hex_tokens:
            clean_pat = f"|{' '.join(hex_tokens).upper()}|"

    # Handle negation prefix
    if is_negated and not clean_pat.startswith("!"):
        clean_pat = f"!{clean_pat}"

    mods: Dict[str, Any] = {}
    if fast_pattern and not is_negated:
        mods["fast_pattern"] = True
    if nocase:
        mods["nocase"] = True

    return RuleOptionAST(name="content", value=clean_pat, modifiers=mods)


def generate_fast_pattern(
    content_node: RuleOptionAST,
    fp_type: Union[bool, str] = True
) -> RuleOptionAST:
    """
    Designate a content or regex node as the fast pattern search anchor.
    fp_type: True (standard fast_pattern), 'only' (fast_pattern:only), or custom range.
    """
    if str(content_node.value).startswith("!"):
        raise ValueError("Cannot assign fast_pattern to a negated content match.")

    content_node.modifiers["fast_pattern"] = fp_type
    return content_node


def generate_nocase_modifier(content_node: RuleOptionAST) -> RuleOptionAST:
    """Set case-insensitive matching on a content or regex node."""
    content_node.modifiers["nocase"] = True
    return content_node


def generate_pcre_match(
    pattern: str,
    flags: str = "i",
    is_negated: bool = False
) -> RuleOptionAST:
    """
    Construct a Snort 3 PCRE regular expression AST node.
    Syntax: pcre:[!]"/pattern/flags";
    Enforces Snort 3 sticky buffer convention (no obsolete Snort 2 /U, /H flags).
    """
    clean_p = str(pattern).strip()

    # Strip existing enclosing slashes if provided
    if clean_p.startswith("/") and len(clean_p) > 2:
        m = re.match(r"^/(.*)/([A-Za-z]*)$", clean_p)
        if m:
            clean_p = m.group(1)
            flags = m.group(2) or flags

    # Filter out obsolete HTTP pcre flags (U, H, B) in Snort 3
    flags = re.sub(r"[UHB]", "", flags)

    pcre_val = f"/{clean_p}/{flags}"
    if is_negated:
        pcre_val = f"!{pcre_val}"

    return RuleOptionAST(name="pcre", value=pcre_val)


def generate_regex_match(
    pattern: str,
    flags: str = "i",
    fast_pattern: bool = False,
    nocase: bool = False,
    is_negated: bool = False
) -> RuleOptionAST:
    """
    Construct a Snort 3 Hyperscan regex AST node.
    Syntax: regex:[!]"/pattern/flags"[,fast_pattern][,nocase];
    """
    clean_p = str(pattern).strip()
    if clean_p.startswith("/") and len(clean_p) > 2:
        m = re.match(r"^/(.*)/([A-Za-z]*)$", clean_p)
        if m:
            clean_p = m.group(1)
            flags = m.group(2) or flags

    regex_val = f"/{clean_p}/{flags}"
    if is_negated:
        regex_val = f"!{regex_val}"

    mods: Dict[str, Any] = {}
    if fast_pattern and not is_negated:
        mods["fast_pattern"] = True
    if nocase:
        mods["nocase"] = True

    return RuleOptionAST(name="regex", value=regex_val, modifiers=mods)


def generate_encoding_options(
    content_node: RuleOptionAST,
    width: Optional[int] = None,
    endian: Optional[str] = None
) -> RuleOptionAST:
    """Add character width and endianness modifiers to content match."""
    if width in [1, 2, 4]:
        content_node.modifiers["width"] = width
    if endian in ["big", "little"]:
        content_node.modifiers["endian"] = endian
    return content_node


def validate_pattern_against_evidence(
    pattern: str,
    evidence: Dict[str, Any]
) -> Tuple[bool, Optional[str]]:
    """
    Verify that a proposed content pattern is grounded in capture evidence
    rather than being hallucinated from malware family reputation.
    """
    clean_pat = str(pattern).strip().strip('"').strip("'")
    if clean_pat.startswith("!"):
        clean_pat = clean_pat[1:].strip()
    if clean_pat.startswith("|") and clean_pat.endswith("|"):
        clean_pat = clean_pat[1:-1].replace(" ", "").lower()

    ev_str = json.dumps(evidence).lower()
    clean_pat_lower = clean_pat.lower()

    if clean_pat_lower in ev_str:
        return True, None

    # Check for substring match (at least 4 characters)
    if len(clean_pat_lower) >= 4:
        for word in re.findall(r"\w{4,}", clean_pat_lower):
            if word in ev_str:
                return True, None

    return False, f"Pattern '{pattern}' could not be grounded in provided capture evidence packets or summaries."


# ─────────────────────────────────────────────────────────────────────────────
# 5.3 SUB-STAGE C: POSITION AND RELATIONSHIP CONSTRAINTS
# ─────────────────────────────────────────────────────────────────────────────

def generate_offset(value: int) -> Dict[str, int]:
    """Search start position relative to buffer beginning."""
    return {"offset": max(0, int(value))}


def generate_depth(value: int) -> Dict[str, int]:
    """Maximum search depth relative to buffer beginning."""
    return {"depth": max(1, int(value))}


def generate_distance(value: int) -> Dict[str, int]:
    """Relative search offset from end of previous content match."""
    return {"distance": int(value)}


def generate_within(value: int, pattern_len: Optional[int] = None) -> Dict[str, int]:
    """
    Maximum search window relative to end of previous content match.
    Enforces Snort 3 rule: within must be >= length of pattern.
    """
    val = int(value)
    if pattern_len and val < pattern_len:
        val = pattern_len
    return {"within": max(1, val)}


def generate_isdataat(
    location: int,
    relative: bool = False,
    is_negated: bool = False
) -> RuleOptionAST:
    """
    Verify that payload data exists at location.
    Syntax: isdataat:[!]location[,relative];
    """
    prefix = "!" if is_negated else ""
    rel = ",relative" if relative else ""
    return RuleOptionAST(name="isdataat", value=f"{prefix}{location}{rel}")


def generate_bufferlen(expr: str, relative: bool = False) -> RuleOptionAST:
    """
    Test length of the currently selected buffer.
    Syntax: bufferlen:[<|>|=|!|<=|>=]length[,relative];
    """
    clean_expr = str(expr).strip()
    rel = ",relative" if relative else ""
    return RuleOptionAST(name="bufferlen", value=f"{clean_expr}{rel}")


def validate_content_relationships(options: List[RuleOptionAST]) -> Tuple[bool, List[str]]:
    """
    Validate positioning and relationship constraints across declared options:
    - offset and depth can be used together (absolute).
    - distance and within can be used together (relative).
    - offset and within CANNOT be combined on the same content match.
    - distance and depth CANNOT be combined on the same content match.
    - distance/within require a preceding content match in the same buffer scope.
    - within must be >= content pattern length.
    """
    errors: List[str] = []
    seen_content = False
    current_buffer: Optional[str] = None

    for opt in options:
        name = opt.name.strip().lower()

        # Track buffer switches
        if is_valid_buffer(name) and opt.value is None:
            current_buffer = name
            seen_content = False  # Reset relative chain on buffer switch
            continue

        if name == "content":
            mods = opt.modifiers or {}
            val = str(opt.value or "").strip()
            if val.startswith("!"):
                val = val[1:].strip()
            # Calculate pattern length (hex bytes |4D 5A| count as 2 bytes)
            if val.startswith("|") and val.endswith("|"):
                raw_hex = val[1:-1].replace(" ", "")
                pat_len = len(raw_hex) // 2
            else:
                pat_len = len(val)

            has_offset = "offset" in mods
            has_depth = "depth" in mods
            has_dist = "distance" in mods
            has_within = "within" in mods

            # 1. Mutually exclusive positioning systems
            if has_offset and has_within:
                errors.append(f"Positioning conflict on '{val}': cannot combine 'offset' (absolute) with 'within' (relative).")
            if has_dist and has_depth:
                errors.append(f"Positioning conflict on '{val}': cannot combine 'distance' (relative) with 'depth' (absolute).")

            # 2. Relative modifiers require preceding content match
            if (has_dist or has_within) and not seen_content:
                errors.append(f"Orphan relative modifier on '{val}': 'distance'/'within' requires a preceding content match in buffer '{current_buffer or 'default'}'.")

            # 3. within >= pattern length
            if has_within:
                within_val = int(mods["within"])
                if pat_len > 0 and within_val < pat_len:
                    errors.append(f"Invalid 'within' constraint on '{val}': within ({within_val}) must be >= pattern length ({pat_len}).")

            seen_content = True

        elif name in ["isdataat", "bufferlen"]:
            val_str = str(opt.value or "")
            if "relative" in val_str and not seen_content:
                errors.append(f"Orphan relative modifier: '{name}:{val_str}' with 'relative' requires a preceding content match.")

    return len(errors) == 0, errors


# ─────────────────────────────────────────────────────────────────────────────
# 5.4 SUB-STAGE D: NUMERIC, BINARY AND STRUCTURED-DATA INSPECTION
# ─────────────────────────────────────────────────────────────────────────────

def generate_byte_extract(
    count: int,
    offset: int,
    name: str,
    relative: bool = False,
    multiplier: Optional[int] = None,
    align: Optional[int] = None,
    endian: Optional[str] = None,
    string: bool = False,
    num_type: Optional[str] = None,
    bitmask: Optional[str] = None
) -> RuleOptionAST:
    """
    Construct byte_extract AST node.
    Syntax: byte_extract:count,offset,name[,relative][,multiplier M][,endian][,string[,{dec|hex|oct}]][,align A][,bitmask B];
    """
    parts = [str(count), str(offset), str(name)]
    if relative:
        parts.append("relative")
    if multiplier:
        parts.append(f"multiplier {multiplier}")
    if align in [2, 4]:
        parts.append(f"align {align}")
    if endian in ["big", "little"]:
        parts.append(endian)
    if string:
        parts.append("string")
        if num_type in ["dec", "hex", "oct"]:
            parts.append(num_type)
    if bitmask:
        parts.append(f"bitmask {bitmask}")

    return RuleOptionAST(name="byte_extract", value=",".join(parts))


def generate_byte_test(
    count: int,
    operator: str,
    compare: Union[int, str],
    offset: Union[int, str],
    relative: bool = False,
    endian: Optional[str] = None,
    string: bool = False,
    num_type: Optional[str] = None,
    bitmask: Optional[str] = None
) -> RuleOptionAST:
    """
    Construct byte_test AST node.
    Syntax: byte_test:count,[!]operator,compare,offset[,relative][,endian][,string[,{dec|hex|oct}]][,bitmask B];
    """
    parts = [str(count), str(operator), str(compare), str(offset)]
    if relative:
        parts.append("relative")
    if endian in ["big", "little"]:
        parts.append(endian)
    if string:
        parts.append("string")
        if num_type in ["dec", "hex", "oct"]:
            parts.append(num_type)
    if bitmask:
        parts.append(f"bitmask {bitmask}")

    return RuleOptionAST(name="byte_test", value=",".join(parts))


def generate_byte_math(
    bytes_count: int,
    offset: int,
    oper: str,
    val: Union[int, str],
    result_var: str,
    relative: bool = False,
    endian: Optional[str] = None
) -> RuleOptionAST:
    """Construct byte_math AST node."""
    parts = [
        f"bytes {bytes_count}",
        f"offset {offset}",
        f"oper {oper}",
        f"rval {val}",
        f"result {result_var}"
    ]
    if relative:
        parts.append("relative")
    if endian in ["big", "little"]:
        parts.append(f"endian {endian}")
    return RuleOptionAST(name="byte_math", value=",".join(parts))


def generate_byte_jump(
    bytes_count: int,
    offset: int,
    relative: bool = False,
    multiplier: Optional[int] = None,
    align: Optional[int] = None,
    endian: Optional[str] = None
) -> RuleOptionAST:
    """Construct byte_jump AST node."""
    parts = [str(bytes_count), str(offset)]
    if relative:
        parts.append("relative")
    if multiplier:
        parts.append(f"multiplier {multiplier}")
    if align in [2, 4]:
        parts.append(f"align {align}")
    if endian in ["big", "little"]:
        parts.append(endian)
    return RuleOptionAST(name="byte_jump", value=",".join(parts))


def generate_dsize(expr: str) -> RuleOptionAST:
    """
    Construct dsize payload size test AST node.
    Syntax: dsize:[<|>|=|!|<=|>=]size or min<>max
    """
    return RuleOptionAST(name="dsize", value=str(expr).strip())


def generate_ber_options(
    option_name: str,
    value: Optional[str] = None
) -> RuleOptionAST:
    """Construct ber_data or ber_skip AST node."""
    clean_name = option_name.lower().strip()
    return RuleOptionAST(name=clean_name, value=value)


def validate_binary_detection(
    options: List[RuleOptionAST],
    binary_evidence: Optional[Dict[str, Any]] = None
) -> Tuple[bool, List[str]]:
    """Validate argument boundaries and operations for numeric/binary options."""
    errors: List[str] = []
    valid_ops = {"<", ">", "<=", ">=", "=", "&", "^"}

    for opt in options:
        name = opt.name.lower().strip()
        val = str(opt.value or "")

        if name == "byte_test":
            parts = [p.strip() for p in val.split(",")]
            if len(parts) < 4:
                errors.append(f"byte_test requires at least 4 arguments (count, operator, compare, offset), got: {val}")
                continue
            count_str, op, comp, offset_str = parts[0], parts[1], parts[2], parts[3]
            try:
                c = int(count_str)
                if not (1 <= c <= 10):
                    errors.append(f"byte_test count must be in 1..10, got {c}")
            except ValueError:
                errors.append(f"byte_test count must be integer, got '{count_str}'")

            clean_op = op[1:] if op.startswith("!") else op
            if clean_op not in valid_ops:
                errors.append(f"Invalid byte_test operator '{op}'. Valid operators: {valid_ops}")

        elif name == "byte_extract":
            parts = [p.strip() for p in val.split(",")]
            if len(parts) < 3:
                errors.append(f"byte_extract requires at least 3 arguments (count, offset, name), got: {val}")
                continue
            count_str, offset_str, var_name = parts[0], parts[1], parts[2]
            try:
                c = int(count_str)
                if not (1 <= c <= 10):
                    errors.append(f"byte_extract count must be in 1..10, got {c}")
            except ValueError:
                errors.append(f"byte_extract count must be integer, got '{count_str}'")

        elif name == "dsize":
            if not re.match(r"^(?:[<>!=]=?|<=|>=)?\s*\d+(?:\s*(?:<>|<=>)\s*\d+)?$", val):
                errors.append(f"Invalid dsize syntax: '{val}'. Expected e.g. '>100' or '100<>200'.")

    return len(errors) == 0, errors


# ─────────────────────────────────────────────────────────────────────────────
# 5.5 SUB-STAGE E: PROTOCOL-SPECIFIC DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def generate_http_detection(
    uri: Optional[str] = None,
    headers: Optional[List[Tuple[str, str]]] = None,
    body_pattern: Optional[str] = None,
    method: Optional[str] = None,
    stat_code: Optional[int] = None
) -> List[RuleOptionAST]:
    """Generate canonical sequence of HTTP sticky buffers and content options."""
    nodes: List[RuleOptionAST] = []
    has_fp = False

    if uri:
        nodes.append(RuleOptionAST(name="http_uri", value=None))
        nodes.append(RuleOptionAST(name="content", value=uri, modifiers={"nocase": True, "fast_pattern": True}))
        has_fp = True

    if headers:
        nodes.append(RuleOptionAST(name="http_header", value=None))
        for h_name, h_val in headers:
            combined = f"{h_name}: {h_val}"
            mods = {"nocase": True}
            if not has_fp:
                mods["fast_pattern"] = True
                has_fp = True
            nodes.append(RuleOptionAST(name="content", value=combined, modifiers=mods))

    if body_pattern:
        nodes.append(RuleOptionAST(name="http_client_body", value=None))
        mods = {"nocase": True}
        if not has_fp:
            mods["fast_pattern"] = True
            has_fp = True
        nodes.append(RuleOptionAST(name="content", value=body_pattern, modifiers=mods))

    if method:
        nodes.append(RuleOptionAST(name="http_method", value=None))
        nodes.append(RuleOptionAST(name="content", value=method.upper()))

    if stat_code:
        nodes.append(RuleOptionAST(name="http_stat_code", value=None))
        nodes.append(RuleOptionAST(name="content", value=str(stat_code)))

    return nodes


def generate_tls_detection(
    sni: Optional[str] = None,
    state: Optional[str] = None,
    version: Optional[str] = None
) -> List[RuleOptionAST]:
    """Generate SSL/TLS inspection nodes."""
    nodes: List[RuleOptionAST] = []
    if sni:
        nodes.append(RuleOptionAST(name="tls_sni", value=None))
        nodes.append(RuleOptionAST(name="content", value=sni, modifiers={"nocase": True, "fast_pattern": True}))
    if state:
        nodes.append(RuleOptionAST(name="ssl_state", value=state))
    if version:
        nodes.append(RuleOptionAST(name="ssl_version", value=version))
    return nodes


def generate_rpc_detection(
    iface: Optional[str] = None,
    opnum: Optional[int] = None
) -> List[RuleOptionAST]:
    """Generate DCE/RPC inspection nodes."""
    nodes: List[RuleOptionAST] = []
    if iface:
        nodes.append(RuleOptionAST(name="dce_iface", value=iface))
    if opnum is not None:
        nodes.append(RuleOptionAST(name="dce_opnum", value=str(opnum)))
    return nodes


def generate_sip_detection(
    method: Optional[str] = None,
    stat_code: Optional[int] = None,
    header_pattern: Optional[str] = None
) -> List[RuleOptionAST]:
    """Generate SIP inspection nodes."""
    nodes: List[RuleOptionAST] = []
    if method:
        nodes.append(RuleOptionAST(name="sip_method", value=method))
    if stat_code is not None:
        nodes.append(RuleOptionAST(name="sip_stat_code", value=str(stat_code)))
    if header_pattern:
        nodes.append(RuleOptionAST(name="sip_header", value=None))
        nodes.append(RuleOptionAST(name="content", value=header_pattern, modifiers={"nocase": True}))
    return nodes


def generate_industrial_protocol_detection(
    proto: str,
    func: Optional[Union[str, int]] = None,
    unit: Optional[int] = None
) -> List[RuleOptionAST]:
    """Generate Modbus / DNP3 / CIP industrial inspection nodes."""
    nodes: List[RuleOptionAST] = []
    p = proto.lower().strip()
    if p == "modbus":
        if func is not None:
            nodes.append(RuleOptionAST(name="modbus_func", value=str(func)))
        if unit is not None:
            nodes.append(RuleOptionAST(name="modbus_unit", value=str(unit)))
    elif p == "dnp3":
        if func is not None:
            nodes.append(RuleOptionAST(name="dnp3_func", value=str(func)))
    return nodes


def validate_protocol_specific_options(
    options: List[RuleOptionAST],
    protocol: str
) -> Tuple[bool, List[str]]:
    """Validate that protocol options match the declared transport / service."""
    errors: List[str] = []
    proto_clean = protocol.lower().strip()

    # Map aliases
    if proto_clean in ["http", "tcp"]:
        allowed = PROTOCOL_OPTIONS_CATALOGUE.get("http", set())
    elif proto_clean in ["ssl", "tls", "https"]:
        allowed = PROTOCOL_OPTIONS_CATALOGUE.get("ssl", set())
    else:
        allowed = PROTOCOL_OPTIONS_CATALOGUE.get(proto_clean, set())

    # Check for misassigned protocol options
    for opt in options:
        name = opt.name.lower().strip()
        for other_p, other_opts in PROTOCOL_OPTIONS_CATALOGUE.items():
            if other_p != proto_clean and name in other_opts and name not in allowed and name not in VALID_STICKY_BUFFERS:
                errors.append(f"Protocol mismatch: Option '{name}' belongs to '{other_p}' catalogue but rule target protocol is '{protocol}'.")

    return len(errors) == 0, errors


# ─────────────────────────────────────────────────────────────────────────────
# 6. DETECTION VALIDATOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DetectionValidator:
    """
    Deterministic Validation Gate for Stage 5 Detection Conditions.
    Enforces Snort 3 sticky buffer ordering, fast_pattern exclusivity,
    positioning constraints, and grounding in capture evidence.
    """
    def __init__(self):
        pass

    def validate(
        self,
        options: List[RuleOptionAST],
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Evaluate full sequence of proposed detection AST nodes.
        Returns: (passed, errors, details)
        """
        errors: List[str] = []
        details: Dict[str, Any] = {
            "options_count": len(options),
            "buffers_selected": [],
            "content_matches": 0,
            "fast_pattern_found": False
        }

        # Gate 1: Must have at least one substantive detection condition
        detection_ops = [o for o in options if o.name not in ["msg", "flow", "classtype", "sid", "rev", "metadata", "reference"]]
        if not detection_ops:
            errors.append("Empty detection: Stage 5 requires at least one content, buffer, regex, or byte test condition.")
            return ValidationResult(
                status="failed",
                component="detection",
                error=errors[0],
                evidence_required=True,
                details=details
            )

        # Gate 1.0: Mandatory Minimum Anchor Gate (Preventing Broad FP Rules)
        # Any rule must possess at least one substantive inspection condition:
        # content (>= 4 non-generic bytes, not in FORBIDDEN_PLACEHOLDERS), pcre, regex, byte_test, byte_extract, byte_math, itype, flags, dsize
        substantive_anchors = []
        for opt in detection_ops:
            o_name = opt.name.lower().strip()
            if o_name == "content" and opt.value:
                clean_v = str(opt.value).strip().strip('"').strip("'")
                clean_lower = clean_v.lower()
                if clean_lower not in FORBIDDEN_PLACEHOLDERS and not any(ph in clean_lower for ph in ["malicious_artifact", "observed_pattern", "tcp_flags:", "icmp type"]):
                    if DEFAULT_FILTER.calculate_byte_length(clean_v) >= 4:
                        substantive_anchors.append(opt)
            elif o_name in ["pcre", "regex", "byte_test", "byte_extract", "byte_math", "itype", "icode", "flags", "dsize"]:
                substantive_anchors.append(opt)

        if not substantive_anchors:
            errors.append(
                "Mandatory Minimum Anchor Violation: Rule has no substantive detection conditions "
                "(content >= 4 non-generic bytes, pcre, regex, byte_test, itype, flags, dsize). "
                "Rules specifying only sticky buffers or empty headers produce catastrophic false positives across benign traffic."
            )

        # Gate 1.1: Repetition & Loop Guard
        if len(detection_ops) > 15:
            errors.append(
                f"Excessive detection nodes ({len(detection_ops)} options). Safety threshold is 15 options; "
                f"this indicates an autoregressive model repetition loop."
            )

        # Consecutive duplicate options
        for idx in range(1, len(detection_ops)):
            if detection_ops[idx].name.lower().strip() == detection_ops[idx - 1].name.lower().strip():
                errors.append(
                    f"Repetitive declaration loop: option '{detection_ops[idx].name}' declared multiple times consecutively."
                )

        # Duplicate buffer declarations
        seen_bufs: Set[str] = set()
        for opt in detection_ops:
            b_name = opt.name.lower().strip()
            if opt.value is None or is_valid_buffer(b_name):
                if b_name in seen_bufs:
                    errors.append(
                        f"Duplicate buffer declaration: Sticky buffer '{opt.name};' declared multiple times in detection conditions."
                    )
                seen_bufs.add(b_name)

        # Consecutive sticky buffers without intervening content / inspection conditions
        for idx in range(1, len(detection_ops)):
            prev_opt = detection_ops[idx - 1]
            curr_opt = detection_ops[idx]
            if (prev_opt.value is None or is_valid_buffer(prev_opt.name.lower().strip())) and \
               (curr_opt.value is None or is_valid_buffer(curr_opt.name.lower().strip())):
                errors.append(
                    f"Degenerate buffer chain: Sticky buffer '{curr_opt.name};' directly follows buffer '{prev_opt.name};' "
                    f"without an intervening content match or inspection condition."
                )

        # Gate 1.2: Strict Buffer Whitelist & Unknown Keyword Validation
        known_option_names: Set[str] = VALID_STICKY_BUFFERS | VALID_NUMERIC_BINARY_OPTIONS | {
            "content", "pcre", "regex", "isdataat", "bufferlen", "dsize", "flags",
            "itype", "icode", "msg", "flow", "classtype", "sid", "rev", "metadata",
            "reference", "service", "priority", "detection_filter", "tag", "replace",
            "ttl", "tos", "ip_proto", "icmp_id", "icmp_seq", "fast_pattern", "nocase",
            "offset", "depth", "distance", "within", "ssl_state", "ssl_version", "tls_sni"
        }
        for opt in detection_ops:
            o_name = opt.name.lower().strip()
            if opt.value is None and not is_valid_buffer(o_name):
                errors.append(
                    f"Invalid Snort 3 sticky buffer keyword: '{opt.name};' is not a recognized Snort 3 sticky buffer. "
                    f"Allowed buffers: {', '.join(sorted(VALID_STICKY_BUFFERS))}."
                )
            elif o_name not in known_option_names:
                errors.append(
                    f"Unrecognized Snort 3 option keyword: '{opt.name}'. This option does not exist in Snort 3."
                )

        # Gate 1.3: Deprecated Snort 2 Keywords & Unsupported Keywords (e.g. dns_query)
        for opt in options:
            o_name = opt.name.lower().strip()
            if o_name == "dns_query":
                errors.append(
                    "Invalid keyword: 'dns_query;' is not supported in Snort 3 core. "
                    "DNS queries on UDP 53 must match directly against raw UDP payload using length-byte wire-format hex encoding "
                    "(e.g. content:\"|08|carwaded|03|com|00|\",fast_pattern,nocase;)."
                )
            dep_msg = check_deprecated_snort2_option(opt.name)
            if dep_msg:
                errors.append(f"Deprecated Snort 2 Option '{opt.name}': {dep_msg}")

        # Gate 2: Fast Pattern Check & Minimum Length Enforcement
        fp_count = 0
        content_ops = [o for o in detection_ops if o.name == "content"]
        for opt in detection_ops:
            name = opt.name.lower().strip()
            mods = opt.modifiers or {}
            if mods.get("fast_pattern"):
                fp_count += 1
                details["fast_pattern_found"] = True
                if str(opt.value or "").startswith("!"):
                    errors.append(f"Invalid fast_pattern: cannot assign fast_pattern to negated match '{opt.value}'.")
                
                # Enforce minimum fast-pattern length >= 4 bytes
                fp_clean = str(opt.value or "").strip().strip('"').strip("'")
                fp_len = DEFAULT_FILTER.calculate_byte_length(fp_clean)
                if fp_len < 4:
                    errors.append(f"Brittle fast_pattern: Pattern '{opt.value}' is too short ({fp_len} bytes). Fast patterns must be >= 4 bytes to avoid engine saturation.")

        if fp_count > 1:
            errors.append(f"Multiple fast_pattern modifiers specified ({fp_count}). Snort 3 permits at most one fast_pattern per rule.")

        # Gate 2.1: Invariant Sanitization & Ban Hallucinated Placeholders
        for opt in content_ops:
            val_clean = str(opt.value or "").strip().strip('"').strip("'")
            val_lower = val_clean.lower()
            if val_lower in FORBIDDEN_PLACEHOLDERS or any(ph in val_lower for ph in ["malicious_artifact", "observed_pattern", "tcp_flags:", "icmp type"]):
                errors.append(
                    f"Forbidden placeholder pattern '{opt.value}': Detection rules must be grounded in "
                    f"real packet payload invariants, not synthetic LLM placeholders or pseudo-keywords."
                )
            if val_clean.startswith("!"):
                val_clean = val_clean[1:].strip()
            c_len = DEFAULT_FILTER.calculate_byte_length(val_clean)
            if val_clean in ["'", '"', "/", "\\", ";", ":", "=", "&", "?", "#"]:
                errors.append(f"Brittle anchor: Trivial single character '{val_clean}' is prohibited as a content match.")
            elif c_len < 4 and len(content_ops) == 1:
                errors.append(f"Brittle content match: Single pattern '{val_clean}' is too short ({c_len} bytes). Standalone content anchors must be >= 4 bytes.")

        # Gate 3: Buffer Validity and Ordering
        current_buffer: Optional[str] = None
        for idx, opt in enumerate(detection_ops):
            name = opt.name.lower().strip()
            if is_valid_buffer(name) and opt.value is None:
                details["buffers_selected"].append(name)
                current_buffer = name

            if name == "content":
                details["content_matches"] += 1

        # Gate 3.1: Protocol-Aware Sticky Buffer Scoping
        proto = (header.service or header.protocol if header else hypothesis.target_protocol) or "tcp"
        proto = proto.lower().strip()
        dest_port = str(header.dest_port) if header else ""

        # A. HTTP Buffer Scoping Enforcement: Disallow unbuffered raw payload matching
        if proto == "http" or dest_port in ["$HTTP_PORTS", "80", "8080"]:
            valid_http_bufs = {"http_uri", "http_header", "http_client_body", "http_cookie", "http_method", "http_stat_code", "file_data"}
            first_content = next((o for o in detection_ops if o.name == "content"), None)
            if first_content:
                first_content_idx = detection_ops.index(first_content)
                preceding_bufs = [o.name.lower() for o in detection_ops[:first_content_idx] if is_valid_buffer(o.name.lower())]
                if not preceding_bufs or not any(b in valid_http_bufs for b in preceding_bufs):
                    errors.append("HTTP Buffer Scoping Violation: HTTP rules must scope content matches within dedicated sticky buffers (e.g. http_uri, http_header, http_client_body, file_data). Raw unbuffered packet payload matching on HTTP is prohibited.")

        # B. DNS Wire-Format Enforcement: Prohibit raw ASCII dot matching on UDP/53
        if proto in ["dns", "udp"] and (dest_port in ["53", "$DNS_PORTS"] or proto == "dns"):
            for opt in content_ops:
                val_clean = str(opt.value or "").strip().strip('"').strip("'")
                if is_domain_name(val_clean) and not (val_clean.startswith("|") and val_clean.endswith("|")):
                    encoded_example = encode_dns_wire_format(val_clean)
                    errors.append(
                        f"DNS Wire-Format Violation: Searching for raw domain '{val_clean}' with dots on UDP/53 fails "
                        f"because DNS packets encode domain labels with length bytes. "
                        f"Encode domain in length-byte wire format (e.g. {encoded_example})."
                    )

        # Gate 3.2: Protocol Constant Blacklist Evaluation (asset/Protocol Constant Blacklist.txt)
        for opt in content_ops:
            raw_v = str(opt.value or "").strip()
            eval_res = DEFAULT_FILTER.evaluate_invariant_candidate(
                candidate=raw_v,
                protocol=proto,
                buffer_name=current_buffer,
                is_standalone=(len(content_ops) == 1)
            )
            if eval_res.status == "rejected":
                errors.append(eval_res.rejection_reason)

        # Gate 4: Content Relationships and Relative Chains
        rel_ok, rel_errors = validate_content_relationships(detection_ops)
        if not rel_ok:
            errors.extend(rel_errors)

        # Gate 5: Numeric & Binary Verification
        bin_ok, bin_errors = validate_binary_detection(detection_ops)
        if not bin_ok:
            errors.extend(bin_errors)

        # Gate 6: Protocol Suitability & Non-TCP Transport Sanitization
        proto = (header.service or header.protocol if header else hypothesis.target_protocol) or "tcp"
        proto = proto.lower().strip()

        if proto == "icmp":
            for opt in options:
                if opt.name.lower().strip() == "flow":
                    errors.append("Protocol conflict: The 'flow' option is prohibited on ICMP rules. Snort 3 does not support flow tracking for ICMP traffic.")
                if opt.name.lower().strip() == "content" and "icmp" in str(opt.value or "").lower():
                    errors.append("Invalid ICMP syntax: Do not use content:\"ICMP type X\". Use dedicated Snort 3 options 'itype:8;' and/or 'dsize:>1000;'.")

        if proto in ["tcp", "ip"]:
            for opt in content_ops:
                if "tcp_flags" in str(opt.value or "").lower():
                    errors.append("Invalid TCP syntax: Do not use content:\"tcp_flags:...\". Use dedicated Snort 3 options 'flags:S;' or 'flags:A;'.")

        proto_ok, proto_errors = validate_protocol_specific_options(detection_ops, proto)
        if not proto_ok:
            errors.extend(proto_errors)

        # Gate 7: PCRE & Regex Format Checks and Category 3 Deleted Modifier Validation
        for opt in detection_ops:
            name = opt.name.lower().strip()
            val = str(opt.value or "").strip()
            if name in ["pcre", "regex"]:
                raw_v = val[1:] if val.startswith("!") else val
                if not (raw_v.startswith("/") and "/" in raw_v[1:]):
                    errors.append(f"Malformed {name} syntax: '{val}'. Must be enclosed in slashes: [!]\"/pattern/flags\".")
                else:
                    # Extract modifiers/flags after closing slash
                    closing_idx = raw_v.rfind("/")
                    flags = raw_v[closing_idx + 1:]
                    for mod_char in flags:
                        if mod_char in DELETED_PCRE_MODIFIERS:
                            mod_info = DELETED_PCRE_MODIFIERS[mod_char]
                            errors.append(
                                f"Deleted PCRE Modifier '/{mod_char}': Snort 3 removed PCRE modifier /{mod_char}. "
                                f"Use sticky buffer '{mod_info['buffer']};' preceding the pattern instead."
                            )

        passed = len(errors) == 0
        details["errors"] = errors
        error_comp = "content" if any("content" in e.lower() or "pattern" in e.lower() for e in errors) else "detection"
        return ValidationResult(
            status="passed" if passed else "failed",
            component=error_comp,
            error=errors[0] if errors else None,
            evidence_required=any("evidence" in e.lower() or "indicator" in e.lower() for e in errors),
            details=details
        )


# ─────────────────────────────────────────────────────────────────────────────
# 7. DETECTION GENERATOR ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class DetectionGenerator:
    """
    Manages Stage 5 Detection Generation.
    Queries LLM with hypothesis invariants, header, and flow constraints,
    validates output via DetectionValidator, executes self-healing retry loop,
    and provides deterministic fallback synthesis.
    """
    def __init__(self, llm_client: Optional[LLMClient] = None, max_retries: int = 3):
        self.client = llm_client or LLMClient()
        self.validator = DetectionValidator()
        self.max_retries = max_retries

    def generate(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Execute Stage 5: Generate, validate, and commit detection AST nodes to RuleState.
        """
        hyp = state.hypothesis
        header = state.ast.header
        if not hyp:
            state.transition(ConstructionState.CONSTRUCTION_FAILED, reason="Stage 5 requires an approved Detection Hypothesis in RuleState.")
            return state

        msg_opt = next((o for o in state.ast.options if o.name == "msg"), None)
        flow_opt = next((o for o in state.ast.options if o.name == "flow"), None)
        msg_str = msg_opt.value if msg_opt else state.components.get("msg")
        flow_str = (",".join(flow_opt.value) if isinstance(flow_opt.value, list) else str(flow_opt.value)) if flow_opt and flow_opt.value else (",".join(state.components.get("flow")) if state.components.get("flow") else None)

        retry_count = 0
        validation_errors: List[str] = []

        while retry_count <= self.max_retries:
            proposed_nodes = self._propose_detection_llm(
                hypothesis=hyp,
                header=header,
                msg_str=msg_str,
                flow_str=flow_str,
                report=report,
                previous_errors=validation_errors if retry_count > 0 else None
            )

            passed, errors, details = self.validator.validate(
                options=proposed_nodes,
                hypothesis=hyp,
                header=header
            )

            if passed:
                # Commit detection nodes to RuleState components
                state.components["detection"] = [node.to_dict() for node in proposed_nodes]
                state.components["synthesis_source"] = "llm"
                state.components["fallback_used"] = False
                details["synthesis_source"] = "llm"
                details["fallback_used"] = False

                # Update AST options (insert detection nodes after msg and flow)
                self._update_ast_detection_options(state, proposed_nodes)

                state.record_validation("stage5_detection", passed=True, details=details)
                state.transition(ConstructionState.DETECTION_GENERATED, reason=f"Generated {len(proposed_nodes)} detection AST nodes.")
                state.current_stage = 6

                stage_result = StageResult(
                    status="success",
                    component="detection",
                    generated_value=[node.to_dict() for node in proposed_nodes],
                    evidence_refs=[inv.get("value") for inv in (hyp.invariant_indicators or []) if isinstance(inv, dict)],
                    validation_errors=[],
                    reasoning_summary=f"Generated {len(proposed_nodes)} detection AST nodes grounded in verified invariant indicators."
                )
                state.stage_results["stage5_detection"] = stage_result.to_dict()
                state.last_stage_result = stage_result.to_dict()
                state.save_checkpoint(5)
                return state

            # Validation failed -> Retry
            retry_count += 1
            state.stage_retry_counts["stage5_detection"] = retry_count
            validation_errors = errors
            state.record_validation("stage5_detection", passed=False, errors=errors, details=details)

        # Retries exhausted: Fall back to deterministic detection synthesizer
        fallback_nodes = self._synthesize_fallback_detection(hyp, header, report)
        passed = False
        errors = ["No grounded invariants available"]
        details = {}
        if fallback_nodes:
            passed, errors, details = self.validator.validate(fallback_nodes, hyp, header)

        if passed:
            state.components["detection"] = [node.to_dict() for node in fallback_nodes]
            state.components["synthesis_source"] = "deterministic_fallback"
            state.components["fallback_used"] = True
            details["synthesis_source"] = "deterministic_fallback"
            details["fallback_used"] = True

            self._update_ast_detection_options(state, fallback_nodes)
            state.record_validation("stage5_detection", passed=True, details=details)
            state.transition(ConstructionState.DETECTION_GENERATED, reason=f"Deterministic fallback detection ({len(fallback_nodes)} nodes) committed.")
            state.current_stage = 6

            stage_result = StageResult(
                status="success",
                component="detection",
                generated_value=[node.to_dict() for node in fallback_nodes],
                evidence_refs=[inv.get("value") for inv in (hyp.invariant_indicators or []) if isinstance(inv, dict)],
                validation_errors=[],
                reasoning_summary=f"Synthesized deterministic telemetry fallback detection ({len(fallback_nodes)} AST nodes) grounded in verified PCAP telemetry invariants."
            )
            state.stage_results["stage5_detection"] = stage_result.to_dict()
            state.last_stage_result = stage_result.to_dict()
            state.save_checkpoint(5)
            return state

        # If fallback validation failed or no distinctive invariant was found:
        # Transition to CORRELATION_ONLY to avoid synthesizing empty or broad rules that fire false alarms on benign traffic.
        state.transition(
            ConstructionState.CORRELATION_ONLY,
            reason=f"No distinctive payload or transport invariants discovered in PCAP evidence: {'; '.join(validation_errors or errors)}. Preserved as correlation incident."
        )
        fail_result = StageResult(
            status="correlation_only",
            component="detection",
            generated_value=None,
            evidence_refs=[inv.get("value") for inv in (hyp.invariant_indicators or []) if isinstance(inv, dict)],
            validation_errors=validation_errors or errors,
            reasoning_summary="Detection generation transitioned to correlation-only: insufficient discriminative payload invariants."
        )
        state.stage_results["stage5_detection"] = fail_result.to_dict()
        state.last_stage_result = fail_result.to_dict()
        return state

    @staticmethod
    def _extract_payload_candidates(report: Optional[Dict[str, Any]], hypothesis: DetectionHypothesis) -> List[Dict[str, Any]]:
        """
        Extract verified, grounded packet payload substrings and DNS wire encodings
        from report telemetry so the LLM has hard evidence to anchor its rules.
        """
        candidates: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        if not report:
            return candidates

        net_behav = report.get("network_behaviour", {})

        # 1. DNS queries -> extract wire format hex
        dns_queries = net_behav.get("dns_queries", [])
        for dq in dns_queries:
            qname = dq.get("query_name", "")
            if qname and is_domain_name(qname):
                parts = qname.strip(".").split(".")
                domain_list = [qname]
                if len(parts) >= 2:
                    parent_domain = ".".join(parts[-2:])
                    if parent_domain not in domain_list:
                        domain_list.append(parent_domain)
                for d in domain_list:
                    wire = encode_dns_wire_format(d)
                    if wire not in seen:
                        seen.add(wire)
                        candidates.append({
                            "type": "dns_wire_format",
                            "domain": d,
                            "wire_hex": wire,
                            "recommended_content": wire,
                            "notes": f"DNS query wire format for '{d}' (use content:\"{wire}\",fast_pattern,nocase; on UDP 53)"
                        })

        # 2. HTTP requests -> extract URIs and headers
        http_reqs = net_behav.get("http_requests", [])
        for hr in http_reqs:
            uri = hr.get("uri", "")
            if uri and len(uri) >= 3 and uri not in seen:
                seen.add(uri)
                candidates.append({
                    "type": "http_uri",
                    "value": uri,
                    "recommended_buffer": "http_uri",
                    "notes": f"Observed HTTP URI path: {uri}"
                })
            host = hr.get("host", "")
            if host and host not in seen:
                seen.add(host)
                candidates.append({
                    "type": "http_header",
                    "value": f"Host: {host}",
                    "recommended_buffer": "http_header",
                    "notes": f"Observed HTTP Host header: {host}"
                })
            ua = hr.get("user_agent", "")
            if ua and len(ua) >= 5 and ua not in seen:
                seen.add(ua)
                candidates.append({
                    "type": "http_header",
                    "value": ua,
                    "recommended_buffer": "http_header",
                    "notes": f"Observed User-Agent header: {ua}"
                })

        # 3. Packet evidence / raw payloads
        pkt_ev = report.get("packet_evidence", [])
        for pkt in pkt_ev:
            payload = pkt.get("payload", "") or pkt.get("data", "")
            if payload:
                tokens = re.findall(r"[A-Za-z0-9_\-\.\/]{5,}", payload)
                for t in tokens[:5]:
                    if t not in seen and not t.isdigit() and t.lower() not in FORBIDDEN_PLACEHOLDERS:
                        seen.add(t)
                        candidates.append({
                            "type": "packet_payload_substring",
                            "value": t,
                            "notes": f"Observed packet payload substring from packet #{pkt.get('packet_number', '?')}"
                        })

        return candidates[:12]

    def _propose_detection_llm(
        self,
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None,
        msg_str: Optional[str] = None,
        flow_str: Optional[str] = None,
        report: Optional[Dict[str, Any]] = None,
        previous_errors: Optional[List[str]] = None
    ) -> List[RuleOptionAST]:
        """Query LLM to propose Snort 3 detection AST nodes using the 3-Pillar Prompt Schema."""
        family = getattr(hypothesis, "malware_family", "") or hypothesis.family_context.get("malware_family", "Malware")
        target_behaviour = hypothesis.target_behaviour
        objective = hypothesis.detection_objective
        target_proto = hypothesis.target_protocol
        comm_dir = hypothesis.communication_direction
        invariants = hypothesis.invariant_indicators or []
        header_str = header.render() if header else "alert tcp $EXTERNAL_NET any -> $HOME_NET any"
        stage5_catalogue = format_stage_catalogue_for_llm(5)
        ev_refs = hypothesis.evidence.get("triggering_packets", [])
        payload_candidates = self._extract_payload_candidates(report, hypothesis)

        msg_part = f'msg:"{msg_str}"; ' if msg_str else ""
        flow_part = f'flow:{flow_str}; ' if flow_str else ""
        rule_prefix = f"{header_str} ( {msg_part}{flow_part}[INSERT STAGE 5 DETECTION CONDITIONS HERE] )"

        retry_feedback = ""
        if previous_errors:
            retry_feedback = f"""
[CRITICAL CORRECTION REQUIRED]
Your previous detection proposal failed validation with the following errors:
{json.dumps(previous_errors, indent=2)}

Please strictly fix these issues:
1. Ensure sticky buffers (e.g. http_uri, http_header, file_data) precede the content matches they scope.
2. Specify 'fast_pattern' on EXACTLY ONE content or regex match. Never place fast_pattern on negated matches (!).
3. Do not combine 'offset' and 'within' on the same content match.
4. Do not combine 'distance' and 'depth' on the same content match.
5. If using 'within', ensure within value is >= the length of the string pattern.
6. If using relative modifiers (distance, within), ensure there is a preceding content match in the same buffer.
7. NEVER invent placeholders like 'malicious_artifact' or 'observed_pattern'.
8. DNS rules: DO NOT use 'dns_query;'. Use raw UDP length-byte wire format hex (e.g. '|08|carwaded|03|com|00|').
9. ICMP rules: DO NOT use 'flow:'. Use 'itype:8;' and/or 'dsize:>1000;'.
"""

        user_prompt = f"""You are the Snort 3 Rule Engineer operating Stage 5: Detection Generation.

1. COMPONENT-GENERATION INSTRUCTIONS:
Propose the exact detection conditions (sticky buffers, content patterns, modifiers, PCRE, byte tests) starting at AST Option #2+.
Output strictly valid JSON array conforming to this schema:
[
  {{ "name": "http_uri", "value": null }},
  {{ "name": "content", "value": "/malicious_path", "modifiers": {{ "fast_pattern": true, "nocase": true }} }}
]

2. RELEVANT CATALOGUE ENTRIES (Dynamic from OptionSpec):
{stage5_catalogue}

3. CURRENT RULE CONTEXT & ACCUMULATED STATE:
- Detection Hypothesis:
  - Threat Family: {family}
  - Target Behaviour: {target_behaviour}
  - Detection Objective: {objective}
  - Target Protocol: {target_proto}
  - Communication Direction: {comm_dir}
- Verified Invariant Indicators from Evidence:
{json.dumps(invariants, indent=2)}
- Evidence References (Triggering Packets): {ev_refs}
- Upstream AST Components:
  - Header: {header_str}
  - Option #0 (msg): {msg_str or 'Omitted'}
  - Option #1 (flow): {flow_str or 'Omitted'}
- Current Rule Prefix:
  {rule_prefix}

4. GROUND TRUTH EVIDENCE CANDIDATES (FROM PCAP TELEMETRY):
{json.dumps(payload_candidates, indent=2)}

CRITICAL GROUNDING & SYNTAX RULES:
1. You MUST anchor content patterns in the real extracted payload candidates above or verified invariant indicators. NEVER hallucinate strings like "malicious_artifact", "observed_pattern", or "suspicious_payload".
2. DNS Rules: Snort 3 core DOES NOT support 'dns_query;'. For DNS queries on UDP 53, DO NOT write 'dns_query;'. Instead, match on raw UDP payload using length-byte wire format (e.g. '|08|carwaded|03|com|00|') provided in payload_candidates.
3. ICMP Rules: Snort 3 DOES NOT support 'flow' tracking for ICMP traffic. NEVER include 'flow:' on ICMP rules. Use dedicated Snort 3 options 'itype:8;' (for echo request) and/or 'dsize:>1000;' (for packet payload size).
4. TCP Flags: NEVER write content:"tcp_flags:SYN". Use the dedicated keyword 'flags:S;' or 'flags:A;'.
5. HTTP Rules: Always use dedicated sticky buffers (http_uri, http_header, http_client_body).
{retry_feedback}
"""

        SYSTEM_PROMPT = """You are an expert Snort 3 signature engineer specializing in payload inspection options.
You propose strictly valid, dependency-compliant Snort 3 detection options based on verified protocol artifacts.
You output strictly valid JSON array without conversational text or codeblock wrappers."""

        try:
            resp_text = self.client.query(SYSTEM_PROMPT, user_prompt, json_mode=True, temperature=0.1)
            parsed = json.loads(self._extract_json(resp_text))

            if isinstance(parsed, list) and len(parsed) > 0:
                nodes: List[RuleOptionAST] = []
                for item in parsed:
                    if isinstance(item, dict) and "name" in item:
                        opt_node = RuleOptionAST.from_dict(item)
                        if opt_node.name == "content" and opt_node.value:
                            val_str = str(opt_node.value).strip()
                            if re.match(r'^[A-Za-z0-9_-]+:[^\s/]', val_str) and not val_str.startswith("http"):
                                opt_node.value = re.sub(r'^([A-Za-z0-9_-]+):([^\s])', r'\1: \2', val_str)
                        nodes.append(opt_node)
                if nodes:
                    return nodes

            return self._synthesize_fallback_detection(hypothesis, header, report)
        except Exception:
            return self._synthesize_fallback_detection(hypothesis, header, report)

    def _synthesize_fallback_detection(
        self,
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None,
        report: Optional[Dict[str, Any]] = None
    ) -> List[RuleOptionAST]:
        """
        Deterministic, high-fidelity detection synthesizer.
        Extracts verified invariant indicators and constructs compliant Snort 3 detection AST nodes.
        Enforces protocol constant filtering, minimum length, and protocol-aware sticky buffers.
        Grounded in real packet telemetry, zero hallucinated placeholders.
        """
        nodes: List[RuleOptionAST] = []
        invariants = hypothesis.invariant_indicators or []

        proto = (header.service or header.protocol if header else hypothesis.target_protocol) or "tcp"
        proto = proto.lower().strip()
        dest_port = str(header.dest_port) if header else ""
        obj_lower = (hypothesis.detection_objective or "").lower()
        beh_lower = (hypothesis.target_behaviour or "").lower()
        fam_lower = (getattr(hypothesis, "malware_family", "") or "").lower()

        # 1. ICMP Fallback (itype / dsize, no flow)
        if proto == "icmp" or "icmp" in obj_lower or "ping" in obj_lower:
            nodes.append(RuleOptionAST(name="itype", value="8"))
            if any(k in obj_lower or k in beh_lower for k in ["large", "size", "1000", "diagnostic"]):
                nodes.append(RuleOptionAST(name="dsize", value=">1000"))
            return nodes

        # 2. TCP Port Scan / SYN Scan Fallback (flags:S)
        if proto == "tcp" and (any(k in beh_lower or k in obj_lower or k in fam_lower for k in ["scan", "syn", "recon", "probe"]) or dest_port in ["22", "2222", "2022"]):
            nodes.append(RuleOptionAST(name="flags", value="S"))
            return nodes

        # 3. DNS Traffic on UDP/53 (Wire-Format Encoding on raw UDP, NO dns_query;)
        if proto in ["dns", "udp"] and (dest_port in ["53", "$DNS_PORTS"] or proto == "dns"):
            target_domain = None
            if report and report.get("network_behaviour", {}).get("dns_queries"):
                for dq in report["network_behaviour"]["dns_queries"]:
                    qname = dq.get("query_name", "")
                    if qname and is_domain_name(qname):
                        parts = qname.strip(".").split(".")
                        if len(parts) >= 2:
                            target_domain = ".".join(parts[-2:])
                        else:
                            target_domain = qname
                        break
            if not target_domain:
                for inv in invariants:
                    v = str(inv.get("value", "") if isinstance(inv, dict) else str(inv)).strip()
                    if is_domain_name(v):
                        target_domain = v
                        break

            if target_domain:
                wire_val = encode_dns_wire_format(target_domain)
                nodes.append(RuleOptionAST(
                    name="content",
                    value=wire_val,
                    modifiers={"fast_pattern": True, "nocase": True}
                ))
                return nodes

        # 4. HTTP Traffic
        has_http_traffic = bool(report and report.get("network_behaviour", {}).get("http_requests"))
        buf = select_detection_buffer(hypothesis, header)
        if (proto == "http" or dest_port in ["$HTTP_PORTS", "80", "8080"] or has_http_traffic) and buf in [None, "pkt_data"]:
            buf = "http_uri"

        if buf and buf != "pkt_data":
            nodes.append(RuleOptionAST(name=buf, value=None))

        # 5. Extract real patterns from invariants and report
        patterns: List[Tuple[str, str]] = []

        # Grounded HTTP request URIs from telemetry (e.g. PCAP_002 /products?id=1')
        if (buf == "http_uri" or proto == "http" or has_http_traffic) and report and report.get("network_behaviour", {}).get("http_requests"):
            for hr in report["network_behaviour"]["http_requests"]:
                uri = hr.get("uri", "")
                if uri and len(uri) >= 4 and uri != "/":
                    patterns.append((uri, "content"))
                    break

        for inv in invariants:
            val = str(inv.get("value", "") if isinstance(inv, dict) else str(inv)).strip()
            inv_type = str(inv.get("type", "content") if isinstance(inv, dict) else "content")
            if not val or len(val) < 2:
                continue

            if val.lower() in FORBIDDEN_PLACEHOLDERS or any(ph in val.lower() for ph in ["malicious_artifact", "observed_pattern", "tcp_flags:"]):
                continue

            # Evaluate with Protocol Constant Filter
            eval_res = DEFAULT_FILTER.evaluate_invariant_candidate(
                candidate=val,
                protocol=proto,
                buffer_name=buf,
                is_standalone=False
            )
            if eval_res.is_hard_exclusion:
                continue

            if is_domain_name(val) and proto in ["dns", "udp"]:
                val = encode_dns_wire_format(val)

            if DEFAULT_FILTER.calculate_byte_length(val) >= 4:
                if not any(p[0] == val for p in patterns):
                    patterns.append((val, inv_type))

        if not patterns:
            # Cannot synthesize a grounded rule without telemetry evidence
            # Returning empty nodes triggers transition to CORRELATION_ONLY
            return []

        # Primary anchor content match
        primary_val, primary_type = patterns[0]
        nodes.append(RuleOptionAST(
            name="content",
            value=primary_val,
            modifiers={"fast_pattern": True, "nocase": True}
        ))

        # Secondary match if co-occurs in same packet evidence
        if len(patterns) > 1:
            sec_val, sec_type = patterns[1]
            co_occurs = False
            if report and report.get("packet_evidence"):
                for pkt in report["packet_evidence"]:
                    p_text = str(pkt.get("payload", "") or pkt.get("data", "") or pkt.get("summary", ""))
                    if primary_val.lower() in p_text.lower() and sec_val.lower() in p_text.lower():
                        co_occurs = True
                        break

            if co_occurs:
                sec_len = len(sec_val)
                within_dist = max(50, sec_len + 10)
                nodes.append(RuleOptionAST(
                    name="content",
                    value=sec_val,
                    modifiers={"distance": 0, "within": within_dist, "nocase": True}
                ))

        return nodes

    def _update_ast_detection_options(self, state: RuleState, detection_nodes: List[RuleOptionAST]):
        """
        Commit detection nodes into state.ast.options.
        Canonical Snort 3 option order:
        Index 0: msg
        Index 1: flow (if present)
        Index 2+: detection options (sticky buffers, content, pcre, byte tests)
        End: classtype, sid, rev, metadata, reference
        """
        # Separate existing header-level options (msg, flow) and trailing metadata (classtype, sid, rev)
        msg_opt = next((o for o in state.ast.options if o.name == "msg"), None)
        flow_opt = next((o for o in state.ast.options if o.name == "flow"), None)
        trailing_opts = [o for o in state.ast.options if o.name in ["classtype", "sid", "rev", "metadata", "reference"]]

        new_options: List[RuleOptionAST] = []
        if msg_opt:
            new_options.append(msg_opt)
        if flow_opt:
            new_options.append(flow_opt)

        new_options.extend(detection_nodes)
        new_options.extend(trailing_opts)

        state.ast.options = new_options

    def _extract_json(self, text: str) -> str:
        """Extract clean JSON substring from LLM response."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        match = re.search(r"\[[\s\S]*\]", text)
        return match.group(0) if match else text
