"""
Snort 3 Comprehensive Option Specification Catalogue.
Grounded in snort3_complete_rule_documentation.txt (Snort 3 Rule Writing Guide).

Provides a structured 9-field specification schema for each supported Snort 3 option:
1. Option name
2. Option category / stage
3. Valid syntax
4. Arguments and data types
5. Dependencies
6. Compatibility restrictions
7. Applicable protocols and buffers
8. Examples
9. Version constraints (Snort 3 vs Snort 2 differences)

Enables:
- Dynamic prompt injection of exact rules and examples into LLM stage generators.
- Deterministic schema validation across all HDIRC stages.
- Interactive catalog querying for analysts via CLI and Web console.
"""

from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, asdict
import json


@dataclass
class OptionSpec:
    """Canonical 9-field specification for a Snort 3 rule option."""
    name: str
    stage: int  # Stage 2 to 7
    category: str  # header, message, flow, buffer, payload, positioning, binary, protocol, metadata
    syntax: str
    arguments_and_types: Dict[str, str]
    dependencies: List[str]
    compatibility_restrictions: List[str]
    applicable_protocols_and_buffers: List[str]
    examples: List[str]
    version_constraints: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def format_summary(self) -> str:
        """Format clean summary for LLM prompt context."""
        ex_str = " | ".join(self.examples)
        restr_str = "; ".join(self.compatibility_restrictions) if self.compatibility_restrictions else "None"
        dep_str = "; ".join(self.dependencies) if self.dependencies else "None"
        return (
            f"- Option: `{self.name}`\n"
            f"  Syntax: {self.syntax}\n"
            f"  Category: {self.category} (Stage {self.stage})\n"
            f"  Dependencies: {dep_str}\n"
            f"  Restrictions: {restr_str}\n"
            f"  Examples: {ex_str}\n"
            f"  Snort 3 Notes: {self.version_constraints}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 1. OPTION CATALOGUE MASTER STORE
# ─────────────────────────────────────────────────────────────────────────────

SNORT3_OPTION_CATALOGUE: Dict[str, OptionSpec] = {

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 2: RULE HEADER OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    "action": OptionSpec(
        name="action",
        stage=2,
        category="header",
        syntax="<action> <protocol> <src_ip> <src_port> <dir> <dst_ip> <dst_port>",
        arguments_and_types={"action": "enum('alert', 'block', 'drop', 'log', 'pass', 'react', 'reject', 'rewrite')"},
        dependencies=["None (first token in rule)"],
        compatibility_restrictions=["Active inline actions (drop, block, reject) require inline mode deployment. Candidate rules default to 'alert'."],
        applicable_protocols_and_buffers=["All protocols and buffers"],
        examples=["alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS", "alert http ( ... )", "alert file ( ... )"],
        version_constraints="Snort 3 adds 'rewrite' action and supports service/file headers without traditional 7-tuples."
    ),

    "protocol": OptionSpec(
        name="protocol",
        stage=2,
        category="header",
        syntax="alert <protocol> ...",
        arguments_and_types={"protocol": "enum('tcp', 'udp', 'icmp', 'ip')"},
        dependencies=["Follows action token"],
        compatibility_restrictions=["Mutually exclusive with service header name in traditional 7-tuple headers."],
        applicable_protocols_and_buffers=["Transport layer"],
        examples=["alert tcp any any -> any any", "alert udp $HOME_NET any -> $EXTERNAL_NET 53"],
        version_constraints="In Snort 3, application service names (http, ssl, dns) can replace the protocol in new service headers."
    ),

    "header_service": OptionSpec(
        name="header_service",
        stage=2,
        category="header",
        syntax="alert <service_name> ( <rule_options> )",
        arguments_and_types={"service_name": "string (e.g. 'http', 'ssl', 'dns', 'smtp', 'ftp', 'sip', 'modbus')"},
        dependencies=["Follows action token"],
        compatibility_restrictions=["Replaces the traditional 7-tuple (no IP or port fields declared)."],
        applicable_protocols_and_buffers=["Application service inspectors"],
        examples=["alert http ( msg:\"HTTP Exploit\"; http_uri; content:\"/cmd\"; sid:1001; )", "alert ssl ( msg:\"TLS C2\"; tls_sni; content:\"bad.com\"; sid:1002; )"],
        version_constraints="New in Snort 3. Simplifies rules when port and IP bindings are handled by inspector configuration."
    ),

    "header_file": OptionSpec(
        name="header_file",
        stage=2,
        category="header",
        syntax="alert file ( <rule_options> )",
        arguments_and_types={"file_keyword": "literal 'file'"},
        dependencies=["Follows action token"],
        compatibility_restrictions=["Must omit 'service' header and must omit transport options like 'flow'."],
        applicable_protocols_and_buffers=["File processing preprocessors"],
        examples=["alert file ( msg:\"Executable File Delivery\"; file_data; content:\"|4D 5A|\"; sid:1003; )"],
        version_constraints="New in Snort 3. Inspects files extracted across all supported protocols (HTTP, SMTP, SMB, FTP)."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 3: MESSAGE OPTION
    # ═════════════════════════════════════════════════════════════════════════

    "msg": OptionSpec(
        name="msg",
        stage=3,
        category="message",
        syntax="msg:\"<alert_text>\";",
        arguments_and_types={"message": "quoted_string"},
        dependencies=["Positioned as the first rule body option (AST Option #0) by convention"],
        compatibility_restrictions=["Internal double quotes (\") and semicolons (;) must be escaped with backslash (\\\" and \\;). Must not make unverified claims of compromise."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["msg:\"MALWARE-CNC Cobalt Strike outbound beacon request\";", "msg:\"SERVER-WEBAPP Apache Log4j JNDI injection attempt\";"],
        version_constraints="Snort 3 standardizes VRT/Talos naming conventions (<CATEGORY>[-<SUBTYPE>] <Subject> <Activity>)."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 4: FLOW OPTION
    # ═════════════════════════════════════════════════════════════════════════

    "flow": OptionSpec(
        name="flow",
        stage=4,
        category="flow",
        syntax="flow:[to_server|to_client|from_client|from_server][,established|not_established|stateless][,only_stream|no_stream][,only_frag|no_frag];",
        arguments_and_types={
            "direction": "enum('to_server', 'to_client', 'from_client', 'from_server')",
            "state": "enum('established', 'not_established', 'stateless')",
            "stream": "enum('only_stream', 'no_stream')",
            "frag": "enum('only_frag', 'no_frag')"
        },
        dependencies=["Positioned immediately after 'msg' at AST Option #1"],
        compatibility_restrictions=[
            "Strict category exclusivity: AT MOST ONE argument per category.",
            "Prohibited on 'alert file' and 'file_id' rules.",
            "Directional flow (to_server/to_client) conflicts with bidirectional '<>' header.",
            "Connection states ('established', 'not_established') apply only to TCP sessions, not UDP or ICMP."
        ],
        applicable_protocols_and_buffers=["TCP, UDP, IP (connectionless use stateless)"],
        examples=["flow:to_server,established;", "flow:to_client,established,only_stream;", "flow:stateless;"],
        version_constraints="Snort 3 streamlines flow argument parsing and maintains stream tracking across TCP/UDP."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 5.1: STICKY BUFFERS
    # ═════════════════════════════════════════════════════════════════════════

    "http_uri": OptionSpec(
        name="http_uri",
        stage=5,
        category="buffer",
        syntax="http_uri;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires HTTP inspection. Scopes subsequent payload options until next buffer."],
        compatibility_restrictions=["Cannot be used on non-HTTP sessions."],
        applicable_protocols_and_buffers=["HTTP client requests"],
        examples=["http_uri; content:\"/login.php\",fast_pattern,nocase;"],
        version_constraints="In Snort 3, http_uri is a sticky buffer. In Snort 2, 'http_uri' was a content modifier."
    ),

    "http_header": OptionSpec(
        name="http_header",
        stage=5,
        category="buffer",
        syntax="http_header;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires HTTP inspection"],
        compatibility_restrictions=["Inspects normalized HTTP headers (excluding cookies)."],
        applicable_protocols_and_buffers=["HTTP requests and responses"],
        examples=["http_header; content:\"User-Agent: curl\",nocase;"],
        version_constraints="In Snort 3, http_header is sticky. Obsolete PCRE flag /H is removed in favor of sticky http_header."
    ),

    "http_client_body": OptionSpec(
        name="http_client_body",
        stage=5,
        category="buffer",
        syntax="http_client_body;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires HTTP inspection and client request with body"],
        compatibility_restrictions=["Applies only to client requests (POST/PUT data). HTTP response bodies use 'file_data'."],
        applicable_protocols_and_buffers=["HTTP client requests"],
        examples=["http_client_body; content:\"password=\",nocase;"],
        version_constraints="Replaces Snort 2 'http_client_body' content modifier with a sticky buffer."
    ),

    "file_data": OptionSpec(
        name="file_data",
        stage=5,
        category="buffer",
        syntax="file_data;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["File preprocessor or HTTP response with body data"],
        compatibility_restrictions=["Inspects decoded/uncompressed HTTP response bodies and extracted files."],
        applicable_protocols_and_buffers=["HTTP responses, SMTP/IMAP attachments, SMB transfers, alert file rules"],
        examples=["file_data; content:\"|4D 5A|\",offset 0,depth 2;"],
        version_constraints="In Snort 3, file_data is a sticky buffer that works identically across network responses and file rules."
    ),

    "tls_sni": OptionSpec(
        name="tls_sni",
        stage=5,
        category="buffer",
        syntax="tls_sni;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires SSL/TLS inspector with Server Name Indication"],
        compatibility_restrictions=["Valid only for TLS Client Hello packets containing SNI extension."],
        applicable_protocols_and_buffers=["SSL/TLS"],
        examples=["tls_sni; content:\"malicious-c2.example.com\",fast_pattern,nocase;"],
        version_constraints="New in Snort 3. Dedicated sticky buffer for extracted TLS SNI hostname."
    ),

    "dns_query": OptionSpec(
        name="dns_query",
        stage=5,
        category="buffer",
        syntax="dns_query;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires DNS inspector enabled. Scopes subsequent payload matches to normalized domain query."],
        compatibility_restrictions=["Applies to DNS client query transactions. Normalizes domain dot separators so ASCII dots match."],
        applicable_protocols_and_buffers=["DNS queries (UDP/TCP 53)"],
        examples=["dns_query; content:\"carwaded.com\",fast_pattern,nocase;"],
        version_constraints="New in Snort 3 sticky buffer architecture. Replaces complex binary length-byte matching on raw UDP payload."
    ),

    "http_cookie": OptionSpec(
        name="http_cookie",
        stage=5,
        category="buffer",
        syntax="http_cookie;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires HTTP inspection"],
        compatibility_restrictions=["Inspects extracted HTTP Cookie / Set-Cookie headers."],
        applicable_protocols_and_buffers=["HTTP client and server headers"],
        examples=["http_cookie; content:\"session_id=\",nocase;"],
        version_constraints="In Snort 3, http_cookie is a sticky buffer. In Snort 2, it was a content modifier."
    ),

    "http_method": OptionSpec(
        name="http_method",
        stage=5,
        category="buffer",
        syntax="http_method;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires HTTP inspection"],
        compatibility_restrictions=["Inspects normalized request method token (GET, POST, etc.)."],
        applicable_protocols_and_buffers=["HTTP client requests"],
        examples=["http_method; content:\"POST\";"],
        version_constraints="In Snort 3, http_method is a sticky buffer. In Snort 2, it was a content modifier."
    ),

    "http_stat_code": OptionSpec(
        name="http_stat_code",
        stage=5,
        category="buffer",
        syntax="http_stat_code;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Requires HTTP inspection and server response"],
        compatibility_restrictions=["Inspects 3-digit HTTP response status code."],
        applicable_protocols_and_buffers=["HTTP server responses"],
        examples=["http_stat_code; content:\"200\";"],
        version_constraints="In Snort 3, http_stat_code is a sticky buffer. In Snort 2, it was a content modifier."
    ),

    "pkt_data": OptionSpec(
        name="pkt_data",
        stage=5,
        category="buffer",
        syntax="pkt_data;",
        arguments_and_types={"argument": "None (standalone sticky buffer option)"},
        dependencies=["Default initial inspection buffer"],
        compatibility_restrictions=["Used to reset inspection back to normalized packet data from an application sticky buffer."],
        applicable_protocols_and_buffers=["All network protocols"],
        examples=["pkt_data; content:\"raw_packet_bytes\";"],
        version_constraints="Standard Snort 3 sticky buffer to return cursor to raw packet payload."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 5.2: CONTENT AND PATTERN MATCHING
    # ═════════════════════════════════════════════════════════════════════════

    "content": OptionSpec(
        name="content",
        stage=5,
        category="payload",
        syntax="content:[!]\"<pattern>\"[,<modifiers>];",
        arguments_and_types={
            "pattern": "string or hex_bytes (|4D 5A|)",
            "negated": "boolean (leading !)",
            "modifiers": "comma_separated_list"
        },
        dependencies=["Evaluates against currently active sticky buffer"],
        compatibility_restrictions=["Modifiers are comma-separated inside the content clause in Snort 3."],
        applicable_protocols_and_buffers=["All buffers"],
        examples=["content:\"/admin.php\",nocase,fast_pattern;", "content:!\"safe_token\";", "content:\"|4D 5A|\",offset 0,depth 2;"],
        version_constraints="Snort 3 groups modifiers inside the content option separated by commas (e.g. content:\"...\",nocase;)."
    ),

    "fast_pattern": OptionSpec(
        name="fast_pattern",
        stage=5,
        category="payload",
        syntax="content:\"...\",fast_pattern[:only];",
        arguments_and_types={"type": "flag or 'only' or 'offset,length'"},
        dependencies=["Must be attached to a content or regex option"],
        compatibility_restrictions=[
            "At most ONE fast_pattern designation per rule.",
            "PROHIBITED on negated content matches (content:!\"...\")."
        ],
        applicable_protocols_and_buffers=["Content and regex options"],
        examples=["content:\"unique_malware_c2\",fast_pattern,nocase;"],
        version_constraints="In Snort 3, fast_pattern is written as a comma-separated modifier inside content or regex."
    ),

    "nocase": OptionSpec(
        name="nocase",
        stage=5,
        category="payload",
        syntax="content:\"...\",nocase;",
        arguments_and_types={"type": "flag"},
        dependencies=["Must be attached to a content or regex option"],
        compatibility_restrictions=["Applies to alphabetic characters (ASCII). Can also be applied to hex patterns containing ASCII letters."],
        applicable_protocols_and_buffers=["Content and regex options"],
        examples=["content:\"select * from\",nocase;"],
        version_constraints="Standard in Snort 3 as a comma-separated modifier."
    ),

    "pcre": OptionSpec(
        name="pcre",
        stage=5,
        category="payload",
        syntax="pcre:[!]\"/<regex>/[flags]\";",
        arguments_and_types={
            "regex": "pcre_pattern",
            "flags": "string (i, s, m, x, A, E, G, O, R)"
        },
        dependencies=["Evaluates against currently active sticky buffer"],
        compatibility_restrictions=["Obsolete Snort 2 HTTP flags (/U, /H, /B) removed. Use preceding sticky buffer instead."],
        applicable_protocols_and_buffers=["All buffers"],
        examples=["pcre:\"/[?&]cmd=\\d+/i\";", "pcre:!\"/^healthy/m\";"],
        version_constraints="Snort 3 removes inspector-specific pcre flags because sticky buffers define the inspection target."
    ),

    "regex": OptionSpec(
        name="regex",
        stage=5,
        category="payload",
        syntax="regex:[!]\"/<regex>/[flags]\"[,fast_pattern][,nocase];",
        arguments_and_types={
            "regex": "hyperscan_regex",
            "flags": "string (i, s)",
            "modifiers": "fast_pattern, nocase"
        },
        dependencies=["Requires Hyperscan engine support"],
        compatibility_restrictions=["Can take fast_pattern (unlike pcre). Limited to flags 'i' and 's'."],
        applicable_protocols_and_buffers=["All buffers"],
        examples=["regex:\"/malicious_[a-z0-9]+/s\",fast_pattern,nocase;"],
        version_constraints="New in Snort 3. Leverages Intel Hyperscan for high-performance regex evaluation."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 5.3: POSITIONING AND RELATIONSHIPS
    # ═════════════════════════════════════════════════════════════════════════

    "offset": OptionSpec(
        name="offset",
        stage=5,
        category="positioning",
        syntax="content:\"...\",offset <N>;",
        arguments_and_types={"N": "integer (-65535 to 65535)"},
        dependencies=["Attached to content match"],
        compatibility_restrictions=["Mutually exclusive with 'within' on the same content match."],
        applicable_protocols_and_buffers=["Content options"],
        examples=["content:\"recordset\",offset 14,depth 9;"],
        version_constraints="Snort 3 modifier inside content."
    ),

    "depth": OptionSpec(
        name="depth",
        stage=5,
        category="positioning",
        syntax="content:\"...\",depth <N>;",
        arguments_and_types={"N": "integer (1 to 65535)"},
        dependencies=["Attached to content match"],
        compatibility_restrictions=["Mutually exclusive with 'distance' on the same content match."],
        applicable_protocols_and_buffers=["Content options"],
        examples=["content:\"|4D 5A|\",offset 0,depth 2;"],
        version_constraints="Snort 3 modifier inside content."
    ),

    "distance": OptionSpec(
        name="distance",
        stage=5,
        category="positioning",
        syntax="content:\"...\",distance <N>;",
        arguments_and_types={"N": "integer (-65535 to 65535)"},
        dependencies=["Requires a preceding content match in the same buffer"],
        compatibility_restrictions=["Mutually exclusive with 'depth' on the same content match."],
        applicable_protocols_and_buffers=["Content options"],
        examples=["content:\"first\"; content:\"second\",distance 1,within 10;"],
        version_constraints="Snort 3 modifier inside content."
    ),

    "within": OptionSpec(
        name="within",
        stage=5,
        category="positioning",
        syntax="content:\"...\",within <N>;",
        arguments_and_types={"N": "integer (1 to 65535)"},
        dependencies=["Requires a preceding content match in the same buffer"],
        compatibility_restrictions=[
            "Mutually exclusive with 'offset' on the same content match.",
            "CRITICAL: within must be >= length of content pattern."
        ],
        applicable_protocols_and_buffers=["Content options"],
        examples=["content:\"ABC\"; content:\"DEF\",distance 0,within 10;"],
        version_constraints="Snort 3 strictly validates within >= length of pattern and throws fatal compiler error if violated."
    ),

    "isdataat": OptionSpec(
        name="isdataat",
        stage=5,
        category="positioning",
        syntax="isdataat:[!]<location>[,relative];",
        arguments_and_types={
            "location": "integer (0 to 65535)",
            "relative": "flag"
        },
        dependencies=["relative requires a preceding cursor move / content match"],
        compatibility_restrictions=["Valid locations are 0 to 65535."],
        applicable_protocols_and_buffers=["All buffers"],
        examples=["isdataat:100;", "content:\"USER\"; isdataat:29,relative;"],
        version_constraints="Standard Snort 3 syntax."
    ),

    "bufferlen": OptionSpec(
        name="bufferlen",
        stage=5,
        category="positioning",
        syntax="bufferlen:[<|>|=|!|<=|>=]<length>[,relative];",
        arguments_and_types={
            "length": "integer or range (e.g. '>100', '100<>200')",
            "relative": "flag"
        },
        dependencies=["Evaluates against currently active buffer (defaults to pkt_data)"],
        compatibility_restrictions=["Snort 2 'urilen' option is removed. Use 'http_uri; bufferlen:<N>;' instead."],
        applicable_protocols_and_buffers=["All sticky buffers"],
        examples=["http_uri; bufferlen:>100;", "bufferlen:500<>1000;"],
        version_constraints="Replaces Snort 2 urilen. Works generically across any active sticky buffer in Snort 3."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 5.4: NUMERIC AND BINARY INSPECTION
    # ═════════════════════════════════════════════════════════════════════════

    "byte_extract": OptionSpec(
        name="byte_extract",
        stage=5,
        category="binary",
        syntax="byte_extract:<count>,<offset>,<name>[,relative][,multiplier <M>][,align <A>][,endian][,string[,{dec|hex|oct}]][,bitmask <B>];",
        arguments_and_types={
            "count": "integer (1-10 with string, 1-4 binary)",
            "offset": "integer (-65535 to 65535)",
            "name": "variable_identifier"
        },
        dependencies=["Extracted variable can be used in offset, depth, distance, within, byte_test, byte_jump, isdataat"],
        compatibility_restrictions=["Moves detection cursor forward by count bytes."],
        applicable_protocols_and_buffers=["All payload buffers"],
        examples=["byte_extract:2,0,length,relative,big;", "byte_extract:4,0,offset,string,hex;"],
        version_constraints="Standard in Snort 3 with support for bitmask, align, and string conversion."
    ),

    "byte_test": OptionSpec(
        name="byte_test",
        stage=5,
        category="binary",
        syntax="byte_test:<count>,[!]<operator>,<compare>,<offset>[,relative][,endian][,string[,{dec|hex|oct}]][,bitmask <B>];",
        arguments_and_types={
            "count": "integer (1 to 10)",
            "operator": "enum('<', '>', '<=', '>=', '=', '&', '^')",
            "compare": "integer or variable name",
            "offset": "integer or variable name"
        },
        dependencies=["Does not move detection cursor"],
        compatibility_restrictions=["count must be 1 to 10. Valid operators are C relational or bitwise (&, ^)."],
        applicable_protocols_and_buffers=["All payload buffers"],
        examples=["byte_test:2,>,100,0;", "byte_test:2,>,0x7fff,0,relative,little;"],
        version_constraints="Standard Snort 3 syntax."
    ),

    "dsize": OptionSpec(
        name="dsize",
        stage=5,
        category="binary",
        syntax="dsize:[<|>|=|!|<=|>=]<size>;",
        arguments_and_types={"size": "integer (0-65535) or range ('min<>max')"},
        dependencies=["Calculated on payload portion of packet"],
        compatibility_restrictions=["Cannot be used with file rules (file rules do not have packet payloads)."],
        applicable_protocols_and_buffers=["Raw transport payloads (TCP/UDP/ICMP)"],
        examples=["dsize:>1000;", "dsize:300<>400;"],
        version_constraints="Calculates strictly against data portion of packet (excluding transport headers)."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 5.5: PROTOCOL-SPECIFIC OPTIONS
    # ═════════════════════════════════════════════════════════════════════════

    "modbus_func": OptionSpec(
        name="modbus_func",
        stage=5,
        category="protocol",
        syntax="modbus_func:<function_code>;",
        arguments_and_types={"function_code": "integer (1-255) or named function (e.g. 'read_coils', 'write_single_coil')"},
        dependencies=["Requires Modbus inspector"],
        compatibility_restrictions=["Applicable only to Modbus SCADA protocol rules."],
        applicable_protocols_and_buffers=["Modbus"],
        examples=["modbus_func:write_single_coil;", "modbus_func:16;"],
        version_constraints="Snort 3 built-in Modbus inspector option."
    ),

    "modbus_unit": OptionSpec(
        name="modbus_unit",
        stage=5,
        category="protocol",
        syntax="modbus_unit:<unit_id>;",
        arguments_and_types={"unit_id": "integer (0-255)"},
        dependencies=["Requires Modbus inspector"],
        compatibility_restrictions=["Applicable only to Modbus SCADA protocol rules."],
        applicable_protocols_and_buffers=["Modbus"],
        examples=["modbus_unit:73;"],
        version_constraints="Snort 3 built-in Modbus inspector option."
    ),

    "sip_method": OptionSpec(
        name="sip_method",
        stage=5,
        category="protocol",
        syntax="sip_method:<method>;",
        arguments_and_types={"method": "string (e.g. 'INVITE', 'REGISTER', 'CANCEL', 'BYE', 'ACK')"},
        dependencies=["Requires SIP inspector"],
        compatibility_restrictions=["Applicable only to SIP VoIP rules."],
        applicable_protocols_and_buffers=["SIP"],
        examples=["sip_method:INVITE;", "sip_method:REGISTER;"],
        version_constraints="Snort 3 built-in SIP inspector option."
    ),

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 6: SUPPORTING OPTIONS & METADATA
    # ═════════════════════════════════════════════════════════════════════════

    "classtype": OptionSpec(
        name="classtype",
        stage=6,
        category="metadata",
        syntax="classtype:<class_name>;",
        arguments_and_types={"class_name": "string (from valid Snort 3 classtypes table)"},
        dependencies=["Assigns default rule priority based on classification"],
        compatibility_restrictions=["Must match an established Snort 3 classtype. At most ONE classtype per rule."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["classtype:trojan-activity;", "classtype:web-application-attack;", "classtype:malware-cnc;"],
        version_constraints="Standard Snort 3 classtype mapping."
    ),

    "reference": OptionSpec(
        name="reference",
        stage=6,
        category="metadata",
        syntax="reference:<system>,<id>;",
        arguments_and_types={
            "system": "enum('cve', 'url', 'bugtraq', 'nessus', 'arachnids')",
            "id": "identifier_string"
        },
        dependencies=["Can be declared multiple times in a single rule"],
        compatibility_restrictions=["Never invent CVEs or references. Must be strictly grounded in verified evidence."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["reference:cve,2021-44228;", "reference:url,attack.mitre.org/techniques/T1059/;"],
        version_constraints="Standard Snort 3 reference tracking."
    ),

    "sid": OptionSpec(
        name="sid",
        stage=6,
        category="metadata",
        syntax="sid:<integer>;",
        arguments_and_types={"integer": "integer (>= 1000000 for local custom rules)"},
        dependencies=["Mandatory rule option"],
        compatibility_restrictions=["Must be unique across the active ruleset. Custom user rules must be >= 1,000,000. Allocated by deterministic Python function."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["sid:1000001;", "sid:9001001;"],
        version_constraints="Snort 3 mandates positive integer SID."
    ),

    "rev": OptionSpec(
        name="rev",
        stage=6,
        category="metadata",
        syntax="rev:<integer>;",
        arguments_and_types={"integer": "positive_integer (starts at 1)"},
        dependencies=["Requires 'sid' option"],
        compatibility_restrictions=["Incremented on every modification of rule logic. Allocated by deterministic Python function."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["rev:1;", "rev:2;"],
        version_constraints="Standard Snort 3 rule revision tracking."
    ),

    "gid": OptionSpec(
        name="gid",
        stage=6,
        category="identity",
        syntax="gid:<integer>;",
        arguments_and_types={"integer": "integer (default is 1 for standard text rules)"},
        dependencies=["None"],
        compatibility_restrictions=["GID 1 is for standard text rules, GID 3 for shared-object rules, GIDs > 100 for built-ins."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["gid:1;"],
        version_constraints="Standard Snort 3 generator ID."
    ),

    "priority": OptionSpec(
        name="priority",
        stage=6,
        category="metadata",
        syntax="priority:<integer>;",
        arguments_and_types={"integer": "integer (1 to 2147483647, 1 being most severe)"},
        dependencies=["Overrides classtype default priority if set"],
        compatibility_restrictions=["Must be positive integer."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["priority:1;", "priority:2;"],
        version_constraints="Snort 3 standard priority override."
    ),

    "metadata": OptionSpec(
        name="metadata",
        stage=6,
        category="metadata",
        syntax="metadata:<key> <value>[, <key> <value>];",
        arguments_and_types={"key_value_pairs": "comma-separated key value pairs"},
        dependencies=["None"],
        compatibility_restrictions=["Do not put 'service' declarations inside metadata in Snort 3; use the standalone 'service' option."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["metadata:policy max-detect-ips drop, ruleset community;", "metadata:impact_flag red;"],
        version_constraints="In Snort 3, service declarations were moved out of metadata into the standalone 'service' option."
    ),

    "service": OptionSpec(
        name="service",
        stage=6,
        category="general",
        syntax="service:<service_name>[, <service_name>];",
        arguments_and_types={"service_name": "comma-separated service names (e.g. http, ssl, dns, smtp)"},
        dependencies=["Traditional 7-tuple rule headers only"],
        compatibility_restrictions=["Must NOT be used with a service-rule header (e.g. 'alert http'). Must NOT be used in a file rule ('alert file')."],
        applicable_protocols_and_buffers=["Traditional rules (tcp/udp)"],
        examples=["service:http;", "service:http,imap,pop3;"],
        version_constraints="Standalone option in Snort 3; replaces legacy service metadata."
    ),

    "rem": OptionSpec(
        name="rem",
        stage=6,
        category="general",
        syntax="rem:\"<comment_text>\";",
        arguments_and_types={"comment_text": "string"},
        dependencies=["None"],
        compatibility_restrictions=["No effect on detection. Used for human commentary."],
        applicable_protocols_and_buffers=["All rules"],
        examples=['rem:"Detects suspicious URI structure in C2 beacon";'],
        version_constraints="Standard Snort 3 comment option."
    ),

    "file_meta": OptionSpec(
        name="file_meta",
        stage=6,
        category="general",
        syntax="file_meta:type <type>,id <id>[,category \"<cat>\"][,version <ver>];",
        arguments_and_types={"meta_args": "comma-separated key-value tokens"},
        dependencies=["Only valid in file_id rules"],
        compatibility_restrictions=["Must only be used when header is 'file_id'."],
        applicable_protocols_and_buffers=["file_id rules"],
        examples=['file_meta:type MSEXE,id 21,category "Executables";'],
        version_constraints="Snort 3 file-identification metadata."
    ),

    "flags": OptionSpec(
        name="flags",
        stage=6,
        category="non_payload",
        syntax="flags:[!|*|+]<flags>[,<mask_flags>];",
        arguments_and_types={"flags": "string containing flag characters (F, S, R, P, A, U, E, C, 0)"},
        dependencies=["Requires TCP protocol"],
        compatibility_restrictions=["Cannot be used with UDP or ICMP."],
        applicable_protocols_and_buffers=["TCP headers"],
        examples=["flags:S;", "flags:SA;", "flags:!F,12;"],
        version_constraints="Standard Snort 3 TCP flag filter."
    ),

    "ttl": OptionSpec(
        name="ttl",
        stage=6,
        category="non_payload",
        syntax="ttl:[<|>|=]<integer>;",
        arguments_and_types={"ttl": "operator and integer (0-255)"},
        dependencies=["IP layer"],
        compatibility_restrictions=["Often environment-dependent; use with caution."],
        applicable_protocols_and_buffers=["IP headers"],
        examples=["ttl:64;", "ttl:<10;"],
        version_constraints="Standard Snort 3 IP TTL check."
    ),

    "tos": OptionSpec(
        name="tos",
        stage=6,
        category="non_payload",
        syntax="tos:[!]<integer>;",
        arguments_and_types={"tos": "integer (0-255)"},
        dependencies=["IP layer"],
        compatibility_restrictions=["None"],
        applicable_protocols_and_buffers=["IP headers"],
        examples=["tos:0;", "tos:!4;"],
        version_constraints="Standard Snort 3 Type of Service check."
    ),

    "id": OptionSpec(
        name="id",
        stage=6,
        category="non_payload",
        syntax="id:<integer>;",
        arguments_and_types={"id": "integer (0-65535)"},
        dependencies=["IP layer"],
        compatibility_restrictions=["Environment-dependent; use with caution."],
        applicable_protocols_and_buffers=["IP headers"],
        examples=["id:31337;", "id:0;"],
        version_constraints="Standard Snort 3 IP ID check."
    ),

    "fragoffset": OptionSpec(
        name="fragoffset",
        stage=6,
        category="non_payload",
        syntax="fragoffset:[!|<|>]<integer>;",
        arguments_and_types={"offset": "integer"},
        dependencies=["IP layer"],
        compatibility_restrictions=["None"],
        applicable_protocols_and_buffers=["IP headers"],
        examples=["fragoffset:0;", "fragoffset:>0;"],
        version_constraints="Standard Snort 3 fragment offset check."
    ),

    "fragbits": OptionSpec(
        name="fragbits",
        stage=6,
        category="non_payload",
        syntax="fragbits:[+*!]<bits>;",
        arguments_and_types={"bits": "string containing M, D, R"},
        dependencies=["IP layer"],
        compatibility_restrictions=["None"],
        applicable_protocols_and_buffers=["IP headers"],
        examples=["fragbits:M;", "fragbits:D;"],
        version_constraints="Standard Snort 3 fragmentation bits check."
    ),

    "ip_proto": OptionSpec(
        name="ip_proto",
        stage=6,
        category="non_payload",
        syntax="ip_proto:[!|>|<]<proto>;",
        arguments_and_types={"proto": "protocol name or integer (0-255)"},
        dependencies=["IP layer"],
        compatibility_restrictions=["None"],
        applicable_protocols_and_buffers=["IP headers"],
        examples=["ip_proto:tcp;", "ip_proto:udp;", "ip_proto:47;"],
        version_constraints="Standard Snort 3 IP protocol field check."
    ),

    "seq": OptionSpec(
        name="seq",
        stage=6,
        category="non_payload",
        syntax="seq:<integer>;",
        arguments_and_types={"seq": "integer"},
        dependencies=["TCP layer"],
        compatibility_restrictions=["TCP only."],
        applicable_protocols_and_buffers=["TCP headers"],
        examples=["seq:0;"],
        version_constraints="Standard Snort 3 sequence number check."
    ),

    "ack": OptionSpec(
        name="ack",
        stage=6,
        category="non_payload",
        syntax="ack:<integer>;",
        arguments_and_types={"ack": "integer"},
        dependencies=["TCP layer"],
        compatibility_restrictions=["TCP only."],
        applicable_protocols_and_buffers=["TCP headers"],
        examples=["ack:0;"],
        version_constraints="Standard Snort 3 acknowledgement number check."
    ),

    "window": OptionSpec(
        name="window",
        stage=6,
        category="non_payload",
        syntax="window:[!]<integer>;",
        arguments_and_types={"window": "integer"},
        dependencies=["TCP layer"],
        compatibility_restrictions=["TCP only."],
        applicable_protocols_and_buffers=["TCP headers"],
        examples=["window:5840;", "window:!0;"],
        version_constraints="Standard Snort 3 window size check."
    ),

    "itype": OptionSpec(
        name="itype",
        stage=6,
        category="non_payload",
        syntax="itype:[<|>]<integer>;",
        arguments_and_types={"itype": "integer (0-255)"},
        dependencies=["ICMP layer"],
        compatibility_restrictions=["ICMP only."],
        applicable_protocols_and_buffers=["ICMP headers"],
        examples=["itype:8;", "itype:0;"],
        version_constraints="Standard Snort 3 ICMP type check."
    ),

    "icode": OptionSpec(
        name="icode",
        stage=6,
        category="non_payload",
        syntax="icode:[<|>]<integer>;",
        arguments_and_types={"icode": "integer (0-255)"},
        dependencies=["ICMP layer"],
        compatibility_restrictions=["ICMP only."],
        applicable_protocols_and_buffers=["ICMP headers"],
        examples=["icode:0;"],
        version_constraints="Standard Snort 3 ICMP code check."
    ),

    "icmp_id": OptionSpec(
        name="icmp_id",
        stage=6,
        category="non_payload",
        syntax="icmp_id:<integer>;",
        arguments_and_types={"icmp_id": "integer"},
        dependencies=["ICMP layer"],
        compatibility_restrictions=["ICMP only."],
        applicable_protocols_and_buffers=["ICMP headers"],
        examples=["icmp_id:100;"],
        version_constraints="Standard Snort 3 ICMP ID check."
    ),

    "icmp_seq": OptionSpec(
        name="icmp_seq",
        stage=6,
        category="non_payload",
        syntax="icmp_seq:<integer>;",
        arguments_and_types={"icmp_seq": "integer"},
        dependencies=["ICMP layer"],
        compatibility_restrictions=["ICMP only."],
        applicable_protocols_and_buffers=["ICMP headers"],
        examples=["icmp_seq:1;"],
        version_constraints="Standard Snort 3 ICMP sequence check."
    ),

    "flowbits": OptionSpec(
        name="flowbits",
        stage=6,
        category="non_payload",
        syntax="flowbits:<operation>[,<bit_name>];",
        arguments_and_types={
            "operation": "enum('set', 'unset', 'isset', 'isnotset', 'noalert')",
            "bit_name": "string identifier"
        },
        dependencies=["Transport flow tracking"],
        compatibility_restrictions=["Enables state tracking across multiple packets in a flow."],
        applicable_protocols_and_buffers=["TCP/UDP flows"],
        examples=["flowbits:set,logged_in;", "flowbits:isset,logged_in;", "flowbits:noalert;"],
        version_constraints="Standard Snort 3 flowbit state tracking."
    ),

    "file_type": OptionSpec(
        name="file_type",
        stage=6,
        category="non_payload",
        syntax="file_type:\"<type>[,<version>]\";",
        arguments_and_types={"type": "string file type identifier"},
        dependencies=["Requires file identification preprocessor"],
        compatibility_restrictions=["Must match identified file types."],
        applicable_protocols_and_buffers=["Files"],
        examples=['file_type:"PDF";', 'file_type:"PDF,1.6";', 'file_type:"MSEXE";'],
        version_constraints="Snort 3 file type filter."
    ),

    "stream_size": OptionSpec(
        name="stream_size",
        stage=6,
        category="non_payload",
        syntax="stream_size:<direction>,<operator>,<bytes>;",
        arguments_and_types={
            "direction": "enum('server', 'client', 'both', 'either')",
            "operator": "enum('<', '>', '=')",
            "bytes": "integer"
        },
        dependencies=["Reassembled stream"],
        compatibility_restrictions=["Requires TCP stream."],
        applicable_protocols_and_buffers=["TCP streams"],
        examples=["stream_size:server,>,1000;", "stream_size:both,<,500;"],
        version_constraints="Standard Snort 3 stream size check."
    ),

    "stream_reassemble": OptionSpec(
        name="stream_reassemble",
        stage=6,
        category="non_payload",
        syntax="stream_reassemble:<action>[,<direction>];",
        arguments_and_types={
            "action": "enum('enable', 'disable')",
            "direction": "enum('server', 'client', 'both')"
        },
        dependencies=["TCP stream"],
        compatibility_restrictions=["Stream control option."],
        applicable_protocols_and_buffers=["TCP streams"],
        examples=["stream_reassemble:enable,server;", "stream_reassemble:disable,both;"],
        version_constraints="Snort 3 stream reassembly control."
    ),

    "detection_filter": OptionSpec(
        name="detection_filter",
        stage=6,
        category="post_detection",
        syntax="detection_filter:track <by_src|by_dst>,count <count>,seconds <seconds>;",
        arguments_and_types={
            "track": "enum('by_src', 'by_dst')",
            "count": "positive_integer",
            "seconds": "positive_integer"
        },
        dependencies=["Rule-level match rate filter"],
        compatibility_restrictions=["Only ONE detection_filter permitted per rule. Evaluated last after all other options."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["detection_filter:track by_src,count 30,seconds 60;", "detection_filter:track by_dst,count 5,seconds 10;"],
        version_constraints="Standard Snort 3 match rate filter."
    ),

    "tag": OptionSpec(
        name="tag",
        stage=6,
        category="post_detection",
        syntax="tag:<scope>,<units> <count>;",
        arguments_and_types={
            "scope": "enum('session', 'host_src', 'host_dst')",
            "units": "enum('packets', 'bytes', 'seconds')",
            "count": "positive_integer"
        },
        dependencies=["Post-detection logging"],
        compatibility_restrictions=["Requests additional packet logging after event."],
        applicable_protocols_and_buffers=["All rules"],
        examples=["tag:session,packets 10;", "tag:host_src,seconds 60;"],
        version_constraints="Standard Snort 3 tag option."
    ),

    "replace": OptionSpec(
        name="replace",
        stage=6,
        category="post_detection",
        syntax="replace:\"<replacement_string>\";",
        arguments_and_types={"replacement_string": "string of equal length to preceding content"},
        dependencies=["Requires 'rewrite' rule action and preceding 'content' match on raw packet data"],
        compatibility_restrictions=["Operates on raw packets only. Requires rewrite action. Not used for alert rules."],
        applicable_protocols_and_buffers=["Raw packet data"],
        examples=['replace:"EFGH";'],
        version_constraints="Standard Snort 3 payload replacement."
    )
}


# ─────────────────────────────────────────────────────────────────────────────
# 2. QUERY & LOOKUP HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_option_spec(name: str) -> Optional[OptionSpec]:
    """Retrieve the formal 9-field specification for a Snort 3 option."""
    clean_name = name.lower().strip()
    return SNORT3_OPTION_CATALOGUE.get(clean_name)


def get_stage_catalogue(stage: int) -> Dict[str, OptionSpec]:
    """Filter catalogue for all options belonging to a specific HDIRC stage (2 to 7)."""
    return {k: v for k, v in SNORT3_OPTION_CATALOGUE.items() if v.stage == stage}


def format_stage_catalogue_for_llm(stage: int) -> str:
    """Format full stage catalogue as authoritative reference instructions for LLM prompts."""
    stage_opts = get_stage_catalogue(stage)
    if not stage_opts:
        return ""
    lines = [f"### Authoritative Snort 3 Catalogue for Stage {stage}:"]
    for opt in stage_opts.values():
        lines.append(opt.format_summary())
    return "\n\n".join(lines)


def list_options_by_category(category: str) -> List[OptionSpec]:
    """List all options belonging to a specific functional category."""
    cat_clean = category.lower().strip()
    return [v for v in SNORT3_OPTION_CATALOGUE.values() if v.category.lower() == cat_clean]


# ─────────────────────────────────────────────────────────────────────────────
# 3. DEPRECATED SNORT 2 OPTIONS & PROHIBITED KEYWORDS
# Grounded in asset/snort_upgrade.text
# ─────────────────────────────────────────────────────────────────────────────

from snort_pipeline.snort2_to_snort3_migration import (
    STRICT_REJECT_OPTIONS,
    DELETED_PCRE_MODIFIERS,
    REWRITABLE_OPTIONS,
    Snort2CompatibilityValidator
)

DEPRECATED_SNORT2_OPTIONS: Dict[str, str] = STRICT_REJECT_OPTIONS

def check_deprecated_snort2_option(name: str) -> Optional[str]:
    """Check if an option name corresponds to a deprecated/prohibited Snort 2 keyword."""
    clean = name.lower().strip()
    if clean in STRICT_REJECT_OPTIONS:
        return STRICT_REJECT_OPTIONS[clean]
    if clean in REWRITABLE_OPTIONS:
        return f"Legacy Snort 2 syntax '{clean}'. Recommended Snort 3 equivalent: {REWRITABLE_OPTIONS[clean]['snort3_option']}"
    return None


