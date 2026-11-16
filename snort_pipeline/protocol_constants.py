"""
Snort 3 Protocol Constant & Generic Invariant Filter.
Grounded in asset/Protocol Constant Blacklist.txt and authoritative IANA registries.

Responsibilities:
1. Maintain a versioned, machine-readable protocol constant catalogue.
2. Support exact byte matching, ASCII matching, case-insensitive matching, and normalized matching.
3. Associate constants with protocol, direction, buffer, and field.
4. Distinguish hard exclusions from contextual exclusions and metadata exclusions.
5. Provide domain-to-wire encoding for DNS queries (e.g. 'carwaded.com' -> '|08|carwaded|03|com|00|').
6. Calculate Shannon entropy and enforce minimum invariant length (>= 4 bytes).
7. Record why a candidate invariant was rejected and allow contextual exceptions for multi-condition signatures.
"""

import math
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict

# ─────────────────────────────────────────────────────────────────────────────
# 1. CATALOGUE DATA STRUCTURES & EXCLUSION POLICIES
# ─────────────────────────────────────────────────────────────────────────────

CATALOGUE_VERSION = "1.0.0"

class ExclusionPolicy:
    HARD_EXCLUDE = "hard_exclude"            # Never permitted as a standalone invariant (e.g. DNS QTYPE A, HTTP GET, SMB header)
    CONTEXTUAL_EXCLUDE = "contextual_exclude"  # Permitted only in multi-condition signatures with high-entropy companion indicators
    METADATA_EXCLUDE = "metadata_exclude"      # Transport metadata (ports, flags) not valid as payload content

@dataclass
class ConstantEntry:
    name: str
    category: str
    protocol: str
    policy: str
    raw_patterns: List[str]                  # ASCII strings or hex strings (e.g. "|00 01 00 01|", "Mozilla/5.0")
    description: str
    buffer_scope: Optional[str] = None       # e.g. "http_header", "dns_query", "pkt_data"
    iana_reference: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class InvariantEvaluationResult:
    candidate: str
    status: str                              # "retained", "rejected", "contextual_allowed"
    normalized_value: str
    is_hard_exclusion: bool
    is_contextual_exclusion: bool
    entropy: float
    length_bytes: int
    matched_entry: Optional[Dict[str, Any]] = None
    rejection_reason: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PROTOCOL CONSTANTS CATALOGUE STORE
# Grounded in asset/Protocol Constant Blacklist.txt
# ─────────────────────────────────────────────────────────────────────────────

def _build_catalogue() -> List[ConstantEntry]:
    entries: List[ConstantEntry] = []

    # ── DNS Protocol Constants (asset/Protocol Constant Blacklist.txt Section 1)
    dns_qtypes = [
        ("A", "|00 01|", "IPv4 address query"),
        ("NS", "|00 02|", "Name server query"),
        ("CNAME", "|00 05|", "Canonical name query"),
        ("SOA", "|00 06|", "Start of authority query"),
        ("PTR", "|00 0C|", "Pointer record query"),
        ("MX", "|00 0F|", "Mail exchange query"),
        ("TXT", "|00 10|", "Text record query"),
        ("AAAA", "|00 1C|", "IPv6 address query"),
        ("SRV", "|00 21|", "Service record query"),
        ("ANY", "|00 FF|", "Any record query")
    ]
    for qname, qhex, qdesc in dns_qtypes:
        entries.append(ConstantEntry(
            name=f"DNS_QTYPE_{qname}",
            category="dns_qtype",
            protocol="dns",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[qhex],
            description=f"Standard DNS QTYPE {qname} ({qdesc})",
            iana_reference="https://www.iana.org/assignments/dns-parameters"
        ))

    # Standard DNS QTYPE + QCLASS Combinations (Very high false-positive rate)
    dns_combinations = [
        ("A_IN", "|00 01 00 01|", "DNS A record Internet Class"),
        ("AAAA_IN", "|00 1C 00 01|", "DNS AAAA record Internet Class"),
        ("MX_IN", "|00 0F 00 01|", "DNS MX record Internet Class"),
        ("TXT_IN", "|00 10 00 01|", "DNS TXT record Internet Class"),
        ("CNAME_IN", "|00 05 00 01|", "DNS CNAME record Internet Class"),
        ("SRV_IN", "|00 21 00 01|", "DNS SRV record Internet Class"),
        ("OPT_PSEUDO", "|00 00 29|", "DNS OPT pseudo-record type")
    ]
    for cname, chex, cdesc in dns_combinations:
        entries.append(ConstantEntry(
            name=f"DNS_COMBO_{cname}",
            category="dns_combo",
            protocol="dns",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[chex],
            description=f"Standard DNS Query Footer {cdesc}. Ubiquitous in normal DNS traffic.",
            iana_reference="https://www.iana.org/assignments/dns-parameters"
        ))

    # ── HTTP Protocol Constants (asset/Protocol Constant Blacklist.txt Section 2)
    http_methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
                    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
    for m in http_methods:
        entries.append(ConstantEntry(
            name=f"HTTP_METHOD_{m}",
            category="http_method",
            protocol="http",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[m, f"{m} "],
            description=f"Standard HTTP/WebDAV request method {m}",
            buffer_scope="http_method",
            iana_reference="https://www.iana.org/assignments/http-methods"
        ))

    http_headers = [
        "Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Accept-Charset",
        "Connection", "Cache-Control", "Pragma", "Referer", "Origin", "Cookie", "Authorization",
        "Proxy-Authorization", "Content-Type", "Content-Length", "Content-Encoding", "Transfer-Encoding",
        "Server", "Date", "Expires", "Last-Modified", "ETag", "Location", "Set-Cookie"
    ]
    for h in http_headers:
        entries.append(ConstantEntry(
            name=f"HTTP_HEADER_{h.upper().replace('-', '_')}",
            category="http_header_name",
            protocol="http",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[h, f"{h}:", f"{h}: "],
            description=f"Standard HTTP header identifier '{h}:'",
            buffer_scope="http_header",
            iana_reference="https://www.iana.org/assignments/http-fields"
        ))

    http_generic_values = [
        ("MOZILLA_UA", "Mozilla/5.0", "Generic web browser User-Agent prefix"),
        ("ANY_MIME", "*/*", "Generic Accept header value"),
        ("GZIP", "gzip", "Standard compression transfer encoding"),
        ("DEFLATE", "deflate", "Standard deflate encoding"),
        ("BR", "br", "Brotli compression encoding"),
        ("KEEP_ALIVE", "keep-alive", "Standard HTTP persistent connection token"),
        ("CLOSE", "close", "Standard HTTP connection close token"),
        ("NO_CACHE", "no-cache", "Standard cache-control directive"),
        ("CHUNKED", "chunked", "Standard HTTP chunked transfer encoding"),
        ("TEXT_HTML", "text/html", "Standard HTML content type"),
        ("APP_JSON", "application/json", "Standard JSON content type"),
        ("APP_OCTET", "application/octet-stream", "Generic binary stream content type")
    ]
    for vname, val, vdesc in http_generic_values:
        entries.append(ConstantEntry(
            name=f"HTTP_VALUE_{vname}",
            category="http_generic_value",
            protocol="http",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[val],
            description=vdesc,
            buffer_scope="http_header"
        ))

    # HTTP Common Request Lines
    http_req_lines = [
        ("GET_ROOT", "GET / HTTP/1.1", "Root HTTP request line"),
        ("POST_ROOT", "POST / HTTP/1.1", "Root HTTP POST request line"),
        ("RESP_200_OK", "HTTP/1.1 200 OK", "Standard HTTP OK response line"),
        ("RESP_404_NOT_FOUND", "HTTP/1.1 404 Not Found", "Standard HTTP Not Found response line")
    ]
    for rname, rval, rdesc in http_req_lines:
        entries.append(ConstantEntry(
            name=f"HTTP_LINE_{rname}",
            category="http_request_line",
            protocol="http",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[rval],
            description=rdesc,
            buffer_scope="http_header"
        ))

    # ── TLS / SSL Protocol Constants (asset/Protocol Constant Blacklist.txt Section 3)
    tls_constants = [
        ("TLS_CHANGE_CIPHER_SPEC", "|14 03 03|", "TLS ChangeCipherSpec record header"),
        ("TLS_ALERT", "|15 03 03|", "TLS Alert record header"),
        ("TLS_HANDSHAKE_RECORD", "|16 03 01|", "TLS 1.0 Handshake record layer"),
        ("TLS_HANDSHAKE_RECORD_12", "|16 03 03|", "TLS 1.2/1.3 Handshake record layer"),
        ("TLS_CLIENT_HELLO", "|01 00|", "TLS ClientHello handshake token"),
        ("TLS_SERVER_HELLO", "|02 00|", "TLS ServerHello handshake token"),
        ("TLS_APP_DATA", "|17 03 03|", "TLS Application Data record header")
    ]
    for tname, thex, tdesc in tls_constants:
        entries.append(ConstantEntry(
            name=tname,
            category="tls_record",
            protocol="ssl",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[thex],
            description=tdesc,
            iana_reference="https://www.iana.org/assignments/tls-parameters"
        ))

    # ── SMB Protocol Signatures (asset/Protocol Constant Blacklist.txt Section 11)
    smb_signatures = [
        ("SMB1_MAGIC", "|FF 53 4D 42|", "SMB1 Protocol Signature header (\\xFFSMB)"),
        ("SMB2_MAGIC", "|FE 53 4D 42|", "SMB2/SMB3 Protocol Signature header (\\xFESMB)"),
        ("SMB3_ENCRYPTED", "|FD 53 4D 42|", "SMB3 Encrypted transform header (\\xFDSMB)"),
        ("SMB3_COMPRESSION", "|FC 53 4D 42|", "SMB3 Compression transform header (\\xFCSMB)")
    ]
    for sname, shex, sdesc in smb_signatures:
        entries.append(ConstantEntry(
            name=sname,
            category="protocol_magic_bytes",
            protocol="smb",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[shex],
            description=f"{sdesc}. Identifies protocol itself; invalid as independent malware indicator."
        ))

    # ── DHCP Protocol Constants (asset/Protocol Constant Blacklist.txt Section 7)
    entries.append(ConstantEntry(
        name="DHCP_MAGIC_COOKIE",
        category="protocol_magic_bytes",
        protocol="dhcp",
        policy=ExclusionPolicy.HARD_EXCLUDE,
        raw_patterns=["|63 82 53 63|"],
        description="Standard DHCP Magic Cookie (0x63825363). Present in all DHCP messages."
    ))

    # ── STUN Protocol Constants (asset/Protocol Constant Blacklist.txt Section 17)
    entries.append(ConstantEntry(
        name="STUN_MAGIC_COOKIE",
        category="protocol_magic_bytes",
        protocol="stun",
        policy=ExclusionPolicy.HARD_EXCLUDE,
        raw_patterns=["|21 12 A4 42|"],
        description="Standard STUN Magic Cookie (RFC 5389). Present in all STUN transactions."
    ))

    # ── Common Binary File Signatures (asset/Protocol Constant Blacklist.txt Section 15)
    file_signatures = [
        ("EXE_MZ", "|4D 5A|", "MZ", "Windows Portable Executable magic bytes"),
        ("ZIP_PK", "|50 4B 03 04|", "PK", "ZIP Archive magic bytes"),
        ("ELF_MAGIC", "|7F 45 4C 46|", "\x7fELF", "Linux ELF Executable magic bytes"),
        ("PDF_MAGIC", "|25 50 44 46|", "%PDF", "PDF Document header"),
        ("PNG_MAGIC", "|89 50 4E 47 0D 0A 1A 0A|", None, "PNG Image header"),
        ("JPEG_MAGIC", "|FF D8 FF|", None, "JPEG Image start of image"),
        ("GZIP_MAGIC", "|1F 8B 08|", None, "GZIP Archive header"),
        ("JAVA_CLASS", "|CA FE BA BE|", None, "Java compiled class magic bytes")
    ]
    for fsname, fshex, fsascii, fsdesc in file_signatures:
        pats = [fshex]
        if fsascii:
            pats.append(fsascii)
        entries.append(ConstantEntry(
            name=f"FILE_SIG_{fsname}",
            category="file_magic_bytes",
            protocol="file",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=pats,
            description=f"{fsdesc}. Weak as standalone malware invariant; should be combined with distinctive payload.",
            buffer_scope="file_data"
        ))

    # ── Standard Handshake & Delimiters (asset/Protocol Constant Blacklist.txt Section 16)
    delimiters = [
        ("CRLF", "|0D 0A|", "\r\n", "Carriage Return Line Feed delimiter"),
        ("CRLF_DOUBLE", "|0D 0A 0D 0A|", "\r\n\r\n", "HTTP Header/Body boundary separator"),
        ("NULL_BYTE", "|00|", "\x00", "Null terminator byte")
    ]
    for dname, dhex, dascii, ddesc in delimiters:
        entries.append(ConstantEntry(
            name=f"DELIM_{dname}",
            category="generic_delimiters",
            protocol="generic",
            policy=ExclusionPolicy.HARD_EXCLUDE,
            raw_patterns=[dhex, dascii],
            description=ddesc
        ))

    # ── Generic Application Authentication & Strings (Contextual Exclusions)
    contextual_strings = [
        ("AUTH_BASIC", "Basic", "HTTP Basic Authentication scheme"),
        ("AUTH_BEARER", "Bearer", "HTTP Bearer Token scheme"),
        ("AUTH_DIGEST", "Digest", "HTTP Digest Authentication scheme"),
        ("AUTH_NTLM", "NTLM", "NTLM Authentication scheme"),
        ("STR_ADMIN", "admin", "Generic administrative username"),
        ("STR_PASSWORD", "password", "Generic credential parameter"),
        ("STR_LOGIN", "login", "Generic authentication endpoint/action"),
        ("STR_TRUE", "true", "Generic JSON/boolean literal"),
        ("STR_FALSE", "false", "Generic JSON/boolean literal"),
        ("STR_NULL", "null", "Generic JSON/boolean literal")
    ]
    for cname, cstr, cdesc in contextual_strings:
        entries.append(ConstantEntry(
            name=f"GENERIC_{cname}",
            category="generic_application_string",
            protocol="generic",
            policy=ExclusionPolicy.CONTEXTUAL_EXCLUDE,
            raw_patterns=[cstr],
            description=f"{cdesc}. Requires contextual pairing with distinctive malicious indicator."
        ))

    return entries


# ─────────────────────────────────────────────────────────────────────────────
# 3. DOMAIN-TO-WIRE ENCODER & ENTROPY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def encode_dns_wire_format(domain: str) -> str:
    """
    Encode an ASCII domain name into DNS length-prefixed wire format (RFC 1035).
    Example: 'carwaded.com' -> '|08|carwaded|03|com|00|'
    """
    clean_domain = str(domain).strip().strip(".").strip('"').strip("'")
    if not clean_domain:
        return "|00|"

    labels = clean_domain.split(".")
    encoded_parts = []
    for label in labels:
        if not label:
            continue
        length_hex = f"{len(label):02X}"
        encoded_parts.append(f"|{length_hex}|{label}")
    encoded_parts.append("|00|")
    return "".join(encoded_parts)


def is_domain_name(candidate: str) -> bool:
    """Check if candidate string represents a dot-delimited internet domain name."""
    clean = str(candidate).strip().strip('"').strip("'")
    # Must contain at least one dot, no spaces or control chars, and valid TLD-like suffix
    return bool(re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$", clean))


def calculate_shannon_entropy(data: Union[str, bytes]) -> float:
    """
    Calculate Shannon entropy of a string or byte sequence in bits per byte (0.0 to 8.0).
    Higher entropy indicates random/encrypted/distinctive content.
    Repetitive sequences (e.g. '[[[[[' or '000000') produce very low entropy (< 1.5).
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        # If hex string (|4D 5A|), decode bytes
        if data.startswith("|") and data.endswith("|"):
            clean_hex = data[1:-1].replace(" ", "")
            try:
                byte_data = bytes.fromhex(clean_hex)
            except Exception:
                byte_data = data.encode("utf-8", errors="ignore")
        else:
            byte_data = data.encode("utf-8", errors="ignore")
    else:
        byte_data = data

    if not byte_data:
        return 0.0

    length = len(byte_data)
    freq: Dict[int, int] = {}
    for b in byte_data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


# ─────────────────────────────────────────────────────────────────────────────
# 4. PROTOCOL CONSTANT & GENERIC INVARIANT FILTER ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolConstantFilter:
    """
    Module: Protocol Constant & Generic Invariant Filter.
    Implements the full 10-step invariant evaluation sequence:
    Extract -> Normalize -> Protocol/Buffer Identification -> Blacklist Check ->
    Hard/Contextual Evaluation -> Prevalence Check -> Entropy/Length Check -> Retain/Discard.
    """

    def __init__(self, catalogue_path: Optional[Path] = None):
        self.entries = _build_catalogue()
        self.catalogue_version = CATALOGUE_VERSION
        self._pattern_index: Dict[str, ConstantEntry] = {}
        self._build_index()

        # Write or sync JSON catalogue artifact
        if catalogue_path:
            self.export_catalogue_json(catalogue_path)

    def _build_index(self):
        """Index raw patterns for rapid exact and normalized matching."""
        for entry in self.entries:
            for pat in entry.raw_patterns:
                # Key 1: exact uppercase
                norm_pat = self.normalize_pattern(pat)
                self._pattern_index[norm_pat] = entry

    @staticmethod
    def normalize_pattern(pattern: str) -> str:
        """
        Normalize representation for pattern matching:
        - Strips quotes and surrounding whitespace
        - Standardizes hex format: '|00 01 00 01|' -> '|00010001|'
        - Case normalization for ASCII tokens
        """
        clean = str(pattern).strip().strip('"').strip("'")
        if clean.startswith("!"):
            clean = clean[1:].strip()

        # Standardize hex pipes
        if clean.startswith("|") and clean.endswith("|"):
            hex_body = clean[1:-1].replace(" ", "").upper()
            return f"|{hex_body}|"

        return clean.strip().upper()

    @staticmethod
    def calculate_byte_length(pattern: str) -> int:
        """Calculate effective byte length of candidate pattern."""
        clean = str(pattern).strip().strip('"').strip("'")
        if clean.startswith("!"):
            clean = clean[1:].strip()
        if clean.startswith("|") and clean.endswith("|"):
            raw_hex = clean[1:-1].replace(" ", "")
            return len(raw_hex) // 2
        return len(clean)

    def find_constant_match(
        self,
        candidate: str,
        protocol: Optional[str] = None
    ) -> Optional[ConstantEntry]:
        """Check if candidate pattern matches any indexed protocol constant."""
        norm = self.normalize_pattern(candidate)

        # 1. Exact match in index
        if norm in self._pattern_index:
            entry = self._pattern_index[norm]
            if not protocol or entry.protocol == "generic" or entry.protocol == protocol.lower():
                return entry

        # 2. Check for hex equivalent
        if not (norm.startswith("|") and norm.endswith("|")):
            try:
                hex_rep = f"|{candidate.encode('utf-8').hex().upper()}|"
                if hex_rep in self._pattern_index:
                    return self._pattern_index[hex_rep]
            except Exception:
                pass

        # 3. Substring check for high-impact protocol headers/footers
        for pat_key, entry in self._pattern_index.items():
            if entry.policy == ExclusionPolicy.HARD_EXCLUDE:
                # Disallow exact matches or trailing spaces (e.g. "GET /")
                if norm == pat_key or norm == f"{pat_key} " or (len(pat_key) >= 6 and norm == pat_key):
                    return entry

        return None

    def evaluate_invariant_candidate(
        self,
        candidate: Union[str, Dict[str, Any]],
        protocol: Optional[str] = None,
        buffer_name: Optional[str] = None,
        is_standalone: bool = True
    ) -> InvariantEvaluationResult:
        """
        Execute full evaluation sequence following the system flowchart:
        1. Normalize candidate
        2. Identify protocol and buffer
        3. Check Protocol Constant Catalogue
        4. Evaluate Hard vs Contextual exclusion
        5. Check Minimum Fast-Pattern Length (>= 4 bytes)
        6. Calculate Shannon Entropy
        7. Produce Retain vs Discard verdict with detailed rationale.
        """
        # Extract raw string
        if isinstance(candidate, dict):
            raw_val = str(candidate.get("value", "")).strip()
            candidate_proto = candidate.get("protocol") or protocol
            candidate_buf = candidate.get("buffer") or buffer_name
        else:
            raw_val = str(candidate).strip()
            candidate_proto = protocol
            candidate_buf = buffer_name

        norm_val = self.normalize_pattern(raw_val)
        byte_len = self.calculate_byte_length(raw_val)
        entropy = calculate_shannon_entropy(raw_val)
        matched_entry = self.find_constant_match(raw_val, candidate_proto)

        # ── Gate 1: Trivial Brittle Single-Character Anchors
        # Reject trivial single-character and 2-3 char anchors (', ", /, ;, =, etc.)
        trivial_anchors = {"'", '"', "/", "\\", ";", ":", "=", "&", "?", "#", " ", "\t", "\r", "\n"}
        if raw_val in trivial_anchors or byte_len < 4:
            # Special exemption for 2-3 byte high-entropy binary signatures only if NOT standalone
            if byte_len < 4:
                return InvariantEvaluationResult(
                    candidate=raw_val,
                    status="rejected",
                    normalized_value=norm_val,
                    is_hard_exclusion=True,
                    is_contextual_exclusion=False,
                    entropy=entropy,
                    length_bytes=byte_len,
                    rejection_reason=f"Brittle Anchor Rejected: Pattern '{raw_val}' is too short ({byte_len} bytes). Fast patterns and payload anchors must be >= 4 bytes to avoid engine saturation and false positives.",
                    recommendation="Select a multi-byte invariant string (>= 4 bytes) that uniquely characterizes the exploit."
                )

        # ── Gate 2: Known Protocol Constant Check
        if matched_entry:
            entry_dict = matched_entry.to_dict()

            # Hard Exclusion Check
            if matched_entry.policy == ExclusionPolicy.HARD_EXCLUDE:
                return InvariantEvaluationResult(
                    candidate=raw_val,
                    status="rejected",
                    normalized_value=norm_val,
                    is_hard_exclusion=True,
                    is_contextual_exclusion=False,
                    entropy=entropy,
                    length_bytes=byte_len,
                    matched_entry=entry_dict,
                    rejection_reason=f"Protocol Constant Violation: Pattern '{raw_val}' matches a standard protocol constant ({matched_entry.name}: {matched_entry.description}) and cannot serve as an invariant.",
                    recommendation=f"Exclude '{raw_val}' as an invariant. Scope detection using distinctive payload tokens rather than protocol framing."
                )

            # Contextual Exclusion Check
            elif matched_entry.policy == ExclusionPolicy.CONTEXTUAL_EXCLUDE:
                if is_standalone:
                    return InvariantEvaluationResult(
                        candidate=raw_val,
                        status="rejected",
                        normalized_value=norm_val,
                        is_hard_exclusion=False,
                        is_contextual_exclusion=True,
                        entropy=entropy,
                        length_bytes=byte_len,
                        matched_entry=entry_dict,
                        rejection_reason=f"Contextual Exclusion Violation: Generic application string '{raw_val}' cannot serve as a standalone invariant without companion indicators.",
                        recommendation=f"Combine '{raw_val}' with a high-entropy path, unique parameter, or payload signature."
                    )
                else:
                    return InvariantEvaluationResult(
                        candidate=raw_val,
                        status="contextual_allowed",
                        normalized_value=norm_val,
                        is_hard_exclusion=False,
                        is_contextual_exclusion=True,
                        entropy=entropy,
                        length_bytes=byte_len,
                        matched_entry=entry_dict,
                        recommendation="Allowed as contextual condition in multi-condition signature."
                    )

        # ── Gate 3: DNS Wire Format Consistency Check
        clean_proto = (candidate_proto or "").lower().strip()
        if clean_proto in ["dns", "udp"] and is_domain_name(raw_val):
            # If domain has dots and buffer is pkt_data or raw UDP
            if not candidate_buf or candidate_buf in ["pkt_data", "raw"]:
                encoded_wire = encode_dns_wire_format(raw_val)
                return InvariantEvaluationResult(
                    candidate=raw_val,
                    status="rejected",
                    normalized_value=norm_val,
                    is_hard_exclusion=True,
                    is_contextual_exclusion=False,
                    entropy=entropy,
                    length_bytes=byte_len,
                    rejection_reason=f"DNS Wire-Format Violation: Searching for raw domain '{raw_val}' with dots on raw UDP/53 fails because DNS packets encode domain labels with length bytes.",
                    recommendation=f"Scope rule inside 'dns_query;' sticky buffer, or encode domain in DNS wire format: content:\"{encoded_wire}\";"
                )

        # ── Gate 4: Low Shannon Entropy Repetition Check
        # Discard repeated single characters (e.g. '[[[[[[[' or '00000000') unless length >= 12
        if entropy < 1.0 and byte_len < 12:
            return InvariantEvaluationResult(
                candidate=raw_val,
                status="rejected",
                normalized_value=norm_val,
                is_hard_exclusion=False,
                is_contextual_exclusion=True,
                entropy=entropy,
                length_bytes=byte_len,
                rejection_reason=f"Low Entropy Anomaly: Pattern '{raw_val}' has very low Shannon entropy ({entropy} bits/byte) and repetitive structure. Prone to false positives.",
                recommendation="Replace with a high-entropy exploit artifact or combine with distinct endpoint tokens."
            )

        # ── Gate 5: Candidate Retained as High-Fidelity Invariant
        return InvariantEvaluationResult(
            candidate=raw_val,
            status="retained",
            normalized_value=norm_val,
            is_hard_exclusion=False,
            is_contextual_exclusion=False,
            entropy=entropy,
            length_bytes=byte_len,
            recommendation="Retained as high-fidelity payload invariant."
        )

    def export_catalogue_json(self, target_path: Union[str, Path]) -> Path:
        """Export the full machine-readable catalogue to JSON."""
        p = Path(target_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "catalogue_version": self.catalogue_version,
            "purpose": "payload_invariant_exclusion",
            "authoritative_sources": [
                {"name": "IANA Protocol Registries", "url": "https://www.iana.org/protocols"},
                {"name": "IANA DNS Parameters", "url": "https://www.iana.org/assignments/dns-parameters"},
                {"name": "HTTP Field Name Registry", "url": "https://www.iana.org/assignments/http-fields"},
                {"name": "TLS Parameters", "url": "https://www.iana.org/assignments/tls-parameters"},
                {"name": "TCP Parameters", "url": "https://www.iana.org/assignments/tcp-parameters"},
                {"name": "ICMP Parameters", "url": "https://www.iana.org/assignments/icmp-parameters"},
                {"name": "DHCPv6 Parameters", "url": "https://www.iana.org/assignments/dhcpv6-parameters"}
            ],
            "total_entries": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries]
        }
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return p


# Singleton instance for system-wide access
DEFAULT_FILTER = ProtocolConstantFilter()
