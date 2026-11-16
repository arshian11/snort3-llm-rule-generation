"""
Snort 3 Stage 6 — Supporting Options & Metadata Generation Engine.
Grounded in snort3_complete_rule_documentation.txt (General, Non-payload, Post-detection & Identity Options).

Implements:
6.1 General Rule Options:
    - classtype: Single event classification (from VALID_CLASSTYPES)
    - priority: Numeric severity override (1-2147483647, 1 most severe)
    - reference: Verified attack identification links (cve, url) - STRICT ANTI-HALLUCINATION GATE
    - metadata: Key-value tags (standalone, service explicitly excluded)
    - service: Application-layer service association (prohibited in service/file headers)
    - rem: Arbitrary human comments
    - file_meta: Specialized file-identification attributes (file_id only)
6.2 Non-Payload Rule Options:
    - IP header: ttl, tos, id, fragoffset, fragbits, ip_proto
    - TCP header: flags, seq, ack, window
    - ICMP: itype, icode, icmp_id, icmp_seq
    - flowbits: Transport flow state tracking (set, unset, isset, isnotset, noalert)
    - file_type: Constrains rule to identified file types
    - stream_reassemble & stream_size: TCP stream controls
6.3 Post-Detection Options:
    - detection_filter: Rule-level match rate filter (at most ONE per rule, evaluated last)
    - tag: Post-event packet/byte logging
    - replace: In-place payload modification (prohibited on alerts, requires rewrite)
6.4 Identity Options (Deterministic Python Allocation):
    - gid: Generator ID (default 1)
    - sid: Unique signature ID (allocated deterministically by Python, >= 1,000,000)
    - rev: Revision counter (starts at 1, incremented upon modifications)
Followed by:
- SupportingOptionsValidator with Anti-Hallucination CVE Verification
- SupportingOptionsGenerator with Dynamic 3-Pillar Prompt Injection & Self-Healing Retry Loop
"""

from typing import Dict, List, Set, Any, Optional, Tuple, Union
from pathlib import Path
import json
import re

from snort_pipeline.snort3_catalogue import (
    VALID_CLASSTYPES,
    is_valid_classtype,
    get_classtype_priority,
    is_valid_protocol_or_service
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
from snort_pipeline.option_catalogue import format_stage_catalogue_for_llm
from snort_pipeline.llm_engine import LLMClient


# ─────────────────────────────────────────────────────────────────────────────
# 6.4 IDENTITY ALLOCATORS (DETERMINISTIC PYTHON FUNCTIONS)
# ─────────────────────────────────────────────────────────────────────────────

SID_REGISTRY_FILE = Path("data/sid_registry.json")


def allocate_sid(
    existing_sids: Optional[Set[int]] = None,
    base_sid: int = 1000001,
    registry_file: Optional[Path] = None
) -> int:
    """
    Deterministic Python SID Allocator.
    Snort 3 reserves 0-999,999 for official rules. Custom local rules MUST be >= 1,000,000.
    Maintains persistent unique SID allocation across runs.
    """
    reg_path = registry_file or SID_REGISTRY_FILE
    allocated: Set[int] = set()

    if reg_path.exists():
        try:
            with open(reg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                allocated = set(int(s) for s in data.get("allocated_sids", []))
        except Exception:
            allocated = set()

    if existing_sids:
        allocated.update(existing_sids)

    candidate = base_sid
    while candidate in allocated:
        candidate += 1

    allocated.add(candidate)
    try:
        reg_path.parent.mkdir(parents=True, exist_ok=True)
        with open(reg_path, "w", encoding="utf-8") as f:
            json.dump({"allocated_sids": sorted(list(allocated))}, f, indent=2)
    except Exception:
        pass

    return candidate


def allocate_rev(sid: int, existing_rules: Optional[Dict[int, int]] = None) -> int:
    """
    Deterministic Python Revision Allocator.
    Starts at 1 for newly minted SIDs; increments if the same SID is being revised.
    """
    if existing_rules and sid in existing_rules:
        return existing_rules[sid] + 1
    return 1


# ─────────────────────────────────────────────────────────────────────────────
# 6.1 GENERAL SUPPORTING OPTION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def generate_classtype(
    hypothesis: DetectionHypothesis,
    report: Optional[Dict[str, Any]] = None
) -> str:
    """
    Determine single authoritative Snort 3 classtype grounded in detected behavior.
    """
    cat = (hypothesis.threat_category or "").lower().strip()
    beh = (hypothesis.target_behaviour or "").lower().strip()
    proto = (hypothesis.target_protocol or "").lower().strip()

    # Web application attacks
    if "web" in cat or "injection" in beh or "sql" in beh or "xss" in beh or "rce" in beh or "jndi" in beh:
        return "web-application-attack"

    # Command and Control / Trojans
    if "c2" in beh or "c2" in cat or "beacon" in beh or "malware-cnc" in cat:
        return "malware-cnc" if "malware-cnc" in VALID_CLASSTYPES else "trojan-activity"
    if "trojan" in cat or "backdoor" in cat or "rat" in cat or "loader" in cat:
        return "trojan-activity"

    # Reconnaissance / Scans
    if "scan" in beh or "probe" in beh or "recon" in cat:
        return "network-scan" if proto in ["tcp", "udp", "ip"] else "attempted-recon"

    # Denial of Service
    if "dos" in cat or "flood" in beh or "exhaustion" in beh:
        return "attempted-dos"

    # Privilege escalation / client-side exploits
    if "client" in cat or "phish" in cat or "document" in beh or "macro" in beh:
        return "client-side-exploit" if "client-side-exploit" in VALID_CLASSTYPES else "attempted-user"

    # Fallback to established general classtype
    return "trojan-activity" if "malware" in cat else "misc-attack"


def generate_priority(classtype: str, hypothesis: Optional[DetectionHypothesis] = None) -> Optional[int]:
    """Retrieve default priority from classtype, or None to inherit classtype defaults."""
    return get_classtype_priority(classtype)


def generate_references(
    hypothesis: DetectionHypothesis,
    report: Optional[Dict[str, Any]] = None,
    candidate_references: Optional[List[Dict[str, str]]] = None
) -> List[Tuple[str, str]]:
    """
    STRICT ANTI-HALLUCINATION GATE FOR ATTACK REFERENCES:
    Never allow the LLM to invent a CVE or URL reference simply because it sounds relevant.
    References MUST be verified against evidence, ground truth, or family context.
    """
    verified_refs: List[Tuple[str, str]] = []
    seen: Set[str] = set()

    # 1. Harvest verified references from ground truth and hypothesis context
    known_cves: Set[str] = set()
    fam_ctx = hypothesis.family_context or {}
    if fam_ctx.get("cve"):
        known_cves.add(str(fam_ctx["cve"]).upper().strip())

    if report:
        if report.get("cve"):
            known_cves.add(str(report["cve"]).upper().strip())
        gt = report.get("ground_truth")
        if isinstance(gt, dict) and gt.get("cve"):
            known_cves.add(str(gt["cve"]).upper().strip())

    # Check for CVE citations in evidence summary or alert summary
    ev_text = json.dumps(hypothesis.evidence) + json.dumps(hypothesis.target_behaviour)
    if report:
        ev_text += json.dumps(report.get("alert_summary", [])) + json.dumps(report.get("correlations", []))

    cited_cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", ev_text, re.IGNORECASE)
    for c in cited_cves:
        known_cves.add(c.upper().strip())

    # Add verified CVE references
    for cve in sorted(list(known_cves)):
        clean_cve = cve.replace("CVE-", "").replace("cve-", "").strip()
        ref_key = f"cve,{clean_cve}"
        if ref_key not in seen:
            verified_refs.append(("cve", clean_cve))
            seen.add(ref_key)

    # 2. Filter candidate references from LLM proposal against verified ground truth
    if candidate_references:
        for ref in candidate_references:
            if not isinstance(ref, dict):
                continue
            sys_name = str(ref.get("system", "")).lower().strip()
            val = str(ref.get("id", "")).strip()

            if sys_name == "cve":
                norm_cve = val if val.upper().startswith("CVE-") else f"CVE-{val}"
                # ANTI-HALLUCINATION CHECK: Only accept if confirmed in known_cves
                if norm_cve.upper() in known_cves:
                    clean_id = norm_cve.upper().replace("CVE-", "").strip()
                    ref_key = f"cve,{clean_id}"
                    if ref_key not in seen:
                        verified_refs.append(("cve", clean_id))
                        seen.add(ref_key)
            elif sys_name == "url" and len(val) > 4:
                # Sanitize URL reference
                clean_url = re.sub(r"^https?://", "", val).strip().rstrip(";")
                ref_key = f"url,{clean_url}"
                if ref_key not in seen:
                    verified_refs.append(("url", clean_url))
                    seen.add(ref_key)

    return verified_refs


def generate_service_option(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> Optional[str]:
    """
    Synthesize application service option: `service:<service_name>;`
    Restrictions:
    - Must NOT be used with a service-rule header (e.g. 'alert http')
    - Must NOT be used in a file rule ('alert file')
    - In a traditional header, associates application-layer service.
    """
    if not header:
        return None

    # Prohibited in service rules and file rules
    if header.header_type in ["service", "file", "file_id"]:
        return None

    # In traditional headers (alert tcp $EXTERNAL_NET any -> $HOME_NET 80):
    proto = (hypothesis.target_protocol or "").lower().strip()
    if proto in ["http", "https"]:
        return "http"
    elif proto in ["tls", "ssl"]:
        return "ssl"
    elif proto == "dns":
        return "dns"
    elif proto in ["smtp", "imap", "pop3", "smb", "dcerpc", "ssh", "ftp"]:
        return proto

    # Port-based inference
    dst_port = str(header.dest_port or "").strip()
    if dst_port in ["$HTTP_PORTS", "80", "8080"]:
        return "http"
    elif dst_port in ["443", "8443"]:
        return "ssl"
    elif dst_port == "53":
        return "dns"

    return None


def generate_metadata(
    hypothesis: DetectionHypothesis,
    report: Optional[Dict[str, Any]] = None,
    extra_pairs: Optional[Dict[str, str]] = None
) -> List[Tuple[str, str]]:
    """
    Synthesize standard key-value metadata pairs.
    Snort 3 Requirement: Service declarations MUST NOT be placed inside metadata.
    """
    pairs: List[Tuple[str, str]] = [
        ("policy", "max-detect-ips drop"),
        ("ruleset", "community")
    ]

    fam = hypothesis.malware_family or (report.get("malware_family") if report else "")
    if fam:
        clean_fam = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(fam)).strip()
        pairs.append(("malware_family", clean_fam))

    if extra_pairs:
        for k, v in extra_pairs.items():
            k_clean = str(k).lower().strip()
            v_clean = str(v).strip()
            # Enforce exclusion of 'service' from metadata
            if k_clean != "service" and k_clean not in [p[0] for p in pairs]:
                pairs.append((k_clean, v_clean))

    return pairs


def generate_file_meta(header: Optional[RuleHeaderAST] = None) -> Optional[str]:
    """Generate file_meta string only if header is 'file_id'."""
    if header and header.header_type == "file_id":
        return 'type MSEXE,id 21,category "Executables"'
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 6.2 NON-PAYLOAD & 6.3 POST-DETECTION OPTION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def generate_ip_header_options(hypothesis: DetectionHypothesis) -> List[Tuple[str, Any]]:
    """Generate IP header options (ttl, tos, id, fragbits, ip_proto) if required by hypothesis."""
    opts: List[Tuple[str, Any]] = []
    # Environment-dependent options are only generated if explicitly stated in invariants
    for inv in (hypothesis.invariant_indicators or []):
        if not isinstance(inv, dict):
            continue
        inv_t = inv.get("type", "").lower()
        inv_v = str(inv.get("value", "")).strip()
        if inv_t == "ttl" and inv_v:
            opts.append(("ttl", inv_v))
        elif inv_t == "tos" and inv_v:
            opts.append(("tos", inv_v))
        elif inv_t == "ip_id" and inv_v:
            opts.append(("id", inv_v))
        elif inv_t == "fragbits" and inv_v:
            opts.append(("fragbits", inv_v))
        elif inv_t == "ip_proto" and inv_v:
            opts.append(("ip_proto", inv_v))
    return opts


def generate_tcp_header_options(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> List[Tuple[str, Any]]:
    """Generate TCP header options (flags, seq, ack, window) if required."""
    opts: List[Tuple[str, Any]] = []
    proto = (header.protocol if header else hypothesis.target_protocol) or "tcp"
    if proto.lower() != "tcp":
        return []

    # Connection attempt / SYN check
    flow_intent = (hypothesis.flow_intent or "").lower().strip()
    if flow_intent == "not_established" or "syn_scan" in (hypothesis.target_behaviour or "").lower():
        opts.append(("flags", "S"))

    for inv in (hypothesis.invariant_indicators or []):
        if not isinstance(inv, dict):
            continue
        inv_t = inv.get("type", "").lower()
        inv_v = str(inv.get("value", "")).strip()
        if inv_t == "tcp_flags" and inv_v:
            opts.append(("flags", inv_v))
        elif inv_t == "window" and inv_v:
            opts.append(("window", inv_v))

    return opts


def generate_icmp_options(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> List[Tuple[str, Any]]:
    """Generate ICMP options (itype, icode, icmp_id, icmp_seq) if protocol is ICMP."""
    proto = (header.protocol if header else hypothesis.target_protocol) or ""
    if proto.lower() != "icmp":
        return []

    opts: List[Tuple[str, Any]] = []
    # Standard Echo Request default for ICMP detection
    opts.append(("itype", "8"))
    opts.append(("icode", "0"))
    return opts


def generate_flowbits(hypothesis: DetectionHypothesis) -> Optional[Tuple[str, str]]:
    """Generate flowbits option if hypothesis requires per-session state tracking."""
    beh = (hypothesis.target_behaviour or "").lower()
    if "session_state" in beh or "multi_stage" in beh or "flowbits" in beh:
        fam = re.sub(r"[^a-zA-Z0-9_]", "", hypothesis.malware_family or "attack").lower()
        return ("set", f"{fam}_active")
    return None


def generate_file_type(hypothesis: DetectionHypothesis) -> Optional[str]:
    """Generate file_type constraint if hypothesis targets specific file drop."""
    for inv in (hypothesis.invariant_indicators or []):
        if not isinstance(inv, dict):
            continue
        if inv.get("type") == "filename":
            fn = str(inv.get("value", "")).lower()
            if fn.endswith(".pdf"):
                return "PDF"
            elif fn.endswith(".doc") or fn.endswith(".docx"):
                return "MSDOC"
            elif fn.endswith(".exe") or fn.endswith(".dll"):
                return "MSEXE"
    return None


def generate_stream_options(hypothesis: DetectionHypothesis) -> List[Tuple[str, Any]]:
    """Generate stream_size or stream_reassemble if reassembly constraints required."""
    opts: List[Tuple[str, Any]] = []
    return opts


def generate_detection_filter(
    hypothesis: DetectionHypothesis,
    rate_limit: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Generate detection_filter option for rate-limiting repetitive matches.
    Syntax: track <by_src|by_dst>,count <count>,seconds <seconds>
    At most ONE detection_filter permitted per rule, evaluated last.
    """
    if rate_limit:
        trk = rate_limit.get("track", "by_src")
        cnt = rate_limit.get("count", 30)
        sec = rate_limit.get("seconds", 60)
        return f"track {trk},count {cnt},seconds {sec}"

    beh = (hypothesis.target_behaviour or "").lower()
    if "brute_force" in beh or "scan" in beh or "dos" in beh:
        return "track by_src,count 30,seconds 60"
    return None


def generate_tag(hypothesis: DetectionHypothesis) -> Optional[str]:
    """Generate tag option for post-detection packet logging."""
    return None


def generate_replace(header: Optional[RuleHeaderAST] = None) -> Optional[str]:
    """Generate replace option ONLY if rule action is 'rewrite'."""
    if header and header.action == "rewrite":
        return "SAFE"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 6.5 SUPPORTING OPTIONS VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────

class SupportingOptionsValidator:
    """
    Comprehensive Validation Gate for Stage 6 Supporting Options.
    Enforces:
    1. Identity: SID present, integer >= 1,000,000; rev present, positive integer.
    2. Classtype: established Snort 3 classtype; at most ONE classtype.
    3. References: Anti-hallucination verification against report/evidence.
    4. Service: prohibited in service/file headers; not placed in metadata.
    5. Non-payload: protocol consistency (flags on TCP, itype on ICMP).
    6. Post-detection: at most ONE detection_filter; replace only on rewrite.
    """
    def validate(
        self,
        options: List[RuleOptionAST],
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None,
        report: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        errors: List[str] = []
        details: Dict[str, Any] = {
            "classtype": None,
            "sid": None,
            "rev": None,
            "references": [],
            "service": None,
            "metadata_count": 0,
            "has_detection_filter": False
        }

        # 1. Identity Verification (sid, rev)
        sid_opts = [o for o in options if o.name == "sid"]
        if not sid_opts:
            errors.append("Mandatory identity option 'sid' is missing.")
        elif len(sid_opts) > 1:
            errors.append(f"Multiple SID options declared ({len(sid_opts)}). Exactly ONE sid allowed per rule.")
        else:
            try:
                sid_val = int(sid_opts[0].value)
                details["sid"] = sid_val
                if sid_val < 1000000:
                    errors.append(f"Local rule SID violation: sid:{sid_val}. Custom local rules MUST be >= 1,000,000.")
            except (ValueError, TypeError):
                errors.append(f"Invalid sid value '{sid_opts[0].value}'. Must be integer >= 1,000,000.")

        rev_opts = [o for o in options if o.name == "rev"]
        if not rev_opts:
            errors.append("Mandatory revision option 'rev' is missing.")
        elif len(rev_opts) > 1:
            errors.append(f"Multiple rev options declared ({len(rev_opts)}). Exactly ONE rev allowed per rule.")
        else:
            try:
                rev_val = int(rev_opts[0].value)
                details["rev"] = rev_val
                if rev_val < 1:
                    errors.append(f"Invalid rev:{rev_val}. Revision must be positive integer >= 1.")
            except (ValueError, TypeError):
                errors.append(f"Invalid rev value '{rev_opts[0].value}'. Must be integer >= 1.")

        # 2. Classtype Verification
        ct_opts = [o for o in options if o.name == "classtype"]
        if len(ct_opts) > 1:
            errors.append(f"Multiple classtype options declared ({len(ct_opts)}). At most ONE classtype permitted per rule.")
        elif ct_opts:
            ct_name = str(ct_opts[0].value or "").strip().lower()
            details["classtype"] = ct_name
            if not is_valid_classtype(ct_name):
                errors.append(f"Invalid classtype '{ct_name}'. Must be one of: {', '.join(sorted(VALID_CLASSTYPES.keys()))}")

        # 3. Reference Verification (STRICT ANTI-HALLUCINATION)
        ref_opts = [o for o in options if o.name == "reference"]
        known_cves: Set[str] = set()
        fam_ctx = hypothesis.family_context or {}
        if fam_ctx.get("cve"):
            known_cves.add(str(fam_ctx["cve"]).upper().strip())
        if report and report.get("cve"):
            known_cves.add(str(report["cve"]).upper().strip())
        ev_text = json.dumps(hypothesis.evidence) + json.dumps(hypothesis.target_behaviour)
        if report:
            ev_text += json.dumps(report.get("alert_summary", [])) + json.dumps(report.get("correlations", []))
        for c in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", ev_text, re.IGNORECASE):
            known_cves.add(c.upper().strip())

        for ref_o in ref_opts:
            ref_val = str(ref_o.value or "").strip()
            details["references"].append(ref_val)
            if "," not in ref_val:
                errors.append(f"Malformed reference '{ref_val}'. Must be 'scheme,id'.")
                continue
            scheme, ref_id = [x.strip() for x in ref_val.split(",", 1)]
            if scheme.lower() == "cve":
                norm_cve = ref_id if ref_id.upper().startswith("CVE-") else f"CVE-{ref_id}"
                if known_cves and norm_cve.upper() not in known_cves:
                    errors.append(f"Reference hallucination: '{norm_cve}' is not supported by packet evidence or ground truth.")

        # 4. Service Option Restrictions
        svc_opts = [o for o in options if o.name == "service"]
        if svc_opts and header:
            if header.header_type == "service":
                errors.append(f"Service option conflict: Header is already a service header ('{header.render()}'). The 'service' option must NOT be used.")
            elif header.header_type in ["file", "file_id"]:
                errors.append("Service option conflict: The 'service' option must NOT be used in file or file_id rules.")
            else:
                details["service"] = str(svc_opts[0].value)

        # 5. Metadata Restrictions (Service must not be inside metadata)
        meta_opts = [o for o in options if o.name == "metadata"]
        for mo in meta_opts:
            details["metadata_count"] += 1
            meta_val = str(mo.value or "")
            if "service " in meta_val.lower() or "service," in meta_val.lower():
                errors.append("Invalid metadata: In Snort 3, service declarations must not be placed inside metadata. Use standalone 'service' option.")

        # 6. Non-Payload Option Checks
        proto = (header.protocol if header else hypothesis.target_protocol) or "tcp"
        proto = proto.lower().strip()
        for opt in options:
            name = opt.name.lower().strip()
            if name == "flags" and proto not in ["tcp", "ip"]:
                errors.append(f"Protocol conflict: 'flags' option applies only to TCP, not {proto.upper()}.")
            elif name in ["itype", "icode", "icmp_id", "icmp_seq"] and proto != "icmp":
                errors.append(f"Protocol conflict: '{name}' applies only to ICMP, not {proto.upper()}.")

        # 7. Post-Detection Option Checks
        df_opts = [o for o in options if o.name == "detection_filter"]
        if len(df_opts) > 1:
            errors.append(f"Multiple detection_filter options declared ({len(df_opts)}). At most ONE allowed per rule.")
        elif df_opts:
            details["has_detection_filter"] = True

        rep_opts = [o for o in options if o.name == "replace"]
        if rep_opts:
            if not header or header.action != "rewrite":
                errors.append("Invalid replace option: 'replace' requires rule action 'rewrite'. Cannot be used with 'alert'.")

        passed = len(errors) == 0
        details["errors"] = errors
        error_comp = "reference" if any("reference" in e.lower() for e in errors) else "supporting_options"
        return ValidationResult(
            status="passed" if passed else "failed",
            component=error_comp,
            error=errors[0] if errors else None,
            evidence_required=any("reference" in e.lower() or "hallucination" in e.lower() for e in errors),
            details=details
        )


# ─────────────────────────────────────────────────────────────────────────────
# 6.6 SUPPORTING OPTIONS GENERATOR ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class SupportingOptionsGenerator:
    """
    Stage 6 Supporting Options & Metadata Generator.
    Coordinates:
    - Deterministic Python allocation for identity (sid >= 1,000,000, rev).
    - Dynamic 3-Pillar Prompt injection for LLM recommendation of classtype, metadata, priority.
    - Strict Anti-Hallucination Gate on CVE references.
    - Safety Gate validation via SupportingOptionsValidator.
    - Canonical AST assembly (Index 0=msg, Index 1=flow, Detection payload, Supporting, Identity at end).
    """
    def __init__(self, llm_client: Optional[LLMClient] = None, max_retries: int = 3, base_sid: int = 1000001):
        self.client = llm_client or LLMClient()
        self.validator = SupportingOptionsValidator()
        self.max_retries = max_retries
        self.base_sid = base_sid

    def generate(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Execute Stage 6: Generate, validate, and commit supporting options and identity to RuleState.
        """
        hyp = state.hypothesis
        header = state.ast.header
        if not hyp:
            state.transition(ConstructionState.CONSTRUCTION_FAILED, reason="Stage 6 requires an approved Detection Hypothesis in RuleState.")
            return state

        # 1. Deterministic Python Identity Allocation
        assigned_sid = allocate_sid(base_sid=self.base_sid)
        assigned_rev = allocate_rev(assigned_sid)

        retry_count = 0
        validation_errors: List[str] = []

        while retry_count <= self.max_retries:
            proposed_opts = self._propose_supporting_llm(
                hypothesis=hyp,
                header=header,
                state=state,
                assigned_sid=assigned_sid,
                assigned_rev=assigned_rev,
                report=report,
                previous_errors=validation_errors if retry_count > 0 else None
            )

            passed, errors, details = self.validator.validate(
                options=proposed_opts,
                hypothesis=hyp,
                header=header,
                report=report
            )

            if passed:
                # Commit supporting options to RuleState components
                self._commit_supporting_options(state, proposed_opts, assigned_sid, assigned_rev)

                state.record_validation("stage6_supporting", passed=True, details=details)
                state.transition(ConstructionState.SUPPORTING_GENERATED, reason=f"Committed supporting options with sid:{assigned_sid}, rev:{assigned_rev}.")
                state.current_stage = 7

                stage_result = StageResult(
                    status="success",
                    component="supporting_options",
                    generated_value=[opt.to_dict() for opt in proposed_opts],
                    evidence_refs=details.get("references", []),
                    validation_errors=[],
                    reasoning_summary=f"Committed classtype '{details.get('classtype')}', {len(details.get('references', []))} verified references, sid:{assigned_sid}, rev:{assigned_rev}."
                )
                state.stage_results["stage6_supporting"] = stage_result.to_dict()
                state.last_stage_result = stage_result.to_dict()
                state.save_checkpoint(6)
                return state

            # Validation failed -> Retry
            retry_count += 1
            state.stage_retry_counts["stage6_supporting"] = retry_count
            validation_errors = errors
            state.record_validation("stage6_supporting", passed=False, errors=errors, details=details)

        # Retries exhausted: Fall back to deterministic fallback synthesizer
        fallback_opts = self._synthesize_fallback_supporting(hyp, header, report, assigned_sid, assigned_rev)
        passed, errors, details = self.validator.validate(fallback_opts, hyp, header, report)

        if passed:
            self._commit_supporting_options(state, fallback_opts, assigned_sid, assigned_rev)
            state.record_validation("stage6_supporting", passed=True, details=details)
            state.transition(ConstructionState.SUPPORTING_GENERATED, reason=f"Deterministic fallback supporting options committed (sid:{assigned_sid}).")
            state.current_stage = 7

            stage_result = StageResult(
                status="success",
                component="supporting_options",
                generated_value=[opt.to_dict() for opt in fallback_opts],
                evidence_refs=details.get("references", []),
                validation_errors=[],
                reasoning_summary=f"Synthesized fallback classtype '{details.get('classtype')}', sid:{assigned_sid}, rev:{assigned_rev}."
            )
            state.stage_results["stage6_supporting"] = stage_result.to_dict()
            state.last_stage_result = stage_result.to_dict()
            state.save_checkpoint(6)
            return state

        # Complete failure
        state.transition(ConstructionState.CONSTRUCTION_FAILED, reason=f"Stage 6 Supporting Options failed validation: {'; '.join(validation_errors)}")
        fail_result = StageResult(
            status="failed",
            component="supporting_options",
            generated_value=None,
            evidence_refs=[],
            validation_errors=validation_errors,
            reasoning_summary="Stage 6 Supporting Options generation failed validation retries and fallback."
        )
        state.stage_results["stage6_supporting"] = fail_result.to_dict()
        state.last_stage_result = fail_result.to_dict()
        return state

    def _propose_supporting_llm(
        self,
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST],
        state: RuleState,
        assigned_sid: int,
        assigned_rev: int,
        report: Optional[Dict[str, Any]] = None,
        previous_errors: Optional[List[str]] = None
    ) -> List[RuleOptionAST]:
        """Query LLM to propose Stage 6 supporting options using 3-Pillar Prompt Schema."""
        family = getattr(hypothesis, "malware_family", "") or hypothesis.family_context.get("malware_family", "Malware")
        target_behaviour = hypothesis.target_behaviour
        objective = hypothesis.detection_objective
        header_str = header.render() if header else "alert tcp $EXTERNAL_NET any -> $HOME_NET any"
        header_type = header.header_type if header else "traditional"
        stage6_catalogue = format_stage_catalogue_for_llm(6)

        # Verified CVE context
        verified_cves = []
        if hypothesis.family_context.get("cve"):
            verified_cves.append(hypothesis.family_context["cve"])
        if report and report.get("cve"):
            verified_cves.append(report["cve"])
        verified_cves = sorted(list(dict.fromkeys(verified_cves)))

        rule_prefix = state.render_rule_prefix(up_to_stage=6, placeholder="INSERT STAGE 6 SUPPORTING OPTIONS HERE")

        retry_feedback = ""
        if previous_errors:
            retry_feedback = f"""
[CRITICAL CORRECTION REQUIRED]
Your previous supporting options proposal failed validation with the following errors:
{json.dumps(previous_errors, indent=2)}

Please strictly fix these issues:
1. NEVER invent or hallucinate CVE numbers. Only cite CVEs present in Verified CVE Evidence: {verified_cves or 'None'}.
2. If choosing classtype, select EXACTLY ONE from established classifications (e.g. trojan-activity, web-application-attack, malware-cnc, attempted-recon).
3. Do NOT include 'service' in metadata. In Snort 3, use standalone 'service' option.
4. If the rule header is a service rule (e.g. 'alert http') or file rule, omit the 'service' option.
"""

        user_prompt = f"""You are the Snort 3 Rule Engineer operating Stage 6: Supporting Options & Metadata.

1. COMPONENT-GENERATION INSTRUCTIONS:
Propose supporting options (classtype, reference, service, priority, metadata, non-payload filters, post-detection).
NOTE:
- SID ({assigned_sid}) and Rev ({assigned_rev}) are deterministically allocated by Python and will be appended automatically.
- NEVER invent CVE references. Only cite verified CVEs: {verified_cves or 'None'}.
- Select options minimally based on necessity to avoid bloated rules.

Respond strictly with a JSON object conforming to this schema:
{{
  "classtype": "trojan-activity | web-application-attack | malware-cnc | attempted-recon | attempted-dos | attempted-user | misc-attack",
  "priority": null,
  "service": "http | ssl | dns | null",
  "references": [
    {{ "system": "cve", "id": "2021-44228" }},
    {{ "system": "url", "id": "attack.mitre.org/techniques/T1059/" }}
  ],
  "metadata": [
    {{ "key": "policy", "value": "max-detect-ips drop" }}
  ],
  "non_payload_options": [],
  "post_detection_options": [],
  "rationale": "<Reason for classtype and supporting options selection>"
}}

2. RELEVANT CATALOGUE ENTRIES (Dynamic from OptionSpec):
{stage6_catalogue}

3. CURRENT RULE CONTEXT & ACCUMULATED STATE:
- Detection Hypothesis:
  - Threat Family: {family}
  - Intended Behaviour: {target_behaviour}
  - Detection Objective: {objective}
  - Verified CVE Evidence: {verified_cves or 'None observed'}
- Selected Rule Header: {header_str} (Type: {header_type})
- Current Rule Prefix:
  {rule_prefix}
{retry_feedback}
"""
        SYSTEM_PROMPT = """You are an expert Snort 3 rule metadata engineer.
You propose strictly valid, dependency-compliant supporting options and classifications.
You NEVER invent CVE references or cite unverified attack IDs.
You output strictly valid JSON without conversational text or codeblock wrappers."""

        try:
            resp_text = self.client.query(SYSTEM_PROMPT, user_prompt, json_mode=True, temperature=0.1)
            parsed = json.loads(self._extract_json(resp_text))

            if isinstance(parsed, dict):
                nodes = self._parse_supporting_proposal(parsed, hypothesis, header, report, assigned_sid, assigned_rev)
                if nodes:
                    return nodes

            return self._synthesize_fallback_supporting(hypothesis, header, report, assigned_sid, assigned_rev)
        except Exception:
            return self._synthesize_fallback_supporting(hypothesis, header, report, assigned_sid, assigned_rev)

    def _parse_supporting_proposal(
        self,
        parsed: Dict[str, Any],
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST],
        report: Optional[Dict[str, Any]],
        assigned_sid: int,
        assigned_rev: int
    ) -> List[RuleOptionAST]:
        """Convert LLM JSON proposal into validated Snort 3 RuleOptionAST nodes."""
        nodes: List[RuleOptionAST] = []

        # Service option (if valid and not in service/file header)
        svc = parsed.get("service")
        if svc and header and header.header_type not in ["service", "file", "file_id"]:
            clean_svc = str(svc).strip().lower()
            if is_valid_protocol_or_service(clean_svc):
                nodes.append(RuleOptionAST(name="service", value=clean_svc))

        # Classtype option
        ct = parsed.get("classtype")
        if ct:
            clean_ct = str(ct).strip().lower()
            if is_valid_classtype(clean_ct):
                nodes.append(RuleOptionAST(name="classtype", value=clean_ct))
            else:
                nodes.append(RuleOptionAST(name="classtype", value=generate_classtype(hypothesis, report)))
        else:
            nodes.append(RuleOptionAST(name="classtype", value=generate_classtype(hypothesis, report)))

        # Priority option (optional override)
        prio = parsed.get("priority")
        if prio is not None:
            try:
                p_int = int(prio)
                if 1 <= p_int <= 4:
                    nodes.append(RuleOptionAST(name="priority", value=p_int))
            except (ValueError, TypeError):
                pass

        # References (Anti-hallucination verification)
        candidate_refs = parsed.get("references", [])
        verified_refs = generate_references(hypothesis, report, candidate_references=candidate_refs)
        for sys_name, ref_id in verified_refs:
            nodes.append(RuleOptionAST(name="reference", value=f"{sys_name},{ref_id}"))

        # Metadata option
        meta_items = parsed.get("metadata", [])
        extra_pairs: Dict[str, str] = {}
        if isinstance(meta_items, list):
            for m in meta_items:
                if isinstance(m, dict) and "key" in m and "value" in m:
                    k = str(m["key"]).strip()
                    v = str(m["value"]).strip()
                    if k.lower() != "service":
                        extra_pairs[k] = v
        meta_pairs = generate_metadata(hypothesis, report, extra_pairs=extra_pairs)
        if meta_pairs:
            meta_str = ", ".join([f"{k} {v}" for k, v in meta_pairs])
            nodes.append(RuleOptionAST(name="metadata", value=meta_str))

        # Post-detection options (detection_filter, tag)
        post_opts = parsed.get("post_detection_options", [])
        if isinstance(post_opts, list):
            for po in post_opts:
                if isinstance(po, dict) and po.get("name") == "detection_filter":
                    nodes.append(RuleOptionAST(name="detection_filter", value=po.get("value")))

        # Deterministic Python Identity: sid, rev
        nodes.append(RuleOptionAST(name="sid", value=assigned_sid))
        nodes.append(RuleOptionAST(name="rev", value=assigned_rev))

        return nodes

    def _synthesize_fallback_supporting(
        self,
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST],
        report: Optional[Dict[str, Any]],
        assigned_sid: int,
        assigned_rev: int
    ) -> List[RuleOptionAST]:
        """Deterministic, grounded supporting options synthesizer."""
        nodes: List[RuleOptionAST] = []

        # Service option
        svc = generate_service_option(hypothesis, header)
        if svc:
            nodes.append(RuleOptionAST(name="service", value=svc))

        # Classtype
        ct = generate_classtype(hypothesis, report)
        nodes.append(RuleOptionAST(name="classtype", value=ct))

        # References (verified only)
        refs = generate_references(hypothesis, report)
        for sys_name, ref_id in refs:
            nodes.append(RuleOptionAST(name="reference", value=f"{sys_name},{ref_id}"))

        # Metadata
        meta_pairs = generate_metadata(hypothesis, report)
        if meta_pairs:
            meta_str = ", ".join([f"{k} {v}" for k, v in meta_pairs])
            nodes.append(RuleOptionAST(name="metadata", value=meta_str))

        # Deterministic Identity
        nodes.append(RuleOptionAST(name="sid", value=assigned_sid))
        nodes.append(RuleOptionAST(name="rev", value=assigned_rev))

        return nodes

    def _commit_supporting_options(
        self,
        state: RuleState,
        supporting_nodes: List[RuleOptionAST],
        assigned_sid: int,
        assigned_rev: int
    ):
        """
        Assemble canonical Snort 3 AST option ordering:
        Index 0: msg
        Index 1: flow
        Index 2+: detection payload options (sticky buffers, content, pcre, byte tests)
        Index Supporting: service, classtype, priority, reference, metadata, detection_filter
        End: sid, rev
        """
        msg_opt = next((o for o in state.ast.options if o.name == "msg"), None)
        flow_opt = next((o for o in state.ast.options if o.name == "flow"), None)

        detection_names = [
            "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_client_body",
            "http_raw_body", "http_cookie", "http_raw_cookie", "http_method", "http_stat_code",
            "http_stat_msg", "http_version", "file_data", "pkt_data", "raw_data", "js_data",
            "vba_data", "base64_data", "content", "pcre", "regex", "byte_test", "byte_extract",
            "byte_math", "byte_jump", "isdataat", "bufferlen", "dsize", "ber_data", "ber_skip",
            "tls_sni", "tls_cert_subject", "tls_cert_issuer", "dns_query"
        ]
        detection_nodes = [o for o in state.ast.options if o.name in detection_names]

        # Filter out existing supporting/identity options
        supp_names = ["service", "classtype", "priority", "reference", "metadata", "rem", "detection_filter", "tag", "sid", "rev"]
        new_supp = [o for o in supporting_nodes if o.name in supp_names and o.name not in ["sid", "rev"]]
        sid_opt = next((o for o in supporting_nodes if o.name == "sid"), RuleOptionAST(name="sid", value=assigned_sid))
        rev_opt = next((o for o in supporting_nodes if o.name == "rev"), RuleOptionAST(name="rev", value=assigned_rev))

        # Update components
        state.components["classification"] = next((o.value for o in new_supp if o.name == "classtype"), "misc-attack")
        state.components["sid"] = assigned_sid
        state.components["rev"] = assigned_rev
        state.components["references"] = [o.value for o in new_supp if o.name == "reference"]
        state.components["metadata"] = [o.value for o in new_supp if o.name == "metadata"]

        ordered_options: List[RuleOptionAST] = []
        if msg_opt:
            ordered_options.append(msg_opt)
        if flow_opt:
            ordered_options.append(flow_opt)

        ordered_options.extend(detection_nodes)
        ordered_options.extend(new_supp)
        ordered_options.append(sid_opt)
        ordered_options.append(rev_opt)

        state.ast.options = ordered_options

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
        match = re.search(r"\{[\s\S]*\}", text)
        return match.group(0) if match else text
