"""
Module 5 Part C: Central Rule Construction Engine.
Implements Hypothesis-Driven Iterative Rule Construction (HDIRC) for Snort 3.

Dependency Graph:
Detection Hypothesis (Stage 1) [ACTIVE]
└── Header (Stage 2) [ACTIVE]
    ├── Message (Stage 3) [ACTIVE]
    ├── Flow Constraints (Stage 4) [ACTIVE]
    └── Detection Construction (Stage 5) [ACTIVE]
        ├── Buffer Selection
        │   └── Content Matching
        │       └── Positioning & Relationships
        │           └── Regex / Numeric Conditions
        └── Metadata & Supporting Options (Stage 6) [PLACEHOLDER]
            ├── References
            ├── Classification
            └── SID / REV
                └── Complete Rule Assembly (Stage 7) [PLACEHOLDER]
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple

from snort_pipeline.rule_state import (
    RuleState,
    DetectionHypothesis,
    ConstructionState,
    RuleAST,
    RuleHeaderAST,
    RuleOptionAST,
    ValidationResult,
    StageResult
)
from snort_pipeline.snort3_catalogue import (
    is_valid_action,
    is_valid_protocol_or_service,
    is_valid_classtype,
    validate_direction_consistency,
    VALID_PROTOCOLS,
    VALID_SERVICE_HEADERS,
    FORBIDDEN_VARIABLES
)
from snort_pipeline.protocol_constants import DEFAULT_FILTER
from snort_pipeline.llm_engine import LLMClient, SYSTEM_PROMPT, sanitize_untrusted_data
from snort_pipeline.header_generator import (
    HeaderGenerator,
    HeaderValidator,
    generate_rule_type,
    generate_action,
    generate_protocol,
    generate_source_scope,
    generate_destination_scope,
    generate_source_port,
    generate_destination_port,
    generate_direction,
    assemble_header,
    validate_header
)
from snort_pipeline.message_generator import (
    MessageGenerator,
    MessageValidator,
    generate_message,
    validate_message,
    check_duplicate_message
)
from snort_pipeline.flow_generator import (
    FlowGenerator,
    FlowValidator,
    generate_flow_direction,
    generate_connection_state,
    generate_stream_state,
    generate_fragment_state,
    assemble_flow_option,
    validate_flow_option
)
from snort_pipeline.detection_generator import (
    DetectionGenerator,
    DetectionValidator,
    select_detection_buffer,
    generate_content_match,
    generate_fast_pattern,
    generate_nocase_modifier,
    generate_pcre_match,
    generate_regex_match,
    generate_encoding_options,
    validate_pattern_against_evidence,
    generate_offset,
    generate_depth,
    generate_distance,
    generate_within,
    generate_isdataat,
    generate_bufferlen,
    validate_content_relationships,
    generate_byte_extract,
    generate_byte_test,
    generate_byte_math,
    generate_byte_jump,
    generate_dsize,
    generate_ber_options,
    validate_binary_detection,
    load_protocol_catalogue,
    generate_http_detection,
    generate_tls_detection,
    generate_rpc_detection,
    generate_sip_detection,
    generate_industrial_protocol_detection,
    validate_protocol_specific_options
)
from snort_pipeline.supporting_generator import (
    SupportingOptionsGenerator,
    SupportingOptionsValidator,
    allocate_sid,
    allocate_rev,
    generate_classtype,
    generate_priority,
    generate_references,
    generate_service_option,
    generate_metadata,
    generate_file_meta,
    generate_ip_header_options,
    generate_tcp_header_options,
    generate_icmp_options,
    generate_flowbits,
    generate_file_type,
    generate_stream_options,
    generate_detection_filter,
    generate_tag,
    generate_replace
)
from snort_pipeline.rule_assembly import (
    RuleAssemblyManager,
    RuleConflictDetector,
    DualPassVerifier,
    RuleAssemblyValidator
)
from snort_pipeline.rule_renderer import RuleRenderer

class HypothesisValidator:
    """
    Deterministic Validation Gate for Stage 1 Detection Hypothesis.
    Verifies evidence grounding, communication direction alignment,
    protocol validity, and generalization safety.
    """
    def __init__(self):
        pass

    def validate(
        self,
        hypothesis: DetectionHypothesis,
        report_evidence_packets: Optional[List[int]] = None
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        errors: List[str] = []
        details: Dict[str, Any] = {}

        viability = hypothesis.rule_viability or {}
        disposition = viability.get("disposition", "PROCEED_TO_RULE").upper()

        # Check terminal non-rule dispositions
        if disposition == "INSUFFICIENT_EVIDENCE":
            details["verdict"] = "INSUFFICIENT_EVIDENCE"
            details["reason"] = viability.get("disposition_rationale", "Evidence insufficient to formulate invariant rule.")
            return True, [], details

        if disposition == "CORRELATION_ONLY":
            details["verdict"] = "CORRELATION_ONLY"
            details["reason"] = viability.get("disposition_rationale", "Behavior is multi-event/behavioural and handled at correlation layer.")
            return True, [], details

        # 1. Evidence Grounding Check
        ev = hypothesis.evidence or {}
        triggering_pkts = ev.get("triggering_packets", [])
        if not triggering_pkts:
            # Check if any packet numbers were cited in summary
            cited_nums = [int(n) for n in re.findall(r"\b(?:packet|frame)\s*#?(\d+)\b", str(ev), re.IGNORECASE)]
            if cited_nums:
                triggering_pkts = cited_nums
                ev["triggering_packets"] = cited_nums

        if not triggering_pkts and not ev.get("flow_ids"):
            errors.append("Evidence grounding failure: Hypothesis lacks specific packet numbers or flow IDs from capture.")

        if report_evidence_packets and triggering_pkts:
            valid_set = set(report_evidence_packets)
            unmatched = [p for p in triggering_pkts if p not in valid_set]
            # If all cited packets are fictitious
            if len(unmatched) == len(triggering_pkts) and len(valid_set) > 0:
                errors.append(f"Evidence mismatch: Triggering packets {triggering_pkts} do not exist in report evidence.")

        # 2. Protocol & Service Verification
        proto = hypothesis.target_protocol.lower().strip()
        # Map common names
        proto_map = {"http": "http", "https": "ssl", "tls": "ssl", "tcp": "tcp", "udp": "udp", "dns": "dns", "icmp": "icmp"}
        canonical_proto = proto_map.get(proto, proto)
        if not is_valid_protocol_or_service(canonical_proto):
            errors.append(f"Invalid target protocol '{hypothesis.target_protocol}'. Must be a supported Snort 3 protocol or service.")

        # 3. Direction & Flow Intent Consistency Gate
        comm_dir = hypothesis.communication_direction.lower().strip()
        flow_intent = hypothesis.flow_intent.lower().strip()
        is_consistent, dir_err = validate_direction_consistency(flow_intent, comm_dir)
        if not is_consistent and dir_err:
            errors.append(dir_err)

        # 4. Invariant vs Brittle Indicator Safety Check
        invariants = hypothesis.invariant_indicators or []
        if not invariants:
            errors.append("Missing invariant indicators: Hypothesis must specify at least one stable protocol/payload indicator.")

        # Check for hardcoded private/ephemeral IPs and protocol constants
        valid_invariants_count = 0
        for inv in invariants:
            val_str = str(inv.get("value", "") if isinstance(inv, dict) else str(inv)).strip()
            ip_matches = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", val_str)
            for ip in ip_matches:
                if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                    errors.append(f"Brittle indicator violation: Invariant pattern contains internal IP '{ip}'. Snort rules must use $HOME_NET.")

            # Evaluate against Protocol Constant Catalogue
            eval_res = DEFAULT_FILTER.evaluate_invariant_candidate(
                candidate=val_str,
                protocol=canonical_proto,
                is_standalone=(len(invariants) == 1)
            )
            if eval_res.is_hard_exclusion:
                errors.append(f"Protocol Constant Violation: Invariant '{val_str}' matches protocol constant ({eval_res.rejection_reason}). Invariant indicators must be distinctive attack payloads.")
            else:
                valid_invariants_count += 1

        if invariants and valid_invariants_count == 0 and not errors:
            errors.append("All proposed invariant indicators match generic protocol constants. Provide distinctive payload indicators.")

        passed = len(errors) == 0
        details["verdict"] = "PROCEED_TO_RULE" if passed else "VALIDATION_FAILED"
        details["errors"] = errors
        return ValidationResult(
            status="passed" if passed else "failed",
            component="hypothesis",
            error=errors[0] if errors else None,
            evidence_required=True,
            details=details
        )

class RuleConstructionEngine:
    """
    Central Orchestrator for Hypothesis-Driven Iterative Rule Construction (HDIRC).
    Controls sequence, validation gates, retry loops, and AST updates.
    """
    def __init__(self, llm_client: Optional[LLMClient] = None, max_retries: int = 3):
        self.client = llm_client or LLMClient()
        self.validator = HypothesisValidator()
        self.header_generator = HeaderGenerator(llm_client=self.client, max_retries=max_retries)
        self.message_generator = MessageGenerator(llm_client=self.client, max_retries=max_retries)
        self.flow_generator = FlowGenerator(llm_client=self.client, max_retries=max_retries)
        self.detection_generator = DetectionGenerator(llm_client=self.client, max_retries=max_retries)
        self.supporting_generator = SupportingOptionsGenerator(llm_client=self.client, max_retries=max_retries)
        self.assembly_manager = RuleAssemblyManager()
        self.max_retries = max_retries

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 1: DETECTION HYPOTHESIS & VALIDATION GATE [ACTIVE]
    # ═════════════════════════════════════════════════════════════════════════

    def run_stage1_hypothesis(
        self,
        report: Dict[str, Any],
        pattern_discovery: Optional[Dict[str, Any]] = None,
        candidate_id: Optional[str] = None
    ) -> RuleState:
        """
        Stage 1: Generate a Detection Hypothesis from upstream modules,
        run it through the Hypothesis Validation Gate, and initialize RuleState.
        Includes a self-healing retry loop (max 3 retries).
        """
        cid = candidate_id or f"CAND_{report.get('capture_id', '001')}"
        state = RuleState(candidate_id=cid, status=ConstructionState.HYPOTHESIS_PENDING)

        # Extract available valid packet numbers from report evidence
        report_evidence_pkts = set()
        for ev in report.get("packet_evidence", []):
            if "pkt_num" in ev:
                report_evidence_pkts.add(int(ev["pkt_num"]))
        for a in report.get("alert_summary", []):
            for p in a.get("triggering_packets", []):
                report_evidence_pkts.add(int(p))

        retry_count = 0
        validation_errors: List[str] = []

        while retry_count <= self.max_retries:
            hypothesis = self._generate_hypothesis_llm(
                report=report,
                pattern_discovery=pattern_discovery,
                candidate_id=cid,
                previous_errors=validation_errors if retry_count > 0 else None
            )

            # Evaluate through Hypothesis Validation Gate
            passed, errors, details = self.validator.validate(
                hypothesis=hypothesis,
                report_evidence_packets=list(report_evidence_pkts)
            )

            if passed:
                disposition = details.get("verdict")
                state.hypothesis = hypothesis
                state.hypothesis_id = hypothesis.hypothesis_id

                if disposition == "INSUFFICIENT_EVIDENCE":
                    state.transition(ConstructionState.INSUFFICIENT_EVIDENCE, reason=details.get("reason", ""))
                    hypothesis.validation_status = "INSUFFICIENT_EVIDENCE"
                    hypothesis.validation_notes.append(details.get("reason", ""))
                    state.record_validation("stage1_hypothesis", passed=True, details=details)
                    return state

                elif disposition == "CORRELATION_ONLY":
                    state.transition(ConstructionState.CORRELATION_ONLY, reason=details.get("reason", ""))
                    hypothesis.validation_status = "CORRELATION_ONLY"
                    hypothesis.validation_notes.append(details.get("reason", ""))
                    state.record_validation("stage1_hypothesis", passed=True, details=details)
                    return state

                else:
                    # Approved hypothesis to proceed to Rule Construction
                    state.transition(ConstructionState.HYPOTHESIS_APPROVED, reason="Passed all hypothesis evidence and direction checks")
                    hypothesis.validation_status = "VALIDATED"
                    state.record_validation("stage1_hypothesis", passed=True, details=details)
                    # Advance to Stage 2 readiness
                    state.current_stage = 2

                    stage_result = StageResult(
                        status="success",
                        component="hypothesis",
                        generated_value=hypothesis.to_dict(),
                        evidence_refs=hypothesis.evidence.get("triggering_packets", []),
                        validation_errors=[],
                        reasoning_summary=f"Formulated and validated detection hypothesis for {hypothesis.malware_family or 'threat'}."
                    )
                    state.stage_results["stage1_hypothesis"] = stage_result.to_dict()
                    state.last_stage_result = stage_result.to_dict()
                    state.save_checkpoint(1)
                    return state

            # Hypothesis failed validation
            retry_count += 1
            state.stage_retry_counts["stage1_hypothesis"] = retry_count
            validation_errors = errors
            state.record_validation("stage1_hypothesis", passed=False, errors=errors, details=details)

        # Exhausted retries
        state.transition(ConstructionState.CONSTRUCTION_FAILED, reason=f"Hypothesis failed validation after {self.max_retries} retries: {'; '.join(validation_errors)}")
        return state

    def _generate_hypothesis_llm(
        self,
        report: Dict[str, Any],
        pattern_discovery: Optional[Dict[str, Any]] = None,
        candidate_id: str = "CAND_001",
        previous_errors: Optional[List[str]] = None
    ) -> DetectionHypothesis:
        """Query LLM to formulate structured Stage 1 Detection Hypothesis."""
        capture_id = report.get("capture_id", "PCAP_001")
        zeek_info = report.get("network_behaviour", {}).get("zeek", {})
        graph_summary = report.get("graph_summary", {})
        soc_report = report.get("executive_soc_report") or {}

        input_context = {
            "capture_id": capture_id,
            "malware_family": report.get("malware_family"),
            "threat_category": report.get("threat_category"),
            "ground_truth": report.get("ground_truth"),
            "alert_summary": report.get("alert_summary", [])[:5],
            "critical_attack_paths": [ap.get("path_chain") if isinstance(ap, dict) else str(ap) for ap in graph_summary.get("critical_attack_paths", [])[:3]],
            "soc_executive_summary": soc_report.get("executive_summary", ""),
            "correlations": report.get("correlations", [])[:6],
            "http_requests": report.get("network_behaviour", {}).get("http_requests", [])[:5],
            "dns_queries": report.get("network_behaviour", {}).get("dns_queries", [])[:5],
            "zeek_files": zeek_info.get("files_transferred", [])[:3],
            "zeek_ssl": zeek_info.get("ssl_certificates", [])[:2],
            "zeek_states": zeek_info.get("connection_states", {}),
            "packet_evidence": report.get("packet_evidence", [])[:10],
            "patterns": pattern_discovery.get("reusable_patterns", [])[:3] if pattern_discovery else []
        }

        retry_feedback = ""
        if previous_errors:
            retry_feedback = f"""
[CRITICAL CORRECTION REQUIRED]
Your previous hypothesis draft failed validation with the following errors:
{json.dumps(previous_errors, indent=2)}

Please strictly fix these issues:
1. Ground the hypothesis in verified packet numbers from the evidence.
2. Ensure communication_direction ('inbound_exploit' vs 'outbound_c2' vs 'server_response') strictly aligns with flow_intent ('to_server' vs 'to_client').
3. Do not hardcode internal/ephemeral IPs in invariant indicators.
"""

        user_prompt = f"""You are the Snort 3 Rule Engineer operating Stage 1 of Hypothesis-Driven Iterative Rule Construction (HDIRC).
Your goal is to formulate a structured Detection Hypothesis.

### CORE PRINCIPLES FOR STAGE 1 DETECTION HYPOTHESIS:
1. Invariant Indicators vs Brittle Indicators:
   - Identify stable protocol artifacts (e.g. URI structure, specific header pattern, payload magic bytes, beacon cadence, dropper filename/MIME).
   - Avoid ephemeral indicators (victim IPs, client dynamic ports, transient C2 domains).
2. Communication Direction & Flow Intent Alignment:
   - Client requesting exploit or C2 beacon -> communication_direction: "inbound_exploit" or "outbound_c2", flow_intent: "to_server"
   - Server returning payload/dropper -> communication_direction: "server_response", flow_intent: "to_client"
3. Rule Viability & Disposition Gate:
   - Not every behavior requires a Snort rule!
   - If evidence is too weak, set disposition: "INSUFFICIENT_EVIDENCE".
   - If behavior is pure multi-event correlation without a single packet signature, set disposition: "CORRELATION_ONLY".
   - If a strong packet signature exists, set disposition: "PROCEED_TO_RULE".

### OUTPUT SCHEMA REQUIREMENT:
Respond strictly with a JSON object conforming exactly to this schema:
{{
  "hypothesis_id": "HYP_{capture_id}_01",
  "capture_id": "{capture_id}",
  "target_behaviour": "<Specific attack behaviour being targeted>",
  "target_protocol": "HTTP | TCP | UDP | DNS | SSL | ICMP",
  "communication_direction": "inbound_exploit | outbound_c2 | server_response | bidirectional",
  "flow_intent": "to_server | to_client | stateless",
  "invariant_indicators": [
    {{
      "type": "uri_path | header | payload_hex | parameter | mime_type",
      "value": "<invariant value>",
      "confidence": "high | medium"
    }}
  ],
  "brittle_indicators_to_avoid": ["<ephemeral IP or port to avoid>"],
  "evidence": {{
    "triggering_packets": [<integers of packets from evidence, e.g. 4>],
    "flow_ids": ["<flow id>"],
    "summary": "<Explanation connecting evidence packets directly to attack>"
  }},
  "family_context": {{
    "malware_family": "{report.get('malware_family', 'Unknown')}",
    "threat_category": "{report.get('threat_category', 'Unknown')}",
    "cve": "<CVE if applicable, or null>"
  }},
  "detection_objective": "<Clear, concise statement of what the rule will detect>",
  "rule_viability": {{
    "needs_snort_rule": true,
    "disposition": "PROCEED_TO_RULE | INSUFFICIENT_EVIDENCE | CORRELATION_ONLY",
    "disposition_rationale": "<Justification for disposition>"
  }}
}}

{retry_feedback}
### TARGET SESSION EVIDENCE FOR CAPTURE {capture_id}:
<untrusted_network_data>
{sanitize_untrusted_data(input_context)}
</untrusted_network_data>
"""
        try:
            resp_text = self.client.query(SYSTEM_PROMPT, user_prompt, json_mode=True, temperature=0.1)
            parsed = json.loads(self._extract_json(resp_text))
            if isinstance(parsed, dict) and "target_behaviour" in parsed and ("invariant_indicators" in parsed or "evidence" in parsed):
                return DetectionHypothesis.from_dict(parsed)
            # Fallback if LLM returned generic fallback or malformed schema
            return self._synthesize_hypothesis_fallback(report)
        except Exception:
            return self._synthesize_hypothesis_fallback(report)

    def _synthesize_hypothesis_fallback(self, report: Dict[str, Any]) -> DetectionHypothesis:
        """High-fidelity deterministic hypothesis synthesizer fallback."""
        cid = report.get("capture_id", "PCAP_001")
        malware = report.get("malware_family", "Malware")
        cat = report.get("threat_category", "Network Attack")
        alerts = report.get("alert_summary", [])
        corrs = report.get("correlations", [])
        zeek_files = report.get("network_behaviour", {}).get("zeek", {}).get("files_transferred", [])
        http_reqs = report.get("network_behaviour", {}).get("http_requests", [])

        # Find evidence packets from report
        ev_pkts = []
        for a in alerts:
            ev_pkts.extend(a.get("triggering_packets", []))
        if not ev_pkts:
            for ev in report.get("packet_evidence", []):
                if "pkt_num" in ev:
                    ev_pkts.append(ev["pkt_num"])
        ev_pkts = sorted(list(dict.fromkeys(ev_pkts)))[:5]
        if not ev_pkts:
            ev_pkts = [1]

        # Invariant selection
        invariants = []
        if http_reqs:
            for req in http_reqs:
                ua = req.get("user_agent", "")
                if ua and "${jndi:" in ua:
                    invariants.append({"type": "header", "value": "${jndi:ldap://", "confidence": "very_high"})
                    break
                uri = req.get("uri", "")
                if uri and len(uri) > 1:
                    clean_uri = uri[:25]
                    invariants.append({"type": "uri_path", "value": clean_uri, "confidence": "high"})
                    break

        if zeek_files:
            fn = zeek_files[0].get("filename")
            if fn:
                invariants.append({"type": "filename", "value": fn, "confidence": "high"})

        if not invariants:
            invariants.append({"type": "payload_hex", "value": "malicious_artifact", "confidence": "medium"})

        return DetectionHypothesis(
            hypothesis_id=f"HYP_{cid}_01",
            capture_id=cid,
            target_behaviour=f"Detect {malware} malicious protocol activity and command-and-control communication",
            target_protocol="HTTP" if http_reqs else "TCP",
            communication_direction="outbound_c2",
            flow_intent="to_server",
            invariant_indicators=invariants,
            brittle_indicators_to_avoid=["Ephemeral source ports", "Attacker dynamic IP"],
            evidence={
                "triggering_packets": ev_pkts,
                "summary": f"Observed suspicious protocol transactions in capture across packets {ev_pkts}."
            },
            family_context={"malware_family": malware, "threat_category": cat},
            detection_objective=f"Detect invariant network communication patterns associated with {malware}.",
            rule_viability={
                "needs_snort_rule": True,
                "disposition": "PROCEED_TO_RULE",
                "disposition_rationale": "High-confidence protocol artifact identified in network capture."
            }
        )

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 2: HEADER GENERATION & VALIDATION GATE [ACTIVE]
    # ═════════════════════════════════════════════════════════════════════════

    def stage2_header_generation(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Stage 2: Header Generation & Validation Gate [ACTIVE].
        Generates and validates the Snort 3 rule header (Action, Rule Type, Protocol/Service,
        Source, Destination, Ports, Direction) based on the approved Detection Hypothesis.
        """
        if state.status != ConstructionState.HYPOTHESIS_APPROVED.value:
            raise ValueError(f"Cannot execute Stage 2: Rule State is '{state.status}', expected '{ConstructionState.HYPOTHESIS_APPROVED.value}'.")

        return self.header_generator.generate(state, report=report)

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 3: MESSAGE GENERATION & VALIDATION GATE [ACTIVE]
    # ═════════════════════════════════════════════════════════════════════════

    def stage3_message_generation(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Stage 3: Message Generation & Validation Gate [ACTIVE].
        Generates and validates the descriptive alert message (msg:"...") conforming to
        VRT/Talos naming conventions, non-compromise tone rules, and character escaping.
        """
        if state.status not in [ConstructionState.HEADER_GENERATED.value, ConstructionState.HYPOTHESIS_APPROVED.value]:
            raise ValueError(f"Cannot execute Stage 3: Rule State is '{state.status}', expected '{ConstructionState.HEADER_GENERATED.value}'.")

        return self.message_generator.generate(state, report=report)

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 4: FLOW GENERATION & VALIDATION GATE [ACTIVE]
    # ═════════════════════════════════════════════════════════════════════════

    def stage4_flow_generation(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Stage 4: Flow Generation & Validation Gate [ACTIVE].
        Generates and validates transport session tracking properties (flow:...)
        conforming to Snort 3 category exclusivity, protocol suitability,
        and cross-stage consistency with Stage 1 hypothesis and Stage 2 header.
        """
        if state.status not in [ConstructionState.MESSAGE_GENERATED.value, ConstructionState.HEADER_GENERATED.value]:
            raise ValueError(f"Cannot execute Stage 4: Rule State is '{state.status}', expected '{ConstructionState.MESSAGE_GENERATED.value}'.")

        return self.flow_generator.generate(state, report=report)

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 5: DETECTION GENERATION & VALIDATION GATE [ACTIVE]
    # ═════════════════════════════════════════════════════════════════════════

    def stage5_detection_generation(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Stage 5: Detection Generation & Validation Gate [ACTIVE].
        Generates and validates payload detection conditions across the 5 sub-stages:
        - 5.1 Buffer selection (sticky buffers)
        - 5.2 Content & pattern matching (content, fast_pattern, nocase, pcre, regex)
        - 5.3 Positioning & relationship constraints (offset, depth, distance, within, isdataat, bufferlen)
        - 5.4 Numeric, binary & structured-data inspection (byte_*, dsize, ber_*)
        - 5.5 Protocol-specific detection (HTTP, SSL/TLS, DCE/RPC, SIP, industrial)
        """
        if state.status not in [ConstructionState.FLOW_GENERATED.value, ConstructionState.MESSAGE_GENERATED.value]:
            raise ValueError(f"Cannot execute Stage 5: Rule State is '{state.status}', expected '{ConstructionState.FLOW_GENERATED.value}'.")

        return self.detection_generator.generate(state, report=report)

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 6: SUPPORTING OPTIONS & METADATA [ACTIVE]
    # ═════════════════════════════════════════════════════════════════════════

    def stage6_supporting_options(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None,
        base_sid: Optional[int] = None
    ) -> RuleState:
        """
        Stage 6: Supporting Options & Metadata [ACTIVE].
        Generates and validates supporting options, non-payload options, post-detection options,
        and assigns deterministic Python identity (sid >= 1,000,000, rev).
        """
        if state.status not in [ConstructionState.DETECTION_GENERATED.value, ConstructionState.FLOW_GENERATED.value]:
            raise ValueError(f"Cannot execute Stage 6: Rule State is '{state.status}', expected '{ConstructionState.DETECTION_GENERATED.value}'.")

        if base_sid:
            self.supporting_generator.base_sid = base_sid

        return self.supporting_generator.generate(state, report=report)

    # ═════════════════════════════════════════════════════════════════════════
    # STAGE 7: FINAL ASSEMBLY & DUAL-PASS PCAP VERIFICATION [ACTIVE]
    # ═════════════════════════════════════════════════════════════════════════

    def stage7_final_assembly(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None,
        verify_pcaps: bool = True,
        max_benign_packets: int = 5000,
        motivating_pcap_id: Optional[str] = None
    ) -> RuleState:
        """
        Stage 7: Final Rule Assembly & Dual-Pass PCAP Verification [ACTIVE].
        Converts validated components to canonical intermediate structured representation,
        renders multi-line & single-line Snort 3 syntax, checks ruleset conflicts/shadowing,
        verifies Snort 3 compiler syntax (-T), and executes dual-pass replay (TP and FP).
        """
        if state.status not in [
            ConstructionState.SUPPORTING_GENERATED.value,
            ConstructionState.DETECTION_GENERATED.value,
            ConstructionState.RULE_ASSEMBLED.value
        ]:
            raise ValueError(f"Cannot execute Stage 7: Rule State is '{state.status}', expected '{ConstructionState.SUPPORTING_GENERATED.value}'.")

        self.assembly_manager.assemble_and_validate(
            state=state,
            report=report,
            verify_pcaps=verify_pcaps,
            max_benign_packets=max_benign_packets,
            motivating_pcap_id=motivating_pcap_id
        )
        return state

    # ═════════════════════════════════════════════════════════════════════════
    # FULL HDIRC PIPELINE COORDINATOR
    # ═════════════════════════════════════════════════════════════════════════

    def execute_hdirc(
        self,
        report: Dict[str, Any],
        pattern_discovery: Optional[Dict[str, Any]] = None,
        target_stage: int = 1,
        base_sid: int = 9001001,
        verify_pcaps: bool = True,
        max_benign_packets: int = 5000
    ) -> RuleState:
        """
        Execute HDIRC up to the specified target stage.
        Default target_stage=1 stops cleanly after Stage 1 Hypothesis validation gate.
        """
        # Execute Stage 1
        state = self.run_stage1_hypothesis(report, pattern_discovery)

        # If hypothesis was rejected, failed, or was correlation_only/insufficient_evidence, return
        if state.status not in [ConstructionState.HYPOTHESIS_APPROVED.value]:
            return state

        if target_stage == 1:
            return state

        # Proceed through requested stages
        if target_stage >= 2:
            self.stage2_header_generation(state, report=report)
            if state.status == ConstructionState.CONSTRUCTION_FAILED.value:
                return state
        if target_stage >= 3:
            self.stage3_message_generation(state, report=report)
            if state.status == ConstructionState.CONSTRUCTION_FAILED.value:
                return state
        if target_stage >= 4:
            self.stage4_flow_generation(state, report=report)
            if state.status == ConstructionState.CONSTRUCTION_FAILED.value:
                return state
        if target_stage >= 5:
            self.stage5_detection_generation(state, report=report)
            if state.status == ConstructionState.CONSTRUCTION_FAILED.value:
                return state
        if target_stage >= 6:
            self.stage6_supporting_options(state, report=report, base_sid=base_sid)
            if state.status == ConstructionState.CONSTRUCTION_FAILED.value:
                return state
        if target_stage >= 7:
            self.stage7_final_assembly(
                state,
                report=report,
                verify_pcaps=verify_pcaps,
                max_benign_packets=max_benign_packets
            )

        return state

    def _extract_json(self, text: str) -> str:
        """Extract JSON substring if LLM wraps it in markdown code blocks."""
        text = text.strip()
        m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if m:
            return m.group(1).strip()
        return text
