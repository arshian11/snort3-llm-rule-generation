"""
Snort 3 Stage 4 — Flow Generation & Session Tracking Engine.
Grounded in snort3_complete_rule_documentation.txt (Page 30: flow).

Implements:
1. Flow Option Construction:
   - Session property checking across 4 property categories:
     1. Direction: to_server, to_client, from_client, from_server
     2. Connection state: established, not_established, stateless
     3. Stream state: no_stream, only_stream
     4. Fragment state: no_frag, only_frag
   - Strict category exclusivity (at most one property per category)
   - Strict consistency with Stage 1 Detection Hypothesis and Stage 2 Rule Header
   - Contextual requirement checking (mandatory omission for 'alert file' / 'file_id' rules)
2. Helper Functions:
   - generate_flow_direction(hypothesis, header)
   - generate_connection_state(hypothesis, header)
   - generate_stream_state(hypothesis, header)
   - generate_fragment_state(hypothesis, header)
   - assemble_flow_option(direction, connection_state, stream_state, fragment_state)
   - validate_flow_option(flow_option, hypothesis, header)
3. FlowValidator & FlowGenerator Orchestrator with LLM Self-Healing Retry Loop.
"""

from typing import Dict, List, Set, Any, Optional, Tuple, Union
import re
import json

from snort_pipeline.snort3_catalogue import (
    VALID_FLOW_DIRECTIONS,
    VALID_FLOW_STATES,
    VALID_FLOW_STREAM_OPTIONS,
    VALID_FLOW_FRAG_OPTIONS,
    validate_flow_args,
    validate_direction_consistency
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
# 1. HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def generate_flow_direction(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> Optional[str]:
    """
    Synthesize appropriate flow direction argument (to_server, to_client, from_client, from_server).
    - Returns None if flow is not required (e.g. file rules, stateless packets, bidirectional headers).
    - Returns 'to_server' for client-initiated requests (inbound exploit, outbound C2).
    - Returns 'to_client' for server responses (server-side data transfer, C2 replies).
    """
    if header and header.header_type in ["file", "file_id"]:
        return None

    if header and header.direction == "<>":
        # Bidirectional headers cannot be paired with directional flow constraints
        return None

    # Protocol check
    proto = ""
    if header and header.protocol:
        proto = header.protocol.lower().strip()
    elif hypothesis.target_protocol:
        proto = hypothesis.target_protocol.lower().strip()

    if proto in ["icmp", "ip"]:
        return None

    # Evaluate hypothesis communication direction and flow intent
    comm_dir = (hypothesis.communication_direction or "").lower().strip()
    flow_intent = (hypothesis.flow_intent or "").lower().strip()

    if flow_intent in VALID_FLOW_DIRECTIONS:
        return flow_intent

    if comm_dir in ["inbound_exploit", "outbound_c2", "client_request", "inbound_attack", "outbound_exfil"]:
        return "to_server"
    elif comm_dir in ["server_response", "c2_response", "inbound_response", "server_data"]:
        return "to_client"

    # Evaluate header orientation if traditional
    if header and header.header_type == "traditional":
        src = (header.source_addr or "").strip()
        dst = (header.dest_addr or "").strip()
        dst_port = (header.dest_port or "").strip()

        # Outbound C2 from home net to external
        if src == "$HOME_NET" and dst == "$EXTERNAL_NET":
            return "to_server"
        # Inbound exploit from external to internal server
        if src == "$EXTERNAL_NET" and dst == "$HOME_NET" and dst_port in ["80", "443", "$HTTP_PORTS", "8080", "21", "22", "25"]:
            return "to_server"
        # External server responding to internal client
        if src == "$EXTERNAL_NET" and dst == "$HOME_NET" and header.source_port in ["80", "443", "$HTTP_PORTS", "8080"]:
            return "to_client"

    # Default for attack/C2 detection is client request
    return "to_server"


def generate_connection_state(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> Optional[str]:
    """
    Synthesize appropriate connection state argument (established, not_established, stateless).
    - Returns None if flow is not required (e.g. file rules).
    - Returns 'established' for established TCP application sessions (HTTP, SSL, C2, exploit payloads).
    - Returns 'not_established' for initial connection attempts (SYN scan, pre-handshake probes).
    - Returns 'stateless' for raw packet inspections or connectionless protocols when session state is ignored.
    """
    if header and header.header_type in ["file", "file_id"]:
        return None

    # Determine transport protocol
    proto = ""
    if header and header.header_type == "service":
        # Service headers represent application layer protocols running over TCP
        return "established"
    elif header and header.protocol:
        proto = header.protocol.lower().strip()
    elif hypothesis.target_protocol:
        proto = hypothesis.target_protocol.lower().strip()

    if proto in ["icmp", "ip"]:
        return "stateless"

    if proto == "udp":
        # UDP does not have TCP handshake established state; omit or use stateless
        return None

    # For TCP traffic:
    target_behaviour = (hypothesis.target_behaviour or "").lower()
    detection_obj = (hypothesis.detection_objective or "").lower()

    if any(k in target_behaviour or k in detection_obj for k in ["syn flood", "syn scan", "pre-handshake", "connection attempt", "initial syn"]):
        return "not_established"

    if any(k in target_behaviour or k in detection_obj for k in ["stateless", "raw packet", "single packet"]):
        return "stateless"

    # Default for TCP application and exploit traffic
    return "established"


def generate_stream_state(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> Optional[str]:
    """
    Synthesize stream reassembly state argument (no_stream, only_stream).
    - Returns 'only_stream' if detection strictly requires reassembled stream data.
    - Returns 'no_stream' if detection targets non-reassembled individual packets.
    - Returns None (default) for standard rules where Snort's default stream handling applies.
    """
    if header and header.header_type in ["file", "file_id"]:
        return None

    target = (hypothesis.target_behaviour or "").lower()
    invariants = hypothesis.invariant_indicators or []

    # Check if stream-only reassembly is explicitly required
    for inv in invariants:
        inv_type = (inv.get("type", "") if isinstance(inv, dict) else "").lower()
        if inv_type in ["stream_reassembly", "multi_packet_body", "chunked_stream"]:
            return "only_stream"

    if "only_stream" in target or "reassembled stream" in target:
        return "only_stream"

    if "no_stream" in target or "raw packet boundary" in target or "packet-level evasion" in target:
        return "no_stream"

    return None


def generate_fragment_state(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> Optional[str]:
    """
    Synthesize fragmentation state argument (no_frag, only_frag).
    - Returns 'only_frag' for de-fragmented reassembled packets.
    - Returns 'no_frag' for raw fragmented packets.
    - Returns None (default) for standard application traffic.
    """
    if header and header.header_type in ["file", "file_id"]:
        return None

    target = (hypothesis.target_behaviour or "").lower()
    if "only_frag" in target or "defragmented packet" in target:
        return "only_frag"
    if "no_frag" in target or "fragmented packet" in target or "fragment evasion" in target:
        return "no_frag"

    return None


def assemble_flow_option(
    direction: Optional[str] = None,
    connection_state: Optional[str] = None,
    stream_state: Optional[str] = None,
    fragment_state: Optional[str] = None
) -> Optional[List[str]]:
    """
    Assemble the 4 flow categories into a canonical, deduplicated list of flow arguments.
    Enforces standard Snort ordering: [direction, connection_state, stream_state, fragment_state].
    Returns None if all arguments are None (flow omitted).
    """
    args: List[str] = []

    if direction and direction.strip().lower() in VALID_FLOW_DIRECTIONS:
        args.append(direction.strip().lower())

    if connection_state and connection_state.strip().lower() in VALID_FLOW_STATES:
        clean_conn = connection_state.strip().lower()
        if clean_conn not in args:
            args.append(clean_conn)

    if stream_state and stream_state.strip().lower() in VALID_FLOW_STREAM_OPTIONS:
        clean_stream = stream_state.strip().lower()
        if clean_stream not in args:
            args.append(clean_stream)

    if fragment_state and fragment_state.strip().lower() in VALID_FLOW_FRAG_OPTIONS:
        clean_frag = fragment_state.strip().lower()
        if clean_frag not in args:
            args.append(clean_frag)

    return args if args else None


def validate_flow_option(
    flow_option: Optional[List[str]],
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Validate a flow option proposal against Snort 3 syntax, category exclusivity,
    and consistency with Stage 1 Hypothesis and Stage 2 Rule Header.

    Returns:
        (passed, errors, details)
    """
    errors: List[str] = []
    details: Dict[str, Any] = {
        "flow_option": flow_option,
        "is_required": True,
        "categories_present": []
    }

    # 1. Contextual requirement check: File Rules
    if header and header.header_type in ["file", "file_id"]:
        details["is_required"] = False
        if flow_option and len(flow_option) > 0:
            errors.append(
                f"Snort 3 file rules ('{header.header_type}') inspect extracted file preprocessor data and must omit the 'flow' option."
            )
            return False, errors, details
        else:
            details["not_required"] = True
            details["reason"] = f"File rule ('{header.header_type}') correctly omits flow option."
            return True, [], details

    # 2. Check if flow is omitted for network traffic
    if not flow_option:
        # Check transport protocol
        proto = ""
        if header and header.header_type == "service":
            proto = header.service or "tcp"
        elif header and header.protocol:
            proto = header.protocol.lower().strip()
        elif hypothesis.target_protocol:
            proto = hypothesis.target_protocol.lower().strip()

        if proto in ["tcp", "http", "ssl", "tls", "smtp", "ftp"]:
            errors.append(
                f"Missing flow option: TCP / application rules targeting '{proto}' require session tracking (e.g. 'flow:to_server,established;' or 'flow:to_client,established;')."
            )
            return False, errors, details
        else:
            # Connectionless traffic (UDP, ICMP, IP) may omit flow
            details["is_required"] = False
            details["not_required"] = True
            details["reason"] = f"Connectionless traffic ('{proto}') may omit flow option."
            return True, [], details

    # 3. Syntax & Category Exclusivity Verification via Catalogue
    valid_args, arg_errors = validate_flow_args(flow_option)
    if not valid_args:
        errors.extend(arg_errors)

    # Track present categories
    for arg in flow_option:
        a_clean = arg.lower().strip()
        if a_clean in VALID_FLOW_DIRECTIONS:
            details["categories_present"].append("direction")
        elif a_clean in VALID_FLOW_STATES:
            details["categories_present"].append("connection_state")
        elif a_clean in VALID_FLOW_STREAM_OPTIONS:
            details["categories_present"].append("stream_state")
        elif a_clean in VALID_FLOW_FRAG_OPTIONS:
            details["categories_present"].append("fragment_state")

    # 4. Consistency with Stage 1 Hypothesis (Communication Direction & Flow Intent)
    flow_dir = next((a.lower().strip() for a in flow_option if a.lower().strip() in VALID_FLOW_DIRECTIONS), None)
    if flow_dir:
        comm_dir = (hypothesis.communication_direction or "").lower().strip()
        dir_ok, dir_err = validate_direction_consistency(flow_dir, comm_dir)
        if not dir_ok and dir_err:
            errors.append(f"Hypothesis direction mismatch: {dir_err}")

        # Check against hypothesis flow_intent if specified
        flow_intent = (hypothesis.flow_intent or "").lower().strip()
        if flow_intent in VALID_FLOW_DIRECTIONS:
            if flow_intent in ["to_server", "from_client"] and flow_dir in ["to_client", "from_server"]:
                errors.append(f"Inconsistency: Hypothesis flow_intent is '{flow_intent}' (client->server), but flow option specifies '{flow_dir}'.")
            elif flow_intent in ["to_client", "from_server"] and flow_dir in ["to_server", "from_client"]:
                errors.append(f"Inconsistency: Hypothesis flow_intent is '{flow_intent}' (server->client), but flow option specifies '{flow_dir}'.")

    # 5. Consistency with Stage 2 Header
    if header:
        # Bidirectional header check
        if header.direction == "<>" and flow_dir:
            errors.append(
                f"Header conflict: Rule header uses bidirectional direction '<>', which conflicts with directional flow argument '{flow_dir}'."
            )

        # Protocol check for connection states
        proto = (header.protocol or "").lower().strip()
        conn_state = next((a.lower().strip() for a in flow_option if a.lower().strip() in VALID_FLOW_STATES), None)
        if conn_state in ["established", "not_established"]:
            if proto in ["udp", "icmp", "ip"]:
                errors.append(
                    f"Protocol conflict: Connection state '{conn_state}' applies only to TCP connections, not {proto.upper()}."
                )

    passed = len(errors) == 0
    return ValidationResult(
        status="passed" if passed else "failed",
        component="flow",
        error=errors[0] if errors else None,
        evidence_required=False,
        details=details
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. FLOW VALIDATOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class FlowValidator:
    """
    Encapsulates validation logic for Stage 4 Flow Generation.
    Enforces Snort 3 category exclusivity, protocol applicability,
    and cross-stage consistency.
    """
    def validate(
        self,
        flow_option: Optional[List[str]],
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None
    ) -> ValidationResult:
        return validate_flow_option(flow_option, hypothesis, header)


# ─────────────────────────────────────────────────────────────────────────────
# 3. FLOW GENERATOR ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class FlowGenerator:
    """
    Manages Stage 4 Rule Flow Generation.
    Coordinates LLM proposal generation, FlowValidator safety gate evaluation,
    self-healing retry loops, and deterministic fallback synthesis.
    """
    def __init__(self, llm_client: Optional[LLMClient] = None, max_retries: int = 3):
        self.client = llm_client or LLMClient()
        self.validator = FlowValidator()
        self.max_retries = max_retries

    def generate(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Execute Stage 4: Generate and validate Snort 3 flow option, then commit to RuleState AST.
        """
        hyp = state.hypothesis
        header = state.ast.header
        if not hyp:
            state.transition(ConstructionState.CONSTRUCTION_FAILED, reason="Stage 4 requires an approved Detection Hypothesis in RuleState.")
            return state

        # Check if header is a file rule (flow mandatory omission)
        if header and header.header_type in ["file", "file_id"]:
            state.components["flow"] = None
            self._update_ast_flow_option(state, None)
            state.record_validation("stage4_flow", passed=True, details={"not_required": True, "reason": "File rule omits flow."})
            state.transition(ConstructionState.FLOW_GENERATED, reason=f"File rule ('{header.header_type}') correctly omits flow option.")
            state.current_stage = 5

            stage_result = StageResult(
                status="success",
                component="flow",
                generated_value={"flow_args": None},
                evidence_refs=hyp.evidence.get("triggering_packets", []),
                validation_errors=[],
                reasoning_summary=f"File rule ('{header.header_type}') correctly omits flow option."
            )
            state.stage_results["stage4_flow"] = stage_result.to_dict()
            state.last_stage_result = stage_result.to_dict()
            state.save_checkpoint(4)
            return state

        msg_opt = next((o for o in state.ast.options if o.name == "msg"), None)
        msg_str = msg_opt.value if msg_opt else state.components.get("msg")

        retry_count = 0
        validation_errors: List[str] = []

        while retry_count <= self.max_retries:
            proposed_args = self._propose_flow_llm(
                hypothesis=hyp,
                header=header,
                msg_str=msg_str,
                report=report,
                previous_errors=validation_errors if retry_count > 0 else None
            )

            passed, errors, details = self.validator.validate(
                flow_option=proposed_args,
                hypothesis=hyp,
                header=header
            )

            if passed:
                # Commit validated flow arguments to RuleState components
                state.components["flow"] = proposed_args

                # Commit to AST options at index 1 (immediately after msg)
                self._update_ast_flow_option(state, proposed_args)

                flow_repr = ",".join(proposed_args) if proposed_args else "omitted"
                state.record_validation("stage4_flow", passed=True, details=details)
                state.transition(ConstructionState.FLOW_GENERATED, reason=f"Flow option '{flow_repr}' validated and committed to AST.")
                state.current_stage = 5

                stage_result = StageResult(
                    status="success",
                    component="flow",
                    generated_value={"flow_args": proposed_args},
                    evidence_refs=hyp.evidence.get("triggering_packets", []),
                    validation_errors=[],
                    reasoning_summary=f"Established transport session tracking: flow:{','.join(proposed_args) if proposed_args else 'omitted'};"
                )
                state.stage_results["stage4_flow"] = stage_result.to_dict()
                state.last_stage_result = stage_result.to_dict()
                state.save_checkpoint(4)
                return state

            # Flow failed validation -> Retry
            retry_count += 1
            state.stage_retry_counts["stage4_flow"] = retry_count
            validation_errors = errors
            state.record_validation("stage4_flow", passed=False, errors=errors, details=details)

        # Retries exhausted: Fall back to deterministic synthesizer
        fallback_args = self._synthesize_fallback_flow(hyp, header)
        passed, errors, details = self.validator.validate(fallback_args, hyp, header)

        if passed:
            state.components["flow"] = fallback_args
            self._update_ast_flow_option(state, fallback_args)
            flow_repr = ",".join(fallback_args) if fallback_args else "omitted"
            state.record_validation("stage4_flow", passed=True, details=details)
            state.transition(ConstructionState.FLOW_GENERATED, reason=f"Deterministic fallback flow '{flow_repr}' committed to AST.")
            state.current_stage = 5

            stage_result = StageResult(
                status="success",
                component="flow",
                generated_value={"flow_args": fallback_args},
                evidence_refs=hyp.evidence.get("triggering_packets", []),
                validation_errors=[],
                reasoning_summary=f"Synthesized fallback transport session tracking: flow:{','.join(fallback_args) if fallback_args else 'omitted'};"
            )
            state.stage_results["stage4_flow"] = stage_result.to_dict()
            state.last_stage_result = stage_result.to_dict()
            state.save_checkpoint(4)
            return state

        # Complete failure
        state.transition(ConstructionState.CONSTRUCTION_FAILED, reason=f"Stage 4 Flow generation failed validation: {'; '.join(validation_errors)}")
        fail_result = StageResult(
            status="failed",
            component="flow",
            generated_value=None,
            evidence_refs=hyp.evidence.get("triggering_packets", []),
            validation_errors=validation_errors,
            reasoning_summary="Stage 4 Flow generation failed validation retries and fallback."
        )
        state.stage_results["stage4_flow"] = fail_result.to_dict()
        state.last_stage_result = fail_result.to_dict()
        return state

    def _propose_flow_llm(
        self,
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None,
        msg_str: Optional[str] = None,
        report: Optional[Dict[str, Any]] = None,
        previous_errors: Optional[List[str]] = None
    ) -> Optional[List[str]]:
        """Query LLM to propose Snort 3 flow option properties using the 3-Pillar Prompt Schema."""
        family = getattr(hypothesis, "malware_family", "") or hypothesis.family_context.get("malware_family", "Malware")
        target_behaviour = hypothesis.target_behaviour
        objective = hypothesis.detection_objective
        comm_dir = hypothesis.communication_direction
        flow_intent = hypothesis.flow_intent
        target_proto = hypothesis.target_protocol
        header_str = header.render() if header else "alert tcp $EXTERNAL_NET any -> $HOME_NET any"
        stage4_catalogue = format_stage_catalogue_for_llm(4)
        ev_refs = hypothesis.evidence.get("triggering_packets", [])

        msg_part = f'msg:"{msg_str}"; ' if msg_str else ""
        rule_prefix = f"{header_str} ( {msg_part}[INSERT STAGE 4 FLOW HERE] )"

        retry_feedback = ""
        if previous_errors:
            retry_feedback = f"""
[CRITICAL CORRECTION REQUIRED]
Your previous flow proposal failed validation with the following errors:
{json.dumps(previous_errors, indent=2)}

Please strictly fix these issues:
1. Enforce category exclusivity: AT MOST ONE option from each category:
   - Direction: to_server | to_client | from_client | from_server
   - Connection state: established | not_established | stateless
   - Stream state: no_stream | only_stream
   - Fragment state: no_frag | only_frag
2. Consistency with Direction:
   - Client requests (inbound exploit, outbound C2) MUST use 'to_server' (or 'from_client').
   - Server responses MUST use 'to_client' (or 'from_server').
3. For file rules, flow must be omitted.
4. For UDP or ICMP, connection states like 'established' are invalid (TCP only).
"""

        user_prompt = f"""You are the Snort 3 Rule Engineer operating Stage 4: Flow Generation.

1. COMPONENT-GENERATION INSTRUCTIONS:
Propose the transport session tracking properties (`flow`) for AST Option #1. Output strictly valid JSON.
Respond strictly conforming to this schema:
{{
  "required": true,
  "direction": "to_server | to_client | from_client | from_server | null",
  "connection_state": "established | not_established | stateless | null",
  "stream_state": "only_stream | no_stream | null",
  "fragment_state": "only_frag | no_frag | null",
  "flow_args": ["to_server", "established"],
  "rationale": "<Reasoning connecting selected flow options to hypothesis and header>"
}}

2. RELEVANT CATALOGUE ENTRIES (Dynamic from OptionSpec):
{stage4_catalogue}

3. CURRENT RULE CONTEXT & ACCUMULATED STATE:
- Detection Hypothesis:
  - Threat Family: {family}
  - Intended Behaviour: {target_behaviour}
  - Detection Objective: {objective}
  - Target Protocol: {target_proto}
  - Communication Direction: {comm_dir}
  - Hypothesis Flow Intent: {flow_intent}
- Evidence References (Triggering Packets): {ev_refs}
- Upstream AST Components:
  - Header: {header_str}
  - Option #0 (msg): {msg_str or 'Omitted'}
- Current Rule Prefix:
  {rule_prefix}
{retry_feedback}
"""

        SYSTEM_PROMPT = """You are an expert Snort 3 rule engineer specializing in transport session tracking and the flow option.
You propose strictly valid, dependency-consistent flow options adhering to the Snort 3 rule specification.
You output strictly valid JSON without conversational text or codeblock wrappers."""

        try:
            resp_text = self.client.query(SYSTEM_PROMPT, user_prompt, json_mode=True, temperature=0.1)
            parsed = json.loads(self._extract_json(resp_text))

            if not parsed.get("required", True):
                return None

            flow_args = parsed.get("flow_args")
            if isinstance(flow_args, list):
                # Sanitize tokens
                clean_args = [str(x).strip().lower() for x in flow_args if str(x).strip()]
                return clean_args if clean_args else None

            # Alternatively assemble from individual categories
            return assemble_flow_option(
                direction=parsed.get("direction"),
                connection_state=parsed.get("connection_state"),
                stream_state=parsed.get("stream_state"),
                fragment_state=parsed.get("fragment_state")
            )
        except Exception:
            return self._synthesize_fallback_flow(hypothesis, header)

    def _synthesize_fallback_flow(
        self,
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None
    ) -> Optional[List[str]]:
        """Deterministic high-fidelity fallback flow synthesizer."""
        direction = generate_flow_direction(hypothesis, header)
        conn_state = generate_connection_state(hypothesis, header)
        stream_state = generate_stream_state(hypothesis, header)
        frag_state = generate_fragment_state(hypothesis, header)
        return assemble_flow_option(direction, conn_state, stream_state, frag_state)

    def _update_ast_flow_option(self, state: RuleState, flow_args: Optional[List[str]]):
        """
        Commit flow option to RuleState AST.
        Canonical Snort 3 rule option order:
        Index 0: msg
        Index 1: flow (if present)
        Index 2+: detection sticky buffers, payload options, metadata, classtype, sid, rev.
        """
        # Remove any pre-existing flow option
        state.ast.options = [opt for opt in state.ast.options if opt.name != "flow"]

        if not flow_args:
            return

        # Find position to insert flow: immediately after 'msg' if msg exists at position 0
        insert_idx = 0
        for idx, opt in enumerate(state.ast.options):
            if opt.name == "msg":
                insert_idx = idx + 1
                break

        state.ast.options.insert(insert_idx, RuleOptionAST(name="flow", value=flow_args))

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
