"""
Snort 3 Stage 2 — Header Generation & Validation Engine.
Grounded in snort3_complete_rule_documentation.txt (Pages 2-11: Actions, Directions,
File Identification Rules, File Rules, Rule Headers, IP Addresses, Ports, Protocols, Service Rules).

Implements:
1. Header Component Generation:
   - Action (alert, block, drop, log, pass, react, reject, rewrite; default 'alert')
   - Rule Type (traditional, service, file, file_id)
   - Protocol / Service (tcp, udp, icmp, ip, or application services)
   - Source Scope ($HOME_NET, $EXTERNAL_NET, any, lists, negation)
   - Destination Scope ($HOME_NET, $EXTERNAL_NET, any, lists, negation)
   - Source Port (any, static, variables, ranges, negation)
   - Destination Port (any, static, $HTTP_PORTS, ranges, negation)
   - Direction (->, <>)
2. Specialized Header Formats:
   - Traditional: <action> <proto> <src_ip> <src_port> <dir> <dst_ip> <dst_port>
   - Service:     <action> <service>
   - File:        <action> file
   - File ID:     file_id
3. Helper Functions:
   - generate_rule_type()
   - generate_action()
   - generate_protocol()
   - generate_source_scope()
   - generate_destination_scope()
   - generate_source_port()
   - generate_destination_port()
   - generate_direction()
   - assemble_header()
   - validate_header()
4. HeaderGenerator Orchestrator with LLM Prompting & Self-Healing Retry Loop.
"""

from typing import Dict, List, Set, Any, Optional, Tuple, Union
import re
import json

from snort_pipeline.snort3_catalogue import (
    VALID_ACTIONS,
    VALID_RULE_TYPES,
    VALID_PROTOCOLS,
    VALID_SERVICE_HEADERS,
    VALID_DIRECTIONS,
    VALID_IP_VARIABLES,
    VALID_PORT_VARIABLES,
    FORBIDDEN_VARIABLES,
    is_valid_action,
    is_valid_rule_type,
    is_valid_direction,
    is_valid_protocol_or_service,
    is_valid_ip_token,
    is_valid_port_token
)
from snort_pipeline.rule_state import RuleHeaderAST, DetectionHypothesis, RuleState, ConstructionState, ValidationResult, StageResult
from snort_pipeline.option_catalogue import format_stage_catalogue_for_llm
from snort_pipeline.llm_engine import LLMClient, sanitize_untrusted_data

# ─────────────────────────────────────────────────────────────────────────────
# 1. HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def generate_rule_type(hypothesis: DetectionHypothesis, report: Optional[Dict[str, Any]] = None) -> str:
    """
    Determine the Snort 3 rule type (traditional, service, file, or file_id)
    based on the Detection Hypothesis.
    - 'file': Pure file payload / dropper matching (omits service & flow).
    - 'service': Recognized application service where IP/port scoping is unneeded or variable.
    - 'traditional': Network/transport-scoped signature with explicit IP and port filtering.
    """
    proto = (hypothesis.target_protocol or "").lower().strip()
    category = (getattr(hypothesis, "threat_category", "") or hypothesis.family_context.get("threat_category", "")).lower().strip()
    objective = (hypothesis.detection_objective or "").lower().strip()

    # File rule check
    if proto == "file" or "file rule" in objective or "dropper" in category and "file_data" in objective:
        return "file"

    # File identification rule check
    if "file identification" in objective or "file_id" in objective:
        return "file_id"

    # Service rule check: If explicitly targeting application layer and ports may vary
    # Or if hypothesis specifies 'service' rule preference
    if proto in VALID_SERVICE_HEADERS and ("service rule" in objective or "any port" in objective):
        return "service"

    # Default to traditional header for fine-grained network/transport containment
    return "traditional"

def generate_action(hypothesis: Optional[DetectionHypothesis] = None, requested_action: Optional[str] = None) -> str:
    """
    Select the handling action for the rule.
    Supported: alert, block, drop, log, pass, react, reject, rewrite.
    Defaults to 'alert' for candidate detection rules to prevent traffic disruption.
    """
    if requested_action:
        clean = requested_action.lower().strip()
        if is_valid_action(clean):
            return clean
    return "alert"

def generate_protocol(hypothesis: DetectionHypothesis, rule_type: str = "traditional") -> str:
    """
    Identify the transport/network protocol or service name from evidence.
    Traditional headers support: ip, icmp, tcp, udp, or application services in place of protocols.
    Service headers support: http, ssl, dns, smtp, smb, etc.
    File headers support: file.
    """
    if rule_type == "file":
        return "file"
    if rule_type == "file_id":
        return ""

    proto = (hypothesis.target_protocol or "tcp").lower().strip()
    # Normalize common aliases
    proto_map = {
        "https": "ssl",
        "tls": "ssl",
        "http2": "http",
        "http3": "http"
    }
    canonical = proto_map.get(proto, proto)

    if rule_type == "service":
        if canonical in VALID_SERVICE_HEADERS:
            return canonical
        return "http"

    # Traditional header: Can be L4 transport or service in place of protocol
    if canonical in VALID_PROTOCOLS:
        return canonical
    if canonical in VALID_SERVICE_HEADERS:
        return canonical

    return "tcp"

def generate_source_scope(hypothesis: DetectionHypothesis, rule_type: str = "traditional") -> str:
    """
    Define source IP scope using network roles ($HOME_NET, $EXTERNAL_NET, any).
    Avoids hardcoding ephemeral private IPs observed in a single capture.
    """
    if rule_type in ["service", "file", "file_id"]:
        return ""

    direction = (hypothesis.communication_direction or "outbound_c2").lower().strip()

    if direction in ["outbound_c2", "client_request", "internal_compromise"]:
        # Outbound traffic originating from internal victim host
        return "$HOME_NET"
    elif direction in ["inbound_exploit", "external_attack"]:
        # Inbound exploit originating from external attacker
        return "$EXTERNAL_NET"
    elif direction in ["server_response", "c2_response"]:
        # Server responding: external payload server or internal server
        return "$EXTERNAL_NET"
    elif direction == "bidirectional":
        return "$HOME_NET"

    return "$EXTERNAL_NET"

def generate_destination_scope(hypothesis: DetectionHypothesis, rule_type: str = "traditional") -> str:
    """
    Define destination IP scope, inverse of source scope.
    """
    if rule_type in ["service", "file", "file_id"]:
        return ""

    src = generate_source_scope(hypothesis, rule_type)
    if src == "$HOME_NET":
        return "$EXTERNAL_NET"
    elif src == "$EXTERNAL_NET":
        return "$HOME_NET"
    return "any"

def generate_source_port(hypothesis: DetectionHypothesis, rule_type: str = "traditional") -> str:
    """
    Define source port scope. Client sources use dynamic/ephemeral ports ('any').
    Server sources use their listening service ports.
    """
    if rule_type in ["service", "file", "file_id"]:
        return ""

    direction = (hypothesis.communication_direction or "outbound_c2").lower().strip()
    if direction in ["server_response", "c2_response"]:
        # Server is source: check service
        proto = (hypothesis.target_protocol or "").lower().strip()
        if proto == "http":
            return "$HTTP_PORTS"
        elif proto in ["ssl", "https", "tls"]:
            return "443"
        elif proto == "dns":
            return "53"
        return "any"

    # Clients initiate from dynamic ephemeral ports
    return "any"

def generate_destination_port(hypothesis: DetectionHypothesis, rule_type: str = "traditional") -> str:
    """
    Define destination port scope. Targets service listening ports ($HTTP_PORTS, 443, 53, any).
    """
    if rule_type in ["service", "file", "file_id"]:
        return ""

    direction = (hypothesis.communication_direction or "outbound_c2").lower().strip()
    if direction in ["server_response", "c2_response"]:
        # Client receiving response: dynamic client port
        return "any"

    proto = (hypothesis.target_protocol or "tcp").lower().strip()
    if proto == "http":
        return "$HTTP_PORTS"
    elif proto in ["ssl", "https", "tls"]:
        return "443"
    elif proto == "dns":
        return "53"
    elif proto in ["tcp", "udp", "ip"]:
        return "any"

    return "any"

def generate_direction(hypothesis: DetectionHypothesis, rule_type: str = "traditional") -> str:
    """
    Define direction operator ('->' or '<>').
    Standard detection uses unidirectional '->'.
    """
    if rule_type in ["service", "file", "file_id"]:
        return ""

    dir_str = (hypothesis.communication_direction or "").lower().strip()
    if dir_str == "bidirectional":
        return "<>"
    return "->"

def assemble_header(
    action: str = "alert",
    rule_type: str = "traditional",
    protocol: Optional[str] = None,
    source_addr: Optional[str] = None,
    source_port: Optional[str] = None,
    direction: Optional[str] = None,
    dest_addr: Optional[str] = None,
    dest_port: Optional[str] = None,
    service: Optional[str] = None
) -> RuleHeaderAST:
    """
    Assemble the complete RuleHeaderAST from individual components.
    """
    rule_type = rule_type.lower().strip()
    action = action.lower().strip()

    if rule_type == "file_id":
        return RuleHeaderAST(
            action="file_id",
            header_type="file_id",
            protocol=None,
            service=None,
            source_addr="",
            source_port="",
            direction="",
            dest_addr="",
            dest_port=""
        )

    if rule_type == "file":
        return RuleHeaderAST(
            action=action,
            header_type="file",
            protocol="file",
            service=None,
            source_addr="",
            source_port="",
            direction="",
            dest_addr="",
            dest_port=""
        )

    if rule_type == "service":
        svc_name = (service or protocol or "http").lower().strip()
        return RuleHeaderAST(
            action=action,
            header_type="service",
            protocol=None,
            service=svc_name,
            source_addr="",
            source_port="",
            direction="",
            dest_addr="",
            dest_port=""
        )

    # Traditional header
    proto = (protocol or "tcp").lower().strip()
    src_ip = source_addr or "$HOME_NET"
    src_pt = source_port or "any"
    dir_op = direction or "->"
    dst_ip = dest_addr or "$EXTERNAL_NET"
    dst_pt = dest_port or "any"

    return RuleHeaderAST(
        action=action,
        header_type="traditional",
        protocol=proto,
        service=service,
        source_addr=src_ip,
        source_port=src_pt,
        direction=dir_op,
        dest_addr=dst_ip,
        dest_port=dst_pt
    )

def validate_header(header: RuleHeaderAST, hypothesis: Optional[DetectionHypothesis] = None) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Validate RuleHeaderAST against Snort 3 documentation catalogue and Detection Hypothesis.
    Returns (passed, errors, details).
    """
    validator = HeaderValidator()
    return validator.validate(header, hypothesis)


# ─────────────────────────────────────────────────────────────────────────────
# 2. HEADER VALIDATOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class HeaderValidator:
    """
    Deep validation gate for Snort 3 Rule Headers.
    Enforces action validity, rule type constraints, variable legality,
    forbidden variables, anti-brittle IP policies, and hypothesis consistency.
    """
    def validate(
        self,
        header: RuleHeaderAST,
        hypothesis: Optional[DetectionHypothesis] = None
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        errors: List[str] = []
        warnings: List[str] = []
        details: Dict[str, Any] = {
            "header_type": header.header_type,
            "action": header.action,
            "rendered": header.render()
        }

        # 1. Rule Type & Format Validation
        ht = (header.header_type or "traditional").lower().strip()
        if ht not in VALID_RULE_TYPES:
            errors.append(f"Invalid rule type '{header.header_type}'. Must be one of: {sorted(list(VALID_RULE_TYPES))}")

        # 2. Action Validation
        if ht == "file_id":
            # file_id rules have no action keyword prefix
            pass
        else:
            act = (header.action or "").lower().strip()
            if not is_valid_action(act):
                errors.append(f"Invalid rule action '{header.action}'. Must be one of: {sorted(list(VALID_ACTIONS))}")
            elif act not in ["alert", "log"]:
                warnings.append(f"Action '{act}' has active traffic-handling impact. Default 'alert' recommended for candidate detection.")

        # 3. Rule Type-Specific Validation
        if ht == "file_id":
            # file_id format: just "file_id"
            if header.protocol or header.source_addr:
                errors.append("File identification rules ('file_id') must not specify protocols, IP addresses, or ports.")

        elif ht == "file":
            # Format: action file
            if header.source_addr or header.source_port or header.dest_addr or header.dest_port:
                errors.append("File rules ('action file') match files regardless of protocol, endpoints, and ports. Endpoints must be omitted.")

        elif ht == "service":
            # Format: action service
            svc = (header.service or header.protocol or "").lower().strip()
            if not svc:
                errors.append("Service rules require a valid service name (e.g. 'alert http').")
            elif svc not in VALID_SERVICE_HEADERS:
                errors.append(f"Invalid service '{svc}' in service rule header. Must be a valid Snort 3 service: {sorted(list(VALID_SERVICE_HEADERS))}")
            if header.source_addr or header.dest_addr:
                errors.append("Service rules match traffic of a particular service regardless of IPs or ports. Addresses and ports must be omitted.")

        elif ht == "traditional":
            # Format: action proto src_ip src_port dir dst_ip dst_port
            proto = (header.protocol or "").lower().strip()
            if not proto:
                errors.append("Traditional rule header requires a protocol specification.")
            elif not is_valid_protocol_or_service(proto):
                errors.append(f"Invalid protocol/service '{proto}'. Must be transport protocol (tcp, udp, icmp, ip) or valid service.")

            # Addressing Checks
            src_addr = (header.source_addr or "").strip()
            dst_addr = (header.dest_addr or "").strip()

            if not src_addr:
                errors.append("Traditional rule header missing source address.")
            elif not is_valid_ip_token(src_addr):
                errors.append(f"Invalid source address token '{src_addr}'. Must be valid variable, CIDR, or 'any'.")

            if not dst_addr:
                errors.append("Traditional rule header missing destination address.")
            elif not is_valid_ip_token(dst_addr):
                errors.append(f"Invalid destination address token '{dst_addr}'. Must be valid variable, CIDR, or 'any'.")

            # Check for forbidden variables
            for addr_tok in [src_addr, dst_addr]:
                if addr_tok in FORBIDDEN_VARIABLES:
                    errors.append(f"Forbidden variable '{addr_tok}': {FORBIDDEN_VARIABLES[addr_tok]}")

            # Anti-Brittle IP Check: Reject hardcoded private RFC1918 IPs in headers
            for addr_tok in [src_addr, dst_addr]:
                raw_ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", addr_tok)
                for ip in raw_ips:
                    if ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and int(ip.split(".")[1]) in range(16, 32)):
                        errors.append(f"Brittle IP address violation: '{ip}' is a private internal IP. Snort rules must use '$HOME_NET' instead of hardcoded IPs.")

            # Port Checks
            src_port = (header.source_port or "").strip()
            dst_port = (header.dest_port or "").strip()

            if not src_port:
                errors.append("Traditional rule header missing source port.")
            elif not is_valid_port_token(src_port):
                errors.append(f"Invalid source port token '{src_port}'. Must be port number, range, variable, or 'any'.")

            if not dst_port:
                errors.append("Traditional rule header missing destination port.")
            elif not is_valid_port_token(dst_port):
                errors.append(f"Invalid destination port token '{dst_port}'. Must be port number, range, variable, or 'any'.")

            for pt_tok in [src_port, dst_port]:
                if pt_tok in FORBIDDEN_VARIABLES:
                    errors.append(f"Forbidden port variable '{pt_tok}': {FORBIDDEN_VARIABLES[pt_tok]}")

            # Direction Operator Check
            dir_op = (header.direction or "").strip()
            if not dir_op:
                errors.append("Traditional rule header missing direction operator ('->' or '<>').")
            elif not is_valid_direction(dir_op):
                errors.append(f"Invalid direction operator '{dir_op}'. Must be '->' (unidirectional) or '<>' (bidirectional).")

        # 4. Consistency with Detection Hypothesis (if provided)
        if hypothesis:
            hyp_proto = (hypothesis.target_protocol or "").lower().strip()
            hyp_dir = (hypothesis.communication_direction or "").lower().strip()

            # Protocol sanity check
            if ht == "traditional":
                hdr_proto = (header.protocol or "").lower().strip()
                if hyp_proto == "dns" and hdr_proto not in ["udp", "dns", "tcp", "ip"]:
                    errors.append(f"Protocol mismatch: Hypothesis is DNS, but header protocol is '{hdr_proto}'.")
                elif hyp_proto == "http" and hdr_proto not in ["tcp", "http", "ip"]:
                    errors.append(f"Protocol mismatch: Hypothesis is HTTP, but header protocol is '{hdr_proto}'.")

            # Direction sanity check
            if ht == "traditional" and header.direction == "->":
                src = header.source_addr.strip()
                dst = header.dest_addr.strip()

                if hyp_dir in ["outbound_c2", "client_request"]:
                    if src == "$EXTERNAL_NET" and dst == "$HOME_NET":
                        errors.append("Direction mismatch: Hypothesis indicates outbound traffic (client -> server), but header is '$EXTERNAL_NET -> $HOME_NET'. Should be '$HOME_NET -> $EXTERNAL_NET'.")

                elif hyp_dir in ["inbound_exploit", "external_attack"]:
                    if src == "$HOME_NET" and dst == "$EXTERNAL_NET":
                        errors.append("Direction mismatch: Hypothesis indicates inbound exploit (attacker -> internal), but header is '$HOME_NET -> $EXTERNAL_NET'. Should be '$EXTERNAL_NET -> $HOME_NET'.")

            # Bidirectional operator vs flow constraint warning
            if ht == "traditional" and header.direction == "<>":
                if hypothesis.flow_intent in ["to_server", "to_client"]:
                    warnings.append("Bidirectional '<>' header operator combined with directional flow intent ('to_server'/'to_client').")

        passed = len(errors) == 0
        details["errors"] = errors
        details["warnings"] = warnings
        details["verdict"] = "HEADER_APPROVED" if passed else "HEADER_VALIDATION_FAILED"
        return ValidationResult(
            status="passed" if passed else "failed",
            component="header",
            error=errors[0] if errors else None,
            evidence_required=False,
            details=details
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. HEADER GENERATION ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class HeaderGenerator:
    """
    Manages Stage 2 Header Generation.
    Executes LLM proposal task, applies HeaderValidator gate, executes self-healing retries,
    and provides deterministic fallback synthesis.
    """
    def __init__(self, llm_client: Optional[LLMClient] = None, max_retries: int = 3):
        self.client = llm_client or LLMClient()
        self.validator = HeaderValidator()
        self.max_retries = max_retries

    def generate(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Execute Stage 2: Propose and validate Rule Header, then commit to RuleState AST.
        Returns RuleState with persistent checkpoints and StageResult tracking.
        """
        hyp = state.hypothesis
        if not hyp:
            state.transition(ConstructionState.CONSTRUCTION_FAILED, reason="Stage 2 requires an approved Detection Hypothesis in RuleState.")
            return state

        retry_count = 0
        validation_errors: List[str] = []

        while retry_count <= self.max_retries:
            header_ast = self._propose_header_llm(
                hypothesis=hyp,
                report=report,
                previous_errors=validation_errors if retry_count > 0 else None
            )

            passed, errors, details = self.validator.validate(header_ast, hyp)

            if passed:
                state.ast.header = header_ast
                state.components["header"] = header_ast.to_dict()
                state.record_validation("stage2_header", passed=True, details=details)
                state.transition(ConstructionState.HEADER_GENERATED, reason=f"Header '{header_ast.render()}' validated and committed to AST.")
                state.current_stage = 3

                # Record standardized StageResult and save checkpoint
                stage_result = StageResult(
                    status="success",
                    component="header",
                    generated_value=header_ast.to_dict(),
                    evidence_refs=hyp.evidence.get("triggering_packets", []),
                    validation_errors=[],
                    reasoning_summary=f"Generated compliant Snort 3 {header_ast.header_type} header: '{header_ast.render()}'"
                )
                state.stage_results["stage2_header"] = stage_result.to_dict()
                state.last_stage_result = stage_result.to_dict()
                state.save_checkpoint(2)
                return state

            # Header failed validation -> Retry
            retry_count += 1
            state.stage_retry_counts["stage2_header"] = retry_count
            validation_errors = errors
            state.record_validation("stage2_header", passed=False, errors=errors, details=details)

        # Retries exhausted: Fall back to deterministic synthesizer
        fallback_hdr = self._synthesize_fallback_header(hyp, report)
        passed, errors, details = self.validator.validate(fallback_hdr, hyp)

        if passed:
            state.ast.header = fallback_hdr
            state.components["header"] = fallback_hdr.to_dict()
            state.record_validation("stage2_header", passed=True, details=details)
            state.transition(ConstructionState.HEADER_GENERATED, reason=f"Deterministic fallback header '{fallback_hdr.render()}' committed to AST.")
            state.current_stage = 3

            stage_result = StageResult(
                status="success",
                component="header",
                generated_value=fallback_hdr.to_dict(),
                evidence_refs=hyp.evidence.get("triggering_packets", []),
                validation_errors=[],
                reasoning_summary=f"Synthesized fallback Snort 3 {fallback_hdr.header_type} header: '{fallback_hdr.render()}'"
            )
            state.stage_results["stage2_header"] = stage_result.to_dict()
            state.last_stage_result = stage_result.to_dict()
            state.save_checkpoint(2)
            return state

        # Complete failure
        state.transition(ConstructionState.CONSTRUCTION_FAILED, reason=f"Stage 2 Header generation failed validation: {'; '.join(validation_errors)}")
        fail_result = StageResult(
            status="failed",
            component="header",
            generated_value=None,
            evidence_refs=hyp.evidence.get("triggering_packets", []),
            validation_errors=validation_errors,
            reasoning_summary="Stage 2 Header generation failed validation retries and fallback."
        )
        state.stage_results["stage2_header"] = fail_result.to_dict()
        state.last_stage_result = fail_result.to_dict()
        return state

    def _propose_header_llm(
        self,
        hypothesis: DetectionHypothesis,
        report: Optional[Dict[str, Any]] = None,
        previous_errors: Optional[List[str]] = None
    ) -> RuleHeaderAST:
        """Query LLM to propose Snort 3 rule header components using the 3-Pillar Prompt Schema."""
        hyp_context = hypothesis.to_dict()
        stage2_catalogue = format_stage_catalogue_for_llm(2)
        ev_refs = hypothesis.evidence.get("triggering_packets", [])

        retry_feedback = ""
        if previous_errors:
            retry_feedback = f"""
[CRITICAL CORRECTION REQUIRED]
Your previous header proposal failed validation with the following errors:
{json.dumps(previous_errors, indent=2)}

Please strictly fix these issues:
1. Ensure the header aligns with hypothesis communication_direction:
   - Outbound C2 (client -> server): Source is $HOME_NET, Destination is $EXTERNAL_NET.
   - Inbound Exploit (attacker -> target): Source is $EXTERNAL_NET, Destination is $HOME_NET.
2. Never use forbidden variables: '$HTTPS_PORTS' does not exist in Snort 3 (use '443' or 'any'). '$INTERNAL_NET' does not exist (use '$HOME_NET').
3. Never hardcode private internal IP addresses (e.g. 192.168.x.x, 10.x.x.x). Use '$HOME_NET'.
4. If choosing a service rule (e.g. 'alert http'), omit IP addresses and ports.
"""

        user_prompt = f"""You are the Snort 3 Rule Engineer operating Stage 2: Header Generation.

1. COMPONENT-GENERATION INSTRUCTIONS:
Propose the optimal, standard Snort 3 rule header (Action, Rule type, Protocol/Service, Source, Destination, Ports, Direction).
Respond strictly with a JSON object conforming to this schema:
{{
  "rule_type": "traditional | service | file | file_id",
  "action": "alert",
  "protocol": "tcp | udp | icmp | ip | http | ssl | file",
  "service": null,
  "source": {{
    "address": "$HOME_NET | $EXTERNAL_NET | any",
    "port": "any | 80 | $HTTP_PORTS"
  }},
  "direction": "-> | <>",
  "destination": {{
    "address": "$EXTERNAL_NET | $HOME_NET | any",
    "port": "any | $HTTP_PORTS | 443 | 53"
  }},
  "rationale": "<Reason for rule type, address, and port selection>"
}}

2. RELEVANT CATALOGUE ENTRIES (Dynamic from OptionSpec):
{stage2_catalogue}

3. CURRENT RULE CONTEXT & ACCUMULATED STATE:
- Detection Hypothesis:
{json.dumps(hyp_context, indent=2)}
- Evidence References (Triggering Packets): {ev_refs}
- Current Rule Prefix:
  [INSERT STAGE 2 HEADER HERE] ( ... )
{retry_feedback}
"""
        try:
            resp_text = self.client.query(
                "You are an expert Snort 3 rule syntax generator. Output strictly valid JSON.",
                user_prompt,
                json_mode=True,
                temperature=0.1
            )
            parsed = json.loads(self._extract_json(resp_text))
            if isinstance(parsed, dict) and "rule_type" in parsed and "action" in parsed:
                rt = parsed.get("rule_type", "traditional")
                act = parsed.get("action", "alert")
                proto = parsed.get("protocol")
                svc = parsed.get("service")
                src = parsed.get("source", {})
                dst = parsed.get("destination", {})
                dir_op = parsed.get("direction", "->")
                return assemble_header(
                    action=act,
                    rule_type=rt,
                    protocol=proto,
                    service=svc,
                    source_addr=src.get("address"),
                    source_port=src.get("port"),
                    direction=dir_op,
                    dest_addr=dst.get("address"),
                    dest_port=dst.get("port")
                )
            return self._synthesize_fallback_header(hypothesis, report)
        except Exception:
            return self._synthesize_fallback_header(hypothesis, report)

    def _synthesize_fallback_header(
        self,
        hypothesis: DetectionHypothesis,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleHeaderAST:
        """Deterministic, grounded header generator fallback."""
        rt = generate_rule_type(hypothesis, report)
        act = generate_action(hypothesis)
        proto = generate_protocol(hypothesis, rt)
        src_ip = generate_source_scope(hypothesis, rt)
        dst_ip = generate_destination_scope(hypothesis, rt)
        src_pt = generate_source_port(hypothesis, rt)
        dst_pt = generate_destination_port(hypothesis, rt)
        dir_op = generate_direction(hypothesis, rt)

        return assemble_header(
            action=act,
            rule_type=rt,
            protocol=proto,
            source_addr=src_ip,
            source_port=src_pt,
            direction=dir_op,
            dest_addr=dst_ip,
            dest_port=dst_pt,
            service=proto if rt == "service" else None
        )

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
