"""
Snort 3 Stage 3 — Message Generation & Validation Engine.
Grounded in snort3_complete_rule_documentation.txt (Page 18: msg).

Implements:
1. Message Construction:
   - Descriptive alert message summarizing rule purpose
   - VRT / Talos / Local rule naming conventions (<CATEGORY>[-<SUBTYPE>] <Subject> <Activity>)
   - Alignment with Stage 1 Detection Hypothesis and Stage 2 Rule Header
   - Prevention of false compromise claims (detecting activity/attempts, not verified compromise)
   - Proper escaping of reserved characters ('"' and ';')
2. Helper Functions:
   - generate_message(hypothesis, header, rule_catalogue)
   - validate_message(message)
   - check_duplicate_message(message, existing_rules)
3. MessageValidator & MessageGenerator Orchestrator with LLM Self-Healing Retry Loop.
"""

from typing import Dict, List, Set, Any, Optional, Tuple, Union
from pathlib import Path
import re
import json

from snort_pipeline.snort3_catalogue import (
    VALID_MSG_PREFIXES,
    FORBIDDEN_COMPROMISE_CLAIMS
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

def generate_message(
    hypothesis: DetectionHypothesis,
    header: Optional[RuleHeaderAST] = None,
    rule_catalogue: Optional[Dict[str, Any]] = None
) -> str:
    """
    Deterministic synthesis of standard VRT / Talos-compliant Snort 3 rule message.
    Structure: <CATEGORY>[-<SUBTYPE>] <Subject/Malware> <Specific Activity> [attempt]
    - Does not claim verified compromise (uses 'attempt', 'activity', 'pattern', 'request')
    - Escapes reserved characters ('"' and ';')
    """
    direction = (hypothesis.communication_direction or "outbound_c2").lower().strip()
    category = (getattr(hypothesis, "threat_category", "") or hypothesis.family_context.get("threat_category", "")).lower().strip()
    family = (getattr(hypothesis, "malware_family", "") or hypothesis.family_context.get("malware_family", "")).strip()
    if not family or family.lower() in ["unknown", "generic"]:
        family = "Malware"

    proto = (hypothesis.target_protocol or "").lower().strip()
    h_type = header.header_type if header else "traditional"

    # 1. Determine Category Prefix
    if h_type == "file" or "dropper" in category or "file delivery" in category:
        prefix = "MALWARE-OTHER"
    elif direction in ["outbound_c2", "c2_beacon", "c2_traffic"]:
        prefix = "MALWARE-CNC"
    elif "exploit" in category or "rce" in category or "injection" in category:
        prefix = "SERVER-WEBAPP" if proto in ["http", "tcp"] else "EXPLOIT"
    elif proto == "dns":
        prefix = "PROTOCOL-DNS"
    else:
        prefix = "MALWARE-OTHER"

    # 2. Extract Specific Malicious Activity from hypothesis
    # Clean and summarize detection objective or target behaviour
    target = hypothesis.target_behaviour or hypothesis.detection_objective or "suspicious network activity"
    # Remove run-on prefixes like "Detect Log4j..."
    cleaned_target = re.sub(r"^(?:detect\s+(?:the\s+)?|identify\s+(?:the\s+)?|monitors?\s+(?:for\s+)?)", "", target, flags=re.IGNORECASE).strip()
    if family.lower() in cleaned_target.lower():
        # Avoid duplicating family name e.g. "Cobalt Strike Cobalt Strike beacon"
        idx = cleaned_target.lower().find(family.lower())
        tail = cleaned_target[idx + len(family):].strip()
        if tail:
            activity = tail
        else:
            activity = cleaned_target
    else:
        activity = cleaned_target

    # 3. Tone Adjustment: Ensure non-compromise phrasing
    # Replace claim words
    activity = re.sub(r"\bcompromised\b", "infection activity", activity, flags=re.IGNORECASE)
    activity = re.sub(r"\bdata stolen\b", "outbound exfiltration attempt", activity, flags=re.IGNORECASE)

    # For inbound exploit/attack, append 'attempt' if not present
    if direction in ["inbound_exploit", "external_attack"] and "attempt" not in activity.lower():
        activity = f"{activity} attempt"

    # Shorten activity if too long
    if len(activity) > 55:
        activity = activity[:52] + "..."

    # 4. Assemble Message
    msg_raw = f"{prefix} {family} {activity}".strip()
    # Remove multiple spaces
    msg_raw = re.sub(r"\s+", " ", msg_raw)

    # 5. Escape reserved characters per Snort 3 documentation
    msg_escaped = escape_rule_message(msg_raw)
    return msg_escaped


def validate_message(
    message: str,
    hypothesis: Optional[DetectionHypothesis] = None
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Validate Snort 3 rule message against official documentation and engineering constraints:
    1. Length bounds (10 to 120 characters)
    2. Proper escaping of quotes and semicolons
    3. Standard naming convention prefix
    4. Prohibition on claiming successful compromise (only attempts/activity observed)
    5. No placeholder / generic text
    6. Attribution consistency against Stage 1 hypothesis
    """
    errors: List[str] = []
    warnings: List[str] = []
    details: Dict[str, Any] = {"raw_message": message}

    clean_msg = unescape_or_strip_msg_wrapper(message)
    details["cleaned_text"] = clean_msg

    # 1. Non-empty & Length Bounds
    if not clean_msg.strip():
        errors.append("Empty rule message: msg cannot be blank.")
        return False, errors, details

    msg_len = len(clean_msg)
    details["length"] = msg_len
    if msg_len < 10:
        errors.append(f"Message too short ({msg_len} chars). Must be descriptive (at least 10 chars).")
    elif msg_len > 120:
        errors.append(f"Message too long ({msg_len} chars). Snort 3 rule messages should be concise (<= 120 chars).")
    elif msg_len > 95:
        warnings.append(f"Message is relatively long ({msg_len} chars). Consider shortening for analyst readability.")

    # 2. Control Characters & Newlines
    if any(c in clean_msg for c in ["\n", "\r", "\t"]):
        errors.append("Invalid characters: msg must not contain newlines or tabs.")

    # 3. Unescaped Reserved Characters Check
    # In Snort 3, any '"' or ';' inside the string must be escaped with '\'
    # Check for unescaped double quotes inside the content
    unescaped_quotes = re.findall(r'(?<!\\)"', clean_msg)
    if unescaped_quotes:
        errors.append('Unescaped double quote (\") detected inside message text. Double quotes must be escaped with \\".')

    unescaped_semicolons = re.findall(r'(?<!\\);', clean_msg)
    if unescaped_semicolons:
        errors.append('Unescaped semicolon (;) detected inside message text. Semicolons must be escaped with \\;.')

    # 4. Tone Constraint: No False Claims of Verified Compromise
    lower_msg = clean_msg.lower()
    for claim in FORBIDDEN_COMPROMISE_CLAIMS:
        if claim in lower_msg:
            errors.append(f"Compromise claim violation: Rule message claims verified compromise ('{claim}'). Rules must detect network activity or attempts.")

    # 5. Placeholder / Generic Words Check
    placeholders = ["test rule", "sample rule", "new candidate", "lorem ipsum", "temp rule", "placeholder"]
    for ph in placeholders:
        if ph in lower_msg:
            errors.append(f"Generic placeholder violation: Message contains non-descriptive token '{ph}'.")

    # 6. Standard Naming Convention Prefix Check
    first_token = clean_msg.split()[0].rstrip(":") if clean_msg.split() else ""
    first_token_upper = first_token.upper()
    valid_prefix_match = any(
        first_token_upper == p or first_token_upper.startswith(p + "-") or first_token_upper.startswith(p + " ")
        for p in VALID_MSG_PREFIXES
    )
    if not valid_prefix_match:
        warnings.append(f"Non-standard prefix '{first_token}'. Recommended prefixes: MALWARE-CNC, SERVER-WEBAPP, MALWARE-OTHER, PROTOCOL-DNS, etc.")

    # 7. Attribution Consistency
    if hypothesis:
        hyp_family = (getattr(hypothesis, "malware_family", "") or hypothesis.family_context.get("malware_family", "")).strip()
        if hyp_family and hyp_family.lower() not in ["unknown", "generic"]:
            # Check if message mentions the confirmed family
            if hyp_family.lower() not in lower_msg:
                warnings.append(f"Hypothesis identifies family '{hyp_family}', but it is not mentioned in message.")

    passed = len(errors) == 0
    details["errors"] = errors
    details["warnings"] = warnings
    details["verdict"] = "MESSAGE_APPROVED" if passed else "MESSAGE_VALIDATION_FAILED"
    return passed, errors, details


def check_duplicate_message(
    message: str,
    existing_rules: Optional[Union[List[str], str, Path]] = None
) -> Tuple[bool, Optional[str]]:
    """
    Check whether a message is an identical duplicate of an already registered rule message.
    Scans rules/local.rules, rules/candidates.json, or passed existing rules collection.
    Returns (is_duplicate, duplicate_context).
    """
    target_clean = normalize_for_comparison(message)
    if not target_clean:
        return False, None

    # Load from default files if not passed
    rules_to_scan: List[str] = []
    if existing_rules is not None:
        if isinstance(existing_rules, (list, set)):
            rules_to_scan = list(existing_rules)
        elif isinstance(existing_rules, (str, Path)) and Path(existing_rules).is_file():
            with open(existing_rules, "r", encoding="utf-8", errors="ignore") as f:
                rules_to_scan = f.readlines()
    else:
        # Scan local.rules
        local_rules_path = Path("rules/local.rules")
        if local_rules_path.is_file():
            with open(local_rules_path, "r", encoding="utf-8", errors="ignore") as f:
                rules_to_scan.extend(f.readlines())
        # Scan candidates.json
        cand_path = Path("rules/candidates.json")
        if cand_path.is_file():
            try:
                with open(cand_path, "r", encoding="utf-8") as f:
                    cand_data = json.load(f)
                    for cid, cinfo in cand_data.items():
                        if isinstance(cinfo, dict) and "rule_text" in cinfo:
                            rules_to_scan.append(cinfo["rule_text"])
            except Exception:
                pass

    # Extract msg options from lines and compare
    for item in rules_to_scan:
        item_str = str(item)
        match = re.search(r'msg:\s*"([^"]+)"', item_str)
        if match:
            existing_msg = match.group(1)
            if normalize_for_comparison(existing_msg) == target_clean:
                # Extract SID if present
                sid_match = re.search(r'sid:\s*(\d+)', item_str)
                sid_str = f"SID {sid_match.group(1)}" if sid_match else "existing rule"
                return True, f"Duplicate of {sid_str}: '{existing_msg}'"

    return False, None


def escape_rule_message(text: str) -> str:
    """Escape reserved characters (quotes and semicolons) per Snort 3 documentation."""
    # First unescape existing escapes to avoid double-escaping
    cleaned = text.replace(r'\"', '"').replace(r'\;', ';')
    # Escape double quotes
    escaped = cleaned.replace('"', r'\"')
    # Escape semicolons
    escaped = escaped.replace(';', r'\;')
    return escaped


def unescape_or_strip_msg_wrapper(text: str) -> str:
    """Extract raw message text whether wrapped in msg:\"...\" or bare."""
    s = text.strip()
    match = re.search(r'msg:\s*"([\s\S]*?)"\s*;?$', s)
    if match:
        return match.group(1).strip()
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1].strip()
    return s


def normalize_for_comparison(text: str) -> str:
    """Normalize message for duplicate collision comparison."""
    clean = unescape_or_strip_msg_wrapper(text).lower()
    # Remove all punctuation and excess whitespace
    clean = re.sub(r'[^\w\s]', '', clean)
    return re.sub(r'\s+', ' ', clean).strip()


# ─────────────────────────────────────────────────────────────────────────────
# 2. MESSAGE VALIDATOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class MessageValidator:
    """
    Validation Gate for Stage 3 Rule Message.
    Enforces format, length, non-compromise phrasing, escaping, and uniqueness.
    """
    def validate(
        self,
        message: str,
        hypothesis: Optional[DetectionHypothesis] = None,
        check_uniqueness: bool = True
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        passed, errors, details = validate_message(message, hypothesis)

        if check_uniqueness and passed:
            is_dup, dup_info = check_duplicate_message(message)
            if is_dup:
                details["duplicate_conflict"] = dup_info
                details["warnings"].append(f"Message collision: {dup_info}")

        return ValidationResult(
            status="passed" if passed else "failed",
            component="message",
            error=errors[0] if errors else None,
            evidence_required=False,
            details=details
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. MESSAGE GENERATOR ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class MessageGenerator:
    """
    Manages Stage 3 Rule Message Generation.
    Queries LLM with hypothesis, header, and naming constraints, validates output,
    executes self-healing retry loop, and provides deterministic fallback synthesis.
    """
    def __init__(self, llm_client: Optional[LLMClient] = None, max_retries: int = 3):
        self.client = llm_client or LLMClient()
        self.validator = MessageValidator()
        self.max_retries = max_retries

    def generate(
        self,
        state: RuleState,
        report: Optional[Dict[str, Any]] = None
    ) -> RuleState:
        """
        Execute Stage 3: Generate and validate Snort 3 rule message, then commit to RuleState AST.
        """
        hyp = state.hypothesis
        header = state.ast.header
        if not hyp:
            state.transition(ConstructionState.CONSTRUCTION_FAILED, reason="Stage 3 requires an approved Detection Hypothesis in RuleState.")
            return state

        retry_count = 0
        validation_errors: List[str] = []

        while retry_count <= self.max_retries:
            msg_str = self._propose_message_llm(
                hypothesis=hyp,
                header=header,
                report=report,
                previous_errors=validation_errors if retry_count > 0 else None
            )

            passed, errors, details = self.validator.validate(msg_str, hyp)

            if passed:
                clean_msg = unescape_or_strip_msg_wrapper(msg_str)
                # Commit to components dictionary
                state.components["msg"] = clean_msg

                # Insert or update msg at position 0 of AST options (Snort convention)
                self._update_ast_msg_option(state, clean_msg)

                state.record_validation("stage3_message", passed=True, details=details)
                state.transition(ConstructionState.MESSAGE_GENERATED, reason=f"Message '{clean_msg}' validated and committed to AST.")
                state.current_stage = 4

                # Record standardized StageResult and save checkpoint
                stage_result = StageResult(
                    status="success",
                    component="message",
                    generated_value={"msg": clean_msg},
                    evidence_refs=hyp.evidence.get("triggering_packets", []),
                    validation_errors=[],
                    reasoning_summary=f"Generated alert message conforming to Talos/VRT convention: '{clean_msg}'"
                )
                state.stage_results["stage3_message"] = stage_result.to_dict()
                state.last_stage_result = stage_result.to_dict()
                state.save_checkpoint(3)
                return state

            # Message failed validation -> Retry
            retry_count += 1
            state.stage_retry_counts["stage3_message"] = retry_count
            validation_errors = errors
            state.record_validation("stage3_message", passed=False, errors=errors, details=details)

        # Retries exhausted: Fall back to deterministic synthesizer
        fallback_msg = generate_message(hyp, header)
        passed, errors, details = self.validator.validate(fallback_msg, hyp, check_uniqueness=False)

        if passed:
            clean_msg = unescape_or_strip_msg_wrapper(fallback_msg)
            state.components["msg"] = clean_msg
            self._update_ast_msg_option(state, clean_msg)
            state.record_validation("stage3_message", passed=True, details=details)
            state.transition(ConstructionState.MESSAGE_GENERATED, reason=f"Deterministic fallback message '{clean_msg}' committed to AST.")
            state.current_stage = 4

            stage_result = StageResult(
                status="success",
                component="message",
                generated_value={"msg": clean_msg},
                evidence_refs=hyp.evidence.get("triggering_packets", []),
                validation_errors=[],
                reasoning_summary=f"Synthesized fallback alert message: '{clean_msg}'"
            )
            state.stage_results["stage3_message"] = stage_result.to_dict()
            state.last_stage_result = stage_result.to_dict()
            state.save_checkpoint(3)
            return state

        # Complete failure
        state.transition(ConstructionState.CONSTRUCTION_FAILED, reason=f"Stage 3 Message generation failed validation: {'; '.join(validation_errors)}")
        fail_result = StageResult(
            status="failed",
            component="message",
            generated_value=None,
            evidence_refs=hyp.evidence.get("triggering_packets", []),
            validation_errors=validation_errors,
            reasoning_summary="Stage 3 Message generation failed validation retries and fallback."
        )
        state.stage_results["stage3_message"] = fail_result.to_dict()
        state.last_stage_result = fail_result.to_dict()
        return state

    def _propose_message_llm(
        self,
        hypothesis: DetectionHypothesis,
        header: Optional[RuleHeaderAST] = None,
        report: Optional[Dict[str, Any]] = None,
        previous_errors: Optional[List[str]] = None
    ) -> str:
        """Query LLM to propose Snort 3 rule message string using the 3-Pillar Prompt Schema."""
        family = getattr(hypothesis, "malware_family", "") or hypothesis.family_context.get("malware_family", "Malware")
        category = getattr(hypothesis, "threat_category", "") or hypothesis.family_context.get("threat_category", "Network Attack")
        target_behaviour = hypothesis.target_behaviour
        objective = hypothesis.detection_objective
        header_str = header.render() if header else "alert tcp $EXTERNAL_NET any -> $HOME_NET any"
        stage3_catalogue = format_stage_catalogue_for_llm(3)
        ev_refs = hypothesis.evidence.get("triggering_packets", [])

        retry_feedback = ""
        if previous_errors:
            retry_feedback = f"""
[CRITICAL CORRECTION REQUIRED]
Your previous rule message proposal failed validation with the following errors:
{json.dumps(previous_errors, indent=2)}

Please strictly fix these issues:
1. Ensure the message starts with a standard category prefix (e.g. MALWARE-CNC, SERVER-WEBAPP, MALWARE-OTHER, PROTOCOL-DNS).
2. NEVER claim a verified compromise (e.g. do NOT say 'system compromised', 'host infected', 'successful exploit'). Use 'attempt', 'activity', 'pattern', or 'request'.
3. Keep the message concise and readable (between 25 and 85 characters).
4. Escape any internal double quotes (\\\") or semicolons (\\;).
"""

        user_prompt = f"""You are the Snort 3 Rule Engineer operating Stage 3: Message Generation.

1. COMPONENT-GENERATION INSTRUCTIONS:
Propose the human-readable alert message (`msg`) for AST Option #0.
Respond strictly with a JSON object conforming to this schema:
{{
  "category_prefix": "MALWARE-CNC | SERVER-WEBAPP | MALWARE-OTHER | PROTOCOL-DNS | EXPLOIT",
  "message": "<Full formatted message text without outer quotes>",
  "rationale": "<Reason explaining how message summarizes detection objective>"
}}

2. RELEVANT CATALOGUE ENTRIES (Dynamic from OptionSpec):
{stage3_catalogue}

3. CURRENT RULE CONTEXT & ACCUMULATED STATE:
- Detection Hypothesis:
  - Threat Family: {family}
  - Category: {category}
  - Intended Behaviour: {target_behaviour}
  - Detection Objective: {objective}
- Evidence References (Triggering Packets): {ev_refs}
- Upstream AST Components:
  - Header: {header_str}
- Current Rule Prefix:
  {header_str} ( [INSERT STAGE 3 MSG (AST OPTION #0) HERE] )
{retry_feedback}
"""
        try:
            resp_text = self.client.query(
                "You are an expert Snort 3 rule message generator. Output strictly valid JSON.",
                user_prompt,
                json_mode=True,
                temperature=0.1
            )
            parsed = json.loads(self._extract_json(resp_text))
            if isinstance(parsed, dict) and "message" in parsed:
                return str(parsed["message"]).strip()
            return generate_message(hypothesis, header)
        except Exception:
            return generate_message(hypothesis, header)

    def _update_ast_msg_option(self, state: RuleState, msg_text: str):
        """Ensure msg option is placed at position 0 of AST options."""
        # Remove any existing msg option
        state.ast.options = [opt for opt in state.ast.options if opt.name != "msg"]
        # Insert new msg at index 0
        state.ast.options.insert(0, RuleOptionAST(name="msg", value=msg_text))

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
