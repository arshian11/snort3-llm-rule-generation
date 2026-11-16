"""
Shared Rule State & Abstract Syntax Tree (AST) Model for Snort 3 Rules.
Part of Task C: Hypothesis-Driven Iterative Rule Construction (HDIRC).

Maintains structured, auditable rule drafts throughout all construction stages:
Stage 1: Detection Hypothesis & Validation Gate
Stage 2: Header Generation [Placeholder]
Stage 3: Message Generation [Placeholder]
Stage 4: Flow Generation [Placeholder]
Stage 5: Detection Generation [Placeholder]
Stage 6: Supporting Options [Placeholder]
Stage 7: Final Rule Assembly [Placeholder with AST-to-Text Renderer]
"""

import json
import re
from enum import Enum
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict

@dataclass
class ValidationResult:
    """Standardized validation outcome for a Snort 3 rule component."""
    status: str  # "passed" or "failed"
    component: str  # "hypothesis", "header", "message", "flow", "detection", "content", etc.
    error: Optional[str] = None
    evidence_required: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    @property
    def errors(self) -> List[str]:
        if not self.error:
            return []
        if isinstance(self.details.get("all_errors"), list):
            return self.details["all_errors"]
        return [self.error]

    def __iter__(self):
        return iter((self.passed, self.errors, self.details))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "component": self.component,
            "error": self.error,
            "evidence_required": self.evidence_required,
            "details": self.details or {}
        }


@dataclass
class StageResult:
    """Standardized generation outcome for an HDIRC rule construction stage."""
    status: str  # "success" or "failed"
    component: str  # "header", "message", "flow", "detection", "metadata", etc.
    generated_value: Any  # AST node dict, string, list, or structured value
    evidence_refs: List[Any] = field(default_factory=list)
    validation_errors: List[str] = field(default_factory=list)
    reasoning_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "component": self.component,
            "generated_value": self.generated_value,
            "evidence_refs": self.evidence_refs,
            "validation_errors": self.validation_errors,
            "reasoning_summary": self.reasoning_summary
        }


class ConstructionState(str, Enum):
    HYPOTHESIS_PENDING = "hypothesis_pending"
    HYPOTHESIS_APPROVED = "hypothesis_approved"
    HEADER_GENERATED = "header_generated"
    MESSAGE_GENERATED = "message_generated"
    FLOW_GENERATED = "flow_generated"
    DETECTION_IN_PROGRESS = "detection_in_progress"
    DETECTION_GENERATED = "detection_generated"
    SUPPORTING_GENERATED = "supporting_generated"
    COMPONENTS_VALIDATED = "components_validated"
    RULE_ASSEMBLED = "rule_assembled"
    SYNTAX_VALIDATED = "syntax_validated"
    TESTING = "testing"
    APPROVED = "approved"
    REJECTED = "rejected"
    # Terminal non-rule dispositions
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CORRELATION_ONLY = "correlation_only"
    CONSTRUCTION_FAILED = "construction_failed"

class DetectionHypothesis:
    """
    Stage 1 Detection Hypothesis:
    Encapsulates the structured motivation for creating (or declining) a Snort rule.
    Fields: Behaviour, Protocol, Direction, Evidence, Family Context, Detection Objective.
    """
    def __init__(
        self,
        hypothesis_id: str,
        capture_id: str,
        target_behaviour: str,
        target_protocol: str,
        communication_direction: str,
        flow_intent: str,
        invariant_indicators: List[Dict[str, Any]],
        brittle_indicators_to_avoid: List[str],
        evidence: Dict[str, Any],
        family_context: Dict[str, Any],
        detection_objective: str,
        rule_viability: Dict[str, Any],
        validation_status: str = "PENDING",
        validation_notes: Optional[List[str]] = None
    ):
        self.hypothesis_id = hypothesis_id
        self.capture_id = capture_id
        self.target_behaviour = target_behaviour
        self.target_protocol = target_protocol
        self.communication_direction = communication_direction
        self.flow_intent = flow_intent
        self.invariant_indicators = invariant_indicators or []
        self.brittle_indicators_to_avoid = brittle_indicators_to_avoid or []
        self.evidence = evidence or {}
        self.family_context = family_context or {}
        self.detection_objective = detection_objective
        self.rule_viability = rule_viability or {
            "needs_snort_rule": True,
            "disposition": "PROCEED_TO_RULE",
            "disposition_rationale": "High-confidence protocol artifact identified"
        }
        self.validation_status = validation_status
        self.validation_notes = validation_notes or []

    @property
    def malware_family(self) -> str:
        return self.family_context.get("malware_family", "")

    @property
    def threat_category(self) -> str:
        return self.family_context.get("threat_category", "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "capture_id": self.capture_id,
            "target_behaviour": self.target_behaviour,
            "target_protocol": self.target_protocol,
            "communication_direction": self.communication_direction,
            "flow_intent": self.flow_intent,
            "invariant_indicators": self.invariant_indicators,
            "brittle_indicators_to_avoid": self.brittle_indicators_to_avoid,
            "evidence": self.evidence,
            "family_context": self.family_context,
            "detection_objective": self.detection_objective,
            "rule_viability": self.rule_viability,
            "validation_status": self.validation_status,
            "validation_notes": self.validation_notes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionHypothesis":
        return cls(
            hypothesis_id=data.get("hypothesis_id", "HYP_001"),
            capture_id=data.get("capture_id", "UNKNOWN"),
            target_behaviour=data.get("target_behaviour", ""),
            target_protocol=data.get("target_protocol", "TCP"),
            communication_direction=data.get("communication_direction", "outbound_c2"),
            flow_intent=data.get("flow_intent", "to_server"),
            invariant_indicators=data.get("invariant_indicators", []),
            brittle_indicators_to_avoid=data.get("brittle_indicators_to_avoid", []),
            evidence=data.get("evidence", {}),
            family_context=data.get("family_context", {}),
            detection_objective=data.get("detection_objective", ""),
            rule_viability=data.get("rule_viability", {}),
            validation_status=data.get("validation_status", "PENDING"),
            validation_notes=data.get("validation_notes", [])
        )

class RuleOptionAST:
    """An individual Snort 3 rule option node."""
    def __init__(
        self,
        name: str,
        value: Any = None,
        modifiers: Optional[Dict[str, Any]] = None,
        evidence_refs: Optional[List[str]] = None
    ):
        self.name = name
        self.value = value
        self.modifiers = modifiers or {}
        self.evidence_refs = evidence_refs or []

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"name": self.name, "value": self.value}
        if self.modifiers:
            d["modifiers"] = self.modifiers
        if self.evidence_refs:
            d["evidence_refs"] = self.evidence_refs
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleOptionAST":
        return cls(
            name=data["name"],
            value=data.get("value"),
            modifiers=data.get("modifiers", {}),
            evidence_refs=data.get("evidence_refs", [])
        )

class RuleHeaderAST:
    """A Snort 3 rule header node."""
    def __init__(
        self,
        action: str = "alert",
        header_type: str = "traditional",  # traditional, service, file
        protocol: Optional[str] = "tcp",
        service: Optional[str] = None,
        source_addr: str = "$HOME_NET",
        source_port: str = "any",
        direction: str = "->",
        dest_addr: str = "$EXTERNAL_NET",
        dest_port: str = "$HTTP_PORTS"
    ):
        self.action = action
        self.header_type = header_type
        self.protocol = protocol
        self.service = service
        self.source_addr = source_addr
        self.source_port = source_port
        self.direction = direction
        self.dest_addr = dest_addr
        self.dest_port = dest_port

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "header_type": self.header_type,
            "protocol": self.protocol,
            "service": self.service,
            "source": {
                "address": self.source_addr,
                "port": self.source_port
            },
            "direction": self.direction,
            "destination": {
                "address": self.dest_addr,
                "port": self.dest_port
            }
        }

    def render(self) -> str:
        """Render canonical Snort 3 rule header string."""
        if self.header_type == "file_id":
            return "file_id"
        elif self.header_type == "file":
            return f"{self.action} file"
        elif self.header_type == "service":
            svc = self.service or self.protocol or "http"
            return f"{self.action} {svc}"
        else:
            proto = self.protocol or "tcp"
            return f"{self.action} {proto} {self.source_addr} {self.source_port} {self.direction} {self.dest_addr} {self.dest_port}"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleHeaderAST":
        src = data.get("source", {})
        dst = data.get("destination", {})
        return cls(
            action=data.get("action", "alert"),
            header_type=data.get("header_type", "traditional"),
            protocol=data.get("protocol"),
            service=data.get("service"),
            source_addr=src.get("address", "$HOME_NET"),
            source_port=src.get("port", "any"),
            direction=data.get("direction", "->"),
            dest_addr=dst.get("address", "$EXTERNAL_NET"),
            dest_port=dst.get("port", "$HTTP_PORTS")
        )

class RuleAST:
    """The Abstract Syntax Tree representing the complete Snort 3 rule."""
    def __init__(self, header: Optional[RuleHeaderAST] = None, options: Optional[List[RuleOptionAST]] = None):
        self.header = header or RuleHeaderAST()
        self.options = options or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "options": [opt.to_dict() for opt in self.options]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleAST":
        hdr = RuleHeaderAST.from_dict(data.get("header", {}))
        opts = [RuleOptionAST.from_dict(o) for o in data.get("options", [])]
        return cls(header=hdr, options=opts)

class RuleState:
    """
    Central Shared Rule State across all HDIRC stages.
    Stores the evolving draft of the rule, component validation outcomes,
    evidence mapping, and retry tracking.
    """
    def __init__(
        self,
        candidate_id: str,
        hypothesis_id: Optional[str] = None,
        status: Union[ConstructionState, str] = ConstructionState.HYPOTHESIS_PENDING,
        hypothesis: Optional[DetectionHypothesis] = None
    ):
        self.candidate_id = candidate_id
        self.hypothesis_id = hypothesis_id or (hypothesis.hypothesis_id if hypothesis else None)
        self.status = status.value if isinstance(status, ConstructionState) else status
        self.current_stage: int = 1
        self.hypothesis = hypothesis

        # Structured components store
        self.components: Dict[str, Any] = {
            "header": None,
            "msg": None,
            "flow": None,
            "detection": [],
            "metadata": [],
            "references": [],
            "classification": None,
            "sid": None,
            "rev": None
        }

        # Internal AST
        self.ast = RuleAST()

        # Component validation tracking
        self.component_validation: Dict[str, Any] = {}

        # Packet evidence mapping
        self.evidence_mapping: Dict[str, List[int]] = {}

        # Stage retry tracking
        self.stage_retry_counts: Dict[str, int] = {
            "stage1_hypothesis": 0,
            "stage2_header": 0,
            "stage3_msg": 0,
            "stage4_flow": 0,
            "stage5_detection": 0,
            "stage6_metadata": 0,
            "stage7_assembly": 0
        }

        # Audit trail of state transitions
        self.history: List[Dict[str, Any]] = [
            {
                "timestamp": datetime.now().isoformat(),
                "status": self.status,
                "reason": "Initialized Rule State"
            }
        ]

        # Stage results and persistent checkpoints
        self.stage_results: Dict[str, Dict[str, Any]] = {}
        self.last_stage_result: Optional[Dict[str, Any]] = None
        self.checkpoints: Dict[int, Dict[str, Any]] = {}

        # Rendered rule cache
        self.rendered_rule_text: Optional[str] = None

    def transition(self, new_status: Union[ConstructionState, str], reason: str = ""):
        """Record state transition in audit trail."""
        st = new_status.value if isinstance(new_status, ConstructionState) else new_status
        self.status = st
        self.history.append({
            "timestamp": datetime.now().isoformat(),
            "status": st,
            "reason": reason
        })

    def record_validation(self, stage_name: str, passed: bool, errors: Optional[List[str]] = None, details: Optional[Dict[str, Any]] = None):
        """Record component validation results."""
        self.component_validation[stage_name] = {
            "timestamp": datetime.now().isoformat(),
            "passed": passed,
            "errors": errors or [],
            "details": details or {}
        }

    def save_checkpoint(self, stage: int):
        """Save persistent snapshot checkpoint of the rule state at the given stage."""
        self.checkpoints[stage] = {
            "stage": stage,
            "status": self.status,
            "timestamp": datetime.now().isoformat(),
            "components": json.loads(json.dumps(self.components, default=str)),
            "ast": self.ast.to_dict(),
            "rendered_rule_text": self.rendered_rule_text or self.render_snort3_rule()
        }

    def restore_checkpoint(self, stage: int) -> bool:
        """Restore rule state to the checkpoint saved at the given stage."""
        if stage not in self.checkpoints:
            return False
        cp = self.checkpoints[stage]
        self.status = cp["status"]
        self.current_stage = stage
        self.components = cp["components"]
        self.ast = RuleAST.from_dict(cp["ast"])
        self.rendered_rule_text = cp.get("rendered_rule_text")
        self.history.append({
            "timestamp": datetime.now().isoformat(),
            "status": self.status,
            "reason": f"Restored checkpoint from stage {stage}"
        })
        return True

    def render_single_option(self, opt: RuleOptionAST) -> str:
        """Render a single Snort 3 AST option node to compliant string."""
        name = opt.name.strip()
        val = opt.value
        mods = opt.modifiers or {}

        # Sticky buffers without arguments (e.g. http_uri;, file_data;)
        if val is None and not mods:
            return f"{name};"

        # msg option
        if name == "msg":
            clean_val = str(val).strip()
            if clean_val.startswith('"') and clean_val.endswith('"'):
                clean_val = clean_val[1:-1]
            # Escape internal unescaped quotes and semicolons per Snort 3 specification
            clean_val = re.sub(r'(?<!\\)"', r'\"', clean_val)
            clean_val = re.sub(r'(?<!\\);', r'\;', clean_val)
            return f'msg:"{clean_val}";'

        # flow option
        if name == "flow":
            flow_args = ",".join(val) if isinstance(val, list) else str(val)
            return f"flow:{flow_args};"

        # content option with comma-separated Snort 3 modifiers
        if name == "content":
            clean_content = str(val).strip()
            is_neg = False
            if clean_content.startswith("!"):
                is_neg = True
                clean_content = clean_content[1:].strip()
            if clean_content.startswith('"') and clean_content.endswith('"'):
                clean_content = clean_content[1:-1]

            mod_parts = []
            if mods.get("nocase"):
                mod_parts.append("nocase")
            if mods.get("fast_pattern"):
                fp_val = mods.get("fast_pattern")
                if fp_val is True:
                    mod_parts.append("fast_pattern")
                elif isinstance(fp_val, str) and fp_val != "True":
                    mod_parts.append(f"fast_pattern {fp_val}")
            for mod_k in ["offset", "depth", "distance", "within"]:
                if mod_k in mods and mods[mod_k] is not None:
                    mod_parts.append(f"{mod_k} {mods[mod_k]}")

            neg_prefix = "!" if is_neg else ""
            if mod_parts:
                return f'content:{neg_prefix}"{clean_content}",{",".join(mod_parts)};'
            else:
                return f'content:{neg_prefix}"{clean_content}";'

        # pcre option
        if name == "pcre":
            clean_pcre = str(val).strip()
            is_neg = False
            if clean_pcre.startswith("!"):
                is_neg = True
                clean_pcre = clean_pcre[1:].strip()
            if clean_pcre.startswith('"') and clean_pcre.endswith('"'):
                clean_pcre = clean_pcre[1:-1]
            neg_prefix = "!" if is_neg else ""
            return f'pcre:{neg_prefix}"{clean_pcre}";'

        # regex option (Hyperscan)
        if name == "regex":
            clean_regex = str(val).strip()
            is_neg = False
            if clean_regex.startswith("!"):
                is_neg = True
                clean_regex = clean_regex[1:].strip()
            if clean_regex.startswith('"') and clean_regex.endswith('"'):
                clean_regex = clean_regex[1:-1]
            neg_prefix = "!" if is_neg else ""
            mod_parts = []
            if mods.get("fast_pattern"):
                mod_parts.append("fast_pattern")
            if mods.get("nocase"):
                mod_parts.append("nocase")
            if mod_parts:
                return f'regex:{neg_prefix}"{clean_regex}",{",".join(mod_parts)};'
            else:
                return f'regex:{neg_prefix}"{clean_regex}";'

        # rem, replace, and file_type require quotes if not already quoted
        if name in ["rem", "replace", "file_type"]:
            clean_str = str(val).strip()
            if clean_str.startswith('"') and clean_str.endswith('"'):
                clean_str = clean_str[1:-1]
            return f'{name}:"{clean_str}";'

        # numeric / simple keyword options (sid, rev, classtype, service, etc.)
        if isinstance(val, (int, str)):
            return f"{name}:{val};"

        # generic fallback
        return f"{name}:{val};"

    def render_multiline(self, indent: int = 4) -> str:
        """Render rule in canonical multi-line indented format."""
        from snort_pipeline.rule_renderer import RuleRenderer
        return RuleRenderer.render_multiline(self, indent=indent)

    def render_singleline(self) -> str:
        """Render rule in canonical single-line format."""
        from snort_pipeline.rule_renderer import RuleRenderer
        return RuleRenderer.render_singleline(self)

    def to_structured_representation(self) -> Dict[str, Any]:
        """Convert RuleState into intermediate structured representation."""
        from snort_pipeline.rule_renderer import RuleRenderer
        return RuleRenderer.to_structured_representation(self)

    def render_snort3_rule(self) -> str:
        """
        Convert structured AST to canonical, compliant Snort 3 rule text.
        Applies proper comma-separated modifiers inside content clauses.
        """
        header_str = self.ast.header.render()
        rendered_options = [self.render_single_option(opt) for opt in self.ast.options]
        options_body = " ".join(rendered_options)
        self.rendered_rule_text = f"{header_str} ( {options_body} )"
        return self.rendered_rule_text

    def render_rule_prefix(self, up_to_stage: int, placeholder: str = "") -> str:
        """
        Renders the accumulated rule prefix text up to a given stage, with an explicit placeholder
        showing exactly where the new stage component slots into the Snort 3 rule body.
        Stage 2: [INSERT STAGE 2 HEADER HERE] ( ... )
        Stage 3: <header> ( [INSERT STAGE 3 MSG (AST OPTION #0) HERE] )
        Stage 4: <header> ( msg:"..."; [INSERT STAGE 4 FLOW HERE] )
        Stage 5: <header> ( msg:"..."; flow:...; [INSERT STAGE 5 DETECTION CONDITIONS HERE] )
        Stage 6: <header> ( msg:"..."; flow:...; <detection options>; [INSERT STAGE 6 SUPPORTING OPTIONS HERE] )
        """
        if up_to_stage <= 2:
            hdr_str = "[INSERT STAGE 2 HEADER HERE]"
        else:
            hdr_str = self.ast.header.render() if self.ast and self.ast.header else "alert tcp $EXTERNAL_NET any -> $HOME_NET any"

        body_opts = []
        for opt in self.ast.options:
            if up_to_stage == 3 and opt.name in ["msg", "flow", "content", "http_uri", "http_header", "file_data"]:
                continue
            if up_to_stage == 4 and opt.name != "msg":
                continue
            if up_to_stage == 5 and opt.name not in ["msg", "flow"]:
                continue
            if up_to_stage == 6 and opt.name in ["classtype", "sid", "rev", "priority", "metadata", "reference", "service", "rem", "detection_filter", "tag", "replace"]:
                continue
            body_opts.append(self.render_single_option(opt))

        if placeholder:
            body_opts.append(f"[{placeholder}]")

        if body_opts:
            return f"{hdr_str} ( {' '.join(body_opts)} )"
        elif placeholder:
            return f"{hdr_str} ( [{placeholder}] )"
        else:
            return hdr_str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "hypothesis_id": self.hypothesis_id,
            "status": self.status,
            "current_stage": self.current_stage,
            "hypothesis": self.hypothesis.to_dict() if self.hypothesis else None,
            "components": self.components,
            "ast": self.ast.to_dict(),
            "component_validation": self.component_validation,
            "evidence_mapping": self.evidence_mapping,
            "stage_retry_counts": self.stage_retry_counts,
            "stage_results": self.stage_results,
            "last_stage_result": self.last_stage_result,
            "checkpoints": self.checkpoints,
            "history": self.history,
            "rendered_rule_text": self.rendered_rule_text
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleState":
        hyp = DetectionHypothesis.from_dict(data["hypothesis"]) if data.get("hypothesis") else None
        state = cls(
            candidate_id=data.get("candidate_id", "CAND_001"),
            hypothesis_id=data.get("hypothesis_id"),
            status=data.get("status", ConstructionState.HYPOTHESIS_PENDING.value),
            hypothesis=hyp
        )
        state.current_stage = data.get("current_stage", 1)
        state.components = data.get("components", state.components)
        if "ast" in data:
            state.ast = RuleAST.from_dict(data["ast"])
        state.component_validation = data.get("component_validation", {})
        state.evidence_mapping = data.get("evidence_mapping", {})
        state.stage_retry_counts = data.get("stage_retry_counts", state.stage_retry_counts)
        state.stage_results = data.get("stage_results", {})
        state.last_stage_result = data.get("last_stage_result")
        state.checkpoints = data.get("checkpoints", {})
        state.history = data.get("history", state.history)
        state.rendered_rule_text = data.get("rendered_rule_text")
        return state
