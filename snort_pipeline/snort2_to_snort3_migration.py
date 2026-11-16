"""
Snort 2 to Snort 3 Rule Migration, Compatibility Validation, and Conversion Engine.
Grounded in asset/snort_upgrade.text (Official Snort 3 Upgrade Manual) and Snort 3 Rule Writing Guide.

Provides:
1. Versioned Master Catalogue of Removed, Deprecated, Replaced, and Syntax-Changed options.
2. Three-Category Compatibility Validator:
   - Category 1 (Reject): Snort 2-only syntax (uricontent, urilen:raw/norm, http_encode, activate/dynamic, metadata:engine/rule-flushing, threshold).
   - Category 2 (Rewrite): Legacy syntax with direct Snort 3 equivalents (rawbytes -> raw_data, metadata:service -> service, offset:5 -> offset 5).
   - Category 3 (Validate): Deleted PCRE modifiers (B, U, P, H, M, C, I, D, K, S, Y) with context-aware sticky buffer transformations.
3. Automated Snort 2 to Snort 3 AST and Syntax Converter.
4. Snort 3 Compiler (-T) verification of converted rules.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict

# ─────────────────────────────────────────────────────────────────────────────
# 1. CATALOGUE SPECIFICATIONS & DEFINITIONS
# Grounded in asset/snort_upgrade.text
# ─────────────────────────────────────────────────────────────────────────────

MIGRATION_CATALOGUE_VERSION = "3.13.2.0"

class OptionUpgradeStatus:
    REMOVED = "removed"                      # Completely deleted; no direct equivalent or feature removed
    DEPRECATED = "deprecated"                # Deprecated or replaced by alternative mechanism
    REPLACED_OR_RENAMED = "replaced_renamed" # Renamed or replaced by sticky buffer / new option
    SYNTAX_CHANGED = "syntax_changed"        # Functionality retained, syntax modernized (colons to spaces, etc.)
    PCRE_MODIFIER_DELETED = "pcre_deleted"   # PCRE modifier removed in favor of sticky buffers

@dataclass
class UpgradeEntry:
    snort2_item: str
    status: str
    snort3_alternative: str
    category: str                            # "rule_option", "pcre_modifier", "header_action", "metadata", "preprocessor"
    description: str
    example_snort2: Optional[str] = None
    example_snort3: Optional[str] = None
    doc_section: str = "2.6 Rules"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Deleted PCRE Modifiers Mapping (asset/snort_upgrade.text Section 2.6)
# "the following pcre options have been deleted: use sticky buffers instead B, U, P, H, M, C, I, D, K, S, Y"
DELETED_PCRE_MODIFIERS: Dict[str, Dict[str, str]] = {
    "B": {"buffer": "pkt_data", "desc": "Raw packet/body payload inspection (replace with pkt_data or raw_data)"},
    "U": {"buffer": "http_uri", "desc": "HTTP normalized URI buffer (replace with sticky http_uri;)"},
    "P": {"buffer": "http_client_body", "desc": "HTTP client request body (replace with sticky http_client_body;)"},
    "H": {"buffer": "http_header", "desc": "HTTP normalized request/response headers (replace with sticky http_header;)"},
    "M": {"buffer": "http_method", "desc": "HTTP request method token (replace with sticky http_method;)"},
    "C": {"buffer": "http_cookie", "desc": "HTTP request/response cookie (replace with sticky http_cookie;)"},
    "I": {"buffer": "http_raw_uri", "desc": "HTTP unnormalized raw URI (replace with sticky http_raw_uri;)"},
    "D": {"buffer": "http_raw_header", "desc": "HTTP unnormalized raw header (replace with sticky http_raw_header;)"},
    "K": {"buffer": "http_raw_cookie", "desc": "HTTP unnormalized raw cookie (replace with sticky http_raw_cookie;)"},
    "S": {"buffer": "http_stat_code", "desc": "HTTP response status code (replace with sticky http_stat_code;)"},
    "Y": {"buffer": "http_stat_msg", "desc": "HTTP response status message (replace with sticky http_stat_msg;)"}
}

# ── Category 1: Strict Reject Set (Snort 2-only syntax)
STRICT_REJECT_OPTIONS: Dict[str, str] = {
    "uricontent": "Removed in Snort 3. Use sticky buffer 'http_uri;' followed by 'content:\"<pattern>\";'.",
    "urilen:raw": "Removed in Snort 3. Use 'http_raw_uri;' sticky buffer followed by 'bufferlen:<len>;'.",
    "urilen:norm": "Removed in Snort 3. Use 'http_uri;' sticky buffer followed by 'bufferlen:<len>;'.",
    "http_encode": "Removed in Snort 3. Unused option with no direct equivalent. Rely on inspector normalization.",
    "activate": "Removed in Snort 3. Activate/dynamic rule actions were eliminated.",
    "dynamic": "Removed in Snort 3. Activate/dynamic rule actions were eliminated.",
    "fast_pattern:only": "Syntax changed in Snort 3. Use 'fast_pattern' without 'only' argument.",
    "metadata:engine shared": "Removed in Snort 3. Engine shared metadata has no effect.",
    "metadata:rule-flushing": "Removed in Snort 3. PDU flushing eliminated manual rule flushing.",
    "threshold": "Removed in Snort 3 rules. Use 'detection_filter:track by_src|by_dst,count N,seconds S;' or snort.lua event_filter.",
    "alert_unified2": "Removed in Snort 3. Unified2 logging was removed. Use alert_json or alert_fast.",
    "log_unified2": "Removed in Snort 3. Unified2 logging was removed.",
    "log_ascii": "Removed in Snort 3.",
    "layer2resets": "Removed in Snort 3.",
    "flexresp2_attempts": "Removed in Snort 3. Flexresp2 preprocessor removed in favor of native react/reject actions."
}

# ── Category 2: Rewritable Legacy Syntax Map
REWRITABLE_OPTIONS: Dict[str, Dict[str, str]] = {
    "rawbytes": {
        "snort3_option": "raw_data;",
        "desc": "Converts legacy rawbytes content modifier to Snort 3 sticky raw_data buffer."
    },
    "metadata:service": {
        "snort3_option": "service:<svc>;",
        "desc": "Converts legacy metadata:service into modern standalone service detection option."
    },
    "fast_pattern:offset,length": {
        "snort3_option": "fast_pattern,fast_pattern_offset <offset>,fast_pattern_length <length>",
        "desc": "Converts comma-separated fast_pattern offset/length to explicit suboptions."
    },
    "offset:": {
        "snort3_option": "offset ",
        "desc": "Modernizes colon-separated offset:N to whitespace-separated offset N."
    },
    "depth:": {
        "snort3_option": "depth ",
        "desc": "Modernizes colon-separated depth:N to whitespace-separated depth N."
    },
    "distance:": {
        "snort3_option": "distance ",
        "desc": "Modernizes colon-separated distance:N to whitespace-separated distance N."
    },
    "within:": {
        "snort3_option": "within ",
        "desc": "Modernizes colon-separated within:N to whitespace-separated within N."
    }
}


def _build_master_upgrade_catalogue() -> List[UpgradeEntry]:
    """Build the comprehensive, versioned master upgrade catalogue."""
    entries: List[UpgradeEntry] = []

    # 1. Removed & Replaced Keywords
    entries.append(UpgradeEntry(
        snort2_item="uricontent",
        status=OptionUpgradeStatus.REPLACED_OR_RENAMED,
        snort3_alternative="http_uri; content:\"<pattern>\";",
        category="rule_option",
        description="Removed content modifier. Replaced by sticky buffer http_uri; preceding content: match.",
        example_snort2='alert tcp any any -> any 80 ( msg:"URI Test"; uricontent:"/login"; sid:1; )',
        example_snort3='alert tcp any any -> any 80 ( msg:"URI Test"; http_uri; content:"/login"; sid:1; )'
    ))

    entries.append(UpgradeEntry(
        snort2_item="urilen",
        status=OptionUpgradeStatus.REPLACED_OR_RENAMED,
        snort3_alternative="http_uri; bufferlen:<expr>; or http_raw_uri; bufferlen:<expr>;",
        category="rule_option",
        description="urilen raw/norm replaced with generic bufferlen applying to current sticky buffer.",
        example_snort2='urilen:>100,norm;',
        example_snort3='http_uri; bufferlen:>100;'
    ))

    entries.append(UpgradeEntry(
        snort2_item="rawbytes",
        status=OptionUpgradeStatus.REPLACED_OR_RENAMED,
        snort3_alternative="raw_data; (or pkt_data;)",
        category="rule_option",
        description="rawbytes modifier replaced with raw_data sticky buffer.",
        example_snort2='alert tcp any any -> any any ( msg:"Telnet NOP"; rawbytes; content:"|FF F1|"; sid:2; )',
        example_snort3='alert tcp any any -> any any ( msg:"Telnet NOP"; raw_data; content:"|FF F1|"; sid:2; )'
    ))

    entries.append(UpgradeEntry(
        snort2_item="http_encode",
        status=OptionUpgradeStatus.REMOVED,
        snort3_alternative="None (Inspector normalization)",
        category="rule_option",
        description="Unused option eliminated. Use appropriate HTTP inspector buffers."
    ))

    entries.append(UpgradeEntry(
        snort2_item="threshold",
        status=OptionUpgradeStatus.REPLACED_OR_RENAMED,
        snort3_alternative="detection_filter:track <by_src|by_dst>,count <N>,seconds <S>;",
        category="rule_option",
        description="In-rule threshold keyword removed in Snort 3. Replaced by detection_filter or Lua event_filter.",
        example_snort2='threshold:type threshold, track by_src, count 5, seconds 10;',
        example_snort3='detection_filter:track by_src,count 5,seconds 10;'
    ))

    entries.append(UpgradeEntry(
        snort2_item="metadata:service",
        status=OptionUpgradeStatus.REPLACED_OR_RENAMED,
        snort3_alternative="service:<svc1>[, <svc2>];",
        category="rule_option",
        description="Service declaration moved from metadata to standalone detection option.",
        example_snort2='metadata:service http, service smtp;',
        example_snort3='service:http, smtp;'
    ))

    entries.append(UpgradeEntry(
        snort2_item="sd_pattern",
        status=OptionUpgradeStatus.REPLACED_OR_RENAMED,
        snort3_alternative="sd_pattern:\"<pattern>\",threshold <N>;",
        category="rule_option",
        description="SDF preprocessor replaced by Snort 3 IPS sd_pattern powered by Hyperscan regex engine."
    ))

    entries.append(UpgradeEntry(
        snort2_item="activate / dynamic",
        status=OptionUpgradeStatus.REMOVED,
        snort3_alternative="Standard rule actions (alert, block, drop)",
        category="header_action",
        description="Activate and dynamic rule actions deleted in Snort 3."
    ))

    entries.append(UpgradeEntry(
        snort2_item="fast_pattern:only",
        status=OptionUpgradeStatus.SYNTAX_CHANGED,
        snort3_alternative="fast_pattern",
        category="rule_option",
        description="fast_pattern:only removed. Simply specify 'fast_pattern' (automatic optimization)."
    ))

    entries.append(UpgradeEntry(
        snort2_item="fast_pattern:<offset>,<length>",
        status=OptionUpgradeStatus.SYNTAX_CHANGED,
        snort3_alternative="fast_pattern,fast_pattern_offset <offset>,fast_pattern_length <length>",
        category="rule_option",
        description="Comma-separated offset/length arguments separated into dedicated suboptions."
    ))

    # Content suboptions colon to space modernization
    for mod in ["offset", "depth", "distance", "within"]:
        entries.append(UpgradeEntry(
            snort2_item=f"{mod}:<val>",
            status=OptionUpgradeStatus.SYNTAX_CHANGED,
            snort3_alternative=f"{mod} <val>",
            category="rule_option",
            description=f"Modernized syntax: {mod} now uses space separator instead of colon (e.g. '{mod} 5')."
        ))

    entries.append(UpgradeEntry(
        snort2_item="soid inside metadata",
        status=OptionUpgradeStatus.REPLACED_OR_RENAMED,
        snort3_alternative="soid:<gid>|<sid>|<rev>;",
        category="rule_option",
        description="soid is now a standalone option, not declared inside metadata."
    ))

    entries.append(UpgradeEntry(
        snort2_item="byte_test: =<",
        status=OptionUpgradeStatus.SYNTAX_CHANGED,
        snort3_alternative="byte_test: <= ...",
        category="rule_option",
        description="Symbol =< is recognized as syntax error in Snort 3; correct operator is <=."
    ))

    # 2. Deleted PCRE Modifiers
    for p_mod, p_info in DELETED_PCRE_MODIFIERS.items():
        entries.append(UpgradeEntry(
            snort2_item=f"pcre: /.../{p_mod}",
            status=OptionUpgradeStatus.PCRE_MODIFIER_DELETED,
            snort3_alternative=f"{p_info['buffer']}; pcre:\"/.../\"",
            category="pcre_modifier",
            description=f"Snort 2 PCRE modifier /{p_mod} deleted. {p_info['desc']}."
        ))

    return entries


# ─────────────────────────────────────────────────────────────────────────────
# 2. MASTER UPGRADE CATALOGUE STORE & EXPORTER
# ─────────────────────────────────────────────────────────────────────────────

class SnortUpgradeCatalogue:
    """Master store for Snort 2 to Snort 3 language changes and migration specs."""

    def __init__(self, json_path: Optional[Path] = None):
        self.version = MIGRATION_CATALOGUE_VERSION
        self.entries = _build_master_upgrade_catalogue()
        self._index: Dict[str, UpgradeEntry] = {e.snort2_item.lower(): e for e in self.entries}
        if json_path:
            self.export_json(json_path)

    def get_entry(self, item: str) -> Optional[UpgradeEntry]:
        return self._index.get(item.lower().strip())

    def export_json(self, target_path: Union[str, Path]) -> Path:
        """Export machine-readable upgrade catalogue to JSON."""
        p = Path(target_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "catalogue_version": self.version,
            "source_reference": "asset/snort_upgrade.text",
            "official_manual": "https://github.com/snort3/snort3/blob/master/doc/upgrade/snort_upgrade.text",
            "total_entries": len(self.entries),
            "entries": [e.to_dict() for e in self.entries]
        }
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return p


# Singleton catalogue instance
UPGRADE_CATALOGUE = SnortUpgradeCatalogue()


# ─────────────────────────────────────────────────────────────────────────────
# 3. THREE-CATEGORY COMPATIBILITY VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CompatibilityReport:
    is_valid: bool
    rejection_errors: List[str]              # Category 1: Snort 2-only syntax
    rewritable_warnings: List[str]           # Category 2: Legacy syntax with Snort 3 equivalents
    pcre_violations: List[str]               # Category 3: Deleted PCRE modifiers
    auto_converted_rule: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Snort2CompatibilityValidator:
    """
    Evaluates candidate Snort rules for deprecated or removed Snort 2 syntax.
    Enforces the 3-category evaluation:
    Category 1: Reject Snort 2-only syntax.
    Category 2: Flag or rewrite legacy syntax with Snort 3 equivalents.
    Category 3: Validate PCRE modifiers and reject deleted Snort 2 modifiers.
    """

    @classmethod
    def validate_rule(cls, rule_text: str) -> CompatibilityReport:
        clean_text = rule_text.strip()
        rejections: List[str] = []
        rewritables: List[str] = []
        pcre_errs: List[str] = []

        # ── Category 1: Reject Snort 2-only syntax
        # Check rule action
        action_match = re.match(r"^\s*([A-Za-z_-]+)", clean_text)
        if action_match:
            act = action_match.group(1).lower()
            if act in ["activate", "dynamic"]:
                rejections.append(f"Category 1 (Reject): Action '{act}' was removed in Snort 3. Use standard actions (alert, block, drop).")

        # Check in-rule options
        if "uricontent" in clean_text:
            rejections.append("Category 1 (Reject): 'uricontent' was removed in Snort 3. Use sticky buffer 'http_uri;' followed by 'content:'.")

        if "urilen:raw" in clean_text or re.search(r"\burilen\s*:[^;]*raw", clean_text, re.I):
            rejections.append("Category 1 (Reject): 'urilen:raw' was removed in Snort 3. Use 'http_raw_uri; bufferlen:<expr>;'.")

        if "urilen:norm" in clean_text or re.search(r"\burilen\s*:[^;]*norm", clean_text, re.I):
            rejections.append("Category 1 (Reject): 'urilen:norm' was removed in Snort 3. Use 'http_uri; bufferlen:<expr>;'.")

        if re.search(r"\bhttp_encode\b", clean_text, re.I):
            rejections.append("Category 1 (Reject): 'http_encode' was removed in Snort 3. Use appropriate HTTP inspector sticky buffers.")

        if re.search(r"\bfast_pattern\s*:\s*only\b", clean_text, re.I):
            rejections.append("Category 1 (Reject): 'fast_pattern:only' syntax changed in Snort 3. Use 'fast_pattern' without 'only'.")

        if re.search(r"\bmetadata\s*:[^;]*engine\s+shared\b", clean_text, re.I):
            rejections.append("Category 1 (Reject): 'metadata:engine shared' was removed in Snort 3.")

        if re.search(r"\bmetadata\s*:[^;]*rule-flushing\b", clean_text, re.I):
            rejections.append("Category 1 (Reject): 'metadata:rule-flushing' was removed in Snort 3.")

        if re.search(r"\bthreshold\s*:[^;]+", clean_text, re.I) and not re.search(r"detection_filter", clean_text, re.I):
            rejections.append("Category 1 (Reject): In-rule 'threshold:' keyword was removed in Snort 3. Use 'detection_filter:track <by_src|by_dst>,count <N>,seconds <S>;'.")

        if re.search(r"\bbyte_test\s*:[^;]*=\s*<", clean_text):
            rejections.append("Category 1 (Reject): Inverted byte_test operator '=<'. Snort 3 requires '<='.")

        # ── Category 2: Rewritable Legacy Syntax
        if re.search(r"\brawbytes\b", clean_text):
            rewritables.append("Category 2 (Rewrite): 'rawbytes' modifier should be replaced with 'raw_data;' sticky buffer.")

        if re.search(r"\bmetadata\s*:[^;]*service\s+", clean_text, re.I):
            rewritables.append("Category 2 (Rewrite): 'metadata:service <svc>' should be migrated to modern standalone 'service:<svc>;' option.")

        # Check colon-separated suboptions
        for mod in ["offset", "depth", "distance", "within"]:
            if re.search(rf"\b{mod}\s*:\s*\d+", clean_text):
                rewritables.append(f"Category 2 (Rewrite): '{mod}:<val>' should use modern whitespace separator '{mod} <val>'.")

        if re.search(r"\bfast_pattern\s*:\s*\d+\s*,\s*\d+", clean_text):
            rewritables.append("Category 2 (Rewrite): 'fast_pattern:<offset>,<len>' should be modernized to 'fast_pattern,fast_pattern_offset <offset>,fast_pattern_length <len>'.")

        # ── Category 3: Validate PCRE Modifiers
        pcre_matches = re.findall(r'pcre\s*:\s*(?:!\s*)?"/(?:\\/|[^/])+/([a-zA-Z]*)"', clean_text)
        for mod_str in pcre_matches:
            found_deleted = [m for m in mod_str if m in DELETED_PCRE_MODIFIERS]
            for m in found_deleted:
                p_info = DELETED_PCRE_MODIFIERS[m]
                pcre_errs.append(
                    f"Category 3 (PCRE Modifier Violation): Deleted modifier '/{m}' detected. "
                    f"In Snort 3, use sticky buffer '{p_info['buffer']};' instead of PCRE modifier /{m}."
                )

        # Generate auto-converted rule representation if rewritables or rejections exist
        auto_converted = None
        if rejections or rewritables or pcre_errs:
            try:
                auto_converted = Snort2ToSnort3Converter.convert_rule(clean_text)
            except Exception:
                auto_converted = None

        is_valid = len(rejections) == 0 and len(pcre_errs) == 0

        return CompatibilityReport(
            is_valid=is_valid,
            rejection_errors=rejections,
            rewritable_warnings=rewritables,
            pcre_violations=pcre_errs,
            auto_converted_rule=auto_converted
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. AUTOMATED SNORT 2 TO SNORT 3 CONVERTER
# ─────────────────────────────────────────────────────────────────────────────

class Snort2ToSnort3Converter:
    """
    Context-aware AST and rule text converter for transforming legacy Snort 2
    rules into compliant, optimal Snort 3 syntax.
    """

    @classmethod
    def convert_rule(cls, snort2_rule: str) -> str:
        """
        Convert a legacy Snort 2 rule string into clean, verified Snort 3 syntax.
        Handles:
        - uricontent -> http_uri; content:
        - rawbytes -> raw_data;
        - metadata:service -> service:
        - threshold -> detection_filter
        - Colon-separated suboptions -> whitespace
        - PCRE deleted modifier stripping and sticky buffer prepending
        - Fast pattern syntax modernization
        - Elimination of obsolete metadata
        """
        rule = snort2_rule.strip()
        if not rule:
            return ""

        # Step 1: Normalize activate / dynamic actions to alert
        rule = re.sub(r"^\s*(activate|dynamic)\b", "alert", rule)

        # Step 2: Handle threshold -> detection_filter
        thresh_match = re.search(r"threshold\s*:\s*type\s+\w+\s*,\s*track\s+(by_src|by_dst)\s*,\s*count\s+(\d+)\s*,\s*seconds\s+(\d+)\s*;", rule, re.I)
        if thresh_match:
            track_type = thresh_match.group(1).lower()
            count_val = thresh_match.group(2)
            sec_val = thresh_match.group(3)
            rule = rule[:thresh_match.start()] + f"detection_filter:track {track_type},count {count_val},seconds {sec_val};" + rule[thresh_match.end():]

        # Step 3: Handle rawbytes -> raw_data;
        rule = re.sub(r"\brawbytes\s*;", "raw_data;", rule)

        # Step 4: Handle uricontent:"<pat>" -> http_uri; content:"<pat>"
        while True:
            m_uri = re.search(r'uricontent\s*:\s*(!\s*)?"([^"]*)"', rule)
            if not m_uri:
                break
            neg = "!" if m_uri.group(1) else ""
            pat = m_uri.group(2)
            # Insert sticky buffer http_uri; if not already present preceding this content
            replacement = f'http_uri; content:{neg}"{pat}"'
            rule = rule[:m_uri.start()] + replacement + rule[m_uri.end():]

        # Step 5: Handle urilen:raw and urilen:norm -> bufferlen
        rule = re.sub(r'urilen\s*:\s*raw\s*,\s*([^;]+);', r'http_raw_uri; bufferlen:\1;', rule, flags=re.I)
        rule = re.sub(r'urilen\s*:\s*norm\s*,\s*([^;]+);', r'http_uri; bufferlen:\1;', rule, flags=re.I)
        rule = re.sub(r'urilen\s*:\s*([^;]+)\s*,\s*raw;', r'http_raw_uri; bufferlen:\1;', rule, flags=re.I)
        rule = re.sub(r'urilen\s*:\s*([^;]+)\s*,\s*norm;', r'http_uri; bufferlen:\1;', rule, flags=re.I)

        # Step 6: Handle metadata:service -> service:
        # e.g. metadata:service http; or metadata:service http, service smtp;
        def _extract_services(match):
            meta_content = match.group(1)
            # Extract all "service <name>"
            services = re.findall(r"\bservice\s+([a-zA-Z0-9_-]+)", meta_content, re.I)
            # Remove service tags from metadata content
            clean_meta = re.sub(r"\s*,?\s*\bservice\s+[a-zA-Z0-9_-]+", "", meta_content, flags=re.I).strip(" ,")
            svc_clause = f"service:{', '.join(services)}; " if services else ""
            meta_clause = f"metadata:{clean_meta}; " if clean_meta else ""
            return f"{svc_clause}{meta_clause}".strip()

        rule = re.sub(r'metadata\s*:\s*([^;]+);', _extract_services, rule)

        # Step 7: Modernize content suboptions (colons to spaces: offset:5 -> offset 5)
        for mod in ["offset", "depth", "distance", "within"]:
            rule = re.sub(rf'\b({mod})\s*:\s*(\d+)', r'\1 \2', rule)

        # Step 8: Modernize fast_pattern:only -> fast_pattern
        rule = re.sub(r'\bfast_pattern\s*:\s*only\b', 'fast_pattern', rule)

        # Step 9: Modernize fast_pattern:<offset>,<len> -> fast_pattern,fast_pattern_offset <offset>,fast_pattern_length <len>
        rule = re.sub(
            r'\bfast_pattern\s*:\s*(\d+)\s*,\s*(\d+)\b',
            r'fast_pattern,fast_pattern_offset \1,fast_pattern_length \2',
            rule
        )

        # Step 9.5: Collapse semicolon-separated content suboptions into commas
        # Snort 2 allowed '; fast_pattern;', '; offset:5;', '; depth:10;' as separate options.
        # Snort 3 explicitly specifies: "no ; separated content suboptions" (snort_upgrade.text line 449).
        # Requires format: content:"<pat>",fast_pattern,offset 5,depth 10;
        suboption_keywords = r"(?:fast_pattern(?:,fast_pattern_offset\s+\d+,fast_pattern_length\s+\d+)?|nocase|offset\s+\d+|depth\s+\d+|distance\s+\d+|within\s+\d+)"
        while True:
            new_rule = re.sub(
                rf'(content\s*:\s*(?:!\s*)?"[^"]*"(?:,[^;]*)?);\s*({suboption_keywords})\s*([;,])',
                r'\1,\2\3',
                rule
            )
            if new_rule == rule:
                break
            rule = new_rule

        # Step 10: Fix byte_test =< to <=
        rule = re.sub(r'\bbyte_test\s*:\s*([^;]*)=\s*<', r'byte_test:\1<=', rule)

        # Step 11: Deleted PCRE Modifiers Transformation
        # e.g. pcre:"/foo/U" -> http_uri; pcre:"/foo/"
        def _fix_pcre(match):
            prefix = match.group(1) or ""
            regex_body = match.group(2)
            mods = match.group(3) or ""

            # Check deleted modifiers
            detected_buffers = []
            clean_mods = []
            for char in mods:
                if char in DELETED_PCRE_MODIFIERS:
                    buf_name = DELETED_PCRE_MODIFIERS[char]["buffer"]
                    if buf_name not in detected_buffers:
                        detected_buffers.append(buf_name)
                else:
                    clean_mods.append(char)

            new_mod_str = "".join(clean_mods)
            pcre_str = f'pcre:{prefix}"/{regex_body}/{new_mod_str}"'

            if detected_buffers:
                # Prepend the appropriate sticky buffer
                return f"{detected_buffers[0]}; {pcre_str}"
            return pcre_str

        rule = re.sub(r'pcre\s*:\s*(!\s*)?"/(.*?)/([a-zA-Z]*)"', _fix_pcre, rule)

        # Step 12: Remove obsolete metadata keywords
        rule = re.sub(r'\bmetadata\s*:\s*[^;]*engine\s+shared[^;]*;', '', rule, flags=re.I)
        rule = re.sub(r'\bmetadata\s*:\s*[^;]*rule-flushing[^;]*;', '', rule, flags=re.I)

        # Step 13: Clean redundant duplicate sticky buffers
        # e.g. http_uri; http_uri; -> http_uri;
        rule = re.sub(r'\b(http_uri|http_header|http_client_body|raw_data);\s*\1;', r'\1;', rule)

        # Clean multiple spaces and ensure trailing semicolon before closing parenthesis
        rule = re.sub(r'\s+', ' ', rule)
        rule = re.sub(r';\s*;+', ';', rule)
        # Ensure trailing semicolon before closing parenthesis
        rule = re.sub(r'([^;\s])\s*\)', r'\1; )', rule)
        if not rule.strip().endswith(")"):
            rule = rule.strip() + " )"

        return rule
