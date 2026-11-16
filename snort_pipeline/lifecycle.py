"""
Module 7: Rule Lifecycle & Versioned Ruleset Management.
Maintains the state machine:
PROPOSED -> VALIDATED -> PENDING_REVIEW -> APPROVED -> DEPLOYED -> (ROLLED_BACK)

Guarantees isolation:
- Community rules are never modified.
- Experimental candidate rules remain in candidates.json.
- Approved rules are deployed into local.rules with version audit snapshots and rollback capability.
"""

import os
import re
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set

from snort_pipeline.config import (
    LOCAL_RULES_PATH,
    CANDIDATE_RULES_PATH,
    CANDIDATES_HISTORY_PATH,
    RULES_HISTORY_DIR,
    WSL_COMMUNITY_RULES,
)

class RuleLifecycleManager:
    def __init__(
        self,
        local_rules_path: Path = LOCAL_RULES_PATH,
        candidates_path: Path = CANDIDATE_RULES_PATH,
        candidates_history_path: Path = CANDIDATES_HISTORY_PATH,
        history_dir: Path = RULES_HISTORY_DIR,
        community_rules_path: str = WSL_COMMUNITY_RULES
    ):
        self.local_rules_path = Path(local_rules_path)
        self.candidates_path = Path(candidates_path)
        self.candidates_history_path = Path(candidates_history_path)
        self.history_dir = Path(history_dir)
        self.community_rules_path = community_rules_path
        self.audit_log_file = self.history_dir / "audit_log.json"

        self.candidates: Dict[int, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        """Load candidate rules and audit log from disk."""
        if self.candidates_path.is_file():
            try:
                with open(self.candidates_path, "r", encoding="utf-8") as f:
                    self.candidates = {int(k): v for k, v in json.load(f).items()}
            except Exception:
                self.candidates = {}

        if self.audit_log_file.is_file():
            try:
                with open(self.audit_log_file, "r", encoding="utf-8") as f:
                    self.audit_log = json.load(f)
            except Exception:
                self.audit_log = []

    def save(self):
        """Persist candidate rules and audit log."""
        self.candidates_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.candidates_path, "w", encoding="utf-8") as f:
            json.dump({str(k): v for k, v in self.candidates.items()}, f, indent=2)

        with open(self.audit_log_file, "w", encoding="utf-8") as f:
            json.dump(self.audit_log, f, indent=2)

    def get_candidates_history(self) -> Dict[str, Any]:
        """Load and return the history of candidate rules grouped by creation time."""
        if self.candidates_history_path.is_file():
            try:
                with open(self.candidates_history_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def get_allocated_sids(self) -> Set[int]:
        """Collect all SIDs ever allocated in candidates, history, and sid_registry."""
        sids = set(self.candidates.keys())
        history = self.get_candidates_history()
        for batch in history.values():
            for sid_str in batch.get("rules", {}).keys():
                try:
                    sids.add(int(sid_str))
                except (ValueError, TypeError):
                    pass
        sid_reg_path = Path("data/sid_registry.json")
        if sid_reg_path.is_file():
            try:
                with open(sid_reg_path, "r", encoding="utf-8") as f:
                    reg = json.load(f)
                    for s in reg.get("allocated_sids", []):
                        sids.add(int(s))
            except Exception:
                pass
        return sids

    def get_next_sid(self) -> int:
        """Determine next available candidate SID (>= 9001001)."""
        allocated = self.get_allocated_sids()
        candidate_sids = {s for s in allocated if s >= 9001000}
        return max(candidate_sids) + 1 if candidate_sids else 9001001

    def archive_and_reset_candidates(self) -> int:
        """
        Archive any existing rules in candidates.json into candidates_history.json,
        where each set of rules is differentiated by when they were created,
        and keep candidates.json clean/empty ({}).
        Returns the number of rules archived.
        """
        self._load()
        if not self.candidates:
            # Already empty, ensure clean file on disk
            self._save_candidates({})
            return 0

        # Load existing history if present
        history = self.get_candidates_history()

        archived_count = len(self.candidates)
        # Group candidates by their created_at timestamp
        for sid_int, rule in self.candidates.items():
            sid_str = str(sid_int)
            created_ts = rule.get("created_at") or rule.get("timestamp") or datetime.now().isoformat()

            if created_ts not in history:
                history[created_ts] = {
                    "created_at": created_ts,
                    "total_rules": 0,
                    "sids": [],
                    "rules": {}
                }

            history[created_ts]["rules"][sid_str] = rule
            if int(sid_int) not in history[created_ts]["sids"]:
                history[created_ts]["sids"].append(int(sid_int))
            history[created_ts]["sids"].sort()
            history[created_ts]["total_rules"] = len(history[created_ts]["rules"])

        # Persist updated candidates_history.json
        self.candidates_history_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.candidates_history_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)

        # Reset candidates to empty {}
        self.candidates = {}
        self._save_candidates({})
        print(f"[+] Archived {archived_count} candidate rules into {self.candidates_history_path.name} and cleaned {self.candidates_path.name}.")
        return archived_count

    def _save_candidates(self, data: Dict[str, Any]):
        self.candidates_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.candidates_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def register_candidate(
        self,
        candidate_rule_data: Dict[str, Any],
        source_pcap: str = "Unknown"
    ) -> Dict[str, Any]:
        """
        Step 1: Register LLM proposed candidate rule into isolated candidate store.
        Every generated candidate rule gets a unique SID and is permanently preserved.
        No existing rule is ever overwritten or replaced.
        """
        self._load()
        rule_obj = candidate_rule_data.get("candidate_rule", candidate_rule_data) if isinstance(candidate_rule_data, dict) else {}
        rule_text = rule_obj.get("rule_text", "").strip() if isinstance(rule_obj, dict) else ""
        if not rule_obj or not rule_text or rule_text.startswith("# Non-rule"):
            print("[!] Refusing to register empty or non-viable candidate rule. candidates.json remains unchanged.")
            return {}

        sid = rule_obj.get("rule_id")

        # Determine next available SID (must never collide with or overwrite any existing or historical candidate)
        allocated = self.get_allocated_sids()
        if not sid or sid in allocated:
            sid = self.get_next_sid()

        rule_obj["rule_id"] = sid
        rule_text = rule_obj.get("rule_text", "").strip()
        if rule_text:
            if re.search(r"sid:\s*\d+;", rule_text):
                rule_text = re.sub(r"sid:\s*\d+;", f"sid:{sid};", rule_text)
            elif rule_text.endswith(")"):
                rule_text = rule_text[:-1].rstrip() + f" sid:{sid}; rev:1; )"
            rule_obj["rule_text"] = rule_text

        # Check duplicates
        duplicate_check = self.check_duplicates(rule_obj.get("rule_text", ""))

        record = {
            "rule_id": sid,
            "rule_text": rule_obj.get("rule_text", "").strip(),
            "rule_objective": rule_obj.get("rule_objective", ""),
            "evidence": rule_obj.get("evidence", {}),
            "matching_logic": rule_obj.get("matching_logic", {}),
            "generalization": rule_obj.get("generalization", ""),
            "limitations": rule_obj.get("limitations", ""),
            "false_positive_risks": rule_obj.get("false_positive_risks", ""),
            "confidence": rule_obj.get("confidence", "high"),
            "status": rule_obj.get("status") or "PROPOSED",
            "source_pcap": source_pcap,
            "created_at": datetime.now().isoformat(),
            "duplicate_check": duplicate_check,
            "validation_results": rule_obj.get("validation_results"),
            "analyst_review": rule_obj.get("analyst_review"),
            "hdirc_stage1": rule_obj.get("hdirc_stage1")
        }

        self.candidates[sid] = record
        self.save()
        return record

    def check_duplicates(self, rule_text: str) -> Dict[str, Any]:
        """
        Step 2: Duplicate and existing-rule comparison.
        Checks for SID conflict and overlapping content matches.
        """
        sid_match = re.search(r"sid:(\d+);", rule_text)
        candidate_sid = int(sid_match.group(1)) if sid_match else 0

        # Extract contents
        contents = re.findall(r'content:"([^"]+)"', rule_text)

        duplicate_in_local = False
        duplicate_in_community = False
        conflicting_rules = []

        # Check local.rules
        if self.local_rules_path.is_file():
            with open(self.local_rules_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if f"sid:{candidate_sid};" in line:
                        duplicate_in_local = True
                        conflicting_rules.append({"source": "local.rules", "conflict": "SID Collision", "rule": line})
                    for c in contents:
                        if len(c) > 4 and f'content:"{c}"' in line:
                            conflicting_rules.append({"source": "local.rules", "conflict": f"Content overlap: {c}", "rule": line})

        return {
            "has_conflicts": len(conflicting_rules) > 0,
            "duplicate_in_local": duplicate_in_local,
            "conflicts": conflicting_rules
        }

    def update_validation_results(self, sid: int, validation_results: Dict[str, Any]):
        """Record validation results for a candidate rule."""
        self._load()
        if sid not in self.candidates:
            raise KeyError(f"Candidate SID {sid} not found")

        self.candidates[sid]["validation_results"] = validation_results
        status = validation_results.get("overall_status", "VALIDATION_FAILED")
        if status in ["PASSED", "PASSED_WITH_WARNINGS"]:
            self.candidates[sid]["status"] = "PENDING_REVIEW"
        else:
            self.candidates[sid]["status"] = status

        self.save()

    def review_rule(
        self,
        sid: int,
        action: str,  # "approve", "reject", "modify"
        analyst_name: str,
        analyst_notes: str = "",
        modified_rule_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Step 7 & 8: Analyst human review and promotion into production local.rules.
        """
        self._load()
        if sid not in self.candidates:
            raise KeyError(f"Candidate SID {sid} not found")

        cand = self.candidates[sid]
        action = action.lower()

        if action == "modify" and modified_rule_text:
            cand["rule_text"] = modified_rule_text.strip()
            cand["status"] = "MODIFIED_PENDING_REVALIDATION"
            cand["analyst_review"] = {
                "analyst": analyst_name,
                "action": "modify",
                "notes": analyst_notes,
                "timestamp": datetime.now().isoformat()
            }
            self.save()
            return cand

        elif action == "reject":
            cand["status"] = "REJECTED"
            cand["analyst_review"] = {
                "analyst": analyst_name,
                "action": "reject",
                "notes": analyst_notes,
                "timestamp": datetime.now().isoformat()
            }
            self.save()
            return cand

        elif action == "approve":
            # Promotion into production rules/local.rules with full versioning!
            new_version = self._get_next_ruleset_version()
            # 1. Snapshot current local.rules
            snapshot_path = self.history_dir / f"local.rules.v{new_version}"
            if self.local_rules_path.is_file():
                shutil.copy2(self.local_rules_path, snapshot_path)

            # 2. Append approved rule to local.rules with provenance header
            val = cand.get("validation_results", {})
            metrics = val.get("metrics", {})
            provenance_header = (
                f"\n# =========================================================================\n"
                f"# Rule SID: {sid} | Ruleset Version: v{new_version} | Approved by: {analyst_name}\n"
                f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Source Capture: {cand.get('source_pcap')}\n"
                f"# Objective: {cand.get('rule_objective')}\n"
                f"# Validation Metrics: TP={metrics.get('true_positives', 0)}, FP={metrics.get('false_positives', 0)}, "
                f"Precision={metrics.get('precision', 0.0)}, Recall={metrics.get('recall', 0.0)}, F1={metrics.get('f1_score', 0.0)}\n"
                f"# Analyst Notes: {analyst_notes}\n"
                f"# =========================================================================\n"
            )
            rule_entry = f"{provenance_header}{cand['rule_text']}\n"

            with open(self.local_rules_path, "a", encoding="utf-8") as f:
                f.write(rule_entry)

            # 3. Update candidate status
            cand["status"] = "APPROVED_DEPLOYED"
            cand["deployed_version"] = f"v{new_version}"
            cand["analyst_review"] = {
                "analyst": analyst_name,
                "action": "approve",
                "notes": analyst_notes,
                "timestamp": datetime.now().isoformat(),
                "deployed_version": f"v{new_version}"
            }

            # 4. Audit Log Entry
            audit_entry = {
                "action": "PROMOTE_RULE",
                "version": f"v{new_version}",
                "sid": sid,
                "rule_text": cand["rule_text"],
                "analyst": analyst_name,
                "notes": analyst_notes,
                "timestamp": datetime.now().isoformat(),
                "snapshot_file": str(snapshot_path)
            }
            self.audit_log.append(audit_entry)
            self.save()
            return cand

        else:
            raise ValueError(f"Unknown review action: {action}")

    def rollback(self, target_version: int, analyst: str, reason: str) -> Dict[str, Any]:
        """
        Roll back production local.rules to an earlier version snapshot.
        """
        snapshot_file = self.history_dir / f"local.rules.v{target_version}"
        if not snapshot_file.is_file():
            raise FileNotFoundError(f"Ruleset snapshot for version v{target_version} not found at {snapshot_file}")

        # Current version snapshot before rollback
        next_v = self._get_next_ruleset_version()
        pre_rollback_snap = self.history_dir / f"local.rules.v{next_v}_pre_rollback"
        if self.local_rules_path.is_file():
            shutil.copy2(self.local_rules_path, pre_rollback_snap)

        # Restore
        shutil.copy2(snapshot_file, self.local_rules_path)

        audit_entry = {
            "action": "ROLLBACK_RULESET",
            "target_version": f"v{target_version}",
            "resulting_version": f"v{next_v}",
            "analyst": analyst,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        self.audit_log.append(audit_entry)
        self.save()
        return audit_entry

    def _get_next_ruleset_version(self) -> int:
        """Find highest existing version number in history and increment."""
        nums = [0]
        for f in self.history_dir.glob("local.rules.v*"):
            m = re.search(r"v(\d+)", f.name)
            if m:
                nums.append(int(m.group(1)))
        return max(nums) + 1

    def list_candidates(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List candidate rules, optionally filtered by status."""
        self._load()
        results = []
        for c in self.candidates.values():
            if status and c.get("status") != status:
                continue
            results.append(c)
        return sorted(results, key=lambda x: x.get("created_at", ""), reverse=True)
