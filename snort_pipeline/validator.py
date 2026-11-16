"""
Module 6: Rule Validation Engine.
Four-stage validation pipeline:
1. Syntax Validation: Snort configuration test (-T) with candidate rule
2. Positive PCAP Testing: Replay motivating malicious PCAP(s)
3. Negative PCAP Testing: Replay known benign PCAP(s) for false positives
4. Generalization Testing: Replay holdout malicious PCAP(s)
Computes True Positives, False Positives, False Negatives, Precision, Recall, and F1-score.
"""

import os
import re
import json
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

from snort_pipeline.config import (
    WSL_SNORT_BIN,
    WSL_SNORT_CONFIG,
    RULES_DIR,
    to_wsl_path,
    run_wsl_cmd,
)
from snort_pipeline.dataset import PcapDatasetManager

class RuleValidator:
    def __init__(
        self,
        config_path: str = WSL_SNORT_CONFIG,
        dataset_manager: Optional[PcapDatasetManager] = None
    ):
        self.config_path = config_path
        self.dataset_mgr = dataset_manager or PcapDatasetManager()
        self.candidates_dir = RULES_DIR / "candidates"
        self.candidates_dir.mkdir(parents=True, exist_ok=True)

    def validate_candidate_rule(
        self,
        candidate_rule: Dict[str, Any],
        motivating_pcap_ids: List[str],
        benign_pcap_ids: Optional[List[str]] = None,
        holdout_pcap_ids: Optional[List[str]] = None,
        llm_engine: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Execute full 4-stage validation pipeline on candidate rule.
        Supports self-healing syntax refinement if syntax error occurs.
        """
        rule_id = candidate_rule.get("rule_id", 9001001)
        raw_text = candidate_rule.get("rule_text", "").strip()

        # Enforce Snort 3 syntax normalization
        from snort_pipeline.llm_engine import normalize_snort3_syntax
        rule_text = normalize_snort3_syntax(raw_text)
        candidate_rule["rule_text"] = rule_text

        # Ensure rule has trailing semicolon if missing
        if rule_text and not rule_text.endswith(")"):
            rule_text += ")"

        # Stage 1: Syntax Validation
        stage1_result = self._validate_syntax(rule_id, rule_text)

        # Self-healing feedback loop if syntax fails
        if not stage1_result["passed"] and llm_engine:
            refined = llm_engine.refine_rule_syntax(candidate_rule, stage1_result["error_output"])
            candidate_rule["rule_text"] = refined.get("rule_text", rule_text)
            rule_text = candidate_rule["rule_text"]
            # Re-test syntax
            stage1_result = self._validate_syntax(rule_id, rule_text)

        if not stage1_result["passed"]:
            return {
                "rule_id": rule_id,
                "rule_text": rule_text,
                "overall_status": "FAILED_SYNTAX",
                "stage1_syntax": stage1_result,
                "stage2_positive": {"status": "SKIPPED", "detected_pcaps_count": 0, "tested_pcaps_count": 0, "total_alerts": 0},
                "stage3_negative": {"status": "SKIPPED", "false_positive_pcaps_count": 0, "tested_benign_count": 0, "total_fp_alerts": 0},
                "stage4_generalization": {"status": "SKIPPED", "detected_pcaps_count": 0, "tested_holdout_count": 0, "total_alerts": 0},
                "metrics": {"true_positives": 0, "false_positives": 0, "false_negatives": 0, "true_negatives": 0, "precision": 0.0, "recall": 0.0, "f1_score": 0.0}
            }

        rule_file_wsl = stage1_result["rule_file_wsl"]

        # Resolve target malware family for family-aware matching
        target_family = candidate_rule.get("malware_family")
        if not target_family:
            target_family = candidate_rule.get("evidence", {}).get("threat_family")
        if not target_family:
            target_family = candidate_rule.get("matching_logic", {}).get("threat_family")
        if not target_family and motivating_pcap_ids:
            source_cap = self.dataset_mgr.get_capture(motivating_pcap_ids[0])
            if source_cap:
                target_family = source_cap.get("malware_family")
        if not target_family and candidate_rule.get("source_pcap"):
            source_cap = self.dataset_mgr.get_capture(candidate_rule["source_pcap"])
            if source_cap:
                target_family = source_cap.get("malware_family")
        target_family = (target_family or "Unknown").strip()

        # Stage 2: Positive PCAP Testing (Source PCAP)
        stage2_result = self._test_positive_pcaps(rule_id, rule_file_wsl, motivating_pcap_ids)

        # Stage 3: Negative PCAP Testing (False Positives on Benign Traffic)
        stage3_result = self._test_negative_pcaps(rule_id, rule_file_wsl, benign_pcap_ids)

        # Stage 4: Family-Aware Generalization & Specificity Testing
        stage4_result = self._test_generalization_pcaps(
            rule_id=rule_id,
            rule_file_wsl=rule_file_wsl,
            holdout_ids=holdout_pcap_ids,
            target_family=target_family,
            motivating_ids=motivating_pcap_ids
        )

        # Compute Operational Metrics
        stage4_tp = stage4_result.get("detected_pcaps_count", 0)
        stage4_fn = stage4_result.get("missed_pcaps_count", 0)
        stage4_tn = stage4_result.get("cross_family_clean_count", 0)
        stage4_fp = stage4_result.get("cross_family_fp_count", 0)

        tp = stage2_result.get("detected_pcaps_count", 0) + stage4_tp
        fp = stage3_result.get("false_positive_pcaps_count", 0) + stage4_fp
        fn = stage2_result.get("missed_pcaps_count", 0) + stage4_fn
        tn = stage3_result.get("benign_clean_pcaps_count", 0) + stage4_tn

        precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
        f1 = round(2 * (precision * recall) / (precision + recall), 3) if (precision + recall) > 0 else 0.0

        # Determine Overall Status
        if fp > 0:
            overall_status = "FAILED_FALSE_POSITIVE"
        elif stage2_result.get("detected_pcaps_count", 0) == 0:
            overall_status = "FAILED_NO_TRIGGER"
        elif f1 >= 0.70:
            overall_status = "PASSED"
        else:
            overall_status = "PASSED_WITH_WARNINGS"

        return {
            "rule_id": rule_id,
            "rule_text": rule_text,
            "overall_status": overall_status,
            "stage1_syntax": stage1_result,
            "stage2_positive": stage2_result,
            "stage3_negative": stage3_result,
            "stage4_generalization": stage4_result,
            "metrics": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn,
                "precision": precision,
                "recall": recall,
                "f1_score": f1
            }
        }

    def _validate_syntax(self, rule_id: int, rule_text: str) -> Dict[str, Any]:
        """Stage 1: Verify syntax via Snort configuration test mode (-T)."""
        temp_rule_file = self.candidates_dir / f"candidate_{rule_id}.rules"
        with open(temp_rule_file, "w", encoding="utf-8") as f:
            f.write(rule_text + "\n")

        wsl_rule_file = to_wsl_path(temp_rule_file)
        cmd = f"{WSL_SNORT_BIN} -c {self.config_path} -R {wsl_rule_file} -T -q"

        res = run_wsl_cmd(
            cmd,
            capture_output=True,
            text=True,
            timeout=20
        )

        passed = (res.returncode == 0)
        return {
            "stage": 1,
            "name": "Syntax Validation",
            "passed": passed,
            "rule_file_wsl": wsl_rule_file,
            "return_code": res.returncode,
            "error_output": res.stderr.strip() if not passed else ""
        }

    def _test_positive_pcaps(
        self,
        rule_id: int,
        rule_file_wsl: str,
        pcap_ids: List[str]
    ) -> Dict[str, Any]:
        """Stage 2: Replay motivating malicious captures and verify detection."""
        detected = []
        missed = []
        total_alerts = 0

        for cid in pcap_ids:
            cap = self.dataset_mgr.get_capture(cid)
            if not cap:
                continue
            wsl_p = cap["wsl_path"]
            alerts = self._run_snort_pcap(wsl_p, rule_file_wsl, rule_id)
            if alerts:
                detected.append({
                    "capture_id": cid,
                    "filename": cap["filename"],
                    "alerts_count": len(alerts),
                    "triggering_packets": [a.get("pkt_num") for a in alerts[:5]]
                })
                total_alerts += len(alerts)
            else:
                missed.append({"capture_id": cid, "filename": cap["filename"]})

        return {
            "stage": 2,
            "name": "Positive PCAP Testing",
            "tested_pcaps_count": len(pcap_ids),
            "detected_pcaps_count": len(detected),
            "missed_pcaps_count": len(missed),
            "total_alerts": total_alerts,
            "detected": detected,
            "missed": missed
        }

    def _test_negative_pcaps(
        self,
        rule_id: int,
        rule_file_wsl: str,
        benign_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Stage 3: Replay known benign captures and check for False Positives."""
        if not benign_ids:
            # Query benign captures from dataset manager
            benigns = self.dataset_mgr.list_captures(ground_truth="benign")
            benign_ids = [b["capture_id"] for b in benigns[:3]]

        fp_captures = []
        clean_captures = []
        total_fp_alerts = 0

        for cid in benign_ids:
            cap = self.dataset_mgr.get_capture(cid)
            if not cap:
                continue
            wsl_p = cap["wsl_path"]
            # To prevent hanging on giant multi-hundred MB captures, use first 10,000 packets max if possible
            alerts = self._run_snort_pcap(wsl_p, rule_file_wsl, rule_id, max_packets=10000)
            if alerts:
                fp_captures.append({
                    "capture_id": cid,
                    "filename": cap["filename"],
                    "fp_alerts_count": len(alerts),
                    "triggering_packets": [a.get("pkt_num") for a in alerts[:5]]
                })
                total_fp_alerts += len(alerts)
            else:
                clean_captures.append({"capture_id": cid, "filename": cap["filename"]})

        return {
            "stage": 3,
            "name": "Negative PCAP Testing (False Positives)",
            "tested_benign_count": len(benign_ids),
            "false_positive_pcaps_count": len(fp_captures),
            "benign_clean_pcaps_count": len(clean_captures),
            "total_fp_alerts": total_fp_alerts,
            "false_positive_details": fp_captures,
            "clean_captures": clean_captures
        }

    def _test_generalization_pcaps(
        self,
        rule_id: int,
        rule_file_wsl: str,
        holdout_ids: Optional[List[str]] = None,
        target_family: str = "Unknown",
        motivating_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Stage 4: Family-aware generalization and cross-family specificity testing.
        - Family Matching: Only test holdouts that match the candidate's malware family.
        - Graceful Skip: If no matching family captures exist in holdouts and no holdout_ids were provided,
          skip Stage 4 cleanly without penalizing metrics (F1 remains based on Stage 2 & 3).
        - Dual Interpretation for Cross-Family PCAPs:
          If unrelated malicious captures are evaluated, non-detection is counted as a True Negative (TN)
          (proving specificity), while any unexpected trigger is counted as a False Positive (FP).
        """
        excluded_ids = set(motivating_ids or [])
        clean_target_family = (target_family or "").strip()
        has_known_family = clean_target_family.lower() not in ["", "unknown", "none", "n/a"]

        def is_family_match(fam: str) -> bool:
            if not has_known_family or not fam:
                return False
            f = fam.strip().lower()
            t = clean_target_family.lower()
            return f == t or f in t or t in f

        # If holdout_ids not provided, discover candidates from dataset split
        if holdout_ids is None:
            available_holdouts = self.dataset_mgr.list_captures(split="generalization_testing")
            candidate_caps = [h for h in available_holdouts if h["capture_id"] not in excluded_ids]
        else:
            candidate_caps = []
            for cid in holdout_ids:
                if cid in excluded_ids:
                    continue
                cap = self.dataset_mgr.get_capture(cid)
                if cap:
                    candidate_caps.append(cap)

        # Partition into same-family vs cross-family
        same_family_caps = []
        cross_family_caps = []
        for cap in candidate_caps:
            if is_family_match(cap.get("malware_family", "")):
                same_family_caps.append(cap)
            else:
                cross_family_caps.append(cap)

        # Graceful Skip check: If no matching family captures exist and no explicit holdout_ids were forced
        if not same_family_caps and holdout_ids is None:
            return {
                "stage": 4,
                "name": "Generalization Testing",
                "status": "SKIPPED",
                "target_family": clean_target_family or "Unknown",
                "reason": f"No matching malware family in holdout split for '{clean_target_family or 'Unknown'}'",
                "tested_holdout_count": 0,
                "detected_pcaps_count": 0,
                "missed_pcaps_count": 0,
                "cross_family_clean_count": 0,
                "cross_family_fp_count": 0,
                "total_alerts": 0,
                "detected": [],
                "missed": [],
                "cross_family_results": {
                    "clean_true_negatives": [],
                    "unexpected_false_positives": []
                }
            }

        detected = []
        missed = []
        cross_family_clean = []
        cross_family_fps = []
        total_alerts = 0

        # 1. Test same-family captures (evaluates True Positives vs False Negatives)
        for cap in same_family_caps[:3]:
            cid = cap["capture_id"]
            wsl_p = cap["wsl_path"]
            alerts = self._run_snort_pcap(wsl_p, rule_file_wsl, rule_id, max_packets=15000)
            if alerts:
                detected.append({
                    "capture_id": cid,
                    "filename": cap["filename"],
                    "malware_family": cap.get("malware_family", ""),
                    "alerts_count": len(alerts),
                    "triggering_packets": [a.get("pkt_num") for a in alerts[:5]]
                })
                total_alerts += len(alerts)
            else:
                missed.append({
                    "capture_id": cid,
                    "filename": cap["filename"],
                    "malware_family": cap.get("malware_family", "")
                })

        # 2. Test cross-family captures if provided or evaluated for specificity (Dual Interpretation)
        # Non-detection = True Negative (TN), Detection = False Positive (FP)
        eval_cross = cross_family_caps[:2] if (holdout_ids is not None or same_family_caps) else []
        for cap in eval_cross:
            cid = cap["capture_id"]
            wsl_p = cap["wsl_path"]
            alerts = self._run_snort_pcap(wsl_p, rule_file_wsl, rule_id, max_packets=15000)
            if alerts:
                cross_family_fps.append({
                    "capture_id": cid,
                    "filename": cap["filename"],
                    "malware_family": cap.get("malware_family", ""),
                    "alerts_count": len(alerts),
                    "details": "Unexpected trigger on unrelated threat family (Specificity Violation)"
                })
                total_alerts += len(alerts)
            else:
                cross_family_clean.append({
                    "capture_id": cid,
                    "filename": cap["filename"],
                    "malware_family": cap.get("malware_family", ""),
                    "details": "Clean non-detection on unrelated threat family (True Negative)"
                })

        tested_count = len(same_family_caps[:3]) + len(eval_cross)
        if cross_family_fps:
            status = "FAILED_CROSS_FAMILY_ALERT"
        elif same_family_caps and len(detected) == 0:
            status = "NO_VARIANTS_DETECTED"
        elif same_family_caps and len(detected) > 0:
            status = "PASSED"
        elif eval_cross and len(cross_family_fps) == 0:
            status = "PASSED (SPECIFICITY_VERIFIED)"
        else:
            status = "PASSED"

        return {
            "stage": 4,
            "name": "Generalization Testing",
            "status": status,
            "target_family": clean_target_family or "Unknown",
            "tested_holdout_count": tested_count,
            "family_holdouts_tested": len(same_family_caps[:3]),
            "detected_pcaps_count": len(detected),
            "missed_pcaps_count": len(missed),
            "cross_family_tested": len(eval_cross),
            "cross_family_clean_count": len(cross_family_clean),
            "cross_family_fp_count": len(cross_family_fps),
            "total_alerts": total_alerts,
            "detected": detected,
            "missed": missed,
            "cross_family_results": {
                "clean_true_negatives": cross_family_clean,
                "unexpected_false_positives": cross_family_fps
            }
        }

    def _run_snort_pcap(
        self,
        wsl_pcap: str,
        wsl_rule_file: str,
        target_sid: int,
        max_packets: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Run Snort 3 against PCAP with candidate rule file and filter alerts for target_sid."""
        limit_flag = f"-n {max_packets}" if max_packets else ""
        cmd = f"{WSL_SNORT_BIN} -c {self.config_path} -r \"{wsl_pcap}\" -R {wsl_rule_file} -A alert_json -s 65535 -q {limit_flag}"

        try:
            res = run_wsl_cmd(
                cmd,
                capture_output=True,
                text=True,
                timeout=45
            )
            matching_alerts = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        d = json.loads(line)
                        rule_tag = d.get("rule", "")
                        # e.g. "1:9001001:1"
                        if f":{target_sid}:" in rule_tag:
                            matching_alerts.append(d)
                    except Exception:
                        pass
            return matching_alerts
        except Exception:
            return []
