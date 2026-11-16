"""
Command Line Interface for Snort 3 LLM Rule Engineering Pipeline.
Coordinates all modules:
- Dataset Management
- Snort Execution & Alert Extraction
- Network Feature Analysis
- Evidence Correlation
- Investigation Report Generation
- LLM Analysis (Tasks A, B, C)
- 4-Stage Validation
- Rule Lifecycle & Human Review
"""

import sys
import json
import argparse
from pathlib import Path
from typing import List

from snort_pipeline.config import REPORTS_DIR
from snort_pipeline.dataset import PcapDatasetManager
from snort_pipeline.snort_engine import SnortEngine
from snort_pipeline.packet_analyzer import PacketAnalyzer
from snort_pipeline.correlator import EvidenceCorrelator
from snort_pipeline.report_generator import ReportGenerator
from snort_pipeline.llm_engine import LLMAnalysisEngine
from snort_pipeline.validator import RuleValidator
from snort_pipeline.lifecycle import RuleLifecycleManager

def run_end_to_end_pipeline(capture_id: str, auto_approve: bool = False, analyst: str = "security-analyst"):
    print("=" * 75)
    print(f"[*] INITIATING SNORT 3 LLM RULE ENGINEERING PIPELINE FOR: {capture_id}")
    print("=" * 75)

    dataset_mgr = PcapDatasetManager()
    cap = dataset_mgr.get_capture(capture_id)
    if not cap:
        print(f"[!] Error: Capture '{capture_id}' not found in dataset manifest.")
        print("[*] Run 'python -m snort_pipeline.cli dataset discover' to register PCAPs.")
        return

    print(f"[+] Loaded Capture Metadata:")
    print(f"    - ID:             {cap['capture_id']}")
    print(f"    - Filename:       {cap['filename']}")
    print(f"    - Malware Family: {cap['malware_family']}")
    print(f"    - Threat Category:{cap['threat_category']}")
    print(f"    - Ground Truth:   {cap['ground_truth']}")

    # 1. Module 2: Snort Execution
    print("\n[*] [1/6] Executing Snort 3 Detection Engine...")
    snort_eng = SnortEngine()
    snort_res = snort_eng.run_pcap(cap["file_path"], cap["capture_id"])
    print(f"[+] Snort Complete: {snort_res['statistics']['total_alerts']} raw alerts | {snort_res['statistics']['unique_signatures_count']} unique signatures")
    for s in snort_res["alert_summary"][:5]:
        print(f"    - SID {s['sid']} (count={s['count']}, pri={s['priority']}): {s['msg']}")

    # 2. Module 3: Network Traffic Feature Extraction
    print("\n[*] [2/6] Extracting Deep Protocol & Session Features (TShark + Zeek)...")
    analyzer = PacketAnalyzer(max_packets=10000)
    pkt_features = analyzer.analyze(cap["file_path"])
    print(f"[+] Extracted Protocol & Zeek Features:")
    print(f"    - Flows:         {pkt_features['flow_metadata']['total_flows']}")
    print(f"    - DNS Queries:   {pkt_features['dns']['total_queries']}")
    print(f"    - HTTP Reqs:     {pkt_features['http_tls']['http_requests_count']}")
    print(f"    - Periodic/C2:   {len(pkt_features['behavioural']['periodic_connections'])}")
    zeek = pkt_features.get("zeek", {})
    if zeek.get("available"):
        print(f"    - Zeek Conns:    {zeek.get('total_connections')} (States: {dict(zeek.get('connection_states', {}))})")
        print(f"    - Zeek Files:    {zeek.get('total_files')} file stream(s)")
        print(f"    - Zeek SSL/X509: {zeek.get('total_ssl')} SSL session(s) | {zeek.get('total_x509')} X509 cert(s)")

    # 3. Module 4: Correlation Engine & Graph
    print("\n[*] [3/6] Running Evidence Correlation & Event Graph Construction...")
    correlator = EvidenceCorrelator()
    corr_res = correlator.correlate(cap["capture_id"], snort_res, pkt_features)
    gs = corr_res.get("graph_summary", {})
    print(f"[+] Correlation Complete: {corr_res['correlations_count']} behavioural attack correlations established.")
    print(f"[+] Graph Reduction (Stage 1): {gs.get('total_raw_nodes', 0)} raw nodes -> {gs.get('condensed_nodes', 0)} condensed nodes ({gs.get('supernodes_count', 0)} supernodes, {gs.get('pruned_nodes_count', 0)} noise nodes pruned).")
    if gs.get("top_pivots"):
        top_p = gs["top_pivots"][0]
        print(f"[+] Top Attack Pivot Identified: {top_p.get('label')} [{top_p.get('role')}] (PPR: {top_p.get('pagerank_score')})")
    for c in corr_res["correlations"]:
        print(f"    * [{c['type']}] {c['description']}")

    # 4. Intermediate Report
    print("\n[*] [4/6] Generating Standardized Network Investigation Report...")
    rep_gen = ReportGenerator()
    report = rep_gen.generate(cap, snort_res, pkt_features, corr_res)
    report_file = rep_gen.reports_dir / f"{capture_id}_report.json"
    print(f"[+] Investigation Report Saved: {report_file}")

    # 5. Module 5: LLM Analysis Engine
    print("\n[*] [5/6] Engaging LLM Rule Engineering Engine...")
    llm = LLMAnalysisEngine()

    print("    [>] Synthesizing Stage 2 Executive AI SOC Investigation Report...")
    soc_report = llm.generate_executive_soc_report(report)
    report["executive_soc_report"] = soc_report
    print(f"    [+] Executive SOC Verdict: {soc_report.get('verdict')} ({soc_report.get('severity')} SEVERITY)")
    print(f"        Patient Zero: {soc_report.get('patient_zero')} | Attacker: {soc_report.get('primary_attacker_source')}")

    print("    [>] Running Task A: Existing Signature Analysis...")
    task_a = llm.task_a_existing_signatures(report)
    print(f"    [+] Task A Complete: Analyzed coverage gaps and limitations.")

    print("    [>] Running Task B: Behavioural Pattern Discovery...")
    task_b = llm.task_b_pattern_discovery([report])
    patterns = task_b.get("reusable_patterns", [])
    print(f"    [+] Task B Complete: Identified {len(patterns)} stable protocol/behavioural pattern(s).")

    print("    [>] Running Task C: Candidate Snort 3 Rule Generation...")
    task_c = llm.task_c_generate_candidate_rules(report, task_b)
    candidate_rule = task_c.get("candidate_rule")
    if not candidate_rule or not candidate_rule.get("rule_text") or task_c.get("status") == "error":
        print(f"\n[!] Task C Rule Generation failed: {task_c.get('message', 'No candidate rule produced.')}")
        print("[!] Candidate rule registration skipped. No changes made to candidate rules.\n")
        return

    print(f"[+] Candidate Rule Proposed (SID {candidate_rule.get('rule_id')}):")
    print(f"    Rule: {candidate_rule.get('rule_text')}")
    print(f"    Objective: {candidate_rule.get('rule_objective')}")
    print(f"    Confidence: {candidate_rule.get('confidence')}")

    # Register into Lifecycle Manager
    lifecycle = RuleLifecycleManager()
    cand_record = lifecycle.register_candidate(candidate_rule, source_pcap=cap["capture_id"])

    # 6. Module 6: 4-Stage Rule Validation Pipeline
    print("\n[*] [6/6] Executing 4-Stage Rule Validation Pipeline...")
    validator = RuleValidator(dataset_manager=dataset_mgr)
    val_res = validator.validate_candidate_rule(
        candidate_rule=cand_record,
        motivating_pcap_ids=[cap["capture_id"]],
        llm_engine=llm
    )

    lifecycle.update_validation_results(cand_record["rule_id"], val_res)

    print("\n" + "=" * 75)
    print("                     RULE VALIDATION MATRIX")
    print("=" * 75)
    print(f"Candidate SID:       {val_res['rule_id']}")
    print(f"Rule Text:           {val_res.get('rule_text', '')}")
    print(f"Overall Status:      {val_res['overall_status']}")
    print(f"Stage 1 (Syntax):    {'PASSED' if val_res['stage1_syntax']['passed'] else 'FAILED: ' + val_res['stage1_syntax'].get('error_output', '')}")
    if val_res['stage1_syntax']['passed']:
        print(f"Stage 2 (Positive):  {val_res['stage2_positive']['detected_pcaps_count']}/{val_res['stage2_positive']['tested_pcaps_count']} PCAPs detected ({val_res['stage2_positive']['total_alerts']} alerts)")
        print(f"Stage 3 (Negative):  {val_res['stage3_negative']['false_positive_pcaps_count']} False Positives on Benign Traffic")
        s4 = val_res.get('stage4_generalization', {})
        if s4.get("status") == "SKIPPED":
            print(f"Stage 4 (General):   SKIPPED ({s4.get('reason', 'No matching family in holdout split')})")
        else:
            cross_clean = s4.get('cross_family_clean_count', 0)
            cross_str = f" (+{cross_clean} TN cross-family clean)" if cross_clean > 0 else ""
            print(f"Stage 4 (General):   {s4.get('detected_pcaps_count', 0)}/{s4.get('tested_holdout_count', 0)} Holdout Captures detected{cross_str}")
    else:
        print(f"Stage 2 (Positive):  SKIPPED")
        print(f"Stage 3 (Negative):  SKIPPED")
        print(f"Stage 4 (General):   SKIPPED")
    print("-" * 75)
    metrics = val_res["metrics"]
    print(f"True Positives (TP): {metrics['true_positives']} | False Positives (FP): {metrics['false_positives']}")
    print(f"False Negatives (FN):{metrics['false_negatives']} | True Negatives (TN): {metrics['true_negatives']}")
    print(f"Precision:           {metrics['precision']:.3f}")
    print(f"Recall:              {metrics['recall']:.3f}")
    print(f"F1-Score:            {metrics['f1_score']:.3f}")
    print("=" * 75)

    if auto_approve and val_res["overall_status"] in ["PASSED", "PASSED_WITH_WARNINGS"]:
        print(f"\n[*] Auto-approving candidate rule SID {cand_record['rule_id']}...")
        approved = lifecycle.review_rule(
            sid=cand_record["rule_id"],
            action="approve",
            analyst_name=analyst,
            analyst_notes="Automated promotion following successful 4-stage validation."
        )
        print(f"[+] Approved and deployed into production local.rules as version {approved.get('deployed_version')}!")
    else:
        print(f"\n[*] Rule is in status '{cand_record['status']}'.")
        print(f"[*] Human Analyst Review required:")
        print(f"    python -m snort_pipeline.cli review {cand_record['rule_id']} --action approve --notes \"Analyst approved\"")

def run_hdirc_cli(pcap_id: str, stage: int = 1):
    """Execute HDIRC on capture up to specified stage."""
    print("=" * 75)
    print(f"[*] HDIRC ENGINE: EXECUTING ITERATIVE RULE CONSTRUCTION FOR {pcap_id}")
    print("=" * 75)

    dataset_mgr = PcapDatasetManager()
    cap = dataset_mgr.get_capture(pcap_id)
    if not cap:
        print(f"[!] Capture '{pcap_id}' not found in dataset manifest.")
        return

    rep_file = REPORTS_DIR / f"{pcap_id}_report.json"
    if not rep_file.is_file():
        print(f"[*] Report not found. Running upstream extraction & correlation first...")
        snort_eng = SnortEngine()
        snort_res = snort_eng.run_pcap(cap["file_path"], cap["capture_id"])
        analyzer = PacketAnalyzer(max_packets=10000)
        pkt_features = analyzer.analyze(cap["file_path"])
        correlator = EvidenceCorrelator()
        corr_res = correlator.correlate(cap["capture_id"], snort_res, pkt_features)
        rep_gen = ReportGenerator()
        report = rep_gen.generate(cap, snort_res, pkt_features, corr_res)
    else:
        with open(rep_file, "r", encoding="utf-8") as f:
            report = json.load(f)

    from snort_pipeline.rule_construction_engine import RuleConstructionEngine
    engine = RuleConstructionEngine()

    print(f"[*] Invoking HDIRC Target Stage: {stage}")
    state = engine.execute_hdirc(report, target_stage=stage)

    print("\n" + "=" * 75)
    print("                    SHARED RULE STATE SUMMARY")
    print("=" * 75)
    print(f"Candidate ID:        {state.candidate_id}")
    print(f"Hypothesis ID:       {state.hypothesis_id}")
    print(f"Current State:       {state.status.upper()}")
    print(f"Current Stage:       Stage {state.current_stage}")

    if state.hypothesis:
        h = state.hypothesis
        print("\n" + "-" * 75)
        print("               STAGE 1: DETECTION HYPOTHESIS & VALIDATION GATE")
        print("-" * 75)
        print(f"Target Behaviour:    {h.target_behaviour}")
        print(f"Target Protocol:     {h.target_protocol}")
        print(f"Comm Direction:      {h.communication_direction} -> Flow Intent: {h.flow_intent}")
        print(f"Detection Objective: {h.detection_objective}")
        print(f"Evidence Grounding:  Packets {h.evidence.get('triggering_packets', [])}")
        print(f"Evidence Summary:    {h.evidence.get('summary', '')}")
        print("Invariant Indicators:")
        for inv in h.invariant_indicators:
            print(f"  - [{inv.get('type')}] '{inv.get('value')}' (Confidence: {inv.get('confidence')})")
        print(f"Rule Viability:      Disposition = {h.rule_viability.get('disposition')} | Needs Rule = {h.rule_viability.get('needs_snort_rule')}")
        print(f"Rationale:           {h.rule_viability.get('disposition_rationale')}")
        print(f"Validation Status:   {h.validation_status}")

    val_rec = state.component_validation.get("stage1_hypothesis")
    if val_rec:
        print(f"Validation Gate:     {'PASSED' if val_rec['passed'] else 'REJECTED'}")
        if val_rec.get("errors"):
            print(f"Errors Encountered:  {val_rec['errors']}")

    if state.ast.header and state.ast.header.render():
        hdr = state.ast.header
        print("\n" + "-" * 75)
        print("               STAGE 2: RULE HEADER & VALIDATION GATE")
        print("-" * 75)
        print(f"Header Rendered:     {hdr.render()}")
        print(f"Header Type:         {hdr.header_type}")
        print(f"Action:              {hdr.action}")
        if hdr.header_type == "traditional":
            print(f"Protocol:            {hdr.protocol}")
            print(f"Source:              {hdr.source_addr} : {hdr.source_port}")
            print(f"Direction:           {hdr.direction}")
            print(f"Destination:         {hdr.dest_addr} : {hdr.dest_port}")
        elif hdr.header_type == "service":
            print(f"Service:             {hdr.service}")
        s2_rec = state.component_validation.get("stage2_header")
        if s2_rec:
            print(f"Validation Gate:     {'PASSED' if s2_rec.get('passed') else 'REJECTED'}")
            if s2_rec.get("errors"):
                print(f"Header Errors:       {s2_rec['errors']}")

    if state.components.get("msg"):
        print("\n" + "-" * 75)
        print("               STAGE 3: RULE MESSAGE & VALIDATION GATE")
        print("-" * 75)
        print(f"Message String:      msg:\"{state.components['msg']}\";")
        s3_rec = state.component_validation.get("stage3_message")
        if s3_rec:
            print(f"Validation Gate:     {'PASSED' if s3_rec.get('passed') else 'REJECTED'}")
            if s3_rec.get("details", {}).get("duplicate_conflict"):
                print(f"Duplicate Info:      {s3_rec['details']['duplicate_conflict']}")
            if s3_rec.get("errors"):
                print(f"Message Errors:      {s3_rec['errors']}")
            if s3_rec.get("warnings"):
                print(f"Message Warnings:    {s3_rec['warnings']}")

    if "stage4_flow" in state.component_validation or state.components.get("flow") is not None:
        print("\n" + "-" * 75)
        print("               STAGE 4: FLOW GENERATION & VALIDATION GATE")
        print("-" * 75)
        flow_comp = state.components.get("flow")
        flow_repr = f"flow:{','.join(flow_comp)};" if flow_comp else "omitted / not required"
        print(f"Flow Option:         {flow_repr}")
        s4_rec = state.component_validation.get("stage4_flow")
        if s4_rec:
            print(f"Validation Gate:     {'PASSED' if s4_rec.get('passed') else 'REJECTED'}")
            if s4_rec.get("details", {}).get("categories_present"):
                print(f"Categories Present:  {s4_rec['details']['categories_present']}")
            if s4_rec.get("details", {}).get("not_required"):
                print(f"Requirement Note:    {s4_rec['details'].get('reason')}")
            if s4_rec.get("errors"):
                print(f"Flow Errors:         {s4_rec['errors']}")

    if "stage5_detection" in state.component_validation or state.components.get("detection"):
        print("\n" + "-" * 75)
        print("               STAGE 5: DETECTION GENERATION & VALIDATION GATE")
        print("-" * 75)
        det_comp = state.components.get("detection", [])
        print(f"Detection Nodes:     {len(det_comp)} condition(s) configured")
        for i, node in enumerate(det_comp, 1):
            name = node.get("name")
            val = node.get("value")
            mods = node.get("modifiers")
            mod_str = f" [modifiers: {mods}]" if mods else ""
            val_str = f'"{val}"' if val is not None else "(buffer selector)"
            print(f"  {i}. {name}: {val_str}{mod_str}")
        s5_rec = state.component_validation.get("stage5_detection")
        if s5_rec:
            print(f"Validation Gate:     {'PASSED' if s5_rec.get('passed') else 'REJECTED'}")
            if s5_rec.get("details", {}).get("buffers_selected"):
                print(f"Buffers Scoped:      {s5_rec['details']['buffers_selected']}")
            if s5_rec.get("details", {}).get("fast_pattern_found"):
                print(f"Fast Pattern:        ✓ Designated on anchor pattern")
            if s5_rec.get("errors"):
                print(f"Detection Errors:    {s5_rec['errors']}")

    if "stage6_supporting" in state.component_validation or state.components.get("sid"):
        print("\n" + "-" * 75)
        print("           STAGE 6: SUPPORTING OPTIONS & METADATA VALIDATION GATE")
        print("-" * 75)
        print(f"Classification:      {state.components.get('classification') or 'misc-attack'}")
        print(f"Signature ID (SID):  {state.components.get('sid')} (Deterministic Python Allocation)")
        print(f"Revision (REV):      {state.components.get('rev', 1)}")
        refs = state.components.get("references", [])
        print(f"Verified References: {refs if refs else 'None (Anti-Hallucination Enforced)'}")
        metas = state.components.get("metadata", [])
        if metas:
            print(f"Metadata Tags:       {metas}")
        s6_rec = state.component_validation.get("stage6_supporting")
        if s6_rec:
            print(f"Validation Gate:     {'PASSED' if s6_rec.get('passed') else 'REJECTED'}")
            if s6_rec.get("details", {}).get("service"):
                print(f"Service Scoped:      {s6_rec['details']['service']}")
            if s6_rec.get("errors"):
                print(f"Supporting Errors:   {s6_rec['errors']}")

    if "stage7_assembly" in state.component_validation or state.status in [ConstructionState.APPROVED.value, ConstructionState.RULE_ASSEMBLED.value]:
        print("\n" + "-" * 75)
        print("     STAGE 7: FINAL ASSEMBLY & DUAL-PASS PCAP VERIFICATION GATE")
        print("-" * 75)
        s7_rec = state.component_validation.get("stage7_assembly", {})
        det = s7_rec.get("details", {})
        print(f"Assembly Status:     {'PASSED & APPROVED' if s7_rec.get('passed') else 'FAILED'}")
        
        # Syntax / Compiler Check
        syn_res = det.get("syntax_validation", {})
        if syn_res:
            print(f"Snort 3 Compiler:    {'PASSED (Exit 0)' if syn_res.get('passed') else 'FAILED'}")
            if syn_res.get("warnings"):
                print(f"Compiler Warnings:   {syn_res.get('warnings')}")

        # Conflict Detection
        conf_res = det.get("conflict_detection", {})
        if conf_res:
            print(f"Conflict Checks:     {'CLEAN (No Collisions)' if not conf_res.get('has_conflict') else 'CONFLICT DETECTED'}")
            if conf_res.get("shadow_warnings"):
                print(f"Shadow Warnings:     {len(conf_res['shadow_warnings'])} potential rule overlaps")

        # Dual-Pass Verification
        tp_res = det.get("true_positive", {})
        if tp_res and tp_res.get("tested"):
            tp_status = "✓ DETECTED" if tp_res.get("passed") else "✗ MISSED"
            print(f"Pass 1 (True Pos):   {tp_status} ({tp_res.get('alerts_count')} alerts on {tp_res.get('pcap_id', 'malicious capture')})")
            if tp_res.get("triggering_packets"):
                print(f"  Triggering Pkts:   {tp_res.get('triggering_packets')}")

        fp_res = det.get("false_positive", {})
        if fp_res and fp_res.get("tested"):
            fp_status = "✓ ZERO ALERTS" if fp_res.get("passed") else "✗ FALSE POSITIVE DETECTED"
            print(f"Pass 2 (False Pos):  {fp_status} ({fp_res.get('alerts_count')} alerts on {fp_res.get('pcap_id', 'benign traffic')})")

        if s7_rec.get("errors"):
            print(f"Assembly Errors:     {s7_rec['errors']}")

    if state.rendered_rule_text:
        print("\n" + "-" * 75)
        print("                     RENDERED SNORT 3 RULE TEXT")
        print("-" * 75)
        # Check if multiline rendering is available
        try:
            print(state.render_multiline(indent=4))
        except Exception:
            print(state.rendered_rule_text)

    print("=" * 75)

def main():
    parser = argparse.ArgumentParser(description="Snort 3 LLM Rule Engineering Pipeline CLI")
    subparsers = parser.add_subparsers(dest="command", help="Pipeline subcommands")

    # Dataset commands
    ds_parser = subparsers.add_parser("dataset", help="Dataset management")
    ds_parser.add_argument("action", choices=["list", "discover", "get"], help="Action")
    ds_parser.add_argument("--id", type=str, help="Capture ID")

    # Full Pipeline command
    pipe_parser = subparsers.add_parser("run-pipeline", help="Run end-to-end pipeline on a PCAP")
    pipe_parser.add_argument("pcap_id", help="Capture ID (e.g. PCAP_001)")
    pipe_parser.add_argument("--auto-approve", action="store_true", help="Auto-approve if validation passes")
    pipe_parser.add_argument("--analyst", default="sec-analyst", help="Analyst name")

    # Individual Stage commands
    subparsers.add_parser("rules", help="List candidate and approved rules")

    val_parser = subparsers.add_parser("validate", help="Validate a candidate rule")
    val_parser.add_argument("rule_id", type=int, help="Candidate Rule SID")
    val_parser.add_argument("--pcap", type=str, help="Motivating PCAP ID")

    rev_parser = subparsers.add_parser("review", help="Human review of candidate rule")
    rev_parser.add_argument("rule_id", type=int, help="Candidate Rule SID")
    rev_parser.add_argument("--action", choices=["approve", "reject", "modify"], required=True, help="Review action")
    rev_parser.add_argument("--analyst", default="analyst", help="Analyst name")
    rev_parser.add_argument("--notes", default="Reviewed and verified", help="Analyst notes")

    roll_parser = subparsers.add_parser("rollback", help="Roll back local.rules to an earlier version")
    roll_parser.add_argument("version", type=int, help="Target ruleset version number")
    roll_parser.add_argument("--analyst", default="analyst", help="Analyst name")
    roll_parser.add_argument("--reason", default="Rollback triggered due to operational considerations", help="Rollback reason")

    hdirc_parser = subparsers.add_parser("hdirc", help="Hypothesis-Driven Iterative Rule Construction (HDIRC)")
    hdirc_parser.add_argument("pcap_id", help="Capture ID (e.g. PCAP_001)")
    hdirc_parser.add_argument("--stage", type=int, default=1, help="Target HDIRC stage (1=Hypothesis, 7=Full assembly)")

    args = parser.parse_args()

    if args.command == "dataset":
        mgr = PcapDatasetManager()
        if args.action == "discover":
            mgr.auto_discover_all()
            print(f"[+] Discovered and registered {len(mgr.captures)} captures.")
        elif args.action == "list":
            caps = mgr.list_captures()
            print(f"{'Capture ID':<12} {'Family':<28} {'Split':<20} {'Filename'}")
            print("-" * 80)
            for c in caps:
                print(f"{c['capture_id']:<12} {c['malware_family'][:26]:<28} {c['dataset_split']:<20} {c['filename'][:25]}")
        elif args.action == "get" and args.id:
            c = mgr.get_capture(args.id)
            print(json.dumps(c, indent=2))

    elif args.command == "run-pipeline":
        run_end_to_end_pipeline(args.pcap_id, auto_approve=args.auto_approve, analyst=args.analyst)

    elif args.command == "rules":
        lifecycle = RuleLifecycleManager()
        cands = lifecycle.list_candidates()
        print(f"{'SID':<10} {'Status':<18} {'Source':<12} {'Objective'}")
        print("-" * 80)
        for c in cands:
            print(f"{c['rule_id']:<10} {c['status']:<18} {c.get('source_pcap', ''):<12} {c.get('rule_objective', '')[:35]}")

    elif args.command == "review":
        lifecycle = RuleLifecycleManager()
        res = lifecycle.review_rule(
            sid=args.rule_id,
            action=args.action,
            analyst_name=args.analyst,
            analyst_notes=args.notes
        )
        print(f"[+] Rule SID {args.rule_id} updated: Status = {res['status']}")

    elif args.command == "rollback":
        lifecycle = RuleLifecycleManager()
        res = lifecycle.rollback(
            target_version=args.version,
            analyst=args.analyst,
            reason=args.reason
        )
        print(f"[+] Rollback successful: {json.dumps(res, indent=2)}")

    elif args.command == "hdirc":
        run_hdirc_cli(args.pcap_id, stage=args.stage)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
