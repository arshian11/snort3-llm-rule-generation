"""
Module 2: Snort 3 Execution and Alert Extraction Engine.
Runs Snort 3 in WSL with JSON alerts, collects reproducibility hashes and execution stats,
and stores raw JSON alerts without lossy reduction.
"""

import os
import re
import json
import time
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from snort_pipeline.config import (
    WSL_SNORT_BIN,
    WSL_SNORT_CONFIG,
    WSL_COMMUNITY_RULES,
    WSL_SID_MSG_MAP,
    RAW_ALERTS_DIR,
    LOCAL_RULES_PATH,
    to_wsl_path,
    resolve_local_path,
    compute_file_hash,
    run_wsl_cmd,
)

class SnortEngine:
    def __init__(
        self,
        config_path: str = WSL_SNORT_CONFIG,
        community_rules_path: str = WSL_COMMUNITY_RULES,
        custom_rules_path: Optional[str | Path] = None,
        sid_msg_map_path: str = WSL_SID_MSG_MAP,
    ):
        self.config_path = config_path
        self.community_rules_path = community_rules_path
        self.custom_rules_path = str(custom_rules_path) if custom_rules_path else str(LOCAL_RULES_PATH)
        self.sid_msg_map_path = sid_msg_map_path
        self.sid_map: Dict[int, Dict[str, Any]] = {}
        self.snort_version: str = ""
        self._initialize_metadata()

    def _initialize_metadata(self):
        """Fetch Snort version and parse SID map for alert enrichment."""
        # Snort Version
        try:
            res = run_wsl_cmd(
                f"{WSL_SNORT_BIN} -V",
                capture_output=True,
                text=True,
                timeout=10
            )
            m = re.search(r"Version\s+([\d\.]+)", res.stdout)
            self.snort_version = m.group(1) if m else "3.13.2.0"
        except Exception:
            self.snort_version = "3.13.2.0"

        # Load SID -> Msg map
        self._load_sid_maps()

    def _load_sid_maps(self):
        """Load SID-msg map and parse community rules for rich metadata."""
        # 1. Load from sid-msg.map
        try:
            res = run_wsl_cmd(f"cat {self.sid_msg_map_path} 2>/dev/null", capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = [p.strip() for p in line.split("||")]
                    if len(parts) >= 2:
                        try:
                            sid = int(parts[0])
                            msg = parts[1]
                            self.sid_map[sid] = {"msg": msg, "classification": "unknown", "priority": 3}
                        except ValueError:
                            pass
        except Exception:
            pass

        # 2. Parse custom local.rules for local SIDs
        custom_local = resolve_local_path(self.custom_rules_path)
        if custom_local.is_file():
            try:
                with open(custom_local, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        sid_m = re.search(r"sid:(\d+);", line)
                        msg_m = re.search(r'msg:"([^"]+)";', line)
                        pri_m = re.search(r"priority:(\d+);", line)
                        clas_m = re.search(r"classtype:([^;]+);", line)
                        if sid_m:
                            sid = int(sid_m.group(1))
                            msg = msg_m.group(1) if msg_m else f"Custom Rule {sid}"
                            pri = int(pri_m.group(1)) if pri_m else 2
                            clas = clas_m.group(1).strip() if clas_m else "custom-detection"
                            self.sid_map[sid] = {"msg": msg, "classification": clas, "priority": pri}
            except Exception:
                pass

    def run_pcap(
        self,
        pcap_path: str | Path,
        capture_id: str,
        extra_rules_path: Optional[str | Path] = None,
        use_community_rules: bool = True,
        max_packets: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute Snort 3 against PCAP with JSON alert output.
        Collects raw alerts, system hashes, and execution stats for full reproducibility.
        """
        wsl_pcap = to_wsl_path(pcap_path)
        pcap_hash = compute_file_hash(pcap_path)

        # Build rule arguments
        rules_args = []
        ruleset_hashes: Dict[str, str] = {}

        if use_community_rules:
            rules_args.append(f"-R {self.community_rules_path}")
            # Compute hash of community rules in WSL
            try:
                cmd = f"sha256sum {self.community_rules_path} 2>/dev/null"
                res = run_wsl_cmd(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0 and res.stdout:
                    ruleset_hashes["community_rules"] = res.stdout.split()[0]
            except Exception:
                pass

        # Add custom rules if available
        custom_local = resolve_local_path(self.custom_rules_path)
        extra_local = resolve_local_path(extra_rules_path) if extra_rules_path else None
        if extra_local and extra_local.is_file():
            wsl_extra = to_wsl_path(extra_rules_path)
            rules_args.append(f"-R {wsl_extra}")
            ruleset_hashes["extra_rules"] = compute_file_hash(extra_rules_path)
        elif custom_local.is_file() and custom_local.stat().st_size > 0:
            wsl_custom = to_wsl_path(self.custom_rules_path)
            rules_args.append(f"-R {wsl_custom}")
            ruleset_hashes["local_rules"] = compute_file_hash(self.custom_rules_path)

        # Compute config hash
        config_hash = ""
        try:
            cmd = f"sha256sum {self.config_path} 2>/dev/null"
            res = run_wsl_cmd(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout:
                config_hash = res.stdout.split()[0]
        except Exception:
            pass

        rules_flags = " ".join(rules_args)
        limit_flag = f" -n {max_packets}" if max_packets and max_packets > 0 else ""
        # Snort 3 command
        cmd_str = f"{WSL_SNORT_BIN} -c {self.config_path} -r \"{wsl_pcap}\" {rules_flags}{limit_flag} -A alert_json -s 65535 -q"

        start_time = time.time()
        res = run_wsl_cmd(
            cmd_str,
            capture_output=True,
            text=True,
            timeout=90
        )
        elapsed_sec = round(time.time() - start_time, 3)

        raw_lines = [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("{")]

        # Persist raw alerts to data/raw_alerts/<capture_id>_snort_raw.json
        raw_output_path = RAW_ALERTS_DIR / f"{capture_id}_snort_raw.json"
        raw_output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(raw_output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(raw_lines))

        # Parse & enrich alerts
        parsed_alerts = []
        unique_sigs = set()

        for idx, line in enumerate(raw_lines, 1):
            try:
                data = json.loads(line)
                rule_str = data.get("rule", "1:1000000:1")
                # Parse GID:SID:REV
                parts = rule_str.split(":")
                gid = int(parts[0]) if len(parts) > 0 else 1
                sid = int(parts[1]) if len(parts) > 1 else 1000000
                rev = int(parts[2]) if len(parts) > 2 else 1

                sig_meta = self.sid_map.get(sid, {})
                msg = sig_meta.get("msg") or data.get("msg") or f"Snort Rule {gid}:{sid}"
                classtype = sig_meta.get("classification") or data.get("class") or "attempted-admin"
                priority = sig_meta.get("priority", 2)

                # Parse src/dst IP and port
                src_ap = data.get("src_ap", "0.0.0.0:0")
                dst_ap = data.get("dst_ap", "0.0.0.0:0")

                src_ip, src_port = self._parse_ip_port(src_ap)
                dst_ip, dst_port = self._parse_ip_port(dst_ap)

                alert_record = {
                    "alert_id": idx,
                    "capture_id": capture_id,
                    "timestamp": data.get("timestamp", ""),
                    "gid": gid,
                    "sid": sid,
                    "rev": rev,
                    "priority": priority,
                    "classification": classtype,
                    "msg": msg,
                    "proto": data.get("proto", "TCP").upper(),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "pkt_num": data.get("pkt_num", 0),
                    "pkt_len": data.get("pkt_len", 0),
                    "dir": data.get("dir", "C2S"),
                    "action": data.get("action", "allow"),
                    "raw_json": data
                }
                parsed_alerts.append(alert_record)
                unique_sigs.add(f"{gid}:{sid}")
            except Exception as e:
                continue

        # Aggregated alert summary
        alert_summary = self._summarize_alerts(parsed_alerts)

        result = {
            "capture_id": capture_id,
            "reproducibility": {
                "snort_version": self.snort_version,
                "pcap_hash": pcap_hash,
                "config_hash": config_hash,
                "ruleset_hashes": ruleset_hashes,
                "execution_time_sec": elapsed_sec,
                "stderr": res.stderr.strip() if res.stderr else ""
            },
            "statistics": {
                "total_alerts": len(parsed_alerts),
                "unique_signatures_count": len(unique_sigs),
                "unique_signatures": sorted(list(unique_sigs)),
                "raw_alerts_stored_at": str(raw_output_path)
            },
            "alert_summary": alert_summary,
            "alerts": parsed_alerts
        }

        return result

    def _parse_ip_port(self, ap_str: str) -> Tuple[str, int]:
        """Split '1.2.3.4:80' or '[::1]:80' into ip and int port."""
        if ":" in ap_str:
            ip, port_str = ap_str.rsplit(":", 1)
            try:
                return ip.strip("[]"), int(port_str)
            except ValueError:
                return ip.strip("[]"), 0
        return ap_str, 0

    def _summarize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Produce alert summary grouped by (gid, sid)."""
        counts: Dict[str, Dict[str, Any]] = {}
        for a in alerts:
            key = f"{a['gid']}:{a['sid']}"
            if key not in counts:
                counts[key] = {
                    "gid": a["gid"],
                    "sid": a["sid"],
                    "rev": a["rev"],
                    "count": 0,
                    "priority": a["priority"],
                    "classification": a["classification"],
                    "protocol": a["proto"],
                    "msg": a["msg"],
                    "triggering_packets": []
                }
            counts[key]["count"] += 1
            if len(counts[key]["triggering_packets"]) < 10:
                counts[key]["triggering_packets"].append(a["pkt_num"])

        return sorted(list(counts.values()), key=lambda x: x["count"], reverse=True)
