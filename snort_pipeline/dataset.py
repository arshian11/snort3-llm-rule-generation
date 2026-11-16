"""
Module 1: PCAP Ingestion & Dataset Management.
Maintains metadata registry for known malicious, benign, and generalization captures.
"""

import os
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

from snort_pipeline.config import (
    BASE_DIR,
    DATA_DIR,
    MANIFEST_PATH,
    PCAP_DATASET_DIR,
    MALWARE_PCAP_DIR,
    BENIGN_PCAP_DIR,
    DEMO_PCAP_DIR,
    to_wsl_path,
    compute_file_hash,
    run_wsl_cmd,
)

class PcapDatasetManager:
    def __init__(self, manifest_file: Path = MANIFEST_PATH):
        self.manifest_file = Path(manifest_file)
        self.captures: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self):
        """Load manifest from disk if exists."""
        if self.manifest_file.is_file():
            try:
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    self.captures = json.load(f)
            except Exception as e:
                print(f"[!] Warning: Failed to load manifest: {e}")
                self.captures = {}
        else:
            self.captures = {}

    def save(self):
        """Persist manifest to disk."""
        self.manifest_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(self.captures, f, indent=2)

    def generate_capture_id(self, prefix: str = "PCAP") -> str:
        """Generate next sequential capture ID."""
        nums = []
        for cid in self.captures.keys():
            m = re.search(r"(\d+)$", cid)
            if m:
                nums.append(int(m.group(1)))
        next_num = max(nums, default=0) + 1
        return f"{prefix}_{next_num:03d}"

    def register_pcap(
        self,
        file_path: str | Path,
        malware_family: str = "Unknown",
        threat_category: str = "Unknown",
        ground_truth: str = "malicious",
        dataset_split: str = "training",
        capture_id: Optional[str] = None,
        associated_iocs: Optional[List[str]] = None,
        notes: str = "",
        quick_stats: bool = True
    ) -> Dict[str, Any]:
        """Register a single PCAP into the dataset repository."""
        p = Path(file_path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"PCAP file not found: {p}")

        # Check if already registered by path or SHA256
        sha256 = compute_file_hash(p)
        for existing_id, meta in self.captures.items():
            if meta.get("sha256") == sha256 or Path(meta.get("file_path", "")).resolve() == p:
                return meta

        if not capture_id:
            if ground_truth.lower() == "benign":
                capture_id = self.generate_capture_id("BENIGN")
            elif dataset_split == "generalization_testing":
                capture_id = self.generate_capture_id("HOLDOUT")
            else:
                capture_id = self.generate_capture_id("PCAP")

        size_bytes = p.stat().st_size
        packet_count = 0
        duration_sec = 0.0

        if quick_stats:
            packet_count, duration_sec = self._extract_basic_stats(p)

        meta = {
            "capture_id": capture_id,
            "filename": p.name,
            "file_path": str(p),
            "wsl_path": to_wsl_path(p),
            "malware_family": malware_family,
            "threat_category": threat_category,
            "ground_truth": ground_truth.lower(),
            "dataset_split": dataset_split,  # training, benign_validation, generalization_testing
            "sha256": sha256,
            "file_size_bytes": size_bytes,
            "packet_count": packet_count,
            "duration_sec": duration_sec,
            "associated_iocs": associated_iocs or [],
            "notes": notes
        }

        self.captures[capture_id] = meta
        self.save()
        return meta

    def _extract_basic_stats(self, pcap_path: Path) -> tuple[int, float]:
        """Extract packet count and capture duration via tshark/capinfos in WSL."""
        wsl_p = to_wsl_path(pcap_path)
        # Try capinfos in WSL/Linux for instant stats
        try:
            res = run_wsl_cmd(f'capinfos -c -d "{wsl_p}" 2>/dev/null', capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                packets = 0
                duration = 0.0
                for line in res.stdout.splitlines():
                    if "Number of packets:" in line:
                        m = re.search(r"(\d[\d,]*)", line.split(":", 1)[1])
                        if m:
                            packets = int(m.group(1).replace(",", ""))
                    elif "Capture duration:" in line:
                        m = re.search(r"([\d\.]+)\s+seconds", line)
                        if m:
                            duration = float(m.group(1))
                if packets > 0:
                    return packets, duration
        except Exception:
            pass

        return 0, 0.0

    def auto_discover_all(self):
        """Auto-discover and ingest PCAPs from PCAP_dataset and demo folders."""
        info_notes = self._parse_info_file()
        iocs_map = self._parse_iocs_folder()

        # 1. Discover Demo PCAPs
        if DEMO_PCAP_DIR.is_dir():
            for f in DEMO_PCAP_DIR.glob("*.pcap"):
                family = "Synthetic Attack"
                cat = "Exploit / Scan / Anomaly"
                if "log4j" in f.name.lower():
                    family = "Log4j RCE & Cobalt Strike C2"
                    cat = "Web Exploit & C2"
                elif "sqli" in f.name.lower():
                    family = "SQL Injection"
                    cat = "Web Exploit"
                elif "ssh" in f.name.lower():
                    family = "SSH Recon"
                    cat = "Reconnaissance / Port Scan"
                elif "anomalies" in f.name.lower():
                    family = "ICMP / DNS Anomalies"
                    cat = "Protocol Anomaly"

                self.register_pcap(
                    file_path=f,
                    malware_family=family,
                    threat_category=cat,
                    ground_truth="malicious",
                    dataset_split="training",
                    notes="Synthetic multi-vector attack capture"
                )

        # 2. Discover Malware PCAPs
        if MALWARE_PCAP_DIR.is_dir():
            # Sort PCAPs to give deterministic IDs
            pcap_files = sorted(list(MALWARE_PCAP_DIR.glob("*.pcap")) + list(MALWARE_PCAP_DIR.glob("*.pcapng")))
            for idx, f in enumerate(pcap_files):
                fname = f.name
                # Determine family & category
                family = "Unknown Malware"
                category = "Trojan / C2"
                fname_lower = fname.lower()

                if "cobalt" in fname_lower:
                    family = "Cobalt Strike"
                    category = "C2 Communication"
                if "qakbot" in fname_lower:
                    family = "Qakbot Banking Trojan"
                    category = "Trojan / C2 / Loader"
                elif "sliver" in fname_lower:
                    family = "Sliver C2"
                    category = "Command and Control"
                elif "hancitor" in fname_lower:
                    family = "Hancitor Loader (IcedID / ZLoader)"
                    category = "Malware Loader / Spambot"
                elif "angler" in fname_lower:
                    family = "Angler Exploit Kit"
                    category = "Drive-By Exploit Kit"
                elif "redline" in fname_lower or "rigek" in fname_lower:
                    family = "Redline Stealer / RigEK"
                    category = "InfoStealer / Credential Harvesting"
                elif "lumma" in fname_lower:
                    family = "Lumma Stealer"
                    category = "InfoStealer"
                elif "amos" in fname_lower:
                    family = "AMOS Stealer"
                    category = "InfoStealer / macOS Trojan"
                elif "smartape" in fname_lower:
                    family = "SmartApeSG RAT"
                    category = "Remote Access Trojan"
                elif "dns2tcp" in fname_lower or "ozymandns" in fname_lower or "det_a" in fname_lower:
                    family = "DNS Tunneling"
                    category = "Data Exfiltration & Covert Channel"
                elif "capture-win" in fname_lower or "capture_win" in fname_lower:
                    family = "CTU-13 Botnet"
                    category = "Botnet Traffic"

                # Check if this should be training or holdout (generalization)
                # Keep diverse captures for holdout validation
                split = "training"
                if idx % 3 == 2 or "smartape" in fname_lower or "lumma" in fname_lower or "ozymandns_txt_down" in fname_lower:
                    split = "generalization_testing"

                iocs = iocs_map.get(fname, [])
                notes = info_notes.get(fname, "")

                self.register_pcap(
                    file_path=f,
                    malware_family=family,
                    threat_category=category,
                    ground_truth="malicious",
                    dataset_split=split,
                    associated_iocs=iocs,
                    notes=notes
                )

        # 3. Discover Benign PCAPs
        if BENIGN_PCAP_DIR.is_dir():
            for f in sorted(list(BENIGN_PCAP_DIR.glob("*.pcap")) + list(BENIGN_PCAP_DIR.glob("*.pcapng"))):
                self.register_pcap(
                    file_path=f,
                    malware_family="Benign Normal Traffic",
                    threat_category="Normal User / Streaming",
                    ground_truth="benign",
                    dataset_split="benign_validation",
                    notes="Baseline benign network traffic for false positive testing",
                    quick_stats=False  # Avoid slow full scan on giant multi-hundred MB files
                )

        self.save()

    def _parse_info_file(self) -> Dict[str, str]:
        """Parse .info.txt in malware dataset."""
        info_file = MALWARE_PCAP_DIR / ".info.txt"
        notes_map = {}
        if not info_file.is_file():
            return notes_map
        try:
            content = info_file.read_text(encoding="utf-8", errors="ignore")
            current_category = ""
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.endswith(":"):
                    current_category = line[:-1]
                elif "[" in line:
                    # e.g. 2023-07-12-Gozi-infection-with-Cobalt-Strike [https://...]
                    parts = line.split("[", 1)
                    name_key = parts[0].strip()
                    url = parts[1].rstrip("]")
                    notes_map[name_key] = f"Category: {current_category} | Source: {url}"
        except Exception:
            pass
        return notes_map

    def _parse_iocs_folder(self) -> Dict[str, List[str]]:
        """Parse IOC text files into map of related capture -> IOC indicators."""
        iocs_dir = MALWARE_PCAP_DIR / "IOCs"
        iocs_map: Dict[str, List[str]] = {}
        if not iocs_dir.is_dir():
            return iocs_map
        for txt_file in iocs_dir.glob("*.txt"):
            try:
                text = txt_file.read_text(encoding="utf-8", errors="ignore")
                # Extract IPs, domains, hashes
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
                domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
                hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)

                # Filter out obvious false matches like version numbers
                clean_ips = [ip for ip in set(ips) if not ip.startswith("0.") and not ip.startswith("127.")]
                clean_domains = [d for d in set(domains) if not d.endswith(".exe") and not d.endswith(".zip") and not d.endswith(".txt") and not d.endswith(".pcap")][:10]

                indicators = clean_ips[:10] + clean_domains[:10]

                # Associate with matching PCAP base name
                base_name = txt_file.name.replace("-IOCs", "").replace("-IOC", "").replace(".txt", "")
                iocs_map[base_name] = indicators
                for pcap_file in MALWARE_PCAP_DIR.glob("*.pcap*"):
                    if base_name[:12] in pcap_file.name:
                        iocs_map[pcap_file.name] = indicators
            except Exception:
                pass
        return iocs_map

    def list_captures(self, split: Optional[str] = None, ground_truth: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return list of registered captures, optionally filtered."""
        results = []
        for c in self.captures.values():
            if split and c.get("dataset_split") != split:
                continue
            if ground_truth and c.get("ground_truth") != ground_truth:
                continue
            results.append(c)
        return results

    def get_capture(self, capture_id: str) -> Optional[Dict[str, Any]]:
        """Get capture metadata by capture_id or filename."""
        if capture_id in self.captures:
            return self.captures[capture_id]
        for c in self.captures.values():
            if c.get("filename") == capture_id or c.get("capture_id") == capture_id:
                return c
        return None
