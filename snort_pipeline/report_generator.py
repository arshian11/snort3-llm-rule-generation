"""
Intermediate Network Investigation Report Generator.
Populates the standardized structured JSON data contract from Snort, TShark, Zeek, and Correlator outputs.
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any

from snort_pipeline.config import REPORTS_DIR

class ReportGenerator:
    def __init__(self, reports_dir: Path = REPORTS_DIR):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        capture_meta: Dict[str, Any],
        snort_result: Dict[str, Any],
        packet_features: Dict[str, Any],
        correlation_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Assemble the standardized Network Investigation Report with full Snort, TShark, and Zeek telemetry.
        """
        capture_id = capture_meta.get("capture_id", "PCAP_001")
        ground_truth = capture_meta.get("ground_truth", "malicious")
        threat_category = capture_meta.get("threat_category", "Unknown")

        # Snort engine stats
        stats = snort_result.get("statistics", {})
        repro = snort_result.get("reproducibility", {})

        snort_block = {
            "version": repro.get("snort_version", "3.13.2.0"),
            "total_rules_loaded": 4246,  # Community ruleset baseline
            "total_alerts": stats.get("total_alerts", 0),
            "unique_signatures": stats.get("unique_signatures_count", 0),
            "pcap_hash": repro.get("pcap_hash", ""),
            "config_hash": repro.get("config_hash", "")
        }

        # Alert summary format
        alert_summary = []
        for s in snort_result.get("alert_summary", []):
            alert_summary.append({
                "gid": s.get("gid", 1),
                "sid": s.get("sid", 1000000),
                "rev": s.get("rev", 1),
                "count": s.get("count", 1),
                "priority": s.get("priority", 2),
                "protocol": s.get("protocol", "TCP"),
                "msg": s.get("msg", ""),
                "triggering_packets": s.get("triggering_packets", [])
            })

        # Network behaviour block
        dns_queries = packet_features.get("dns", {}).get("queries", [])
        http_requests = packet_features.get("http_tls", {}).get("http_requests", [])
        flows = packet_features.get("flow_metadata", {}).get("flows", [])
        periodic_conns = packet_features.get("behavioural", {}).get("periodic_connections", [])
        suspicious_flows = packet_features.get("behavioural", {}).get("suspicious_flows", [])

        # Clean TCP connections for representation
        tcp_connections = []
        for fl in flows:
            tcp_connections.append({
                "flow_id": fl.get("flow_id"),
                "proto": fl.get("proto"),
                "src_ip": fl.get("src_ip"),
                "dst_ip": fl.get("dst_ip"),
                "src_port": fl.get("src_port"),
                "dst_port": fl.get("dst_port"),
                "duration_sec": fl.get("duration", 0.0),
                "packet_count": fl.get("packet_count", 0),
                "byte_count": fl.get("byte_count", 0),
                "tcp_flags": fl.get("tcp_flags", []),
                "zeek_conn_state": fl.get("zeek_conn_state", ""),
                "zeek_service": fl.get("zeek_service", "")
            })

        # Zeek telemetry block
        zeek_data = packet_features.get("zeek", {})
        zeek_summary = {
            "total_connections": zeek_data.get("total_connections", 0),
            "connection_states": zeek_data.get("connection_states", {}),
            "detected_services": zeek_data.get("detected_services", {}),
            "files_transferred": zeek_data.get("files", [])[:20],
            "ssl_certificates": zeek_data.get("x509", [])[:15],
            "ssl_sessions": zeek_data.get("ssl", [])[:20],
            "failed_connections": zeek_data.get("behavioural", {}).get("failed_connections", [])[:20]
        }

        network_behaviour = {
            "dns_queries": dns_queries[:30],
            "http_requests": http_requests[:30],
            "tcp_connections": tcp_connections[:30],
            "periodic_connections": periodic_conns,
            "suspicious_flows": suspicious_flows,
            "zeek": zeek_summary
        }

        report = {
            "capture_id": capture_id,
            "filename": capture_meta.get("filename", ""),
            "malware_family": capture_meta.get("malware_family", ""),
            "threat_category": threat_category,
            "ground_truth": ground_truth,
            "snort": snort_block,
            "alert_summary": alert_summary,
            "network_behaviour": network_behaviour,
            "correlations": correlation_result.get("correlations", []),
            "packet_evidence": correlation_result.get("packet_evidence", []),
            "event_graph": correlation_result.get("event_graph", {}),
            "raw_graph": correlation_result.get("raw_graph", {}),
            "graph_summary": correlation_result.get("graph_summary", {}),
            "linearized_stories": correlation_result.get("linearized_stories", "")
        }

        # Save to disk
        out_file = self.reports_dir / f"{capture_id}_report.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return report
