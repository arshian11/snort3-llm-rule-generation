"""
Module 3: Network Traffic Feature Extraction Engine.
Extracts protocol-level and session features via TShark, Zeek, and Scapy:
1. Flow metadata (TShark + Zeek conn states & services)
2. DNS features & Shannon entropy (TShark + Zeek dns.log)
3. HTTP & TLS features (TShark + Zeek http.log, ssl.log, x509.log)
4. Behavioural indicators (periodicity, beaconing, failure bursts, abnormal volume, Zeek conn states)
5. Deep Zeek extraction: conn.log, dns.log, http.log, ssl.log, x509.log, files.log
"""

import os
import re
import math
import json
import uuid
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter

from snort_pipeline.config import to_wsl_path, run_wsl_cmd

def calculate_shannon_entropy(data_str: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data_str:
        return 0.0
    freq = Counter(data_str)
    length = len(data_str)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 3)

class PacketAnalyzer:
    def __init__(self, max_packets: int = 50000):
        self.max_packets = max_packets

    def _extract_zeek_logs(self, wsl_pcap_path: str) -> Dict[str, Any]:
        """
        Execute Zeek in WSL with JSON output (LogAscii::use_json=T),
        parsing conn.log, dns.log, http.log, ssl.log, x509.log, files.log.
        """
        run_id = uuid.uuid4().hex[:8]
        temp_dir = f"/tmp/zeek_{run_id}"
        cmd = f"mkdir -p {temp_dir} && cd {temp_dir} && zeek -r '{wsl_pcap_path}' LogAscii::use_json=T"
        
        try:
            res = run_wsl_cmd(cmd, capture_output=True, text=True, timeout=120)
        except Exception as e:
            return {
                "available": False,
                "error": str(e),
                "total_connections": 0,
                "connections": [],
                "total_dns": 0,
                "dns": [],
                "total_http": 0,
                "http": [],
                "total_ssl": 0,
                "ssl": [],
                "total_x509": 0,
                "x509": [],
                "total_files": 0,
                "files": [],
                "connection_states": {},
                "detected_services": {},
                "behavioural": {
                    "failed_connections_count": 0,
                    "failed_connections": [],
                    "suspicious_certs": [],
                    "suspicious_files": []
                }
            }

        raw_logs: Dict[str, List[Dict[str, Any]]] = {}
        for log_name in ["conn", "dns", "http", "ssl", "x509", "files"]:
            cat_cmd = f"cat {temp_dir}/{log_name}.log 2>/dev/null"
            cat_res = run_wsl_cmd(cat_cmd, capture_output=True, text=True)
            lines = []
            if cat_res.stdout.strip():
                for line in cat_res.stdout.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            lines.append(json.loads(line))
                        except Exception:
                            pass
            raw_logs[log_name] = lines

        # Clean up temporary directory in WSL
        run_wsl_cmd(f"rm -rf {temp_dir}")

        # Parse & normalize conn.log
        connections = []
        conn_states = Counter()
        services = Counter()
        for r in raw_logs.get("conn", []):
            state = r.get("conn_state", "UNKNOWN")
            service = r.get("service") or "other"
            conn_states[state] += 1
            services[service] += 1
            connections.append({
                "uid": r.get("uid"),
                "ts": r.get("ts"),
                "orig_h": r.get("id.orig_h"),
                "orig_p": r.get("id.orig_p"),
                "resp_h": r.get("id.resp_h"),
                "resp_p": r.get("id.resp_p"),
                "proto": str(r.get("proto", "")).upper(),
                "service": service,
                "duration": round(float(r.get("duration") or 0.0), 3),
                "orig_bytes": int(r.get("orig_bytes") or 0),
                "resp_bytes": int(r.get("resp_bytes") or 0),
                "conn_state": state,
                "history": r.get("history", ""),
                "orig_pkts": int(r.get("orig_pkts") or 0),
                "resp_pkts": int(r.get("resp_pkts") or 0)
            })

        # Parse & normalize dns.log
        dns_records = []
        for r in raw_logs.get("dns", []):
            dns_records.append({
                "uid": r.get("uid"),
                "ts": r.get("ts"),
                "orig_h": r.get("id.orig_h"),
                "resp_h": r.get("id.resp_h"),
                "query": r.get("query"),
                "qtype": r.get("qtype_name", "A"),
                "rcode": r.get("rcode_name", "NOERROR"),
                "answers": r.get("answers", []) or [],
                "ttls": r.get("TTLs", []) or [],
                "rejected": bool(r.get("rejected", False))
            })

        # Parse & normalize http.log
        http_records = []
        for r in raw_logs.get("http", []):
            http_records.append({
                "uid": r.get("uid"),
                "ts": r.get("ts"),
                "orig_h": r.get("id.orig_h"),
                "orig_p": r.get("id.orig_p"),
                "resp_h": r.get("id.resp_h"),
                "resp_p": r.get("id.resp_p"),
                "trans_depth": r.get("trans_depth", 1),
                "method": r.get("method", "GET"),
                "host": r.get("host", ""),
                "uri": r.get("uri", ""),
                "user_agent": r.get("user_agent", ""),
                "status_code": r.get("status_code"),
                "status_msg": r.get("status_msg", ""),
                "resp_filenames": r.get("resp_filenames", []) or [],
                "resp_mime_types": r.get("resp_mime_types", []) or []
            })

        # Parse & normalize ssl.log
        ssl_records = []
        for r in raw_logs.get("ssl", []):
            ssl_records.append({
                "uid": r.get("uid"),
                "ts": r.get("ts"),
                "orig_h": r.get("id.orig_h"),
                "orig_p": r.get("id.orig_p"),
                "resp_h": r.get("id.resp_h"),
                "resp_p": r.get("id.resp_p"),
                "version": r.get("version", ""),
                "cipher": r.get("cipher", ""),
                "server_name": r.get("server_name", ""),
                "established": bool(r.get("established", False)),
                "cert_chain_fps": r.get("cert_chain_fps", []) or [],
                "sni_matches_cert": r.get("sni_matches_cert")
            })

        # Parse & normalize x509.log
        x509_records = []
        for r in raw_logs.get("x509", []):
            subj = r.get("certificate.subject", "")
            issuer = r.get("certificate.issuer", "")
            x509_records.append({
                "fingerprint": r.get("fingerprint", ""),
                "subject": subj,
                "issuer": issuer,
                "is_self_signed": (subj == issuer) if (subj and issuer) else False,
                "key_alg": r.get("certificate.key_alg", ""),
                "sig_alg": r.get("certificate.sig_alg", ""),
                "key_length": r.get("certificate.key_length"),
                "ca": bool(r.get("basic_constraints.ca", False))
            })

        # Parse & normalize files.log
        file_records = []
        for r in raw_logs.get("files", []):
            file_records.append({
                "fuid": r.get("fuid"),
                "uid": r.get("uid"),
                "orig_h": r.get("id.orig_h"),
                "resp_h": r.get("id.resp_h"),
                "source": r.get("source", ""),
                "mime_type": r.get("mime_type", ""),
                "filename": r.get("filename", ""),
                "total_bytes": int(r.get("total_bytes") or r.get("seen_bytes") or 0)
            })

        # Behavioral indicators from Zeek
        failed_conns = [c for c in connections if c["conn_state"] in ["S0", "REJ", "RSTO", "RSTR"]]
        suspicious_certs = [
            x for x in x509_records 
            if x["is_self_signed"] or any(k in (x["subject"] or "") for k in ["Widgits", "Default", "Example", "localhost"])
        ]
        suspicious_files = [
            f for f in file_records 
            if any(m in (f["mime_type"] or "").lower() for m in ["dosexec", "executable", "msword", "officedocument", "zip", "pdf", "vbs", "powershell"])
        ]

        return {
            "available": True,
            "total_connections": len(connections),
            "connections": connections,
            "total_dns": len(dns_records),
            "dns": dns_records,
            "total_http": len(http_records),
            "http": http_records,
            "total_ssl": len(ssl_records),
            "ssl": ssl_records,
            "total_x509": len(x509_records),
            "x509": x509_records,
            "total_files": len(file_records),
            "files": file_records,
            "connection_states": dict(conn_states),
            "detected_services": dict(services),
            "behavioural": {
                "failed_connections_count": len(failed_conns),
                "failed_connections": failed_conns[:25],
                "suspicious_certs": suspicious_certs,
                "suspicious_files": suspicious_files
            }
        }

    def analyze(self, pcap_path: str | Path) -> Dict[str, Any]:
        """
        Run deep protocol extraction using TShark and Zeek in WSL.
        Produces structured records across all protocol and behavioural categories.
        """
        wsl_p = to_wsl_path(pcap_path)

        # Fields to extract via TShark
        fields = [
            "-e frame.number",
            "-e frame.time_epoch",
            "-e frame.len",
            "-e ip.src",
            "-e ip.dst",
            "-e _ws.col.Protocol",
            "-e tcp.srcport",
            "-e tcp.dstport",
            "-e tcp.flags",
            "-e udp.srcport",
            "-e udp.dstport",
            "-e dns.qry.name",
            "-e dns.qry.type",
            "-e dns.flags.response",
            "-e dns.resp.ttl",
            "-e dns.a",
            "-e dns.flags.rcode",
            "-e http.request.method",
            "-e http.host",
            "-e http.request.uri",
            "-e http.user_agent",
            "-e http.response.code",
            "-e tls.handshake.extensions_server_name"
        ]

        fields_cmd = " ".join(fields)
        cmd = f'tshark -r "{wsl_p}" -T fields -E separator=/t {fields_cmd} -c {self.max_packets}'

        res = run_wsl_cmd(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        lines = res.stdout.splitlines()

        # Storage
        flows: Dict[str, Dict[str, Any]] = {}
        dns_queries: List[Dict[str, Any]] = []
        dns_resolutions: Dict[str, List[str]] = defaultdict(list)
        http_requests: List[Dict[str, Any]] = []
        tls_handshakes: List[Dict[str, Any]] = []
        all_packets: List[Dict[str, Any]] = []

        for line in lines:
            parts = line.split("\t")
            if len(parts) < 6:
                continue

            def get_f(idx: int) -> str:
                return parts[idx].strip() if idx < len(parts) else ""

            pkt_num_str = get_f(0)
            if not pkt_num_str:
                continue
            pkt_num = int(pkt_num_str)
            time_epoch = float(get_f(1)) if get_f(1) else 0.0
            pkt_len = int(get_f(2)) if get_f(2) else 0
            src_ip = get_f(3)
            dst_ip = get_f(4)
            proto_col = get_f(5).upper()

            tcp_sport = get_f(6)
            tcp_dport = get_f(7)
            tcp_flags = get_f(8)
            udp_sport = get_f(9)
            udp_dport = get_f(10)

            dns_name = get_f(11)
            dns_type = get_f(12)
            dns_is_resp = get_f(13)
            dns_ttl = get_f(14)
            dns_a = get_f(15)
            dns_rcode = get_f(16)

            http_method = get_f(17)
            http_host = get_f(18)
            http_uri = get_f(19)
            http_ua = get_f(20)
            http_code = get_f(21)

            tls_sni = get_f(22)

            # Determine L4 protocol & ports
            proto = "OTHER"
            sport = 0
            dport = 0
            if tcp_sport or tcp_dport:
                proto = "TCP"
                sport = int(tcp_sport) if tcp_sport else 0
                dport = int(tcp_dport) if tcp_dport else 0
            elif udp_sport or udp_dport:
                proto = "UDP"
                sport = int(udp_sport) if udp_sport else 0
                dport = int(udp_dport) if udp_dport else 0
            elif "ICMP" in proto_col:
                proto = "ICMP"

            pkt_record = {
                "pkt_num": pkt_num,
                "time_epoch": time_epoch,
                "len": pkt_len,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": proto,
                "sport": sport,
                "dport": dport
            }
            all_packets.append(pkt_record)

            # 1. Flow Aggregation (Canonical bidirectional key)
            if src_ip and dst_ip:
                if (src_ip, sport) <= (dst_ip, dport):
                    flow_id = f"{src_ip}:{sport}<->{dst_ip}:{dport}/{proto}"
                    fwd = True
                else:
                    flow_id = f"{dst_ip}:{dport}<->{src_ip}:{sport}/{proto}"
                    fwd = False

                if flow_id not in flows:
                    flows[flow_id] = {
                        "flow_id": flow_id,
                        "src_ip": src_ip if fwd else dst_ip,
                        "dst_ip": dst_ip if fwd else src_ip,
                        "src_port": sport if fwd else dport,
                        "dst_port": dport if fwd else sport,
                        "proto": proto,
                        "packet_count": 0,
                        "fwd_packets": 0,
                        "rev_packets": 0,
                        "byte_count": 0,
                        "fwd_bytes": 0,
                        "rev_bytes": 0,
                        "start_time": time_epoch,
                        "end_time": time_epoch,
                        "packet_numbers": [],
                        "inter_arrival_times": [],
                        "tcp_flags": set(),
                        "state": "OBSERVED"
                    }

                fl = flows[flow_id]
                fl["packet_count"] += 1
                fl["byte_count"] += pkt_len
                fl["end_time"] = time_epoch
                if len(fl["packet_numbers"]) < 50:
                    fl["packet_numbers"].append(pkt_num)

                if fwd:
                    fl["fwd_packets"] += 1
                    fl["fwd_bytes"] += pkt_len
                else:
                    fl["rev_packets"] += 1
                    fl["rev_bytes"] += pkt_len

                if tcp_flags:
                    fl["tcp_flags"].add(tcp_flags)

            # 2. DNS Parsing
            if dns_name:
                is_response = dns_is_resp == "1"
                entropy = calculate_shannon_entropy(dns_name)
                dns_rec = {
                    "pkt_num": pkt_num,
                    "time_epoch": time_epoch,
                    "query_name": dns_name,
                    "query_type": dns_type,
                    "is_response": is_response,
                    "ttl": int(dns_ttl) if dns_ttl and dns_ttl.isdigit() else None,
                    "resolved_ip": dns_a if dns_a else None,
                    "rcode": dns_rcode,
                    "entropy": entropy,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip
                }
                dns_queries.append(dns_rec)
                if is_response and dns_a:
                    for ip_addr in dns_a.split(","):
                        ip_clean = ip_addr.strip()
                        if ip_clean and ip_clean not in dns_resolutions[dns_name]:
                            dns_resolutions[dns_name].append(ip_clean)

            # 3. HTTP Parsing
            if http_method or http_uri or http_host:
                http_requests.append({
                    "pkt_num": pkt_num,
                    "time_epoch": time_epoch,
                    "method": http_method or "GET",
                    "host": http_host,
                    "uri": http_uri,
                    "user_agent": http_ua,
                    "status_code": http_code,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dport
                })

            # 4. TLS Parsing
            if tls_sni:
                tls_handshakes.append({
                    "pkt_num": pkt_num,
                    "time_epoch": time_epoch,
                    "sni": tls_sni,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dport
                })

        # Calculate Flow Durations and Inter-Arrivals
        flow_list = []
        periodic_connections = []
        suspicious_flows = []

        for fl in flows.values():
            fl["duration"] = round(max(0.0, fl["end_time"] - fl["start_time"]), 3)
            fl["tcp_flags"] = sorted(list(fl["tcp_flags"]))

            # Check Beaconing / Periodicity
            pkts = fl["packet_numbers"]
            if len(pkts) >= 4 and fl["duration"] > 1.0:
                fl_times = [p["time_epoch"] for p in all_packets if p["pkt_num"] in pkts]
                if len(fl_times) >= 3:
                    deltas = [fl_times[i] - fl_times[i - 1] for i in range(1, len(fl_times))]
                    mean_delta = sum(deltas) / len(deltas)
                    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    std_dev = math.sqrt(variance)
                    if mean_delta > 0.5 and (std_dev / (mean_delta + 1e-5)) < 0.35:
                        beacon_item = {
                            "flow_id": fl["flow_id"],
                            "src_ip": fl["src_ip"],
                            "dst_ip": fl["dst_ip"],
                            "dst_port": fl["dst_port"],
                            "mean_interval_sec": round(mean_delta, 2),
                            "std_dev": round(std_dev, 2),
                            "packet_count": fl["packet_count"],
                            "packets": pkts[:10],
                            "type": "C2_Beaconing_Candidate"
                        }
                        periodic_connections.append(beacon_item)

            # Suspicious Flows: non-standard high ports or asymmetric data transfer
            is_suspicious = False
            reasons = []
            if fl["dst_port"] not in [80, 443, 53, 22, 123] and fl["dst_port"] > 1024:
                is_suspicious = True
                reasons.append(f"Unusual destination port {fl['dst_port']}")
            if fl["fwd_bytes"] > 5000 and fl["rev_bytes"] < 500:
                is_suspicious = True
                reasons.append("High outbound data transfer / Potential exfiltration")

            if is_suspicious:
                suspicious_flows.append({
                    "flow_id": fl["flow_id"],
                    "src_ip": fl["src_ip"],
                    "dst_ip": fl["dst_ip"],
                    "dst_port": fl["dst_port"],
                    "proto": fl["proto"],
                    "reasons": reasons,
                    "packets": fl["packet_numbers"][:5]
                })

            flow_list.append(fl)

        # Sort flows by packet count
        flow_list.sort(key=lambda x: x["packet_count"], reverse=True)

        # -------------------------------------------------------------
        # 5. Execute Zeek Extraction & Cross-Correlation
        # -------------------------------------------------------------
        zeek_data = self._extract_zeek_logs(wsl_p)

        # Cross-correlate TShark flows with Zeek stateful connection records
        zeek_lookup: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}
        for zc in zeek_data.get("connections", []):
            try:
                orig_p = int(zc.get("orig_p") or 0)
                resp_p = int(zc.get("resp_p") or 0)
                k1 = (str(zc.get("orig_h")), orig_p, str(zc.get("resp_h")), resp_p, str(zc.get("proto")).upper())
                k2 = (str(zc.get("resp_h")), resp_p, str(zc.get("orig_h")), orig_p, str(zc.get("proto")).upper())
                zeek_lookup[k1] = zc
                zeek_lookup[k2] = zc
            except Exception:
                continue

        for fl in flow_list:
            match = zeek_lookup.get((fl["src_ip"], fl["src_port"], fl["dst_ip"], fl["dst_port"], fl["proto"]))
            if match:
                fl["zeek_conn_state"] = match.get("conn_state")
                fl["zeek_service"] = match.get("service")
                fl["zeek_uid"] = match.get("uid")

        return {
            "total_packets_parsed": len(all_packets),
            "flow_metadata": {
                "total_flows": len(flow_list),
                "flows": flow_list[:100]  # top 100 flows
            },
            "dns": {
                "total_queries": len(dns_queries),
                "queries": dns_queries[:50],
                "resolutions": dict(dns_resolutions)
            },
            "http_tls": {
                "http_requests_count": len(http_requests),
                "http_requests": http_requests[:50],
                "tls_handshakes_count": len(tls_handshakes),
                "tls_handshakes": tls_handshakes[:50]
            },
            "behavioural": {
                "periodic_connections": periodic_connections,
                "suspicious_flows": suspicious_flows,
                "zeek_failed_connections": zeek_data.get("behavioural", {}).get("failed_connections", []),
                "zeek_suspicious_certs": zeek_data.get("behavioural", {}).get("suspicious_certs", []),
                "zeek_suspicious_files": zeek_data.get("behavioural", {}).get("suspicious_files", [])
            },
            "zeek": zeek_data
        }
