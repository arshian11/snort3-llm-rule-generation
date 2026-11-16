"""
Module 4: Evidence Correlation & Event Graph Engine.
Performs Temporal, Entity-based, and Behavioural correlation combining Snort alerts,
TShark deep packet inspection, and Zeek stateful session logs.
Represents correlations internally as a NetworkX MultiDiGraph where every node
and edge carries explicit evidence references pointing to original packets, flows, and alerts.

Includes Stage 1 Algorithmic Graph Reduction:
- Supernode Contraction (Folds repeated flows, DNS queries, HTTP transactions, burst alerts)
- Dead-End & Background Noise Pruning (Eliminates non-malicious background components)
- Threat Cluster Partitioning (Weakly Connected Components with Threat Scoring)
- Attack Path & Pivot Extraction (Personalized PageRank seeded on alerts, Betweenness Centrality, Shortest Paths)
- Stage 2 Linearized Graph Serialization for LLM ingestion.
"""

import math
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
import networkx as nx

def format_bytes(b: int) -> str:
    """Format byte counts into human-readable strings."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b / (1024 * 1024):.1f} MB"

class EvidenceCorrelator:
    def __init__(self, time_window_sec: float = 60.0):
        self.time_window_sec = time_window_sec

    def correlate(
        self,
        capture_id: str,
        snort_result: Dict[str, Any],
        packet_features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build correlation graph and extract structured correlation stories
        across Snort alerts, TShark packet metadata, and Zeek session logs.
        Applies multi-stage graph reduction, community partitioning, pivot discovery,
        and attack path extraction.
        """
        raw_graph = nx.MultiDiGraph()

        alerts = snort_result.get("alerts", [])
        if not alerts and "alert_summary" in snort_result:
            alerts = snort_result["alert_summary"]
        if not alerts and isinstance(packet_features, dict) and "alert_summary" in packet_features:
            alerts = packet_features["alert_summary"]

        flow_meta = packet_features.get("flow_metadata", {})
        flows = flow_meta.get("flows", []) if isinstance(flow_meta, dict) else []
        if not flows and "tcp_connections" in packet_features:
            flows = packet_features["tcp_connections"]

        dns_info = packet_features.get("dns", {})
        dns_queries = dns_info.get("queries", []) if isinstance(dns_info, dict) else []
        if not dns_queries and "dns_queries" in packet_features:
            dns_queries = packet_features["dns_queries"]
        dns_resolutions = dns_info.get("resolutions", {}) if isinstance(dns_info, dict) else packet_features.get("dns_resolutions", {})

        http_info = packet_features.get("http_tls", {})
        http_reqs = http_info.get("http_requests", []) if isinstance(http_info, dict) else []
        if not http_reqs and "http_requests" in packet_features:
            http_reqs = packet_features["http_requests"]

        behav_info = packet_features.get("behavioural", {})
        periodic_conns = behav_info.get("periodic_connections", []) if isinstance(behav_info, dict) else []
        if not periodic_conns and "periodic_connections" in packet_features:
            periodic_conns = packet_features["periodic_connections"]
        suspicious_flows = behav_info.get("suspicious_flows", []) if isinstance(behav_info, dict) else packet_features.get("suspicious_flows", [])

        # Zeek telemetry
        zeek = packet_features.get("zeek", {})
        zeek_files = zeek.get("files", []) if isinstance(zeek, dict) else []
        zeek_ssl = zeek.get("ssl", []) if isinstance(zeek, dict) else []
        zeek_x509 = zeek.get("x509", []) if isinstance(zeek, dict) else []
        zeek_conns = zeek.get("connections", []) if isinstance(zeek, dict) else []
        zeek_behavioural = zeek.get("behavioural", {}) if isinstance(zeek, dict) else {}

        # Master evidence reference list
        packet_evidence_map: Dict[int, Dict[str, Any]] = {}

        # -------------------------------------------------------------
        # 1. Populate Nodes & Entities in Raw Graph
        # -------------------------------------------------------------
        # A. Alert Nodes
        for a in alerts:
            gid = a.get("gid", 1)
            sid = a.get("sid", 0)
            pkt = a.get("pkt_num") or (a.get("triggering_packets", [0])[0] if a.get("triggering_packets") else 0)
            alert_node_id = f"alert:{gid}:{sid}:{pkt}"
            src_ip = a.get("src_ip", "")
            dst_ip = a.get("dst_ip", "")
            msg = a.get("msg", f"Alert SID {sid}")
            proto = a.get("proto") or a.get("protocol", "TCP")
            prio = a.get("priority", 2)
            classtype = a.get("classification", "trojan-activity")
            ts = a.get("timestamp", 0.0)

            evidence = {
                "capture_id": capture_id,
                "packets": a.get("triggering_packets") or [pkt],
                "alert_sid": sid,
                "gid": gid,
                "msg": msg,
                "proto": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": ts
            }
            raw_graph.add_node(
                alert_node_id,
                node_type="alert",
                label=f"Alert: {msg[:30]}...",
                sid=sid,
                priority=prio,
                classification=classtype,
                evidence=evidence
            )
            packet_evidence_map[pkt] = {
                "pkt_num": pkt,
                "source": "snort_alert",
                "summary": f"SID {sid}: {msg}",
                "proto": proto,
                "src": f"{src_ip}:{a.get('src_port', '')}",
                "dst": f"{dst_ip}:{a.get('dst_port', '')}"
            }

            # Link alert to IP entities
            if src_ip:
                src_node = f"ip:{src_ip}"
                raw_graph.add_node(src_node, node_type="entity_ip", label=src_ip, ip=src_ip)
                raw_graph.add_edge(src_node, alert_node_id, relation="ORIGINATED_ALERT", evidence=evidence)
            if dst_ip:
                dst_node = f"ip:{dst_ip}"
                raw_graph.add_node(dst_node, node_type="entity_ip", label=dst_ip, ip=dst_ip)
                raw_graph.add_edge(alert_node_id, dst_node, relation="TARGETED_ALERT", evidence=evidence)

        # B. Flow Nodes
        for fl in flows:
            fid = fl.get("flow_id") or f"{fl.get('src_ip')}:{fl.get('src_port')}<->{fl.get('dst_ip')}:{fl.get('dst_port')}/{fl.get('proto', 'TCP')}"
            flow_node_id = f"flow:{fid}"
            src_ip = fl.get("src_ip", "")
            dst_ip = fl.get("dst_ip", "")
            proto = fl.get("proto", "TCP")
            port = fl.get("dst_port", 0)
            pkts = fl.get("packet_numbers") or fl.get("packets", [])
            evidence = {
                "capture_id": capture_id,
                "flow_id": fid,
                "packets": pkts[:10],
                "byte_count": fl.get("byte_count", 0),
                "packet_count": fl.get("packet_count", 0),
                "duration": fl.get("duration", fl.get("duration_sec", 0.0)),
                "start_time": fl.get("start_time", 0.0),
                "end_time": fl.get("end_time", 0.0),
                "zeek_conn_state": fl.get("zeek_conn_state", ""),
                "zeek_service": fl.get("zeek_service", "")
            }
            raw_graph.add_node(
                flow_node_id,
                node_type="flow",
                label=f"Flow: {proto} {port}" + (f" ({fl.get('zeek_conn_state')})" if fl.get('zeek_conn_state') else ""),
                proto=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port,
                evidence=evidence
            )
            if src_ip:
                src_node = f"ip:{src_ip}"
                raw_graph.add_node(src_node, node_type="entity_ip", label=src_ip, ip=src_ip)
                raw_graph.add_edge(src_node, flow_node_id, relation="INITIATED_FLOW", evidence=evidence)
            if dst_ip:
                dst_node = f"ip:{dst_ip}"
                raw_graph.add_node(dst_node, node_type="entity_ip", label=dst_ip, ip=dst_ip)
                raw_graph.add_edge(flow_node_id, dst_node, relation="DELIVERED_TO", evidence=evidence)

        # C. DNS Nodes & Resolutions
        for d in dns_queries:
            query_id = f"dns:{d['pkt_num']}"
            evidence = {
                "capture_id": capture_id,
                "packets": [d["pkt_num"]],
                "query_name": d["query_name"],
                "resolved_ip": d.get("resolved_ip"),
                "ttl": d.get("ttl"),
                "entropy": d.get("entropy", 0.0),
                "is_response": d["is_response"]
            }
            raw_graph.add_node(
                query_id,
                node_type="dns_event",
                label=f"DNS: {d['query_name'][:25]}",
                query_name=d["query_name"],
                entropy=d.get("entropy", 0.0),
                evidence=evidence
            )
            domain_node = f"domain:{d['query_name']}"
            raw_graph.add_node(domain_node, node_type="entity_domain", label=d["query_name"], entropy=d.get("entropy", 0.0))
            raw_graph.add_edge(domain_node, query_id, relation="OBSERVED_IN_QUERY", evidence=evidence)

            if d.get("resolved_ip"):
                for ip in str(d["resolved_ip"]).split(","):
                    ip_node = f"ip:{ip.strip()}"
                    raw_graph.add_node(ip_node, node_type="entity_ip", label=ip.strip(), ip=ip.strip())
                    raw_graph.add_edge(domain_node, ip_node, relation="RESOLVES_TO", evidence=evidence)

            packet_evidence_map[d["pkt_num"]] = {
                "pkt_num": d["pkt_num"],
                "source": "dns_protocol",
                "summary": f"DNS {'Response' if d['is_response'] else 'Query'}: {d['query_name']} (TTL={d.get('ttl')}, Entropy={d.get('entropy')})",
                "proto": "UDP/53",
                "src": d["src_ip"],
                "dst": d["dst_ip"]
            }

        # D. HTTP Nodes
        for h in http_reqs:
            http_id = f"http:{h['pkt_num']}"
            evidence = {
                "capture_id": capture_id,
                "packets": [h["pkt_num"]],
                "method": h["method"],
                "host": h["host"],
                "uri": h["uri"],
                "user_agent": h.get("user_agent", "")
            }
            raw_graph.add_node(
                http_id,
                node_type="http_event",
                label=f"HTTP: {h['method']} {h['uri'][:20]}",
                method=h["method"],
                host=h["host"],
                uri=h["uri"],
                evidence=evidence
            )
            if h.get("host"):
                domain_node = f"domain:{h['host']}"
                raw_graph.add_node(domain_node, node_type="entity_domain", label=h["host"])
                raw_graph.add_edge(domain_node, http_id, relation="SERVES_HTTP", evidence=evidence)

            packet_evidence_map[h["pkt_num"]] = {
                "pkt_num": h["pkt_num"],
                "source": "http_protocol",
                "summary": f"HTTP {h['method']} {h.get('host', '')}{h.get('uri', '')} (UA={h.get('user_agent', '')[:30]})",
                "proto": "TCP/HTTP",
                "src": h["src_ip"],
                "dst": f"{h['dst_ip']}:{h['dst_port']}"
            }

        # E. Zeek File Entities
        for f in zeek_files[:30]:
            fuid = f.get("fuid")
            if not fuid:
                continue
            file_node_id = f"file:{fuid}"
            evidence = {
                "capture_id": capture_id,
                "fuid": fuid,
                "filename": f.get("filename", ""),
                "mime_type": f.get("mime_type", ""),
                "total_bytes": f.get("total_bytes", 0),
                "source": f.get("source", ""),
                "orig_h": f.get("orig_h"),
                "resp_h": f.get("resp_h")
            }
            raw_graph.add_node(
                file_node_id,
                node_type="entity_file",
                label=f"File: {f.get('filename') or f.get('mime_type') or fuid}",
                filename=f.get("filename", ""),
                mime_type=f.get("mime_type", ""),
                size_bytes=f.get("total_bytes", 0),
                evidence=evidence
            )
            if f.get("resp_h"):
                server_node = f"ip:{f['resp_h']}"
                raw_graph.add_node(server_node, node_type="entity_ip", label=f["resp_h"], ip=f["resp_h"])
                raw_graph.add_edge(server_node, file_node_id, relation="DELIVERED_FILE", evidence=evidence)
            if f.get("orig_h"):
                client_node = f"ip:{f['orig_h']}"
                raw_graph.add_node(client_node, node_type="entity_ip", label=f["orig_h"], ip=f["orig_h"])
                raw_graph.add_edge(file_node_id, client_node, relation="DOWNLOADED_BY", evidence=evidence)

        # F. Zeek X509 Certificate Entities
        for cert in zeek_x509[:20]:
            fp = cert.get("fingerprint", "")
            if not fp:
                continue
            cert_node_id = f"cert:{fp[:16]}"
            evidence = {
                "capture_id": capture_id,
                "fingerprint": fp,
                "subject": cert.get("subject", ""),
                "issuer": cert.get("issuer", ""),
                "is_self_signed": cert.get("is_self_signed", False),
                "sig_alg": cert.get("sig_alg", "")
            }
            raw_graph.add_node(
                cert_node_id,
                node_type="entity_cert",
                label=f"Cert: {cert.get('subject', '')[:25] or fp[:8]}",
                subject=cert.get("subject", ""),
                issuer=cert.get("issuer", ""),
                is_self_signed=cert.get("is_self_signed", False),
                evidence=evidence
            )

        # -------------------------------------------------------------
        # 2. Correlation Reasoning Passes
        # -------------------------------------------------------------
        correlations: List[Dict[str, Any]] = []

        # A. DNS Query Followed by Outbound Connection Correlation
        for d in dns_queries:
            if d.get("resolved_ip"):
                resolved_ips = [ip.strip() for ip in str(d["resolved_ip"]).split(",")]
                for ip in resolved_ips:
                    matching_flows = [fl for fl in flows if fl.get("dst_ip") == ip or fl.get("src_ip") == ip]
                    for fl in matching_flows:
                        fl_start = fl.get("start_time", 0.0)
                        d_time = d.get("time_epoch") or d.get("timestamp", 0.0)
                        if fl_start > 1e9 and d_time > 1e9:
                            time_delta = round(fl_start - d_time, 3)
                        else:
                            time_delta = 0.5 if (fl_start == 0.0 or d_time == 0.0) else round(abs(fl_start - d_time), 3)
                        if time_delta < 0 or time_delta > 3600:
                            time_delta = 0.5
                        if 0 <= time_delta <= self.time_window_sec or fl_start == 0.0:
                            fid = fl.get("flow_id") or f"{fl.get('src_ip')}:{fl.get('src_port')}<->{fl.get('dst_ip')}:{fl.get('dst_port')}/{fl.get('proto', 'TCP')}"
                            q_pkt = d.get("pkt_num", 0)
                            fl_pkts = fl.get("packet_numbers") or fl.get("packets", [])
                            corr_item = {
                                "type": "DNS_RESOLUTION_TO_COMMUNICATION",
                                "confidence": "high",
                                "description": f"DNS resolution for '{d.get('query_name')}' resolved to {ip}, followed within {time_delta}s by {fl.get('proto', 'TCP')} traffic to port {fl.get('dst_port')}",
                                "domain": d.get("query_name"),
                                "resolved_ip": ip,
                                "target_port": fl.get("dst_port"),
                                "time_delta_sec": time_delta,
                                "evidence_packets": [q_pkt] + fl_pkts[:5],
                                "evidence_summary": f"Packet {q_pkt} queried {d.get('query_name')} -> {ip}; flow {fid} initiated immediately."
                            }
                            correlations.append(corr_item)
                            raw_graph.add_edge(
                                f"dns:{q_pkt}",
                                f"flow:{fid}",
                                relation="TRIGGERED_COMMUNICATION",
                                evidence=corr_item
                            )

        # B. Periodic C2 Beaconing Correlation
        for p in periodic_conns:
            corr_item = {
                "type": "C2_BEACONING_ACTIVITY",
                "confidence": "high",
                "description": f"Periodic outbound communication from {p.get('src_ip')} to {p.get('dst_ip')}:{p.get('dst_port')} with cadence {p.get('mean_interval_sec')}s (std_dev={p.get('std_dev')})",
                "src_ip": p.get("src_ip"),
                "dst_ip": p.get("dst_ip"),
                "dst_port": p.get("dst_port"),
                "interval_sec": p.get("mean_interval_sec"),
                "evidence_packets": p.get("packets", []),
                "evidence_summary": f"Consistent low-jitter connection intervals across packets {p.get('packets', [])} characteristic of C2 beaconing."
            }
            correlations.append(corr_item)

        # C. High DNS Entropy / Potential Tunneling Correlation
        high_entropy_dns = [d for d in dns_queries if d.get("entropy", 0.0) >= 3.8 and len(d.get("query_name", "")) >= 15]
        if high_entropy_dns:
            domains_found = list({d.get("query_name") for d in high_entropy_dns})[:5]
            packets = [d.get("pkt_num", 0) for d in high_entropy_dns][:10]
            corr_item = {
                "type": "HIGH_ENTROPY_DNS_ANOMALY",
                "confidence": "high",
                "description": f"Observed {len(high_entropy_dns)} high-entropy DNS queries (Shannon entropy >= 3.8) indicating possible DGA or DNS covert channel/exfiltration",
                "sample_domains": domains_found,
                "evidence_packets": packets,
                "evidence_summary": f"Packets {packets} queried unusually random domain structures: {', '.join(str(x) for x in domains_found[:3])}"
            }
            correlations.append(corr_item)

        # D. Exploit to C2 Sequence Correlation
        p1_alerts = [a for a in alerts if a.get("priority") == 1]
        for a in p1_alerts:
            compromised_ip = a.get("dst_ip")
            subsequent_flows = [fl for fl in flows if fl.get("src_ip") == compromised_ip and fl.get("dst_ip") != a.get("src_ip")]
            if subsequent_flows:
                fl = subsequent_flows[0]
                fid = fl.get("flow_id") or f"{fl.get('src_ip')}:{fl.get('src_port')}<->{fl.get('dst_ip')}:{fl.get('dst_port')}/{fl.get('proto', 'TCP')}"
                a_pkt = a.get("pkt_num") or (a.get("triggering_packets", [0])[0] if a.get("triggering_packets") else 0)
                fl_pkts = fl.get("packet_numbers") or fl.get("packets", [])
                corr_item = {
                    "type": "EXPLOIT_TO_SECONDARY_CALLBACK_CHAIN",
                    "confidence": "very_high",
                    "description": f"Exploit alert SID {a.get('sid')} ('{a.get('msg')}') targeting {compromised_ip} was immediately followed by outbound connection to {fl.get('dst_ip')}:{fl.get('dst_port')}",
                    "exploit_sid": a.get("sid"),
                    "compromised_host": compromised_ip,
                    "secondary_c2": f"{fl.get('dst_ip')}:{fl.get('dst_port')}",
                    "evidence_packets": [a_pkt] + fl_pkts[:5],
                    "evidence_summary": f"Exploit in packet {a_pkt} triggered secondary flow {fid} across packets {fl_pkts[:3]}."
                }
                correlations.append(corr_item)

        # E. Zeek Suspicious File Download to Outbound C2 Sequence
        suspicious_zeek_files = zeek_behavioural.get("suspicious_files", [])
        for sf in suspicious_zeek_files:
            client_ip = sf.get("orig_h")
            server_ip = sf.get("resp_h")
            if client_ip:
                post_download_flows = [
                    fl for fl in flows 
                    if fl["src_ip"] == client_ip and fl["dst_ip"] != server_ip and fl.get("start_time", 0.0) >= sf.get("ts", 0.0)
                ]
                evidence_pkts = post_download_flows[0]["packet_numbers"][:5] if post_download_flows else []
                corr_item = {
                    "type": "ZEEK_MALWARE_DROPPER_TO_C2_SEQUENCE",
                    "confidence": "very_high",
                    "description": f"Host {client_ip} downloaded suspicious file '{sf.get('filename')}' ({sf.get('mime_type')}) from {server_ip}, followed by outbound communication to {post_download_flows[0]['dst_ip'] if post_download_flows else 'external destination'}",
                    "client_ip": client_ip,
                    "file_server": server_ip,
                    "filename": sf.get("filename"),
                    "mime_type": sf.get("mime_type"),
                    "file_size": sf.get("total_bytes"),
                    "evidence_packets": evidence_pkts,
                    "evidence_summary": f"Zeek extracted file {sf.get('filename')} (FUID {sf.get('fuid')}) from {server_ip}; client subsequently connected to {len(post_download_flows)} external hosts."
                }
                correlations.append(corr_item)
                if post_download_flows:
                    raw_graph.add_edge(
                        f"file:{sf.get('fuid')}",
                        f"flow:{post_download_flows[0]['flow_id']}",
                        relation="PRECEDED_C2_FLOW",
                        evidence=corr_item
                    )

        # F. Zeek Suspicious / Self-Signed SSL Certificate
        suspicious_certs = zeek_behavioural.get("suspicious_certs", [])
        for sc in suspicious_certs:
            cert_fp = sc.get("fingerprint")
            matching_ssl = [s for s in zeek_ssl if cert_fp in s.get("cert_chain_fps", [])]
            target_hosts = list({s.get("resp_h") for s in matching_ssl if s.get("resp_h")})
            corr_item = {
                "type": "ZEEK_SUSPICIOUS_SSL_CERTIFICATE",
                "confidence": "high",
                "description": f"TLS session using suspicious/self-signed certificate with Subject '{sc.get('subject')}' across endpoints {target_hosts}",
                "fingerprint": cert_fp,
                "subject": sc.get("subject"),
                "issuer": sc.get("issuer"),
                "is_self_signed": sc.get("is_self_signed"),
                "endpoints": target_hosts,
                "evidence_packets": [],
                "evidence_summary": f"Zeek x509 log revealed anomalous certificate (Subject='{sc.get('subject')}', Issuer='{sc.get('issuer')}')."
            }
            correlations.append(corr_item)

        # G. Zeek Port Scan / Connection Rejections
        failed_conns = zeek_behavioural.get("failed_connections", [])
        if len(failed_conns) >= 5:
            scanned_ports = list({c["resp_p"] for c in failed_conns})
            src_hosts = list({c["orig_h"] for c in failed_conns})
            corr_item = {
                "type": "ZEEK_RECONNAISSANCE_PORT_SCAN",
                "confidence": "high",
                "description": f"Zeek recorded {len(failed_conns)} rejected/unanswered connection attempts (S0/REJ/RSTO) from {src_hosts[:2]} targeting ports {scanned_ports[:10]}",
                "source_hosts": src_hosts,
                "scanned_ports": scanned_ports[:10],
                "failure_count": len(failed_conns),
                "evidence_packets": [],
                "evidence_summary": f"Repeated connection failures across ports {scanned_ports[:5]} indicative of scanning activity."
            }
            correlations.append(corr_item)

        # -------------------------------------------------------------
        # 3. Stage 1: Algorithmic Graph Reduction Pipeline
        # -------------------------------------------------------------
        # A. Contract Supernodes (Repeated flows, queries, bursts)
        condensed_graph, node_mapping, supernode_stats = self._contract_supernodes(
            raw_graph=raw_graph,
            alerts=alerts,
            flows=flows,
            dns_queries=dns_queries,
            http_reqs=http_reqs
        )

        # B. Dead-End & Background Noise Pruning
        pruned_graph, pruned_stats = self._prune_dead_ends_and_noise(
            condensed_graph=condensed_graph,
            correlations=correlations
        )

        # C. Community / Subgraph Partitioning (Weakly Connected Components)
        ranked_clusters = self._partition_threat_clusters(
            graph=pruned_graph,
            correlations=correlations
        )

        # D. Attack Path & Pivot Extraction (Personalized PageRank & Shortest Paths)
        top_pivots, attack_paths = self._extract_pivots_and_attack_paths(
            graph=pruned_graph,
            clusters=ranked_clusters,
            correlations=correlations
        )

        # -------------------------------------------------------------
        # 4. Stage 2: Linearized Graph Serialization
        # -------------------------------------------------------------
        graph_summary = {
            "total_raw_nodes": raw_graph.number_of_nodes(),
            "total_raw_edges": raw_graph.number_of_edges(),
            "condensed_nodes": pruned_graph.number_of_nodes(),
            "condensed_edges": pruned_graph.number_of_edges(),
            "pruned_nodes_count": pruned_stats["pruned_nodes_count"],
            "supernodes_count": supernode_stats["total_supernodes"],
            "supernode_breakdown": supernode_stats,
            "threat_clusters_count": len(ranked_clusters),
            "clusters": ranked_clusters,
            "top_pivots": top_pivots,
            "critical_attack_paths": attack_paths
        }

        linearized_stories = self._linearize_graph_stories(
            capture_id=capture_id,
            graph_summary=graph_summary,
            correlations=correlations
        )

        # Format sorted packet evidence list
        packet_evidence_list = sorted(list(packet_evidence_map.values()), key=lambda x: x["pkt_num"])

        return {
            "capture_id": capture_id,
            "correlations_count": len(correlations),
            "correlations": correlations,
            "event_graph": self._serialize_graph(pruned_graph), # Default high-signal condensed view
            "raw_graph": self._serialize_graph(raw_graph),       # Complete unpruned raw telemetry view
            "graph_summary": graph_summary,
            "linearized_stories": linearized_stories,
            "packet_evidence": packet_evidence_list
        }

    # -----------------------------------------------------------------
    # Stage 1 Graph Reduction Helper Methods
    # -----------------------------------------------------------------
    def _contract_supernodes(
        self,
        raw_graph: nx.MultiDiGraph,
        alerts: List[Dict[str, Any]],
        flows: List[Dict[str, Any]],
        dns_queries: List[Dict[str, Any]],
        http_reqs: List[Dict[str, Any]]
    ) -> Tuple[nx.MultiDiGraph, Dict[str, str], Dict[str, Any]]:
        """
        Folds high-volume repeating nodes into semantic Supernodes:
        - Repetitive TCP/UDP flows between identical 4-tuples
        - High-frequency DNS queries for identical domain targets
        - Repetitive HTTP transactions matching identical URI endpoints
        - Alert storms matching identical signature and endpoint pairs
        """
        node_map: Dict[str, str] = {}
        condensed_nodes: Dict[str, Dict[str, Any]] = {}

        flow_groups = defaultdict(list)
        dns_groups = defaultdict(list)
        http_groups = defaultdict(list)
        alert_groups = defaultdict(list)

        for n_id, d in raw_graph.nodes(data=True):
            ntype = d.get("node_type", "")
            if ntype == "flow":
                src = d.get("src_ip", "")
                dst = d.get("dst_ip", "")
                port = d.get("dst_port", "")
                proto = d.get("proto", "TCP")
                flow_groups[(src, dst, port, proto)].append((n_id, d))
            elif ntype == "dns_event":
                qname = d.get("query_name", d.get("label", ""))
                dns_groups[qname].append((n_id, d))
            elif ntype == "http_event":
                host = d.get("host", "")
                uri = d.get("uri", "")
                http_groups[(host, uri[:30])].append((n_id, d))
            elif ntype == "alert":
                sid = d.get("sid", "")
                ev = d.get("evidence", {})
                src = ev.get("src_ip", "")
                dst = ev.get("dst_ip", "")
                alert_groups[(sid, src, dst)].append((n_id, d))

        supernode_stats = {"flows_folded": 0, "dns_folded": 0, "http_folded": 0, "alerts_folded": 0, "total_supernodes": 0}

        # Contract Flows
        for key, items in flow_groups.items():
            src, dst, port, proto = key
            if len(items) > 1:
                agg_id = f"flow_agg:{src}->{dst}:{port}:{proto}"
                total_bytes = sum(it[1].get("evidence", {}).get("byte_count", 0) for it in items)
                total_pkts = sum(it[1].get("evidence", {}).get("packet_count", 0) for it in items)
                all_pkts: List[int] = []
                states = set()
                for it in items:
                    all_pkts.extend(it[1].get("evidence", {}).get("packets", []))
                    st = it[1].get("evidence", {}).get("zeek_conn_state")
                    if st:
                        states.add(st)

                condensed_nodes[agg_id] = {
                    "id": agg_id,
                    "label": f"Flows: {proto} {port} ({len(items)}x, {format_bytes(total_bytes)})",
                    "node_type": "flow",
                    "is_supernode": True,
                    "count": len(items),
                    "details": {
                        "src_ip": src,
                        "dst_ip": dst,
                        "dst_port": port,
                        "proto": proto,
                        "total_flows": len(items),
                        "total_bytes": total_bytes,
                        "total_packets": total_pkts,
                        "packets": sorted(list(set(all_pkts)))[:20],
                        "zeek_conn_states": list(states),
                        "is_supernode": True
                    }
                }
                supernode_stats["flows_folded"] += len(items)
                supernode_stats["total_supernodes"] += 1
                for it in items:
                    node_map[it[0]] = agg_id
            else:
                n_id, d = items[0]
                node_map[n_id] = n_id
                condensed_nodes[n_id] = {
                    "id": n_id,
                    "label": d.get("label"),
                    "node_type": d.get("node_type"),
                    "is_supernode": False,
                    "details": {k: v for k, v in d.items() if k not in ["label", "node_type"]}
                }

        # Contract DNS
        for qname, items in dns_groups.items():
            if len(items) > 1:
                agg_id = f"dns_agg:{qname}"
                all_pkts = []
                for it in items:
                    all_pkts.extend(it[1].get("evidence", {}).get("packets", []))
                entropy = max([it[1].get("entropy", 0.0) for it in items] or [0.0])
                condensed_nodes[agg_id] = {
                    "id": agg_id,
                    "label": f"DNS: {qname[:22]} ({len(items)}x)",
                    "node_type": "dns_event",
                    "is_supernode": True,
                    "count": len(items),
                    "details": {
                        "query_name": qname,
                        "query_count": len(items),
                        "entropy": entropy,
                        "packets": sorted(list(set(all_pkts)))[:20],
                        "is_supernode": True
                    }
                }
                supernode_stats["dns_folded"] += len(items)
                supernode_stats["total_supernodes"] += 1
                for it in items:
                    node_map[it[0]] = agg_id
            else:
                n_id, d = items[0]
                node_map[n_id] = n_id
                condensed_nodes[n_id] = {
                    "id": n_id,
                    "label": d.get("label"),
                    "node_type": d.get("node_type"),
                    "is_supernode": False,
                    "details": {k: v for k, v in d.items() if k not in ["label", "node_type"]}
                }

        # Contract HTTP
        for key, items in http_groups.items():
            host, uri = key
            if len(items) > 1:
                agg_id = f"http_agg:{host}:{uri}"
                method = items[0][1].get("method", "GET")
                all_pkts = []
                for it in items:
                    all_pkts.extend(it[1].get("evidence", {}).get("packets", []))
                condensed_nodes[agg_id] = {
                    "id": agg_id,
                    "label": f"HTTP: {method} {uri[:18]} ({len(items)}x)",
                    "node_type": "http_event",
                    "is_supernode": True,
                    "count": len(items),
                    "details": {
                        "host": host,
                        "uri": uri,
                        "method": method,
                        "request_count": len(items),
                        "packets": sorted(list(set(all_pkts)))[:20],
                        "is_supernode": True
                    }
                }
                supernode_stats["http_folded"] += len(items)
                supernode_stats["total_supernodes"] += 1
                for it in items:
                    node_map[it[0]] = agg_id
            else:
                n_id, d = items[0]
                node_map[n_id] = n_id
                condensed_nodes[n_id] = {
                    "id": n_id,
                    "label": d.get("label"),
                    "node_type": d.get("node_type"),
                    "is_supernode": False,
                    "details": {k: v for k, v in d.items() if k not in ["label", "node_type"]}
                }

        # Contract Burst Alerts (Same SID between same endpoints)
        for key, items in alert_groups.items():
            sid, src, dst = key
            if len(items) > 1:
                first_d = items[0][1]
                ev = first_d.get("evidence", {})
                msg = ev.get("msg", first_d.get("label", ""))
                agg_id = f"alert_agg:{sid}:{src}->{dst}"
                all_pkts = []
                for it in items:
                    all_pkts.extend(it[1].get("evidence", {}).get("packets", []))
                condensed_nodes[agg_id] = {
                    "id": agg_id,
                    "label": f"Alert: SID {sid} ({len(items)}x)",
                    "node_type": "alert",
                    "is_supernode": True,
                    "count": len(items),
                    "details": {
                        "sid": sid,
                        "priority": first_d.get("priority", 1),
                        "classification": first_d.get("classification", ""),
                        "evidence": {
                            "packets": sorted(list(set(all_pkts))),
                            "msg": msg,
                            "src_ip": src,
                            "dst_ip": dst,
                            "sid": sid,
                            "count": len(items)
                        },
                        "is_supernode": True
                    }
                }
                supernode_stats["alerts_folded"] += len(items)
                supernode_stats["total_supernodes"] += 1
                for it in items:
                    node_map[it[0]] = agg_id
            else:
                n_id, d = items[0]
                node_map[n_id] = n_id
                condensed_nodes[n_id] = {
                    "id": n_id,
                    "label": d.get("label"),
                    "node_type": d.get("node_type"),
                    "is_supernode": False,
                    "details": {k: v for k, v in d.items() if k not in ["label", "node_type"]}
                }

        # Pass remaining entity nodes (IPs, domains, files, certs)
        for n_id, d in raw_graph.nodes(data=True):
            if n_id not in node_map:
                node_map[n_id] = n_id
                condensed_nodes[n_id] = {
                    "id": n_id,
                    "label": d.get("label"),
                    "node_type": d.get("node_type"),
                    "is_supernode": False,
                    "details": {k: v for k, v in d.items() if k not in ["label", "node_type"]}
                }

        # Build condensed NetworkX graph
        condensed_graph = nx.MultiDiGraph()
        for n_id, ndata in condensed_nodes.items():
            condensed_graph.add_node(
                n_id,
                label=ndata["label"],
                node_type=ndata["node_type"],
                is_supernode=ndata["is_supernode"],
                details=ndata["details"]
            )

        # Rewire directed edges and consolidate parallel relations
        edge_set = set()
        for u, v, d in raw_graph.edges(data=True):
            u_new = node_map.get(u, u)
            v_new = node_map.get(v, v)
            if u_new == v_new:
                continue
            rel = d.get("relation", "CONNECTED")
            edge_key = (u_new, v_new, rel)
            if edge_key not in edge_set:
                condensed_graph.add_edge(u_new, v_new, relation=rel, evidence=d.get("evidence", {}))
                edge_set.add(edge_key)

        return condensed_graph, node_map, supernode_stats

    def _prune_dead_ends_and_noise(
        self,
        condensed_graph: nx.MultiDiGraph,
        correlations: List[Dict[str, Any]]
    ) -> Tuple[nx.MultiDiGraph, Dict[str, Any]]:
        """
        Prunes background noise, non-anomalous isolated nodes, and components
        that possess zero security relevance.
        """
        pruned_graph = condensed_graph.copy()
        threat_seeds: Set[str] = set()

        for n, d in pruned_graph.nodes(data=True):
            if d.get("node_type") == "alert":
                threat_seeds.add(n)

        # Seed from behavioural correlations
        for c in correlations:
            pkts = set(c.get("evidence_packets", []))
            for n, d in pruned_graph.nodes(data=True):
                details = d.get("details", {})
                ev = details.get("evidence", {})
                node_pkts = set(details.get("packets", []) or ev.get("packets", []))
                if pkts & node_pkts:
                    threat_seeds.add(n)

        # Propagate threat seeds 1 hop forward and backward
        for s in list(threat_seeds):
            for nbr in pruned_graph.predecessors(s):
                threat_seeds.add(nbr)
            for nbr in pruned_graph.successors(s):
                threat_seeds.add(nbr)

        pruned_nodes_count = 0
        if threat_seeds:
            comps = list(nx.weakly_connected_components(pruned_graph))
            nodes_to_remove = []
            for comp in comps:
                if not any(n in threat_seeds for n in comp):
                    nodes_to_remove.extend(comp)
            pruned_graph.remove_nodes_from(nodes_to_remove)
            pruned_nodes_count += len(nodes_to_remove)

        return pruned_graph, {"pruned_nodes_count": pruned_nodes_count}

    def _partition_threat_clusters(
        self,
        graph: nx.MultiDiGraph,
        correlations: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Partitions the graph into Weakly Connected Components (WCC) representing
        distinct attack campaigns or threat clusters, and calculates threat severity scores.
        """
        clusters: List[Dict[str, Any]] = []
        if graph.number_of_nodes() == 0:
            return clusters

        comp_list = list(nx.weakly_connected_components(graph))
        for idx, comp in enumerate(comp_list):
            alerts_in_comp = [n for n in comp if graph.nodes[n].get("node_type") == "alert"]
            flows_in_comp = [n for n in comp if graph.nodes[n].get("node_type") == "flow"]
            ips_in_comp = [n for n in comp if graph.nodes[n].get("node_type") == "entity_ip"]

            # Calculate threat score
            score = 0
            for a in alerts_in_comp:
                prio = graph.nodes[a].get("details", {}).get("priority", 2)
                score += 15 if prio == 1 else (8 if prio == 2 else 3)
            score += len(flows_in_comp) * 2

            cluster_id = f"cluster_{idx}"
            for n in comp:
                graph.nodes[n]["cluster_id"] = cluster_id

            clusters.append({
                "cluster_id": cluster_id,
                "threat_score": score,
                "alerts_count": len(alerts_in_comp),
                "flows_count": len(flows_in_comp),
                "hosts_count": len(ips_in_comp),
                "nodes_count": len(comp),
                "nodes": list(comp),
                "title": f"Threat Cluster {idx + 1}"
            })

        # Rank clusters descending by threat score
        clusters.sort(key=lambda x: x["threat_score"], reverse=True)
        if clusters:
            clusters[0]["title"] = "Primary Attack Incident"
            for i in range(1, len(clusters)):
                clusters[i]["title"] = f"Secondary Activity {i}"

        return clusters

    def _extract_pivots_and_attack_paths(
        self,
        graph: nx.MultiDiGraph,
        clusters: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Computes Personalized PageRank (PPR) seeded on Snort alerts and Betweenness Centrality
        to identify critical pivot entities (Patient Zero, Ingress Sources, C2 Destinations)
        and extracts directed shortest attack paths across the kill chain.
        """
        top_pivots: List[Dict[str, Any]] = []
        attack_paths: List[Dict[str, Any]] = []

        if graph.number_of_nodes() == 0:
            return top_pivots, attack_paths

        # A. Personalized PageRank
        pers = {}
        for n, d in graph.nodes(data=True):
            if d.get("node_type") == "alert":
                pers[n] = 10.0
            elif d.get("is_supernode"):
                pers[n] = 3.0
            else:
                pers[n] = 1.0

        try:
            ppr = nx.pagerank(graph, alpha=0.85, personalization=pers)
        except Exception:
            ppr = {n: 1.0 / graph.number_of_nodes() for n in graph.nodes()}

        # B. Betweenness Centrality
        try:
            bc = nx.betweenness_centrality(graph)
        except Exception:
            bc = {n: 0.0 for n in graph.nodes()}

        for n in graph.nodes():
            graph.nodes[n]["ppr_score"] = round(ppr.get(n, 0.0), 4)
            graph.nodes[n]["betweenness_score"] = round(bc.get(n, 0.0), 4)

        # C. Extract Top Pivots (Focus on IP and Domain entities)
        entity_nodes = [
            n for n in graph.nodes()
            if graph.nodes[n].get("node_type") in ("entity_ip", "entity_domain")
        ]
        sorted_entities = sorted(entity_nodes, key=lambda x: ppr.get(x, 0.0), reverse=True)

        for node_id in sorted_entities[:6]:
            d = graph.nodes[node_id]
            in_edges = list(graph.in_edges(node_id, data=True))
            out_edges = list(graph.out_edges(node_id, data=True))
            
            # Determine role in incident
            has_alert_in = any(e[2].get("relation") == "TARGETED_ALERT" for e in in_edges)
            has_alert_out = any(e[2].get("relation") == "ORIGINATED_ALERT" for e in out_edges)
            has_c2_flow = any("flow" in e[1] for e in out_edges)

            role = "Target Host"
            if has_alert_in and has_c2_flow:
                role = "Compromised Host (Patient Zero)"
            elif has_alert_out:
                role = "Attacker Ingress Source"
            elif has_c2_flow or "domain:" in node_id:
                role = "Command & Control / Exfiltration Endpoint"

            top_pivots.append({
                "node_id": node_id,
                "label": d.get("label", node_id),
                "type": d.get("node_type"),
                "role": role,
                "pagerank_score": round(ppr.get(node_id, 0.0), 4),
                "betweenness_score": round(bc.get(node_id, 0.0), 4)
            })

        # D. Directed Shortest Attack Path Extraction
        # Find paths connecting: Alert Ingress -> Compromised Host -> External Egress Flow/IP
        alert_nodes = [n for n in graph.nodes() if graph.nodes[n].get("node_type") == "alert"]
        ip_nodes = [n for n in graph.nodes() if graph.nodes[n].get("node_type") == "entity_ip"]

        path_count = 0
        for a_node in alert_nodes[:4]:
            for ip in ip_nodes[:8]:
                if a_node != ip and nx.has_path(graph, a_node, ip):
                    try:
                        p = nx.shortest_path(graph, a_node, ip)
                        if len(p) >= 3:
                            # Mark edges in attack path for UI glowing visualization
                            for i in range(len(p) - 1):
                                u, v = p[i], p[i+1]
                                for k, d in graph.get_edge_data(u, v, {}).items():
                                    d["is_attack_path"] = True

                            chain_labels = [graph.nodes[x].get("label", x) for x in p]
                            attack_paths.append({
                                "source": p[0],
                                "target": p[-1],
                                "hops_count": len(p) - 1,
                                "path_chain": " ──> ".join(chain_labels),
                                "nodes": p
                            })
                            path_count += 1
                            if path_count >= 5:
                                break
                    except Exception:
                        continue
            if path_count >= 5:
                break

        return top_pivots, attack_paths

    def _linearize_graph_stories(
        self,
        capture_id: str,
        graph_summary: Dict[str, Any],
        correlations: List[Dict[str, Any]]
    ) -> str:
        """
        Stage 2 Linearized Graph Serialization.
        Translates complex graph topologies and causality paths into structured,
        highly informative text for direct LLM ingestion.
        """
        lines = [
            f"=== CORRELATION GRAPH TOPOLOGY & CAUSAL ATTACK CHAINS ({capture_id}) ===",
            f"Graph Scale: {graph_summary['total_raw_nodes']} raw nodes condensed into {graph_summary['condensed_nodes']} high-signal nodes.",
            f"Reduction: Pruned {graph_summary['pruned_nodes_count']} background nodes; folded {graph_summary['supernodes_count']} repetitive flow/DNS supernodes.",
            ""
        ]

        # Pivots
        lines.append("TOP INCIDENT PIVOTS (PageRank & Betweenness Centrality):")
        for p in graph_summary.get("top_pivots", [])[:4]:
            lines.append(f"  • {p['label']} [{p['role']}] - PPR: {p['pagerank_score']}, Centrality: {p['betweenness_score']}")
        lines.append("")

        # Threat Clusters
        for idx, cl in enumerate(graph_summary.get("clusters", []), 1):
            lines.append(f"[{cl['title']} | Threat Score: {cl['threat_score']} | Alerts: {cl['alerts_count']} | Nodes: {cl['nodes_count']}]")

        # Attack Paths
        lines.append("\nCRITICAL ATTACK PATHS:")
        paths = graph_summary.get("critical_attack_paths", [])
        if paths:
            for idx, ap in enumerate(paths, 1):
                lines.append(f"  [{idx}] {ap['path_chain']}")
        else:
            lines.append("  • Single-stage or point-to-point alert communication.")

        # High-confidence correlations
        lines.append("\nBEHAVIOURAL CORRELATION HIGHLIGHTS:")
        for c in correlations[:6]:
            lines.append(f"  - [{c.get('type')}] {c.get('description')}")

        return "\n".join(lines)

    def _serialize_graph(self, graph: nx.MultiDiGraph) -> Dict[str, Any]:
        """Serialize a NetworkX MultiDiGraph into JSON-compliant format."""
        return {
            "nodes": [
                {
                    "id": n,
                    "label": graph.nodes[n].get("label", n),
                    "type": graph.nodes[n].get("node_type", "entity"),
                    "is_supernode": graph.nodes[n].get("is_supernode", False),
                    "cluster_id": graph.nodes[n].get("cluster_id", "cluster_0"),
                    "ppr_score": graph.nodes[n].get("ppr_score", 0.0),
                    "betweenness_score": graph.nodes[n].get("betweenness_score", 0.0),
                    "details": graph.nodes[n].get("details", {k: v for k, v in graph.nodes[n].items() if k not in ["label", "node_type"]})
                }
                for n in graph.nodes()
            ],
            "links": [
                {
                    "source": u,
                    "target": v,
                    "relation": d.get("relation", "CONNECTED"),
                    "is_attack_path": d.get("is_attack_path", False),
                    "evidence": d.get("evidence", {})
                }
                for u, v, d in graph.edges(data=True)
            ]
        }
