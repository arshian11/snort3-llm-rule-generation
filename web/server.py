#!/usr/bin/env python3
"""
Snort 3 Live Web Application Server
Provides real-time packet/alert analytics, correlation, and ground truth classification.
Matches the architectural elegance and SOC styling of Archer.
"""

import os
import re
import sys
import json
import time
import queue
import shutil
import random
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
import uuid
from typing import Dict, List, Any, Optional, Tuple

from flask import Flask, render_template, request, jsonify, Response, session

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static")
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or f"snort3_secret_{int(time.time())}_{os.urandom(8).hex()}"
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.jinja_env.auto_reload = True

# Register Snort 3 LLM Rule Engineering & Investigation Pipeline Blueprint
repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_dir not in sys.path:
    sys.path.insert(0, repo_dir)

try:
    try:
        from web.pipeline_routes import pipeline_bp
    except ImportError:
        from pipeline_routes import pipeline_bp
    app.register_blueprint(pipeline_bp)
    print("[+] Registered Snort 3 LLM Pipeline REST API at /api/pipeline/*")
except Exception as e:
    print(f"[!] Warning: Could not register pipeline blueprint: {e}")

# ── In-Memory Alert Store & Correlation Engine ─────────────────────────────────

class SnortStore:
    def __init__(self, max_alerts: int = 100000):
        self.lock = threading.RLock()
        self.max_alerts = max_alerts
        self.alerts: List[Dict[str, Any]] = []
        self.alert_id_counter = 1
        self.total_alerts_count = 0

        # Aggregation indexes
        self.unique_signatures: Dict[str, Dict[str, Any]] = {}
        self.priority_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.protocol_counts = Counter()
        self.ground_truth_counts = Counter({"Malicious": 0, "Benign": 0, "Suspicious": 0})

        # Connection 5-tuple correlation map
        # key -> flow dict
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.flow_id_counter = 1

        # SSE subscription queues
        self.subscribers: List[queue.Queue] = []

        # Tailing thread status
        self.tailing_file: Optional[str] = None
        self.tailing_thread: Optional[threading.Thread] = None
        self.stop_tailing = threading.Event()

    def clear(self):
        with self.lock:
            self.alerts.clear()
            self.unique_signatures.clear()
            self.priority_counts.clear()
            self.src_ip_counts.clear()
            self.dst_ip_counts.clear()
            self.protocol_counts.clear()
            self.ground_truth_counts = Counter({"Malicious": 0, "Benign": 0, "Suspicious": 0})
            self.flows.clear()
            self.alert_id_counter = 1
            self.flow_id_counter = 1
            self.total_alerts_count = 0
        self.broadcast({"type": "clear", "data": {}})

    def add_alert(self, alert: Dict[str, Any], broadcast: bool = True) -> Dict[str, Any]:
        with self.lock:
            alert["id"] = self.alert_id_counter
            self.alert_id_counter += 1
            self.total_alerts_count += 1

            if not alert.get("timestamp"):
                alert["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            # Canonical Signature Key
            gid = alert.get("gid", 1)
            sid = alert.get("sid", 1000000)
            rev = alert.get("rev", 1)
            sig_key = f"{gid}:{sid}"
            alert["sig_key"] = sig_key

            # Canonical 5-Tuple Connection Key
            src = alert.get("src_ip", "0.0.0.0")
            sport = alert.get("src_port") or 0
            dst = alert.get("dst_ip", "0.0.0.0")
            dport = alert.get("dst_port") or 0
            proto = alert.get("proto", "TCP").upper()
            conn_key = f"{src}:{sport}->{dst}:{dport}/{proto}"
            alert["conn_key"] = conn_key

            # Correlation Flow Tracking
            flow = self.flows.get(conn_key)
            if not flow:
                flow = {
                    "flow_id": self.flow_id_counter,
                    "conn_key": conn_key,
                    "src_ip": src,
                    "src_port": sport,
                    "dst_ip": dst,
                    "dst_port": dport,
                    "proto": proto,
                    "first_seen": alert["timestamp"],
                    "last_seen": alert["timestamp"],
                    "alert_count": 0,
                    "unique_sids": set(),
                    "signatures": [],
                    "max_priority": alert.get("priority", 3),
                    "ground_truth": alert.get("ground_truth", "Suspicious"),
                    "alerts": []
                }
                self.flow_id_counter += 1
                self.flows[conn_key] = flow

            flow["alert_count"] += 1
            flow["last_seen"] = alert["timestamp"]
            flow["unique_sids"].add(sig_key)
            if alert.get("msg") and alert["msg"] not in flow["signatures"]:
                flow["signatures"].append(alert["msg"])
            flow["max_priority"] = min(flow["max_priority"], alert.get("priority", 3))
            flow["alerts"].append(alert["id"])

            # If flow has multiple alerts and contains malicious alerts, elevate
            if alert.get("ground_truth") == "Malicious":
                flow["ground_truth"] = "Malicious"

            alert["flow_id"] = flow["flow_id"]
            alert["correlated_alerts_count"] = flow["alert_count"]

            # Update unique signatures
            if sig_key not in self.unique_signatures:
                self.unique_signatures[sig_key] = {
                    "sig_key": sig_key,
                    "gid": gid,
                    "sid": sid,
                    "rev": rev,
                    "msg": alert.get("msg", "Unknown Rule"),
                    "classification": alert.get("classification", "Generic"),
                    "priority": alert.get("priority", 3),
                    "count": 0,
                    "first_seen": alert["timestamp"],
                    "last_seen": alert["timestamp"],
                    "ground_truth": alert.get("ground_truth", "Suspicious")
                }
            self.unique_signatures[sig_key]["count"] += 1
            self.unique_signatures[sig_key]["last_seen"] = alert["timestamp"]

            # Update stats
            prio = alert.get("priority", 3)
            self.priority_counts[prio] += 1
            self.src_ip_counts[src] += 1
            self.dst_ip_counts[dst] += 1
            self.protocol_counts[proto] += 1
            gt = alert.get("ground_truth", "Suspicious")
            self.ground_truth_counts[gt] += 1

            self.alerts.append(alert)
            if len(self.alerts) > self.max_alerts:
                self.alerts.pop(0)

        if broadcast:
            self.broadcast({
                "type": "alert",
                "alert": alert,
                "stats": self.get_summary_stats()
            })

        return alert

    def get_summary_stats(self) -> Dict[str, Any]:
        with self.lock:
            # Consistent total evaluated count
            malicious_count = self.ground_truth_counts.get("Malicious", 0)
            benign_count = self.ground_truth_counts.get("Benign", 0)
            suspicious_count = self.ground_truth_counts.get("Suspicious", 0)
            total_evaluated = malicious_count + benign_count + suspicious_count

            total_alerts = max(len(self.alerts), self.total_alerts_count, total_evaluated)
            total_sigs = len(self.unique_signatures)
            total_flows = len(self.flows)
            correlated_flows = sum(1 for f in self.flows.values() if f["alert_count"] > 1)

            # Priorities
            p1_count = self.priority_counts.get(1, 0)
            p2_count = self.priority_counts.get(2, 0)
            p3_count = self.priority_counts.get(3, 0)
            p_other = sum(v for k, v in self.priority_counts.items() if k not in (1, 2, 3))

            # Protocols
            tcp_count = self.protocol_counts.get("TCP", 0)
            udp_count = self.protocol_counts.get("UDP", 0)
            icmp_count = self.protocol_counts.get("ICMP", 0)
            proto_other = sum(v for k, v in self.protocol_counts.items() if k not in ("TCP", "UDP", "ICMP"))

            # Base denominator for percentages
            denom = max(total_alerts, 1)

            # Top sources (top 5)
            top_sources = [
                {"ip": ip, "count": c, "pct": round(c / denom * 100, 1)}
                for ip, c in self.src_ip_counts.most_common(5)
            ]

            # Top destinations (top 5)
            top_destinations = [
                {"ip": ip, "count": c, "pct": round(c / denom * 100, 1)}
                for ip, c in self.dst_ip_counts.most_common(5)
            ]

            # Ground truth percentages
            gt_denom = max(total_evaluated, 1)
            malicious_pct = round(malicious_count / gt_denom * 100, 1)
            benign_pct = round(benign_count / gt_denom * 100, 1)
            suspicious_pct = round(suspicious_count / gt_denom * 100, 1)

            return {
                "total_alerts": total_alerts,
                "unique_signatures_count": total_sigs,
                "total_flows": total_flows,
                "correlated_flows_count": correlated_flows,
                "priority_distribution": {
                    "p1": p1_count,
                    "p2": p2_count,
                    "p3": p3_count,
                    "other": p_other,
                    "p1_pct": round(p1_count / denom * 100, 1),
                    "p2_pct": round(p2_count / denom * 100, 1),
                    "p3_pct": round(p3_count / denom * 100, 1),
                },
                "protocol_distribution": {
                    "tcp": tcp_count,
                    "udp": udp_count,
                    "icmp": icmp_count,
                    "other": proto_other,
                    "tcp_pct": round(tcp_count / denom * 100, 1),
                    "udp_pct": round(udp_count / denom * 100, 1),
                    "icmp_pct": round(icmp_count / denom * 100, 1),
                },
                "top_sources": top_sources,
                "top_destinations": top_destinations,
                "ground_truth": {
                    "malicious": malicious_count,
                    "benign": benign_count,
                    "suspicious": suspicious_count,
                    "total_evaluated": total_evaluated,
                    "malicious_pct": malicious_pct,
                    "benign_pct": benign_pct,
                    "suspicious_pct": suspicious_pct,
                },
                "tailing_file": self.tailing_file
            }

    def get_correlations(self, only_correlated: bool = True) -> List[Dict[str, Any]]:
        with self.lock:
            # Sort flows by alert_count descending, then last_seen
            res = []
            for flow in self.flows.values():
                if only_correlated and flow["alert_count"] <= 1:
                    continue
                flow_copy = dict(flow)
                flow_copy["unique_sids"] = list(flow["unique_sids"])
                flow_copy["is_correlated"] = flow["alert_count"] > 1
                res.append(flow_copy)
            res.sort(key=lambda x: (x["alert_count"], x["last_seen"]), reverse=True)
            return res

    def get_signatures_list(self) -> List[Dict[str, Any]]:
        with self.lock:
            sigs = list(self.unique_signatures.values())
            sigs.sort(key=lambda x: x["count"], reverse=True)
            return sigs

    def subscribe(self) -> queue.Queue:
        q = queue.Queue(maxsize=100)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def broadcast(self, message: Dict[str, Any]):
        data_str = json.dumps(message)
        dead = []
        with self.lock:
            for q in self.subscribers:
                try:
                    q.put_nowait(data_str)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                if q in self.subscribers:
                    self.subscribers.remove(q)

# Global store instance
store = SnortStore()

# ── Snort Parser & Ground Truth Engine ────────────────────────────────────────

def classify_ground_truth(msg: str, classification: str, priority: int) -> str:
    """
    Evaluates signature metadata and maps it to Ground Truth:
    'Malicious', 'Benign' (false positive alarm), or 'Suspicious'.
    """
    text = (msg + " " + classification).lower()

    # Known high-confidence malicious signatures
    malicious_keywords = [
        "exploit", "cve-", "log4j", "rce", "reverse shell", "shellcode",
        "cobalt strike", "meterpreter", "malware", "trojan", "ransomware",
        "privilege escalation", "sql injection", "command injection",
        "brute force", "bruteforce", "mimikatz", "backdoor", "c2 beacon",
        "eternalblue", "mirai", "web-client", "root login attempt"
    ]
    for kw in malicious_keywords:
        if kw in text:
            return "Malicious"

    # Known benign noise / common false positive alerts in enterprise environments
    benign_keywords = [
        "icmp ping", "echo request", "generic protocol", "misconfiguration",
        "noop sled detected in binary font", "font download", "ntp query rate",
        "google-analytics", "cdn traffic", "internal dns query", "http 404 response",
        "standard response", "policy allowed"
    ]
    for kw in benign_keywords:
        if kw in text:
            return "Benign"

    if priority == 1:
        return "Malicious"
    elif priority == 2:
        return "Suspicious"
    return "Benign"

SID_MSG_MAP: Dict[int, Dict[str, Any]] = {}

def load_sid_msg_map(path: Optional[str] = None):
    candidates = [
        path,
        os.environ.get("SNORT_SID_MSG_MAP"),
        "/usr/local/etc/snort/rules/sid-msg.map",
        "demo/rules/sid-msg.map"
    ]
    for p in candidates:
        if p and os.path.exists(p):
            try:
                count = 0
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = [pt.strip() for pt in line.split("||")]
                        if len(parts) >= 2:
                            try:
                                s_id = int(parts[0])
                                msg_text = parts[1]
                                refs = parts[2:] if len(parts) > 2 else []
                                SID_MSG_MAP[s_id] = {"msg": msg_text, "refs": refs}
                                count += 1
                            except ValueError:
                                pass
                print(f"[+] Loaded {count} signature mappings from {p}")
                return count
            except Exception as e:
                print(f"[-] Could not load {p}: {e}")
    return 0

load_sid_msg_map()

FAST_ALERT_REGEX = re.compile(
    r'^(?:(?P<timestamp>\d{2}/\d{2}(?:-\d{2}:\d{2}:\d{2}\.\d+)?|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?'
    r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.+?)\s+\[\*\*\]\s*'
    r'(?:\[Classification:\s*(?P<class>[^\]]+)\]\s*)?'
    r'(?:\[Priority:\s*(?P<priority>\d+)\]\s*)?'
    r'\{(?P<proto>[A-Za-z0-9]+)\}\s+'
    r'(?P<src_ip>[^\s:]+)(?::(?P<src_port>\d+))?\s+->\s+'
    r'(?P<dst_ip>[^\s:]+)(?::(?P<dst_port>\d+))?'
)

def parse_snort_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Check for Snort 3 JSON format
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            gid = int(data.get("gid", 1))
            sid = int(data.get("sid", 1000000))
            rev = int(data.get("rev", 1))
            msg = (data.get("msg") or data.get("rule", "Snort Rule Match")).strip(' \t\r\n"')
            refs = []
            if sid in SID_MSG_MAP:
                mapped = SID_MSG_MAP[sid]
                if not msg or msg == "Snort Rule Match" or msg.startswith("1:"):
                    msg = mapped["msg"]
                refs = mapped.get("refs", [])
            classification = (data.get("classification") or data.get("class", "Generic")).strip()
            priority = int(data.get("priority", 2))
            if priority == 0:
                priority = 1 if "exploit" in msg.lower() or "c2" in msg.lower() else (2 if "scan" in msg.lower() else 3)
            proto = str(data.get("proto", "TCP")).upper()
            src_ip = data.get("src_addr") or data.get("src_ip", "0.0.0.0")
            src_port = int(data.get("src_port", 0)) if data.get("src_port") else None
            dst_ip = data.get("dst_addr") or data.get("dst_ip", "0.0.0.0")
            dst_port = int(data.get("dst_port", 0)) if data.get("dst_port") else None
            ts = data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            gt = data.get("ground_truth") or classify_ground_truth(msg, classification, priority)

            return {
                "timestamp": ts,
                "gid": gid,
                "sid": sid,
                "rev": rev,
                "msg": msg,
                "classification": classification,
                "priority": priority,
                "proto": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "service": data.get("service", proto.lower()),
                "references": refs,
                "ground_truth": gt,
                "raw": line
            }
        except Exception:
            pass

    # Match Fast Alert format
    m = FAST_ALERT_REGEX.search(line)
    if m:
        gid = int(m.group("gid"))
        sid = int(m.group("sid"))
        rev = int(m.group("rev"))
        msg = m.group("msg").strip(' \t\r\n"')
        refs = []
        if sid in SID_MSG_MAP:
            mapped = SID_MSG_MAP[sid]
            if not msg or msg.startswith("1:"):
                msg = mapped["msg"]
            refs = mapped.get("refs", [])
        classification = m.group("class").strip() if m.group("class") else "Generic"
        priority = int(m.group("priority")) if m.group("priority") else 3
        if priority == 0:
            priority = 1 if ("exploit" in msg.lower() or "malware" in msg.lower() or "rce" in msg.lower()) else (2 if "scan" in msg.lower() else 3)
        proto = m.group("proto").upper()
        src_ip = m.group("src_ip")
        src_port = int(m.group("src_port")) if m.group("src_port") else None
        dst_ip = m.group("dst_ip")
        dst_port = int(m.group("dst_port")) if m.group("dst_port") else None
        ts = m.group("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        gt = classify_ground_truth(msg, classification, priority)

        return {
            "timestamp": ts,
            "gid": gid,
            "sid": sid,
            "rev": rev,
            "msg": msg,
            "classification": classification,
            "priority": priority,
            "proto": proto,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "service": proto.lower(),
            "references": refs,
            "ground_truth": gt,
            "raw": line
        }

    return None

# ── Flask Routes & API ─────────────────────────────────────────────────────────

@app.after_request
def add_cache_control_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/")
def index():
    now = time.time()
    session_id = session.get("browser_session_id")
    last_seen = session.get("last_seen", 0)
    is_new_session = False

    if not session_id:
        is_new_session = True
    elif (now - last_seen) > 3600:  # 1 hour inactivity threshold
        is_new_session = True

    if is_new_session:
        session["browser_session_id"] = str(uuid.uuid4())
        session["session_started_at"] = datetime.now().isoformat()
        try:
            try:
                from web.pipeline_routes import lifecycle_mgr
            except ImportError:
                from pipeline_routes import lifecycle_mgr
            archived = lifecycle_mgr.archive_and_reset_candidates()
            print(f"[+] New web browser session started ({session['browser_session_id']}): Cleaned candidates.json (archived {archived} candidates).")
        except Exception as e:
            print(f"[!] Note on resetting candidates for new session: {e}")

    session["last_seen"] = now
    return render_template("index.html")

@app.route("/events")
def sse_events():
    def event_stream():
        q = store.subscribe()
        try:
            # Send initial state snapshot on connection
            init_msg = json.dumps({
                "type": "stats",
                "stats": store.get_summary_stats()
            })
            yield f"event: stats\ndata: {init_msg}\n\n"

            while True:
                try:
                    data = q.get(timeout=15)
                    parsed = json.loads(data)
                    event_type = parsed.get("type", "message")
                    yield f"event: {event_type}\ndata: {data}\n\n"
                except queue.Empty:
                    # Heartbeat keep-alive
                    hb = json.dumps({"timestamp": datetime.now().isoformat(), "state": "healthy"})
                    yield f"event: heartbeat\ndata: {hb}\n\n"
        except GeneratorExit:
            store.unsubscribe(q)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/api/stats")
def api_stats():
    return jsonify(store.get_summary_stats())

@app.route("/api/alerts")
def api_alerts():
    try:
        limit = int(request.args.get("limit", 100))
    except (ValueError, TypeError):
        limit = 100

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    prio_filter = request.args.get("priority")
    proto_filter = request.args.get("protocol")
    gt_filter = request.args.get("ground_truth")
    flow_filter = request.args.get("flow_id")
    search = request.args.get("q", "").lower().strip()

    with store.lock:
        res = list(store.alerts)

    if prio_filter:
        try:
            p_val = int(prio_filter)
            res = [a for a in res if a.get("priority") == p_val]
        except ValueError:
            pass

    if proto_filter:
        res = [a for a in res if a.get("proto", "").upper() == proto_filter.upper()]

    if gt_filter:
        gt_lower = gt_filter.lower().strip()
        if gt_lower in ["threats", "suspicious_or_malicious", "malicious_or_suspicious", "suspicious_malicious", "suspicious,malicious"]:
            res = [a for a in res if a.get("ground_truth", "").lower() in ["malicious", "suspicious"]]
        elif gt_lower not in ["all", ""]:
            res = [a for a in res if a.get("ground_truth", "").lower() == gt_lower]

    if flow_filter:
        try:
            f_val = int(flow_filter)
            res = [a for a in res if a.get("flow_id") == f_val]
        except ValueError:
            pass

    if search:
        res = [
            a for a in res
            if search in a.get("msg", "").lower()
            or search in a.get("src_ip", "").lower()
            or search in a.get("dst_ip", "").lower()
            or search in a.get("sig_key", "").lower()
            or search in a.get("classification", "").lower()
            or search in a.get("proto", "").lower()
            or search in str(a.get("sid", "")).lower()
        ]

    # Return newest first
    reversed_res = list(reversed(res))
    total_matching = len(reversed_res)
    total_alerts = max(store.total_alerts_count, len(store.alerts))

    if limit > 0:
        total_pages = max(1, (total_matching + limit - 1) // limit)
        page = max(1, min(page, total_pages)) if total_matching > 0 else 1
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_res = reversed_res[start_idx:end_idx]
    else:
        total_pages = 1
        page = 1
        paginated_res = reversed_res

    return jsonify({
        "total_matching": total_matching,
        "total_alerts": total_alerts,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "count": len(paginated_res),
        "alerts": paginated_res
    })

@app.route("/api/alert/<int:alert_id>")
def api_get_alert(alert_id: int):
    with store.lock:
        for a in reversed(store.alerts):
            if a.get("id") == alert_id:
                return jsonify({"status": "success", "alert": a})
    return jsonify({"status": "error", "message": "Alert not found"}), 404

@app.route("/api/correlations")
def api_correlations():
    filter_mode = request.args.get("filter", "correlated").lower()
    only_correlated = filter_mode != "all"
    flows = store.get_correlations(only_correlated=only_correlated)
    summary = store.get_summary_stats()
    return jsonify({
        "count": len(flows),
        "correlated_count": summary["correlated_flows_count"],
        "total_flows": summary["total_flows"],
        "flows": flows
    })

@app.route("/api/signatures")
def api_signatures():
    sigs = store.get_signatures_list()
    return jsonify({"count": len(sigs), "signatures": sigs})

@app.route("/api/clear", methods=["POST"])
def api_clear():
    store.clear()
    return jsonify({"status": "cleared"})

@app.route("/api/ground_truth/override", methods=["POST"])
def api_ground_truth_override():
    payload = request.get_json() or {}
    alert_id = payload.get("alert_id")
    new_gt = payload.get("ground_truth")

    if not alert_id or new_gt not in ("Malicious", "Benign", "Suspicious"):
        return jsonify({"error": "Invalid parameters"}), 400

    with store.lock:
        found = None
        for a in store.alerts:
            if a["id"] == alert_id:
                old_gt = a.get("ground_truth", "Suspicious")
                store.ground_truth_counts[old_gt] -= 1
                store.ground_truth_counts[new_gt] += 1
                a["ground_truth"] = new_gt
                found = a
                break

    if found:
        store.broadcast({
            "type": "stats",
            "stats": store.get_summary_stats()
        })
        return jsonify({"status": "updated", "alert": found})
    return jsonify({"error": "Alert not found"}), 404

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    content = file.read().decode("utf-8", errors="replace")
    added = 0
    for line in content.splitlines():
        parsed = parse_snort_line(line)
        if parsed:
            store.add_alert(parsed, broadcast=False)
            added += 1

    # Broadcast updated stats
    store.broadcast({
        "type": "stats",
        "stats": store.get_summary_stats()
    })
    return jsonify({"status": "success", "alerts_ingested": added})

# ── Seed with authentic dataset alerts & PCAP Runner ──────────────────────────

def seed_initial_data():
    base_dir = Path(__file__).resolve().parent.parent
    candidate_paths = [
        base_dir / "data" / "pcap_dataset_alerts.txt",
        base_dir / "web" / "sample_alerts" / "alert_fast.txt",
    ]
    for p in candidate_paths:
        if p.is_file():
            loaded = load_log_file(str(p), clear_first=True)
            print(f"[+] Pre-seeded alert database with {loaded} authentic alerts from {p.name}")
            return

try:
    from snort_pipeline.config import to_wsl_path
except ImportError:
    def to_wsl_path(p: str) -> str:
        if not p:
            return ""
        p_str = str(p).strip().strip('"').strip("'")
        if p_str.startswith("/mnt/"):
            return p_str.replace("\\", "/")
        m = re.match(r"^([a-zA-Z]):[\\/](.*)", p_str)
        if m:
            return f"/mnt/{m.group(1).lower()}/{m.group(2).replace('\\', '/')}"
        return p_str.replace("\\", "/")

def get_snort_binary() -> Optional[Tuple[str, bool]]:
    """Return (binary_command, is_wsl) or None if not found."""
    native_snort = shutil.which("snort")
    if native_snort:
        return (native_snort, False)

    if sys.platform == "win32":
        try:
            res = subprocess.run(
                ["wsl", "bash", "-c", "command -v snort || ls /usr/local/bin/snort 2>/dev/null"],
                capture_output=True,
                text=True,
                timeout=4
            )
            out = res.stdout.strip()
            if res.returncode == 0 and ("snort" in out):
                return (out.splitlines()[0], True)
        except Exception:
            pass

    return None

def run_on_pcap_target(pcap_path: str, tail_live: bool = False) -> int:
    """
    Execute Snort offline against a PCAP target (directory or file) or ingest
    existing alerts. Snort strictly runs in offline PCAP read mode (no network sniffing).
    """
    pcap_path = os.path.abspath(pcap_path)
    base_dir = Path(__file__).resolve().parent.parent
    pcap_dataset_dir = base_dir / "PCAP_dataset"

    print(f"[*] Targeting PCAP repository: {pcap_path}")
    print("[*] 100% Offline PCAP mode active (Network interfaces disabled).")

    # Check if target is PCAP_dataset
    is_pcap_dataset = False
    try:
        is_pcap_dataset = Path(pcap_path).resolve() == pcap_dataset_dir.resolve()
    except Exception:
        pass

    # 1. If target is PCAP_dataset, pre-load baseline authentic alerts immediately
    dataset_alert_file = base_dir / "data" / "pcap_dataset_alerts.txt"
    if not dataset_alert_file.is_file():
        dataset_alert_file = base_dir / "web" / "sample_alerts" / "alert_fast.txt"

    if is_pcap_dataset and dataset_alert_file.is_file():
        loaded = load_log_file(str(dataset_alert_file), clear_first=True)
        print(f"[+] Ingested {loaded} verified baseline alerts from {dataset_alert_file.name}")
        print("[*] Offline analysis dataset loaded. No background capture running.")
        return loaded

    # 2. Check if Snort binary is available to run offline analysis on custom PCAP
    snort_info = get_snort_binary()
    if not snort_info:
        print("[!] Snort 3 binary not detected on PATH or WSL. Running in pure dataset review mode.")
        return len(store.alerts)

    snort_bin, is_wsl = snort_info
    print(f"[*] Snort 3 engine detected: {snort_bin} (WSL={is_wsl})")

    # Output log file for offline PCAP run
    runtime_dir = base_dir / "data" / "logs"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    alert_file = runtime_dir / "alert_fast.txt"
    if alert_file.exists():
        try:
            alert_file.unlink()
        except Exception:
            pass

    if is_wsl:
        wsl_target = to_wsl_path(pcap_path)
        wsl_log_dir = to_wsl_path(str(runtime_dir))
        target_flag = f"--pcap-dir \"{wsl_target}\"" if os.path.isdir(pcap_path) else f"-r \"{wsl_target}\""
        cmd = f"{snort_bin} -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/snort/rules/snort3-community.rules {target_flag} -l \"{wsl_log_dir}\" --lua 'alert_fast = {{ file = true }}' -q"
        full_cmd = ["wsl", "bash", "-c", cmd]
    else:
        target_flag = ["--pcap-dir", pcap_path] if os.path.isdir(pcap_path) else ["-r", pcap_path]
        full_cmd = [
            snort_bin,
            "-c", "/usr/local/etc/snort/snort.lua",
            "-R", "/usr/local/etc/snort/rules/snort3-community.rules",
            *target_flag,
            "-l", str(runtime_dir),
            "--lua", "alert_fast = { file = true }",
            "-q"
        ]

    try:
        print(f"[*] Running Snort 3 offline analysis against {pcap_path}...")
        subprocess.run(full_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        if alert_file.is_file():
            loaded = load_log_file(str(alert_file), clear_first=True)
            print(f"[+] Snort analysis complete: Ingested {loaded} alerts from PCAP '{pcap_path}'")
            return loaded
    except Exception as e:
        print(f"[-] Warning: Failed to execute Snort process: {e}")

    return len(store.alerts)

def load_log_file(filepath: str, clear_first: bool = False):
    if not filepath or not os.path.exists(filepath):
        return 0
    if clear_first:
        store.clear()
    count = 0
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_snort_line(line)
                if parsed:
                    store.add_alert(parsed, broadcast=False)
                    count += 1
        print(f"[+] Loaded {count} alerts from {filepath}")
    except Exception as e:
        print(f"[-] Error loading {filepath}: {e}")
    return count

def start_tailing_log(filepath: str):
    if not filepath or not os.path.exists(filepath):
        return
    store.tailing_file = filepath
    def _tail_worker():
        print(f"[*] Live tailing Snort log: {filepath}")
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                # Seek to end
                f.seek(0, os.SEEK_END)
                while not store.stop_tailing.is_set():
                    line = f.readline()
                    if line:
                        parsed = parse_snort_line(line)
                        if parsed:
                            store.add_alert(parsed, broadcast=True)
                    else:
                        time.sleep(0.2)
        except Exception as e:
            print(f"[-] Tail error on {filepath}: {e}")

    store.stop_tailing.clear()
    store.tailing_thread = threading.Thread(target=_tail_worker, daemon=True)
    store.tailing_thread.start()

# Check environment for initial log file
init_log = os.environ.get("SNORT_LOG_FILE")
if init_log and os.path.exists(init_log):
    load_log_file(init_log, clear_first=True)
else:
    seed_initial_data()

# Check environment for live tailing
tail_log = os.environ.get("SNORT_TAIL_FILE")
if tail_log and os.path.exists(tail_log):
    start_tailing_log(tail_log)

# ── Main Entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Snort 3 Live Web Console")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)))
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--pcap", type=str, default=os.environ.get("SNORT_PCAP"), help="Path to PCAP file or directory (default: PCAP_dataset)")
    parser.add_argument("--pcap-dir", type=str, default=os.environ.get("SNORT_PCAP_DIR"), help="Path to PCAP directory (default: PCAP_dataset)")
    parser.add_argument("--log-file", type=str, default=os.environ.get("SNORT_LOG_FILE"), help="Path to Snort alert log file to load")
    parser.add_argument("--tail", type=str, default=os.environ.get("SNORT_TAIL_FILE"), help="Path to Snort alert log file to tail live")
    args = parser.parse_args()

    repo_dir = Path(__file__).resolve().parent.parent
    default_dataset = repo_dir / "PCAP_dataset"

    pcap_target = args.pcap or args.pcap_dir

    if args.log_file:
        load_log_file(args.log_file, clear_first=True)
    elif pcap_target:
        run_on_pcap_target(pcap_target)
    else:
        # Default to PCAP_dataset if no pcap or log file specified
        print(f"[*] No PCAP directory specified. Using '{default_dataset.name}' as default demo directory.")
        run_on_pcap_target(str(default_dataset))

    if args.tail:
        start_tailing_log(args.tail)

    print(f"[*] Starting Snort 3 Live Web Console on http://127.0.0.1:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
