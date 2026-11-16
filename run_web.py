#!/usr/bin/env python3
"""
Snort 3 Live Web Application Launcher
Usage:
    python run_web.py
    python run_web.py --port 8080
    python run_web.py --pcap-dir PCAP_dataset
    python run_web.py --pcap PCAP_dataset/Malware_traffic_pcap/2021-10-20-TA551-pushes-Sliver.pcap
"""

import sys
import os
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Launch Snort 3 Live Web Console")
    parser.add_argument("--port", type=int, default=8080, help="HTTP server port (default: 8080)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="HTTP server host (default: 0.0.0.0)")
    parser.add_argument("--pcap", type=str, default=None, help="Path to PCAP file or directory (default: PCAP_dataset)")
    parser.add_argument("--pcap-dir", type=str, default=None, help="Path to PCAP directory (default: PCAP_dataset)")
    parser.add_argument("--log-file", type=str, default=None, help="Path to initial Snort alert log file to load")
    parser.add_argument("--tail", type=str, default=None, help="Path to Snort alert log file to tail live")
    args = parser.parse_args()

    # Add web directory to path
    repo_dir = Path(__file__).resolve().parent
    web_dir = repo_dir / "web"
    sys.path.insert(0, str(web_dir))
    sys.path.insert(0, str(repo_dir))

    # Keep candidates.json clean/empty on boot-up; archive prior candidates to candidates_history.json
    try:
        from snort_pipeline.lifecycle import RuleLifecycleManager
        RuleLifecycleManager().archive_and_reset_candidates()
    except Exception as e:
        print(f"[!] Note: Candidate lifecycle boot check: {e}")

    from server import app, load_log_file, start_tailing_log, run_on_pcap_target
    print("=" * 70)
    print("   SNORT 3 LIVE WEB CONSOLE")
    print("   Intrusion Detection & Prevention Live Monitoring")
    print("=" * 70)

    pcap_target = args.pcap or args.pcap_dir or os.environ.get("SNORT_PCAP") or os.environ.get("SNORT_PCAP_DIR")
    default_dataset = repo_dir / "PCAP_dataset"

    if args.log_file:
        load_log_file(args.log_file, clear_first=True)
    elif pcap_target:
        run_on_pcap_target(pcap_target)
    else:
        # Default to PCAP_dataset directory if no pcap or log file specified
        print(f"[*] No PCAP file/directory specified. Defaulting demo directory to: {default_dataset.name}")
        run_on_pcap_target(str(default_dataset))

    if args.tail:
        start_tailing_log(args.tail)

    print(f"[*] Serving web interface at: http://127.0.0.1:{args.port}")
    print(f"[*] SSE stream active at:     http://127.0.0.1:{args.port}/events")
    print("[*] Press Ctrl+C to terminate.")
    print("=" * 70)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
