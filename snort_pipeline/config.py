"""
Configuration & Environment Settings for Snort 3 LLM Rule Engineering Pipeline.
"""

import os
import re
import hashlib
from pathlib import Path
from typing import Optional, List
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
RAW_ALERTS_DIR = DATA_DIR / "raw_alerts"
MANIFEST_PATH = DATA_DIR / "pcap_manifest.json"

RULES_DIR = BASE_DIR / "rules"
LOCAL_RULES_PATH = RULES_DIR / "local.rules"
CANDIDATE_RULES_PATH = RULES_DIR / "candidates.json"
CANDIDATES_HISTORY_PATH = RULES_DIR / "candidates_history.json"
RULES_HISTORY_DIR = RULES_DIR / "history"

PCAP_DATASET_DIR = BASE_DIR / "PCAP_dataset"
MALWARE_PCAP_DIR = PCAP_DATASET_DIR / "Malware_traffic_pcap"
BENIGN_PCAP_DIR = PCAP_DATASET_DIR / "Benign_traffic_pcap"
DEMO_PCAP_DIR = BASE_DIR / "demo" / "pcaps"

# Ensure directories exist
for d in [DATA_DIR, REPORTS_DIR, RAW_ALERTS_DIR, RULES_DIR, RULES_HISTORY_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Load .env
load_dotenv(BASE_DIR / ".env")

# Snort & WSL paths
WSL_SNORT_BIN = "/usr/local/bin/snort"
WSL_TSHARK_BIN = "/usr/bin/tshark"
WSL_SNORT_CONFIG = "/usr/local/etc/snort/snort.lua"
WSL_COMMUNITY_RULES = "/usr/local/etc/snort/rules/snort3-community.rules"
WSL_SID_MSG_MAP = "/usr/local/etc/snort/rules/sid-msg.map"

def get_groq_api_keys() -> List[str]:
    """
    Extract all configured Groq API keys from environment.
    Supports comma-separated GROQ_API_KEYS, GROQ_API_KEY, and numbered keys (GROQ_API_KEY_1, ...).
    """
    keys: List[str] = []

    # 1. Check GROQ_API_KEYS (comma-separated string: "key1,key2,key3")
    raw_keys = os.getenv("GROQ_API_KEYS", "")
    if raw_keys:
        for k in raw_keys.split(","):
            k = k.strip().strip("'\"")
            if k and k not in keys:
                keys.append(k)

    # 2. Check GROQ_API_KEY (can also be comma-separated or single)
    single_or_multi = os.getenv("GROQ_API_KEY", "")
    if single_or_multi:
        for k in single_or_multi.split(","):
            k = k.strip().strip("'\"")
            if k and k not in keys:
                keys.append(k)

    # 3. Check numbered keys: GROQ_API_KEY_1, GROQ_API_KEY_2, ...
    for i in range(1, 20):
        nk = os.getenv(f"GROQ_API_KEY_{i}", "")
        if nk:
            nk = nk.strip().strip("'\"")
            if nk and nk not in keys:
                keys.append(nk)

    return keys

# LLM Configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()
GROQ_API_KEYS: List[str] = get_groq_api_keys()
GROQ_API_KEY: str = GROQ_API_KEYS[0] if GROQ_API_KEYS else ""
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_TIMEOUT = float(os.getenv("GROQ_TIMEOUT", "60.0"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:latest")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

def to_wsl_path(path: str | Path) -> str:
    """Convert Windows path or POSIX path to WSL /mnt/... path."""
    if not path:
        return ""
    p_str = str(path).strip().strip('"').strip("'")
    if p_str.startswith("/mnt/"):
        return p_str.replace("\\", "/")
    m = re.match(r"^([a-zA-Z]):[\\/](.*)", p_str)
    if m:
        drive = m.group(1).lower()
        rest = m.group(2).replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    if p_str.startswith("/"):
        return p_str
    import sys
    if sys.platform == "win32":
        abs_p = str(Path(p_str).resolve())
        m = re.match(r"^([a-zA-Z]):[\\/](.*)", abs_p)
        if m:
            drive = m.group(1).lower()
            rest = m.group(2).replace("\\", "/")
            return f"/mnt/{drive}/{rest}"
        return abs_p.replace("\\", "/")
    else:
        return str(Path(p_str).resolve())

def to_win_path(path: str | Path) -> str:
    """Convert WSL /mnt/d/... path to Windows D:\\... path."""
    if not path:
        return ""
    p_str = str(path).strip().strip('"').strip("'")
    m = re.match(r"^/mnt/([a-zA-Z])/(.*)", p_str)
    if m:
        drive = m.group(1).upper()
        rest = m.group(2).replace("/", "\\")
        return f"{drive}:\\{rest}"
    if re.match(r"^[a-zA-Z]:", p_str):
        return p_str.replace("/", "\\")
    return p_str

def resolve_local_path(path: str | Path) -> Path:
    """
    Ensure the path is converted to a native Path object that works on the CURRENT Python runtime OS.
    If Python is running on Windows (sys.platform == 'win32'): converts /mnt/d/... -> D:\\...
    If Python is running on Linux/WSL (sys.platform != 'win32'): converts D:\\... -> /mnt/d/...
    """
    import sys
    if not path:
        return Path(".")
    p_str = str(path).strip().strip('"').strip("'")
    if sys.platform == "win32":
        return Path(to_win_path(p_str))
    else:
        return Path(to_wsl_path(p_str))

def compute_file_hash(path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    p = resolve_local_path(path)
    if not p.is_file():
        return ""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_wsl_cmd(cmd: str, timeout: Optional[int] = None, **kwargs):
    """
    Execute a bash shell command in the Snort Linux environment.
    If running under Windows host, delegates to 'wsl bash -c <cmd>'.
    If running natively under Linux (inside WSL or Linux container), executes 'bash -c <cmd>'.
    """
    import sys
    import subprocess
    if sys.platform == "win32":
        full_args = ["wsl", "bash", "-c", cmd]
    else:
        full_args = ["bash", "-c", cmd]
    if timeout is not None:
        kwargs["timeout"] = timeout
    return subprocess.run(full_args, **kwargs)
