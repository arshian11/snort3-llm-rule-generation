# Autonomous Snort 3 LLM Rule Engineering & Threat Investigation Pipeline

> **Official Snort 3 Documentation & Repository Links:**
> - 📖 **Official Upstream Snort 3 Repository:** [https://github.com/snort3/snort3](https://github.com/snort3/snort3)
> - 📄 **Official Upstream Snort 3 README (Preserved Locally):** [README_SNORT_OFFICIAL.md](file:///d:/GitHub/snort3/README_SNORT_OFFICIAL.md)
> - 🌐 **Official Snort 3 Documentation:** [https://docs.snort.org/](https://docs.snort.org/)
> - 📜 **Official Snort 3 Rules Reference Guide:** [https://docs.snort.org/rules/](https://docs.snort.org/rules/)

---

## Table of Contents

- [1. Brief Explanation of the Project](#1-brief-explanation-of-the-project)
- [2. How to Install This Project](#2-how-to-install-this-project)
- [3. Where to Place Your PCAP Files](#3-where-to-place-your-pcap-files)
- [4. Where to Put Your Groq or Other API Keys](#4-where-to-put-your-groq-or-other-api-keys)
- [5. How to Run the Project](#5-how-to-run-the-project)
- [6. System Architecture & Module-by-Module Explanation](#6-system-architecture--module-by-module-explanation)
- [7. LLM Counters & Observability Metrics](#7-llm-counters--observability-metrics)
- [8. Additional Noteworthy Highlights & Best Practices](#8-additional-noteworthy-highlights--best-practices)

---

## 1. Brief Explanation of the Project

The **Autonomous Snort 3 LLM Rule Engineering Pipeline** is an intelligent, automated network intrusion detection and prevention framework.

Traditionally, writing Snort rules requires experienced security analysts to manually inspect raw packet captures (PCAPs), reverse-engineer proprietary malware protocols, avoid false positives against legitimate background traffic, and format complex rule options by hand.

This project automates that entire process from end to end:
1. **Ingests Network Traffic (PCAPs):** Ingests malicious traffic and benign background captures.
2. **Executes Snort 3 & Deep Packet Decoders:** Runs Snort 3 alongside TShark and Zeek to extract comprehensive protocol sessions, HTTP/TLS transactions, DNS queries, and X.509 certificates.
3. **Builds Correlated Attack Graphs:** Uses graph analytics (Personalized PageRank and supernode abstraction) to isolate genuine attack pivots from network noise.
4. **Synthesizes Rules via LLMs (HDIRC):** Leverages a 7-stage **Hypothesis-Driven Iterative Rule Construction** engine powered by Large Language Models (Groq, Ollama, OpenAI, Gemini, Anthropic) to produce standards-compliant Snort 3 rules according to Cisco Talos/VRT methodology.
5. **Enforces a 4-Stage Safety Gate:** Validates candidate rules across syntax, true positive detection on malicious traffic, zero false positives on benign traffic, and generalization on unseen holdout traffic.
6. **Manages Rule Lifecycles:** Deploys verified rules to production (`local.rules`) with deterministic SID allocation, revision tracking, and automated rollback.
7. **Real-Time SOC Console:** Includes an interactive web dashboard with Server-Sent Events (SSE) for live monitoring, attack graph visualization, packet inspection, and an Autonomous Rule Engineering Studio.

---

## 2. How to Install This Project

### Prerequisites

| Component | Minimum Version | Description / Notes |
| :--- | :--- | :--- |
| **Operating System** | Linux (Ubuntu 20.04/22.04+) or Windows 10/11 with WSL 2 (Ubuntu) | Snort 3 and packet decoders run natively in Linux / WSL |
| **Python** | 3.10+ | Used for the pipeline, web console, and CLI |
| **Snort 3** | 3.0.0+ | Compiled binary at `/usr/local/bin/snort` |
| **TShark** | 3.2+ | Packet analysis utility (`sudo apt install tshark`) |
| **Zeek** *(Optional)* | 5.0+ | Deep network security monitor (`conn.log`, `ssl.log`, `dns.log`, `x509.log`) |

### Step-by-Step Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/arshian11/snort3-llm-rule-generation.git
cd snort3-llm-rule-generation
```

#### 2. Set Up a Python Virtual Environment
```bash
# On Linux / WSL:
python3 -m venv venv
source venv/bin/activate

# On Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies include `flask`, `python-dotenv`, `networkx`, and `requests`)*.

#### 4. Configure Your Environment Variables
Copy the template `.env.example` to create your active `.env` file:
```bash
# Linux / WSL
cp .env.example .env

# Windows (Command Prompt / PowerShell)
copy .env.example .env
```

#### 5. Verify Snort 3 & System Tools
Ensure that Snort 3 is executable in your Linux / WSL environment:
```bash
# Test Snort 3 binary
wsl snort -V
# Or natively on Linux:
snort -V
```

#### 6. Set Up Snort 3 Community Rules (Recommended)
The pipeline utilizes the official Snort 3 Community Rules for baseline alert correlation, gap analysis (Task A), and preventing duplicate message strings (Stage 3). The pipeline and `./demo.sh` look for these files at `/usr/local/etc/snort/rules/`.

Run the following commands in your Linux / WSL terminal:

```bash
# 1. Create the rules directory if it does not already exist
sudo mkdir -p /usr/local/etc/snort/rules

# 2. Download the official Snort 3 Community Rules tarball
wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz

# 3. Extract the archive
tar -xzvf snort3-community-rules.tar.gz

# 4. Copy the community rules and SID message map into place
sudo cp snort3-community-rules/snort3-community.rules /usr/local/etc/snort/rules/
sudo cp snort3-community-rules/sid-msg.map /usr/local/etc/snort/rules/

# 5. Clean up temporary files (optional)
rm -rf snort3-community-rules snort3-community-rules.tar.gz

# 6. Verify Snort 3 loads the community rules without syntax errors
snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/snort/rules/snort3-community.rules
```

> **Note:** If community rules are not present at `/usr/local/etc/snort/rules/snort3-community.rules`, the pipeline will issue a warning and continue analyzing captures with your local rule definitions.

---

## 3. Where to Place Your PCAP Files

PCAP files are organized within the `PCAP_dataset/` directory in the repository root:

```text
snort3/
├── PCAP_dataset/
│   ├── Malware_traffic_pcap/    <-- Place all MALICIOUS attack captures here
│   │   ├── 2021-10-20-TA551-pushes-Sliver.pcap
│   │   ├── 2021-11-03-Qakbot-traffic.pcap
│   │   ├── 2022-03-21-Emotet-epoch4-infection.pcap
│   │   └── ...
│   └── Benign_traffic_pcap/     <-- Place all CLEAN / BENIGN captures here
│       ├── casual_traffic.pcapng
│       ├── yt_watch_40_min.pcapng
│       └── ...
└── demo/
    └── pcaps/                   <-- Sample PCAPs for quick offline demos
```

### Purpose of Each Directory:
- **`PCAP_dataset/Malware_traffic_pcap/`**: Contains malware traffic (trojans, ransomware, C2 beacons, exploit kits) used by the pipeline to discover attack patterns and validate **True Positives (TP)**.
- **`PCAP_dataset/Benign_traffic_pcap/`**: Contains normal user traffic (browsing, office applications, video streams) used during Stage 3 negative validation to guarantee **Zero False Positives (FP)**.
- **`demo/pcaps/`**: Sample captures bundled with the repository for testing `./demo.sh`.

### Registering and Discovering Captures
After adding new PCAPs, run the dataset discovery command to automatically scan files, compute SHA-256 hashes, determine malware families, and assign train/test/holdout splits:
```bash
python -m snort_pipeline.cli dataset discover
```

Captures are recorded in `data/pcap_manifest.json` and assigned unique IDs (e.g., `PCAP_001`, `PCAP_002`).

---

## 4. Where to Put Your Groq or Other API Keys

All credentials and LLM provider settings must be configured in the **`.env`** file at the root of the project:

```text
snort3/
├── .env          <-- Put your API keys and provider configurations here
├── .env.example  <-- Reference configuration template
```

### Configuring Providers in `.env`

#### Option 1: Groq (Recommended — Ultra-Fast Inference & Prompt Caching)
Groq provides instant inference and supports **Multi-Key Rotation** (failover across multiple keys upon hitting rate limits) and **Model-Aware Prompt Caching**:
```env
# Set active provider to groq
LLM_PROVIDER=groq

# Single key OR multiple comma-separated keys for automated failover & rotation
GROQ_API_KEYS=gsk_yourKey1Here,gsk_yourKey2Here,gsk_yourKey3Here

# Alternatively, configure numbered keys:
# GROQ_API_KEY_1=gsk_...
# GROQ_API_KEY_2=gsk_...

# Model selection (Supported models: openai/gpt-oss-120b, llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768)
GROQ_MODEL=openai/gpt-oss-120b
GROQ_TIMEOUT=60.0
```

#### Option 2: Ollama (Local Air-Gapped / Privacy-Preserving)
For fully offline or confidential environments without external internet connectivity:
```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3:latest
```
*(Ensure Ollama is running via `ollama serve` and pull your model: `ollama pull llama3` or `ollama pull deepseek-r1`)*.

#### Option 3: Google Gemini
```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-1.5-flash
```

#### Option 4: OpenAI
```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your_openai_api_key_here
OPENAI_MODEL=gpt-4o-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

#### Option 5: Anthropic Claude
```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your_anthropic_api_key_here
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
```

#### Option 6: Custom OpenAI-Compatible (vLLM, LM Studio, LocalAI)
```env
LLM_PROVIDER=custom
CUSTOM_LLM_BASE_URL=http://localhost:8000/v1
CUSTOM_LLM_API_KEY=your_optional_key
CUSTOM_LLM_MODEL=default
```

---

## 5. How to Run the Project

### Method 1: Interactive Live Web Console (Recommended)

Launch the web console to monitor live alerts, inspect packet flows, explore attack graphs, and trigger autonomous rule engineering through a browser interface:

```bash
# Launch server on default port 8080
python run_web.py

# Launch on a custom port or bind to all interfaces
python run_web.py --port 8080 --host 0.0.0.0

# Process a specific PCAP on startup
python run_web.py --pcap PCAP_dataset/Malware_traffic_pcap/2021-10-20-TA551-pushes-Sliver.pcap

# Tail an active Snort alert log file in real time
python run_web.py --tail /var/log/snort/alert_fast.txt
```

Once running, open your web browser at:
👉 **`http://127.0.0.1:8080`**

### Method 2: Shell Demo Script (Linux / WSL)

The project includes an automated demo script:

```bash
# Run on default PCAP_dataset directory
./demo.sh

# Run on a specific PCAP
./demo.sh PCAP_dataset/Malware_traffic_pcap/2021-10-20-TA551-pushes-Sliver.pcap

# Force re-analysis of packets
./demo.sh PCAP_dataset --reanalyze
```

### Method 3: Command-Line Interface (CLI)

The CLI provides full programmatic control over all modules:

#### 1. Dataset Operations
```bash
# Scan and discover PCAPs
python -m snort_pipeline.cli dataset discover

# List all registered captures
python -m snort_pipeline.cli dataset list

# Inspect metadata of a specific capture
python -m snort_pipeline.cli dataset get --id PCAP_001
```

#### 2. End-to-End Autonomous Pipeline
Run full packet extraction, correlation, LLM rule synthesis, and 4-stage validation on a capture:
```bash
python -m snort_pipeline.cli run-pipeline PCAP_001

# Auto-approve into local.rules if validation passes
python -m snort_pipeline.cli run-pipeline PCAP_001 --auto-approve --analyst "SecAnalyst"
```

#### 3. Hypothesis-Driven Iterative Rule Construction (HDIRC)
Execute HDIRC up to a designated stage (1 to 7):
```bash
# Stage 1: Generate & validate detection hypothesis
python -m snort_pipeline.cli hdirc PCAP_001 --stage 1

# Stage 7: Full multi-stage assembly and dual-pass verification
python -m snort_pipeline.cli hdirc PCAP_001 --stage 7
```

#### 4. Rule Management, Review & Rollback
```bash
# List candidate and deployed rules
python -m snort_pipeline.cli rules

# Validate a candidate rule SID against positive and negative traffic
python -m snort_pipeline.cli validate 1000001 --pcap PCAP_001

# Human analyst review (approve or reject)
python -m snort_pipeline.cli review 1000001 --action approve --notes "Verified C2 pattern"

# Roll back production ruleset to a previous version
python -m snort_pipeline.cli rollback 1 --analyst "SecAnalyst" --reason "Operational revert"
```

---

## 6. System Architecture & Module-by-Module Explanation

The system is structured as an end-to-end intelligence and validation pipeline:

```text
[PCAP Ingestion] ────────> [Snort 3 Execution]
        │                           │
        ▼                           ▼
[TShark + Zeek Extractor] ───> [Evidence Correlator & Graph]
                                    │
                                    ▼
                         [Standardized Report]
                                    │
                                    ▼
                     [LLM Analysis & HDIRC Engine]
                      (Tasks A, B, C & Stages 1-7)
                                    │
                                    ▼
                     [4-Stage Rule Validation Gate]
                                    │
                                    ▼
                   [Lifecycle & Production local.rules]
```

### Module 1: PCAP Ingestion & Dataset Management (`dataset.py`)
- Discovers and catalogs packet captures from `PCAP_dataset/`.
- Computes SHA-256 cryptographic hashes for forensic reproducibility.
- Identifies malware families, threat categories, and splits datasets into 60% Train, 20% Test, and 20% Holdout splits.
- Stores dataset state in `data/pcap_manifest.json`.

### Module 2: Snort 3 Execution & Alert Extraction (`snort_engine.py`)
- Runs Snort 3 in WSL / Linux container using `/usr/local/bin/snort`.
- Evaluates community and custom rules against captures with zero lossy alert reduction.
- Correlates alert signatures with `sid-msg.map` and parses execution statistics (packet counts, runtimes, unique signatures).
- Saves raw structured alert telemetry into `data/raw_alerts/`.

### Module 3: Network Traffic Feature Extraction Engine (`packet_analyzer.py`)
- Performs deep protocol inspection via **TShark** and **Zeek**:
  - Extracts network flows, session states, and protocol distributions.
  - Decodes DNS queries and computes **Shannon entropy** to detect DGA (Domain Generation Algorithms).
  - Inspects HTTP transactions (methods, URIs, user agents, server headers) and TLS handshakes (SNI, cipher suites, X.509 cert hashes).
  - Ingests Zeek logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `x509.log`, `files.log`).
  - Detects behavioral anomalies: periodic C2 beaconing, connection failure bursts, and asymmetric byte ratios.

### Module 4: Evidence Correlation & Event Graph Engine (`correlator.py`)
- Synthesizes raw Snort alerts and deep network flows into a directed behavioral graph using **NetworkX**.
- Connects communication endpoints, protocols, and triggering alerts into cohesive attack trees.
- Executes **Personalized PageRank (PPR)** anchored on malicious alerts to calculate centrality scores.
- Collapses repetitive flow noise into **Supernodes** while pruning benign background edges.
- Identifies the highest-priority **Attack Pivots** representing true adversary activity.

### Intermediate Investigation Report Generator (`report_generator.py`)
- Unifies outputs from Modules 1–4 into standardized, reproducible investigation reports saved to `data/reports/<capture_id>_report.json`.
- Forms the foundational context provided to the LLM rule generation engine.

### Module 5: LLM Analysis Engine (`llm_engine.py`)
Executes four security intelligence tasks with built-in prompt injection defense:
- **Executive SOC Incident Report:** Synthesizes an executive incident verdict, identifying patient zero, attacker source IP, attack narrative, and recommended remediation.
- **Task A (Existing Signature Analysis):** Evaluates existing rule coverage, identifying detection gaps and evasion vulnerabilities.
- **Task B (Behavioral Pattern Discovery):** Identifies persistent, protocol-level malware invariants across captures while filtering out transient tokens.
- **Task C (Candidate Rule Generation):** Proposes initial Snort 3 rules complete with rule objectives, classtypes, and confidence scoring.

### Groq Provider & Error Mitigation Engine (`groq_provider.py`)
Production-grade inference orchestration for Groq:
- **Multi-Key Rotation (`GroqKeyManager`):** Rotates across multiple API keys with automated cooldown timers upon encountering HTTP 429 rate limits.
- **Model-Aware Prompt Caching (`GroqCacheStats` & `GroqPromptOptimizer`):** Structures system prompts and schemas as static prefixes, unlocking 50% token cost discounts and reduced latency.
- **Automatic Recovery:** Handles HTTP 400 (token clamping for exceeding context), HTTP 500/503 (exponential backoff retry), and finish reason `length` JSON recovery.

### Central Rule Construction Engine: HDIRC 7-Stage Pipeline (`rule_construction_engine.py`)
Constructs production-grade Snort 3 rules through seven distinct validation gates:
1. **Stage 1 — Detection Hypothesis & Validation Gate:** Evaluates whether the observed traffic warrants a network rule or endpoint action, identifying invariant indicators and triggering packets.
2. **Stage 2 — Header Generation (`header_generator.py`):** Determines whether to generate a traditional IP/port header or a modern Snort 3 service header (`alert http`, `alert ssl`, `alert file`).
3. **Stage 3 — Message Generation (`message_generator.py`):** Formats standardized message strings following Cisco Talos conventions (`MALWARE-CNC`, `EXPLOIT-KIT`), avoiding duplicate collision with community rules.
4. **Stage 4 — Flow Generation (`flow_generator.py`):** Formulates session-tracking flow options (`flow:to_server,established;`), ensuring proper directionality and stream reassembly.
5. **Stage 5 — Detection Generation (`detection_generator.py`):** Implements the VRT "Bail Early" architecture:
   - Selects sticky buffers (`http_uri;`, `http_header;`, `http_client_body;`, `file_data;`).
   - Designates the longest, most unique pattern as `fast_pattern`.
   - Modifiers formatted in Snort 3 syntax (`content:"...",nocase,fast_pattern;`).
   - Uses relative DOE navigation (`distance`, `within`) and `isdataat` guards before PCRE.
6. **Stage 6 — Supporting Options & Metadata (`supporting_generator.py`):** Allocates deterministic custom SIDs (1,000,000+), revision numbers, classtypes, and verified external references (CVE, ThreatFox, Malware-Traffic-Analysis).
7. **Stage 7 — Rule Assembly & Dual-Pass Verification (`rule_assembly.py`):** Assembles the AST model, validates compiler syntax, performs shadow/conflict analysis, and verifies the rule against both malicious and clean captures.

### Catalogues & Protocol Constants
- **`option_catalogue.py` & `snort3_catalogue.py`:** Comprehensive dictionary of valid Snort 3 rule options, sticky buffers, and rule modifiers.
- **`protocol_constants.py` & `protocol_constants_catalogue.json`:** Protocol invariant filter that prevents the LLM from hallucinating common protocol tokens (such as `HTTP/1.1`, `GET`, `User-Agent:`) as unique malware signatures.
- **`snort2_to_snort3_migration.py` & `snort_upgrade_catalogue.json`:** Automatic converter translating legacy Snort 2 rules into Snort 3 syntax.

### Module 6: 4-Stage Rule Validation Pipeline (`validator.py`)
Every candidate rule must clear four rigorous validation stages:
- **Stage 1 (Syntax Check):** Compiles the candidate rule through the official Snort 3 engine (`snort -c snort.lua --rule <rule>`). Must return exit code 0.
- **Stage 2 (Positive Validation):** Tests the rule against the motivating malicious PCAP. Must trigger alerts (True Positives).
- **Stage 3 (Negative Validation):** Tests the rule against clean benign traffic captures (`PCAP_dataset/Benign_traffic_pcap/`). Must produce **0 False Positives**.
- **Stage 4 (Generalization Validation):** Tests the rule against unseen holdout malware captures to evaluate detection efficacy across variants.
- Calculates True Positives (TP), False Positives (FP), False Negatives (FN), Precision, Recall, and F1-Score.

### Module 7: Rule Lifecycle & Version Management (`lifecycle.py`)
- Tracks rules across states: `CANDIDATE` ➔ `VALIDATED` ➔ `APPROVED` / `REJECTED` ➔ `DEPLOYED`.
- Active candidates are maintained in `rules/candidates.json`; historical candidates are archived to `rules/candidates_history.json`.
- Production rules are appended to `rules/local.rules`.
- Backs up ruleset snapshots into `rules/history/local.rules.v<N>` before every change, enabling single-command rollback.

### Web Console & Live Monitoring Services (`web/server.py` & `web/pipeline_routes.py`)
- Flask backend with Server-Sent Events (SSE) streaming live alert updates.
- 6 interactive tabs: Overview, Alerts Feed, Traffic Flow Inspector, Attack Graph Visualizer, PCAP Inspector, and Autonomous Rule Engineering Studio.

---

## 7. LLM Counters & Observability Metrics

The system incorporates comprehensive token tracking, rate limiting, and observability telemetry throughout the pipeline:

### 1. Groq Inference & Prompt Cache Telemetry (`GroqCacheStats` in `groq_provider.py`)
- **`total_requests`**: Monotonically increasing counter of total LLM queries executed.
- **`cached_requests`**: Count of requests that successfully achieved a prompt cache hit.
- **`total_prompt_tokens`**: Cumulative volume of input/prompt tokens processed.
- **`total_cached_tokens`**: Cumulative volume of prompt tokens served directly from Groq's prefix cache (50% cost reduction).
- **`total_completion_tokens`**: Cumulative volume of output/completion tokens generated.
- **`overall_hit_rate_pct`**: Cumulative cache hit rate percentage, calculated as:
  $$\text{Hit Rate (\%)} = \left( \frac{\text{Total Cached Tokens}}{\text{Total Prompt Tokens}} \right) \times 100$$
  *(i.e. `(total_cached_tokens / total_prompt_tokens) * 100%`)*
- **`last_request` metrics**:
  - `last_prompt_tokens`: Prompt token count of the most recent query.
  - `last_cached_tokens`: Number of tokens served from cache for the most recent query.
  - `last_hit_rate_pct`: Hit rate percentage for the most recent query.
  - `last_latency_sec`: Response time (in seconds) for the most recent query.
  - `last_model`: The specific model ID that served the last request.

### 2. API Key Management & Rate-Limit Telemetry (`GroqKeyManager`)
- **`key_count`**: Counter of active, available API keys currently in rotation.
- **`total_configured`**: Total count of API keys initially provided in configuration.
- **`_cooldowns`**: Timestamp dictionary tracking individual per-key cooldown timers upon encountering HTTP 429 (Rate Limit / Quota Exceeded).
- **`_disabled_keys`**: Set of permanently disabled keys (e.g., invalid authentication or revoked credentials).

### 3. Context & Token Clamping Counters
- **`max_tokens` clamping counter**: Tracks automatic parameter reductions when models reject requests exceeding token limits (e.g., dynamically clamping to 4096 tokens).
- **`finish_reason: length` recovery**: Tracks automated token window expansion when a response is truncated mid-JSON.

### 4. Alert & Flow Tracking Counters (`web/server.py`)
- **`alert_id_counter`**: Monotonically increasing ID assigned to incoming Snort alerts.
- **`flow_id_counter`**: Monotonically increasing ID assigned to distinct 5-tuple network sessions.
- **`priority_counts`**: Counter categorizing alerts by priority (High / Priority 1, Medium / Priority 2, Low / Priority 3).
- **`protocol_counts`**: Counter segmenting alerts by transport protocol (TCP, UDP, ICMP).
- **`ground_truth_counts`**: Counter tallying events by ground truth classification (Malicious, Benign, Suspicious).
- **`src_ip_counts` / `dst_ip_counts`**: Frequency counters identifying top talkers and target systems.

---

## 8. Additional Noteworthy Highlights & Best Practices

### Strict Prompt Injection Defense
Network traffic payloads often contain hostile data designed to manipulate language models. The pipeline implements defense-in-depth sanitization:
- All raw packet payloads, HTTP headers, and strings are stripped of delimiters (`</untrusted_network_data>`, `<|im_start|>`, `<|im_end|>`).
- Data is strictly enclosed within `<untrusted_network_data>` boundaries.
- System prompts instruct the LLM to treat all enclosed data as passive byte sequences and never interpret instructions or execute commands.

### Anti-Hallucination Enforcements
- **Deterministic SIDs:** Custom SIDs are allocated strictly by Python logic starting at SID 1,000,000+, preventing SID collision.
- **Reference Verification:** CVE IDs, ThreatFox tags, and URLs are validated against ground-truth capture metadata. Unverified references are omitted.
- **Protocol Constants Filtering:** Common protocol strings (`HTTP/1.1`, `Apache`, `GET`) are automatically blocked from being used as malware signatures.

### Cisco Talos / VRT "Bail Early" Performance Philosophy
Rules generated by this pipeline adhere to Cisco Talos rule engineering principles:
1. **Flow Check First:** Place `flow:established,to_server;` immediately after `msg:` to bail early on non-established or reverse traffic.
2. **Fast Pattern Designation:** Designate the longest, most distinctive non-negative byte sequence as `fast_pattern` to accelerate multi-pattern matching.
3. **Sticky Buffers:** Use Snort 3 sticky buffers (`http_uri;`, `http_client_body;`) rather than legacy Snort 2 modifiers to avoid redundant payload scanning.
4. **Guarded PCRE:** Always guard PCRE expressions with an anchored `content` match and `isdataat` boundary check to eliminate regular expression CPU denial-of-service.

### Modern Snort 3 vs. Snort 2 Syntax Compliance
Snort 3 introduced significant syntax updates that this system enforces:
- Modifiers inside `content`: Snort 3 requires modifiers to be comma-separated inside the `content` option:
  - *Correct (Snort 3):* `content:"malware_str",fast_pattern,nocase;`
  - *Incorrect (Snort 2):* `content:"malware_str"; fast_pattern; nocase;`
- Service Rules: Traditional headers like `alert tcp $EXTERNAL_NET any -> $HOME_NET 80` are upgraded where appropriate to portless service rules:
  ```snort
  alert http ( msg:"MALWARE-CNC Suspicious Request"; flow:to_server,established; http_uri; content:"/beacon.php",fast_pattern,nocase; sid:1000001; rev:1; )
  ```

### Safe Production Deployment & One-Click Rollback
Before any approved rule is appended to `rules/local.rules`, the existing ruleset is automatically archived as `rules/history/local.rules.v<N>`. If an operational issue or unexpected false positive occurs in production, the entire ruleset can be restored instantaneously using:
```bash
python -m snort_pipeline.cli rollback <version_number> --analyst "AnalystName" --reason "Operational rollback"
```
