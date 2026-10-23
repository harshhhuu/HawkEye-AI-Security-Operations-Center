# 🦅 HawkEye-AI

**AI-Assisted Log Triage & Intrusion Alert System for Cloud Security Operations**

HawkEye-AI is an end-to-end security pipeline that ingests network logs, detects anomalies using Isolation Forest, scores risk severity, and generates plain-English explanations for each flagged alert via an LLM — all presented on a dark-themed SOC analyst dashboard.

---

## Architecture

```
Log Source (NSL-KDD / Synthetic)
        │
        ▼
┌─────────────────────┐
│  Log Ingestion &    │──── SHA-256 batch hash
│  Parsing            │     (tamper detection)
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  Anomaly Detection  │──── Isolation Forest
│  (scikit-learn)     │     (contamination=0.15)
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  Risk Scoring       │──── likelihood × impact
│  (severity 1-5)     │     → 1 (Low) to 5 (Critical)
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  LLM Explanation    │──── Google Gemini API (gemini-3.6-flash)
│  (cached responses) │     with fallback message
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  Streamlit Dashboard│──── Role-gated (admin/viewer)
│  (SOC dark theme)   │     Integrity verification
└─────────────────────┘
```

---

## Quick Start

### 1. Install dependencies

```bash
cd hawkeye
pip install -r requirements.txt
```

### 2. (Optional) Set up LLM API key

Get a **free** API key from [Google AI Studio](https://aistudio.google.com/) and set it:

```bash
# Windows PowerShell
$env:GEMINI_API_KEY = "your-api-key-here"

# Linux / macOS
export GEMINI_API_KEY="your-api-key-here"
```

> If no API key is set, the pipeline still runs — explanations will show a fallback message.

### 3. Dataset Support (UNSW-NB15 / NSL-KDD / Synthetic)

HawkEye-AI supports modern intrusion datasets:
- **UNSW-NB15** (Modern ACCS dataset with Exploits, Fuzzers, DoS, Reconnaissance, Backdoor, Shellcode, Worms): Place `UNSW_NB15_testing-set.csv` or `UNSW_NB15_training-set.csv` in `hawkeye/data/`.
- **NSL-KDD**: Place `KDDTrain+.txt` in `hawkeye/data/`.
- **Synthetic Fallback**: If no dataset is present, a 500-entry synthetic benchmark is auto-generated.

### 4. Run the pipeline

```bash
python main.py
```

This produces `alerts.json` with all flagged alerts, severity scores, and explanations.

**Options:**
```bash
python main.py --sample-size 2000                  # Stratified sample (default: 2000, 0 for all)
python main.py --max-explain 10                    # Cap LLM calls (e.g. top 10 highest-risk)
python main.py --data-path data/custom_logs.csv    # Custom dataset file
python main.py --output results/alerts.json        # Custom output path
```

### 5. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

---

## Project Structure

```
hawkeye/
├── data/
│   ├── loader.py           # Load UNSW-NB15, NSL-KDD or synthetic CSV
│   └── synthetic.py        # Generate fallback dataset
├── pipeline/
│   ├── ingest.py           # Parse + clean + SHA-256 hash
│   ├── detect.py           # Isolation Forest anomaly detection
│   ├── score.py            # Risk scoring (severity 1-5)
│   ├── explain.py          # LLM explanation + response caching
│   ├── threat_intel.py     # MITRE ATT&CK & CIA Triad mapping (Step 1)
│   ├── benchmark.py        # ML evaluation, confusion matrix & RF comparison (Step 2)
│   ├── playbooks.py        # SOAR playbooks, iptables & AWS SG rules (Step 3)
│   └── geoip.py            # GeoIP coordinates & threat reputation (Bonus)
├── dashboard/
│   └── app.py              # Multi-tab Streamlit SOC intelligence dashboard
├── auth/
│   └── roles.py            # Admin/viewer role gating
├── tests/
│   └── test_pipeline.py    # Pytest suite (24 unit tests)
├── .streamlit/
│   └── config.toml         # Dark theme configuration
├── main.py                 # Pipeline orchestrator
├── requirements.txt
└── README.md
```

---

## Dashboard Features

| Feature | Description |
|---|---|
| **🚨 SOC Alert Triage** | Live incident queue with severity color-coding, IP endpoints, port/service, and AI explanations |
| **🎯 MITRE ATT&CK & CIA Triad** | Tags every alert with Confidentiality/Integrity/Availability and MITRE Technique IDs (T1499, T1190, etc.) |
| **🛡️ SOAR Playbooks & Firewall** | Generates copyable Linux `iptables`, AWS Security Group revocation commands, Snort rules & NIST workflows |
| **🗺️ Global Threat Map** | Interactive 3D/2D Pydeck map showing geographical attack origins targeting HawkEye Cloud VPC |
| **📊 AI / ML Model Benchmark** | Confusion Matrix, Accuracy (92.5%), Precision (92.1%), Recall (97.3%), ROC-AUC (0.976) & Top Features |
| **🔐 Log Integrity** | Cryptographic SHA-256 batch hash with live interactive attacker tampering simulation |
| **👤 Role-Based Access** | Admin can dismiss alerts, execute playbooks, and export CSVs; viewer is read-only |

---

## Running Tests

```bash
cd hawkeye
pytest tests/test_pipeline.py -v
```

All LLM calls are mocked in tests — no API key needed.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Data | pandas |
| ML | scikit-learn (Isolation Forest) |
| LLM | OpenRouter — NVIDIA Nemotron (free) |
| Dashboard | Streamlit |
| Integrity | hashlib (SHA-256) |
| Dataset | NSL-KDD / synthetic fallback |

---

## Authors

- Harsh Makwana (A018)
- Achal Chhag (A012)

MCA — SVKM's NMIMS MPSTME | Cloud Computing & Cyber Security | 2026–27
