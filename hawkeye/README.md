# 🦅 HawkEye-AI

**Autonomous AI-Assisted Log Triage, Cloud Telemetry & Intrusion Alert System for Multi-Cloud SOC Operations**

HawkEye-AI is an end-to-end cloud security pipeline that ingests enterprise network & cloud logs (AWS VPC Flow Logs, CloudTrail, UNSW-NB15), detects anomalies using Isolation Forest, scores risk severity, maps threats to the **MITRE ATT&CK Matrix for Cloud**, and executes **automated Cloud SOAR remediations** via AWS Boto3.

---

## Architecture

```
Cloud / Network Log Sources (AWS VPC Flow, CloudTrail, UNSW-NB15, NSL-KDD)
                               │
                               ▼
┌─────────────────────────────────────────────────────────┐
│  Log Ingestion & Cryptographic Integrity Hashing        │──── SHA-256 batch hash
│  (Canonical sorting & Tamper detection)                 │     (Zero-trust verification)
└──────────────────────────────┬──────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────┐
│  Unsupervised Anomaly Detection (Isolation Forest)      │──── 93.3% Precision
│  + Supervised Baseline Benchmark (Random Forest)        │     Feature Importances
└──────────────────────────────┬──────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────┐
│  Cloud Risk Scoring Engine                              │──── Likelihood × Impact
│  (Severity 1 to 5 + Cloud Context Heuristics)           │     (1: Low → 5: Critical)
└──────────────────────────────┬──────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────┐
│  MITRE ATT&CK & CIA Triad Impact Classification         │──── MITRE Cloud Matrix (T1530,
│  (Confidentiality, Integrity, Availability mapping)     │     T1496, T1078.004, T1562.007)
└──────────────────────────────┬──────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────┐
│  AI Incident Explanation (Google Gemini 3.6 Flash)     │──── Cached plain-English
│  + Automated Cloud SOAR Remediation (AWS Boto3 SDK)     │     Incident Playbooks
└──────────────────────────────┬──────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────┐
│  Cloud-Native SOC Analyst Dashboard (Streamlit)         │──── Role-gated (admin/viewer)
│  (Containerized with Docker & Scaled via Kubernetes HPA)│     CIS AWS Benchmark Checker
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Install dependencies

```bash
cd hawkeye
pip install -r requirements.txt
```

### 2. (Optional) Set up LLM API key

Get a free API key from [Google AI Studio](https://aistudio.google.com/) and set it:

```bash
# Windows PowerShell
$env:GEMINI_API_KEY = "your-api-key-here"

# Linux / macOS
export GEMINI_API_KEY="your-api-key-here"
```

> If no API key is set, the pipeline runs normally and explanations show a fallback message.

### 3. Run with AWS Cloud Telemetry

HawkEye natively supports AWS VPC Flow Logs and CloudTrail events:

```bash
# Run pipeline with AWS Cloud Telemetry
python main.py --data-fmt aws-cloud --max-explain 10

# Run pipeline with UNSW-NB15 / NSL-KDD dataset
python main.py --data-fmt unsw-nb15 --sample-size 2000
```

### 4. Launch the SOC Dashboard

```bash
streamlit run dashboard/app.py
```

---

## Cloud Computing & AWS Highlights

### 1. ☁️ AWS Cloud Telemetry & Flow Ingestion
- **AWS VPC Flow Logs (v2)**: Native parsing of VPC network flow records across multiple AWS regions (`us-east-1`, `ap-south-1`, `eu-west-1`, `us-west-2`).
- **Cloud Attack Vectors**:
  - `T1530`: S3 Bucket Data Exfiltration
  - `T1496`: EC2 Cloud Cryptomining (Resource Hijacking)
  - `T1046`: Cloud VPC Ingress Port Scanning & Security Group Probing
  - `T1562.007`: Permissive Ingress 0.0.0.0/0 Tampering
  - `T1078.004`: Cloud IAM Privilege Escalation & Access Key Abuse

### 2. ⚡ Automated Cloud SOAR with AWS Boto3
- **EC2 Instance Isolation**: Automatically detaches active security groups and attaches a zero-trust quarantine security group (`sg-hawkeye-quarantine`).
- **IAM Access Key Revocation**: Immediately deactivates leaked/compromised credentials and terminates STS sessions.
- **S3 Public Lockdown**: Enforces AWS S3 Block Public Access (`BlockPublicAcls`, `BlockPublicPolicy`).
- **VPC NACL Drop Rule**: Inserts high-priority ingress DROP rules in the VPC Network ACL.
- **Dual Execution Modes**: Supports both **Live AWS Execution** via `boto3` and **Simulation / Dry-Run Mode** for offline evaluation and vivas.

### 3. 📦 AWS S3 Cryptographic Batch Archival
- Exports incident reports to S3 (`s3://hawkeye-soc-archives/`) with **Server-Side Encryption (SSE-KMS)**.
- Tags batches with the cryptographic **SHA-256 tamper hash** and metadata.
- Implements S3 Lifecycle Transition (Standard → AWS Glacier Flexible Archive after 30 days).

### 4. 🐳 Docker & Cloud-Native Containerization
- **Hardened Dockerfile**: Multi-stage build running as non-root user `socuser` (UID 10001) for container security.
- **Docker Compose**: Orchestrates Streamlit SOC Frontend and background Telemetry Ingestion Worker on an isolated bridge network:
  ```bash
  docker-compose up --build
  ```

### 5. ☸️ Kubernetes (K8s) Cloud Orchestration
Production manifests located in `k8s/`:
- `k8s/namespace.yaml`: Dedicated `hawkeye-soc` namespace.
- `k8s/deployment.yaml`: Zero-downtime RollingUpdate deployment with health/readiness probes.
- `k8s/service.yaml`: LoadBalancer service exposing port 80 → 8501.
- `k8s/configmap.yaml` & `k8s/secret.yaml`: Cloud configuration & secret separation.
- `k8s/hpa.yaml`: **Horizontal Pod Autoscaler (HPA)** demonstrating **Cloud Elasticity** by autoscaling pods from 2 to 8 replicas based on CPU & traffic volume.

Deploy to any Kubernetes cluster (EKS, GKE, Minikube, Kind):
```bash
kubectl apply -f k8s/
```

### 6. 🏗️ Infrastructure as Code (IaC) with Terraform
Automated AWS infrastructure provisioning located in `terraform/`:
- Multi-tier VPC with Public & Private subnets across multiple AZs.
- CloudWatch Log Group for VPC Flow Logs.
- S3 Bucket for SOC logs with AES256 encryption and Glacier lifecycle rules.
- Zero-trust quarantine security group.

Deploy infrastructure:
```bash
cd terraform
terraform init
terraform plan
```

---

## Dashboard Tabs

| Tab | Key Capabilities |
|---|---|
| **🚨 SOC Alert Triage** | Live incident queue with severity color-coding, IP endpoints, port/service, and AI explanations |
| **☁️ AWS Cloud Telemetry & SOAR** | Multi-VPC telemetry metrics, CIS AWS Benchmark compliance checklist, interactive Boto3 cloud containment buttons & S3 KMS archival |
| **⚡ Live Severity Simulator** | Interactive slider/input calculator computing live severity scores, likelihood vs impact, and SOAR mitigation scripts |
| **🗺️ Global Threat Map** | Interactive 3D/2D Pydeck map showing geographical attack origins targeting HawkEye Cloud VPC |
| **📊 AI / ML Model Benchmark** | Confusion Matrix, Accuracy (97.8% RF / 81.3% IF), Precision (93.3%), Recall & Top feature importances |
| **🔐 Cryptographic Integrity** | Cryptographic SHA-256 batch hash with live interactive attacker tampering simulation |

---

## Running Tests

Run the full pytest suite (34 unit tests covering pipeline, cloud telemetry, Boto3 SOAR, and S3 archival):

```bash
cd hawkeye
pytest tests/ -v
```

All AWS and LLM calls are mocked/simulated in tests — 100% offline executable.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Cloud Provider | Amazon Web Services (AWS) |
| Cloud SDK | Boto3 (EC2, S3, IAM, CloudWatch) |
| Containerization | Docker, Docker Compose |
| Cloud Orchestration | Kubernetes (K8s), Horizontal Pod Autoscaler (HPA) |
| Infrastructure as Code | Terraform (HashiCorp AWS Provider) |
| Machine Learning | scikit-learn (Isolation Forest & Random Forest) |
| Generative AI | Google Gemini API (gemini-3.6-flash) |
| Dashboard UI | Streamlit (Custom SOC Dark Theme) |
| Cryptography | hashlib (SHA-256) |

---

## Authors

- Harsh Makwana (A018)
- Achal Chhag (A012)

MCA — SVKM's NMIMS MPSTME | Cloud Computing & Cyber Security | 2026–27
