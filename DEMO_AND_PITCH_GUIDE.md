# 🦅 HawkEye-AI: Project Pitch & Demonstration Guide

**Autonomous AI-Assisted Multi-Cloud Security Operations Center (SOC)**  
*Cloud Computing & Cyber Security (CC&CS) Project | SVKM's NMIMS MPSTME — MCA Sem 3 (2026–27)*  
**Authors:** Harsh Makwana (A018) | Achal Chhag (A012)

---

## 1. The Executive Project Pitch (The 60-Second Hook)

> *"Good morning / afternoon professors. Today, we are presenting **HawkEye-AI** — an autonomous, cloud-native Security Operations Center (SOC) platform designed to solve the single largest bottleneck in enterprise cloud security: **Alert Fatigue and Delayed Incident Response**."*

| Dimension | Description |
|---|---|
| **The Enterprise Problem** | Modern cloud infrastructures on AWS generate millions of telemetry records daily (VPC Flow Logs, CloudTrail). SOC analysts are overwhelmed by false alarms, taking an average of 20 to 45 minutes to investigate a single incident, during which data exfiltration or lateral movement occurs. |
| **The HawkEye Solution** | HawkEye-AI combines **Unsupervised Machine Learning (Isolation Forest)** with **Generative AI (Google Gemini)** and **Cloud SOAR Automation (AWS Boto3 & Terraform)** to ingest cloud telemetry, detect subtle anomalies in milliseconds, explain them in plain English, and isolate compromised workloads with zero human latency. |
| **Dual-Subject Bridge** | Bridges **Cyber Security** (Zero-Trust, MITRE ATT&CK Matrix for Cloud, SHA-256 tamper detection) directly with **Cloud Computing** (AWS VPC Flow Logs, S3 Glacier lifecycle tiering, Docker container hardening, Kubernetes Horizontal Pod Autoscaler elasticity, and Terraform Infrastructure as Code). |
| **Key Business Impact** | Reduces mean-time-to-detect (MTTD) from 30 minutes to sub-second ingestion, achieves **93.3% Precision** in filtering false alarms, and automates AWS containment playbooks with a single click. |

---

## 2. Step-by-Step Live Demonstration Walkthrough

### Step 1: Real Cloud Telemetry Pipeline Execution
**Terminal Command:**
```bash
python main.py --data-fmt aws-cloud --max-explain 5
```
**What to Explain to Examiners:**
- HawkEye ingests real AWS VPC Flow Logs (Version 2) across 3 VPCs and 4 AWS regions (`us-east-1`, `ap-south-1`, `eu-west-1`, `us-west-2`).
- Highlight the 5-stage automated pipeline: `Loading` ➔ `SHA-256 Hashing` ➔ `Isolation Forest Anomaly Detection` ➔ `Likelihood × Impact Risk Scoring` ➔ `Gemini GenAI Explanations`.
- In under 3 seconds, 600 cloud logs were parsed and 90 true threats were isolated.

---

### Step 2: Launch the SOC Analyst Intelligence Dashboard
**Terminal Command:**
```bash
streamlit run dashboard/app.py
```
**What to Show on Screen:**
- Live dark-themed SOC interface with real-time KPI metrics.
- **Role-Based Access Control (RBAC)**: Toggle between `Admin` (Read & Write with containment permissions) and `Viewer` (Read-Only auditing).
- **Live Incident Triage Queue**: Each alert shows Source/Target IP, Port, Severity Level (1 to 5), and the AI-generated plain-English explanation.

---

### Step 3: The Dedicated "☁️ AWS Cloud Telemetry & SOAR" Center
**Where to Click:** Tab 2 in the Dashboard (`☁️ AWS Cloud Telemetry & SOAR`)  
**What to Show & Demonstrate:**
1. **Cloud Architecture KPIs**: 3 Monitored VPCs, 4 AWS Regions, Flagged EC2 Instance (`i-0a87612f`).
2. **Cloud-Native Attack Queue**:
   - `T1530`: S3 Bucket Data Exfiltration
   - `T1496`: EC2 Cloud Cryptomining Resource Hijacking
   - `T1562.007`: Permissive Ingress `0.0.0.0/0` Security Group Tampering
   - `T1078.004`: Cloud IAM Privilege Escalation
3. **Interactive Cloud SOAR Remediation**:
   - Select an incident, click **"🚀 Execute Cloud Remediation Now"**
   - Show the real-time AWS Boto3 JSON execution receipt with Request ID, affected resource, and zero-trust quarantine security group attachment (`sg-hawkeye-quarantine`).
4. **CIS AWS Foundations Benchmark**:
   - 5 automated compliance checks (Root MFA, Ingress 22/3389, S3 Public Block, Multi-region CloudTrail, VPC Flow Logs).
5. **S3 Encrypted Archival**:
   - Click **"Archive to S3"** ➔ Demonstrates Server-Side Encryption (SSE-KMS) and the 30-day AWS Glacier lifecycle transition.

---

### Step 4: AI / ML Model Benchmark & False Positive Reduction
**Where to Click:** Tab 5 in Dashboard (`📊 AI / ML Model Benchmark`)  
**What to Explain to Examiners:**
- **Unsupervised Model (Isolation Forest)**: 81.3% Accuracy, **93.3% Precision** (only 6 false positives out of 600 records!). Explain why unsupervised learning is required for real-world zero-day attacks where training labels don't exist.
- **Supervised Benchmark (Random Forest Baseline)**: 97.8% Accuracy, 100% Precision, 0.997 ROC-AUC.
- **Top Feature Importances**: Connection duration (45.9%), packet velocity (23.7%), bytes transferred (12.1%).

---

### Step 5: Cryptographic Tamper-Proof Log Integrity Demo
**Where to Click:** Tab 6 in Dashboard (`🔐 Cryptographic Integrity`)  
**Live Interactive Demo:**
- Point out the SHA-256 batch hash computed at ingestion time.
- Click the **"⚠️ Mutate Telemetry Row (Simulate Attacker Tampering)"** button.
- The SHA-256 hash immediately recomputes, mismatches the original digest, and displays a RED Alert: *"TAMPERING DETECTED! Zero-Trust Cryptographic Verification Failed!"*

---

### Step 6: Docker Container Hardening & Kubernetes Autoscaling
**What Code to Open & Explain:**
- **Dockerfile** ([`hawkeye/Dockerfile`](file:///d:/NMIMS%20-%20MCA/Sem%203/CC&CS%20Project/hawkeye/Dockerfile)): Explain container hardening — runs as non-root user `socuser` (UID 10001) for Least Privilege compliance.
- **docker-compose.yml** ([`hawkeye/docker-compose.yml`](file:///d:/NMIMS%20-%20MCA/Sem%203/CC&CS%20Project/hawkeye/docker-compose.yml)): Microservice separation between `soc-dashboard` and `pipeline-worker` with bounded CPU/RAM quotas.
- **Kubernetes HPA** ([`hawkeye/k8s/hpa.yaml`](file:///d:/NMIMS%20-%20MCA/Sem%203/CC&CS%20Project/hawkeye/k8s/hpa.yaml)): Explain Cloud Elasticity — autoscales pods from 2 to 8 replicas based on CPU threshold (75%) and ingestion spikes.

---

### Step 7: Real AWS Infrastructure as Code (Terraform)
**Terminal Command & AWS Proof:**
```bash
cd terraform
terraform output
```
**What to Show to Examiners:**
- Show that Terraform provisioned real AWS cloud infrastructure in account **`305718149998`** (region: `us-east-1`):
  - **Real VPC ID**: `vpc-0933a144e352bfcaa`
  - **Real S3 Bucket**: `hawkeye-soc-archives-staging-305718149998`
  - **Real Quarantine SG**: `sg-08e00f85fe6e0fa5c`
  - **Real Subnets**: `subnet-01dcd510b125503ac` & `subnet-08bfd5dd657cc8a8d`
- Demonstrate `terraform plan` showing how Terraform calculates the declarative 15-resource diff before touching the cloud.

---

## 3. Viva Q&A & Examiner Talking Points Cheat Sheet

### Q1: Why did you use Isolation Forest (Unsupervised) instead of normal classification?
> **Answer:** In real enterprise cloud operations, 99% of logs are unlabeled, and attackers constantly invent novel zero-day exploits. Supervised algorithms only recognize attacks they were trained on. Isolation Forest isolates anomalies based on the principle that outliers are few and statistically distinct in feature space, making it capable of catching brand-new attack patterns without prior training labels.

### Q2: What is the point of Docker if you are running it on a local laptop?
> **Answer:** In Cloud Computing, code is never shipped as loose files. The industry-standard deployment unit is an OCI-compliant container image. Docker eliminates the "works on my machine" issue by packaging dependencies, guarantees identical runtime on AWS ECS or Kubernetes, and enforces security hardening by running as an unprivileged non-root user (UID 10001) to prevent container escape.

### Q3: What is the difference between Terraform and Python Boto3 scripts?
> **Answer:** Boto3 is **imperative** (you must write code specifying HOW to create resources, handle existing resources, and handle deletion). Terraform is **declarative** (you declare WHAT the target state should be in `main.tf`). Terraform maintains a state file (`terraform.tfstate`), automatically calculates dependencies via a Directed Acyclic Graph (DAG), and provides drift detection via `terraform plan`.

### Q4: How does your project address FinOps and Cloud Cost Optimization?
> **Answer:** Storing raw security logs in AWS S3 Standard costs $0.023 per GB/month. In `hawkeye/terraform/main.tf`, we implemented an automated S3 Lifecycle Configuration rule that transitions logs to AWS Glacier Flexible Archive after 30 days ($0.0036/GB/month), reducing cloud log retention costs by approximately **84%** while maintaining regulatory compliance.

### Q5: How does the AI LLM (Gemini) help the SOC analyst?
> **Answer:** Junior SOC analysts often lack the specialized knowledge to decode raw hex flags or strange port combinations. HawkEye feeds structured telemetry into Google Gemini 3.6 Flash with a zero-shot prompt template, generating plain-English explanations explaining why the packet is suspicious and mapping it to NIST SP 800-61 incident response containment playbooks.

### Q6: How do you prevent LLM API rate limits and unnecessary cloud API costs?
> **Answer:** We built a deterministic response-caching engine (`hawkeye/alerts_cache.json`). Every alert is hashed by its core telemetry tuple. If an identical packet signature has already been triaged, HawkEye serves the cached explanation instantly with 0ms latency and zero API cost.

---

## 4. Project Metrics & Cloud Architecture Summary Table

| Metric / Dimension | Implementation in HawkEye-AI |
|---|---|
| **Cloud Provider** | Amazon Web Services (AWS) — Region: `us-east-1` (N. Virginia) |
| **Live AWS Infrastructure** | VPC (`vpc-0933a144e352bfcaa`), S3 Bucket (`hawkeye-soc-archives-staging-305718149998`), Quarantine SG (`sg-08e00f85fe6e0fa5c`), Subnets, CloudWatch |
| **Cloud Telemetry** | AWS VPC Flow Logs (v2) + AWS CloudTrail Management Plane events |
| **ML Anomaly Detection** | scikit-learn Isolation Forest (`contamination=0.15`, **Precision: 93.3%**) |
| **Supervised Baseline** | Random Forest Classifier (**Accuracy: 97.8%**, **Precision: 100%**, ROC-AUC: 0.997) |
| **Containerization** | Hardened multi-stage Dockerfile (non-root `socuser` UID 10001) |
| **Cloud Elasticity** | Kubernetes Horizontal Pod Autoscaler (HPA) auto-scaling 2 to 8 pod replicas |
| **Infrastructure as Code** | HashiCorp Terraform (Validated 15-resource cloud blueprint) |
| **Automated Cloud SOAR** | AWS Boto3 Remediation (EC2 Quarantine, IAM Revocation, S3 Lockdown, NACL Drop) |
| **Cost Optimization (FinOps)** | S3 Lifecycle transition to Glacier Flexible Archive (84% storage savings) |
