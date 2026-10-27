# 🦅 HawkEye-AI — Official Run Commands Guide

**Essential Execution Cheat Sheet for Demonstration & Evaluation**  
*SVKM's NMIMS MPSTME — MCA Sem 3 | Cloud Computing & Cyber Security*  
**Authors:** Harsh Makwana (A018) | Achal Chhag (A012)

---

### 1. Environment Setup & Dependencies
Run once to install all dependencies:
```powershell
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye"
pip install -r requirements.txt
$env:GEMINI_API_KEY = "your-api-key-here"  # Optional
```

---

### 2. Run the Main Cloud AI Pipeline
Ingests AWS VPC Flow Logs & CloudTrail, runs Isolation Forest anomaly detection, risk scoring, and Gemini explanations:
```powershell
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye"
python main.py --data-fmt aws-cloud --max-explain 5
```

---

### 3. Launch the Live SOC Intelligence Dashboard
Starts the interactive Streamlit SOC dashboard with multi-VPC metrics, Boto3 cloud containment, and MITRE mapping:
```powershell
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye"
streamlit run dashboard/app.py
```
> Opens automatically in your browser at: `http://localhost:8501`

---

### 4. Run the Full Test Suite
Runs all 34 automated unit tests covering pipeline, cloud telemetry, Boto3 SOAR, and S3 archival:
```powershell
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye"
pytest tests/ -v
```

---

### 5. Run with Docker Compose (Multi-Container)
Builds and runs the SOC Dashboard and Background Telemetry Worker in isolated containers:
```powershell
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye"
docker-compose up --build

# To stop and cleanly remove containers:
docker-compose down
```

---

### 6. Deploy to Kubernetes (K8s) Cluster
Deploys namespace, configmaps, pods, load balancer service, and Horizontal Pod Autoscaler (HPA):
```powershell
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye"
kubectl apply -f k8s/

# Verify running pods & autoscaler:
kubectl get pods,hpa -n hawkeye-soc
```

---

### 7. Terraform Infrastructure as Code (AWS Cloud)
Manages the 15 AWS cloud resources (VPC, Subnets, S3 encrypted bucket with Glacier lifecycle, Quarantine SG):
```powershell
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye\terraform"

# 1. Preview changes (Dry-run / free)
terraform plan

# 2. Provision resources in AWS
terraform apply

# 3. View live AWS IDs (VPC, S3, Security Group)
terraform output

# 4. Clean up and delete all AWS resources
terraform destroy
```

---

### 8. The 3-Step Live Viva / Presentation Sequence
The exact 3 commands to run when demonstrating to the examiner:
```powershell
# Step 1: Run Cloud Ingestion & AI Pipeline
cd "d:\NMIMS - MCA\Sem 3\CC&CS Project\hawkeye"
python main.py --data-fmt aws-cloud --max-explain 5

# Step 2: Show Live AWS Cloud Provisioning IDs
cd terraform
terraform output

# Step 3: Launch the SOC Analyst Dashboard
cd ..
streamlit run dashboard/app.py
```
