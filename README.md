# Adaptive Threat Detection & Hunting Platform (Mini-SIEM)

A lightweight, real-time threat detection and hunting platform designed for modern Security Operations Center (SOC) workflows. This platform ingests live system logs, normalizes them, runs behavioral detection rules, and visualizes alerts in a premium cyber-themed dashboard.

---

## 🚀 Architecture Overview
The platform follows a modular pipeline architecture:
**Log Sources** (Windows Events, System Files) → **Live Collector** → **Normalization Engine** → **Detection Rules** → **Risk Scorer** → **FastAPI Backend** → **React Dashboard**

---

## ✨ Key Features
- **Real-Time Log Ingestion**: Active polling of Windows Security and System events using `pywin32`.
- **Intelligent Normalization**: Converts diverse log formats (Windows, Linux, JSON) into a unified JSON schema.
- **Modular Detection Engine**: Built-in rules for catching **SSH Brute Force**, **Port Scanning**, and **Suspicious Process Executions** (e.g., encoded PowerShell).
- **Dynamic Risk Scoring**: Risk scores are calculated per event and alert, allowing for prioritization of critical threats.
- **Premium Dashboard**: A "Cyber-Dark" themed React UI featuring real-time log streams, risk trend charts (Chart.js), and severity-based alert cards.

---

## 🛠️ Tech Stack
- **Backend**: Python 3.x, FastAPI, SQLModel (SQLAlchemy)
- **Database**: PostgreSQL (Production)
- **Frontend**: React, Vite, Tailwind CSS, Chart.js, Lucide Icons
- **Operating System**: Windows (Optimized for win32 event logs)

---

## 📦 Installation & Setup

### 1. Database Configuration
Ensure PostgreSQL is installed and running.
1. Create a database named `threat_platform`.
2. Configure your credentials in `backend/app/database.py` or set environment variables:
   ```powershell
   $env:DB_USER="postgres"
   $env:DB_PASSWORD="your_password"
   ```

### 2. Backend Setup
```bash
cd backend
pip install -r requirements.txt  # If requirements.txt is provided, or install:
# pip install fastapi uvicorn sqlmodel psycopg2-binary pywin32
python -m uvicorn app.main:app --reload
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## 🛡️ Running Live Detection

### Launch the Live Collector (Elevated)
To read Windows Security Logs (for brute-force detection), the collector must run with Administrator privileges:
1. Locate `run_collector_admin.bat` in the root directory.
2. Double-click to run. It will trigger a UAC prompt and launch the real-time collector in a new window.

### Simulated Attack Verification
If you wish to test the engine without waiting for real attacks, use the included script:
```bash
python simulate_attacks.py
```

---

## 📊 Dashboard Usage
- **Alert Feed**: Monitor the top section for glowing red cards indicating critical threats.
- **Risk Trends**: Check the line graph to identify spikes in suspicious activity.
- **Raw Stream**: Use the right-hand panel to view every single event being processed by your machine in real-time.

---

## 🔮 Future Roadmap
- [ ] Integration with Elastic Stack (ELK)
- [ ] ML-based Anomaly Detection Module
- [ ] Graph-based Attack Path Visualization (Cytoscape.js)
- [ ] Automated Incident Response (SOAR) playbooks

---

**Developed for SOC Analysts & Detection Engineers.**
