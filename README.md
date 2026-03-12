<div align="center">

# 🛡️ Visual Network Tracker (VNT)

**An enterprise-grade Security Operations Center (SOC) platform built for everyone — from security analysts to everyday users.**



</div>

---

## 🚀 What is VNT?

Visual Network Tracker detects, analyzes, and visualizes **real-time network anomalies** using a hybrid rule-based + behavioral detection engine — and translates everything into plain English for non-technical users.

> Built as an academic mini-project by CSE students at Royal College of Engineering & Technology.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Hybrid Detection** | Combines rule-based logic with statistical anomaly detection |
| 🧠 **MITRE ATT&CK Mapping** | Every alert maps to a real-world attack technique |
| 🎭 **3-Mode Dashboard** | Analyst, Executive, and Simple mode for every type of user |
| ⚔️ **Attack Simulator** | Trigger live DoS, Port Scan, Brute Force & more |
| 📊 **Real-Time Charts** | Live polling dashboard with Chart.js visualizations |
| 💡 **Explainable AI** | Every detection comes with plain-English reasoning |

---

## 🖥️ Three Dashboard Modes

### 🔬 Analyst Mode
Raw technical data — sortable IP tables, MITRE technique IDs, JSON context drawers, risk formulas.

### 📈 Executive Mode
High-level risk summaries — translates telemetry into corporate risk statements.

### 👤 Simple Mode
Zero jargon — IPs become *"Web Server"*, attacks become *"Repeated Login Failures"*. Designed for everyday users.

---

## ⚙️ Architecture

```
Traffic Simulator (background thread, every 2–5s)
        ↓
Rule-Based Detection Engine       (detector.py)
        ↓
Behavioral Anomaly Engine         (anomaly_engine.py)
        ↓
Risk Fusion Engine  →  Final = 0.55×Rule + 0.45×Anomaly
        ↓
Explainability Engine             (explainability.py)
        ↓
SQLite Database                   (database.py)
        ↓
REST API Layer                    (app.py)
        ↓
Frontend Dashboard (polling every 5s)
```

---

## 🛠️ Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Mohdnihad17/VisualNetworkTracker.git
cd VisualNetworkTracker

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the app (Windows)
START.bat

# OR manually
cd backend
python app.py
```

### ⚠️ Important
**Do NOT open `index.html` directly.** Always run the Flask server first, then visit:
```
http://localhost:5000
```

---

## 🎯 MITRE ATT&CK Coverage

| Attack Type | Tactic | Technique |
|-------------|--------|-----------|
| `dos` | Impact | T1499 — Endpoint DoS |
| `portscan` | Discovery | T1046 — Network Service Scanning |
| `bruteforce` | Credential Access | T1110 — Brute Force |
| `suspdns` | Command & Control | T1071.004 — DNS |
| `lateral` | Lateral Movement | T1021 — Remote Services |

---

## 🧪 Trigger a Simulated Attack

From the UI, or via curl:

```bash
curl -X POST http://localhost:5000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "portscan"}'
```

Available types: `dos`, `portscan`, `bruteforce`, `suspdns`, `lateral`

---



## 📄 License

This project is licensed under the MIT License.

---


