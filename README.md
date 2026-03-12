# Visual Network Tracker

## 1. Project Overview
Visual Network Tracker is an enterprise-grade Security Operations Center (SOC) platform designed to simulate, analyze, and visualize network traffic in real-time. Uniquely, this platform bridges the gap between highly technical security analysts and non-technical stakeholders by employing an innovative three-mode interface system (Simple, Executive, Analyst). It utilizes a Python/Flask/SQLite backend with a continuous traffic generation engine and a vanilla HTML5/JS/CSS frontend.

## 2. Architecture Diagram

```asciidoc
Traffic Simulator (background thread, every 2-5s)
        ↓
Rule-Based Detection Engine          (detector.py)
        ↓
AI-Style Behavioral Deviation Engine (anomaly_engine.py)
        ↓
Risk Fusion Engine                   (explainability.py)
        ↓
Explainability Engine                (explainability.py)
        ↓
SQLite Database (persistent)         (database.py)
        ↓
REST API Layer                       (app.py)
        ↓
Frontend Dashboard (fetch polling every 5s)
```

## 3. Installation and Setup
Ensure you have Python 3.10+ installed on your system.
1. Clone the repository and navigate to the project root directory.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the startup script to initialize the SQLite database and start the backend Flask server:
   ```bash
   ./run.sh
   # (Alternatively on Windows: cd backend && python app.py)
   ```
4. Important: Do not open `index.html` directly in the browser (you will see "CONNECTION LOST").
   Instead, open `http://localhost:5000` in your web browser. The Flask backend serves the frontend automatically!

```text
THE PROBLEM:
You are opening index.html directly in the browser.
This means no data loads because the Flask backend is not running.

THE FIX — DO THIS EVERY TIME:

Step 1: Open a terminal (Command Prompt or PowerShell on Windows)

Step 2: Navigate to your project folder:
  cd path/to/VisualNetworkTracker

Step 3: Install dependencies (only needed once):
  pip install flask flask-cors python-dateutil

Step 4: Run the backend:
  cd backend
  python app.py

Step 5: You will see:
  "DB initialized."
  "Running on http://0.0.0.0:5000"
  
Step 6: NOW open the frontend:
  Open frontend/index.html in your browser
  OR go to http://localhost:5000 if Flask serves the HTML

Step 7: The green LIVE indicator confirms connection.
```

## 4. API Reference
- **GET /api/kpi**: Returns Top KPI metrics.
  - `{"total_flows": 120, "high": 5, "medium": 12, "low": 40, "avg_risk": 35.5, "open_incidents": 5}`
- **GET /api/trend**: Returns array of average risk per minute (last 30m).
- **GET /api/severity**: Returns severity distribution.
  - `{"High": 1, "Medium": 5, "Low": 50}`
- **GET /api/protocol**: Returns protocol counts.
- **GET /api/live**: Returns last 50 full detection objects.
- **GET /api/alerts**: Returns max 5 Open High-severity detections.
- **GET /api/top_src**: Top 10 source IPs.
- **GET /api/top_dst**: Top 10 destination IPs.
- **GET /api/heatmap**: Hourly count per protocol.
- **GET /api/story**: Returns last 20 5-minute story window narratives.
- **GET /api/debrief/<int:id>**: Returns an active or finished simulation grade report.
- **GET /api/report**: Returns massive report text generation endpoints.
- **POST /api/investigate**: Marks an alert as investigated. (Body: `{"id": 1}`)
- **POST /api/simulate**: Triggers a simulated attack cycle. (Body: `{"attack_type": "dos"}`)

## 5. Detection Engine Explanation
The platform utilizes a Hybrid Detection engine:
1. **Rule-Based (detector.py):** Triggers deterministic logical rules matching industry threats (e.g., Packet Bursts > 500, Port Scans across > 15 unique ports).
2. **Behavioral Anomaly (anomaly_engine.py):** Establishes an active running baseline per-internal IP. Calculates percentage deviation across data fields (packet count, byte count, flow duration) combined with statistical protocol rarity weights (e.g., IRC=90 weight vs TCP=5).
3. **Risk Fusion (explainability.py):** Fuses the results using physical constant weighting: `Final = 0.55 × Rule + 0.45 × Anomaly`.

## 6. MITRE ATT&CK Mapping Table

| Attack Profile | Tactic | Technique ID | Technique Name |
|----------------|--------|--------------|----------------|
| dos | Impact | T1499 | Endpoint Denial of Service
| portscan | Discovery | T1046 | Network Service Scanning
| bruteforce | Credential Access | T1110 | Brute Force
| suspdns | Command & Control | T1071.004 | Application Layer Protocol: DNS
| lateral | Lateral Movement | T1021 | Remote Services
| packet_burst | Impact | T1498 | Network Denial of Service
| suspicious_proto | Lateral Movement | T1021.004 | Remote Services: SSH

## 7. Three Mode System
- **Analyst Mode (Mode 1):** Raw technical data. Extensive charts, tables with sortable IP parameters, technical MITRE mappings, deep-dive JSON context, and manual investigation flows. 
- **Executive Mode (Mode 2):** High-level risk status. Translates technical telemetry into broad corporate risk statements ("Risk trending upward over last 30 minutes"). Simple severity charts, huge trend markers.
- **Simple Mode (Mode 3):** Specifically designed for non-technical users. Strips away all raw IP addresses, replacing them with generic terminology (e.g., `10.0.10.10` becomes 'Web Server'). Translates attack vectors into plain-English (e.g., 'Brute Force' -> 'Repeated Login Failures').

## 8. Flashcard System Explanation
Every detection triggers an explainability pipeline generating dual-context logic.
- **Analyst Drawers:** Deep-dives detailing specific rule scores, formula calculations, MITRE methodology links, and confidence tracking logic.
- **Simple 3D Flashcards:** Utilizes CSS 3D matrix transformations to flip cards, revealing 8th-grade-reading-level contextual analogies. (E.g., comparing port scanning to "checking all the doorknobs in a building").

## 9. Attack Simulator and Debrief System
Both Analysts and Simple users can trigger controlled simulation attacks injected natively into the data-generation pipeline. 
When triggered, a 60-second countdown tracks real-time alert parsing and provides a graded "Debrief" overlay explaining what successfully penetrated the engine, how long the system took to detect it, and real-world implications.

## 10. Design System Reference
All visual parameters operate strictly on CSS Custom Properties to simulate a professional Cyber SaaS deployment without front-end styling frameworks. Color themes include `var(--high)` #f85149, `var(--medium)` #e3b341, `var(--low)` #3fb950 across raw CSS layout-grids. All JS directly DOM manipulates for high-speed table rendering and `Chart.js` integrations without heavy Virtual DOM memory lags.

## 11. How to Trigger Simulated Attacks
Attacks can be triggered directly from the Frontend UI, or via manual Curl commands to the Flask App API:
```bash
curl -X POST http://localhost:5000/api/simulate \
     -H "Content-Type: application/json" \
     -d '{"attack_type": "portscan"}'
```

Available types: `dos`, `portscan`, `bruteforce`, `suspdns`, `lateral`

## 12. Academic Context
Visual Network Tracker heavily demonstrates modern cybersecurity methodologies:
- **Hybrid Detection:** Interfacing deterministic rule-based engines with active statistical anomaly behavior tracking.
- **Explainable AI:** Preventing algorithmic 'black boxes' by attaching plain-English readouts directly to detection instances.
- **Real-time Streaming Architecture:** Multi-threaded pipeline handling dynamic generation and polling consumption natively.
- **Non-Technical User Accessibility:** Demonstrating that strong security tools must be usable by managers and average employees using audience-tailored translations.
