
# 🍯 Zero-Trust Micro Honeypot Mesh for SME Networks

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![Cloudflare](https://img.shields.io/badge/Cloudflare-Tunnel-orange?style=for-the-badge&logo=cloudflare)

> A professional-grade, modular honeypot mesh system designed for Small-to-Medium Enterprise (SME) defensive cybersecurity. Built for SOC engineering, security research, and portfolio demonstration.

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Public Access](#-public-access-via-cloudflare-tunnel)
- [Dashboard Features](#-dashboard-features)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Threat Scoring](#-threat-scoring)
- [Requirements](#-requirements)
- [Security Note](#-security-note)
- [Project Phases](#-project-phases)
- [Author](#-author)
- [License](#-license)

---

## 🎯 Project Overview

This project deploys a network of fake services (SSH, HTTP, SMB) that attract and log attacker behavior in real time. All captured data is analyzed using AI-based anomaly detection and mapped to the MITRE ATT&CK framework.

**Key Goals:**
- Capture real attacker credentials and behavior
- Detect brute force, lateral movement, and web attacks
- Provide real-time visual monitoring via web dashboard
- Map all attacks to MITRE ATT&CK techniques
- Deploy using Docker for zero-trust isolation

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 SSH Honeypot | Captures username/password brute force attempts |
| 🌐 HTTP Honeypot | Logs web-based login attacks |
| 📁 SMB Honeypot | Detects lateral movement attempts |
| 🧠 AI Detection | Threat scoring and anomaly analysis |
| 🎯 MITRE ATT&CK | Maps attacks to MITRE techniques |
| 🔗 Mesh Controller | Quarantines IPs that exceed threshold |
| 📊 Live Dashboard | Real-time web dashboard with charts |
| 📄 PDF Export | Download attack reports as PDF |
| 📊 CSV Export | Export attack logs as CSV |
| 🐳 Docker Ready | Full containerized deployment |
| ☁️ Cloudflare Tunnel | Public URL without port forwarding |
| 🔄 Auto Refresh | Dashboard updates every 10 seconds |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│           Zero-Trust Honeypot Mesh           │
├─────────────┬─────────────┬─────────────────┤
│ SSH Honeypot│ HTTP Honeypot│  SMB Honeypot  │
│  Port 2222  │  Port 8080  │   Port 4445     │
├─────────────┴─────────────┴─────────────────┤
│              Core Logging Engine             │
│           (JSON + Rotating Files)            │
├─────────────────────────────────────────────┤
│              Mesh Controller                 │
│         (Quarantine + Blocklist)             │
├─────────────────────────────────────────────┤
│           AI Anomaly Detector                │
│       (Threat Scoring + MITRE Mapping)       │
├─────────────────────────────────────────────┤
│            Web Dashboard                     │
│     (Real-time Charts + Export)              │
└─────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
zt-honeypot-mesh/
├── config/
│   └── settings.py              # Central configuration
├── core_logging/
│   └── logger.py                # JSON logging engine
├── honeypots/
│   ├── ssh/
│   │   └── ssh_honeypot.py      # Fake SSH server
│   ├── http/
│   │   └── http_honeypot.py     # Fake HTTP server
│   └── smb/
│       └── smb_honeypot.py      # Fake SMB server
├── mesh/
│   └── controller.py            # Mesh + quarantine logic
├── ai/
│   └── anomaly_detector.py      # AI threat detection
├── siem/
│   └── wazuh_forwarder.py       # SIEM integration
├── dashboard/
│   ├── app.py                   # Flask web server
│   ├── templates/
│   │   └── index.html           # Dashboard UI
│   └── static/
│       ├── style.css            # Styling
│       └── script.js            # Charts + logic
├── Dockerfile                   # SSH honeypot container
├── Dockerfile.http              # HTTP honeypot container
├── Dockerfile.smb               # SMB honeypot container
├── docker-compose.yml           # Full mesh deployment
├── requirements.txt             # Python dependencies
├── start.sh                     # One-click start script
└── .gitignore                   # Ignored files
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Docker + Docker Compose
- Kali Linux / Ubuntu

### Installation

```bash
# Clone the repository
git clone https://github.com/alsaif26/zt-honeypot-mesh.git
cd zt-honeypot-mesh

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make start script executable
chmod +x start.sh
```

### Run Locally

```bash
./start.sh
```

### Run with Docker

```bash
docker compose up --build
```

### Access Dashboard

Open your browser and go to:

```
http://localhost:8888
```

---

## 🌐 Public Access via Cloudflare Tunnel

### Install cloudflared

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
```

### Start Tunnel

```bash
cloudflared tunnel --url http://localhost:8888
```

You will get a public URL like:

```
https://your-tunnel.trycloudflare.com
```

Share this URL with anyone — they can view your live dashboard from anywhere in the world.

---

## 📊 Dashboard Features

| Feature | Description |
|---|---|
| Live Stats | Real-time SSH, HTTP, SMB attack counts |
| Attack Charts | Doughnut chart for attack distribution |
| MITRE Heatmap | Bar chart for ATT&CK techniques |
| Top Attacker IPs | Ranked list with threat levels |
| Search & Filter | Filter by IP or attack type |
| Live Attack Feed | Real-time attack log table |
| PDF Export | Download full attack report |
| CSV Export | Export raw attack data |
| JSON Export | Raw API data |
| Auto Refresh | Updates every 10 seconds |

---

## 🎯 MITRE ATT&CK Mapping

| Event | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| SSH Password Attack | T1110.001 | Brute Force: Password Guessing | Credential Access |
| SSH Public Key Attack | T1110.004 | Brute Force: Credential Stuffing | Credential Access |
| HTTP Login Attack | T1190 | Exploit Public-Facing Application | Initial Access |
| SMB Connection | T1021.002 | Remote Services: SMB | Lateral Movement |
| IP Quarantine | T1110 | Brute Force | Credential Access |

---

## 🔒 Threat Scoring

| Score | Level | Description |
|---|---|---|
| 0 - 30 | 🟢 LOW | Normal scanning activity |
| 31 - 60 | 🟡 MEDIUM | Targeted attack attempt |
| 61 - 100 | 🔴 HIGH | Active brute force attack |

**Scoring Formula:**
- 1-4 attempts: `count × 2` points
- 5-9 attempts: `+15` points
- 10-19 attempts: `+30` points
- 20+ attempts: `+50` points
- Multiple service attacks: `+10` per unique service

---

## 📦 Requirements

```
paramiko==3.4.0
cryptography==42.0.5
bcrypt==4.1.3
flask==3.0.3
```

---

## 🛡️ Security Note

This project is for **defensive cybersecurity** purposes only.

All honeypot services:
- ✅ Never grant access to any real system
- ✅ Only log attacker behavior
- ✅ Run in isolated Docker containers
- ✅ Follow zero-trust architecture principles
- ✅ Use rotating log files to prevent disk exhaustion
- ✅ Run as non-root users inside containers

---

## 📈 Project Phases

| Phase | Description | Status |
|---|---|---|
| Phase 1 | SSH Honeypot + Docker + JSON Logging | ✅ Complete |
| Phase 2 | HTTP + SMB Honeypot + Central Logging | ✅ Complete |
| Phase 3 | Mesh Communication + Quarantine Logic | ✅ Complete |
| Phase 4 | SIEM Integration + Wazuh Forwarder | ✅ Complete |
| Phase 5 | AI Anomaly Detection + MITRE ATT&CK | ✅ Complete |
| Bonus | Web Dashboard + PDF/CSV Export + Cloudflare | ✅ Complete |

---

## 👤 Author

**Mohammed Saif Al Sabah**

- 🐙 GitHub: [@alsaif26](https://github.com/alsaif26)
- 📧 Email: mohammedsaifalsabah@gmail.com

---

## 📄 License

MIT License — Free to use for educational and research purposes.

---

<div align="center">

⭐ **Star this repo if you found it useful!** ⭐

</div>
