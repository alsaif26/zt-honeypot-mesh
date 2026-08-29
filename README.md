
# 🍯 Zero-Trust Micro Honeypot Mesh for SME Networks

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker%20Compose-Deployed-2496ED?style=for-the-badge&logo=docker)
![Flask](https://img.shields.io/badge/Flask-3.0.3-000000?style=for-the-badge&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)

> A modular honeypot mesh for Small-to-Medium Enterprise (SME) defensive
> cybersecurity. Six containerised services capture attacker behaviour on fake
> SSH, HTTP and SMB endpoints, score it against MITRE ATT&CK, and surface it in
> a real-time SOC dashboard. Built for SOC engineering practice, security
> research and portfolio demonstration.

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Service & Port Map](#-service--port-map)
- [Architecture](#-architecture)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Operating the Mesh](#-operating-the-mesh)
- [Testing the Honeypots](#-testing-the-honeypots)
- [Dashboard](#-dashboard)
- [Threat Scoring](#-threat-scoring)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Logging](#-logging)
- [Local Python Development (Optional)](#-local-python-development-optional)
- [Public Access via Cloudflare Tunnel (Optional)](#-public-access-via-cloudflare-tunnel-optional)
- [Security & Responsible Use](#-security--responsible-use)
- [Project Status](#-project-status)
- [Requirements](#-requirements)
- [Roadmap](#-roadmap)
- [Author](#-author)
- [License](#-license)

---

## 🎯 Project Overview

This project deploys a mesh of deliberately fake network services that attract
and record attacker behaviour. Nothing it exposes grants access to anything
real — every service exists purely to observe and log.

Captured events flow through a shared JSON logging engine into two analysis
services: a mesh controller that quarantines noisy source IPs, and an anomaly
detector that assigns threat scores and maps activity to MITRE ATT&CK
techniques. A Flask dashboard then presents the result as a SOC-style console.

**Key goals**

- Capture real attacker credentials, payloads and behaviour
- Detect brute-force, web exploitation and lateral-movement attempts
- Score and prioritise activity per source IP
- Map observed activity to MITRE ATT&CK techniques
- Present everything in a live monitoring dashboard
- Run isolated in Docker, following zero-trust principles

---

## 🔌 Service & Port Map

All six services are defined in `docker-compose.yml` and run on the isolated
`honeypot-mesh` bridge network (`172.20.0.0/24`).

| Service | Container | Port | Purpose |
|---|---|---:|---|
| SSH Honeypot | `zt-ssh-honeypot` | 2222 | Captures SSH authentication attempts |
| HTTP Honeypot | `zt-http-honeypot` | 8080 | Captures web/login attacks |
| SMB Honeypot | `zt-smb-honeypot` | 4445 | Captures SMB activity |
| Dashboard | `zt-dashboard` | 8888 | Web-based SOC monitoring |
| AI Detector | `zt-ai-detector` | — | Threat scoring + MITRE mapping (no exposed port) |
| Mesh Controller | `zt-mesh-controller` | — | Quarantine / blocklist logic (no exposed port) |

The AI detector and mesh controller intentionally publish no ports; they are
log processors, not network listeners.

---

## 🏗️ Architecture

```
                    ┌──────────────────────────────────────┐
   Attacker  ──────▶│  SSH :2222   HTTP :8080   SMB :4445  │
   traffic          │        (honeypot containers)          │
                    └───────────────────┬──────────────────┘
                                        │  JSON events
                                        ▼
                    ┌──────────────────────────────────────┐
                    │  Core Logging Engine                  │
                    │  core_logging/logger.py               │
                    │  JSON lines + rotating files          │
                    │  Docker volume: honeypot-logs         │
                    └───────┬───────────────────┬──────────┘
                            │ tails logs        │ tails logs
                            ▼                   ▼
              ┌───────────────────────┐ ┌──────────────────────────┐
              │  Mesh Controller       │ │  Anomaly Detector         │
              │  mesh/controller.py    │ │  ai/anomaly_detector.py   │
              │  counts attempts,      │ │  threat score 0-100,      │
              │  quarantines IPs       │ │  MITRE ATT&CK mapping     │
              │  → mesh_controller.json│ │  → ai_detector.json       │
              └───────────┬───────────┘ └────────────┬─────────────┘
                          │                          │
                          └────────────┬─────────────┘
                                       ▼
                    ┌──────────────────────────────────────┐
                    │  Dashboard :8888                      │
                    │  dashboard/app.py (Flask)             │
                    │  reads all JSON logs, serves REST API │
                    │  + SOC Command Center UI              │
                    └──────────────────────────────────────┘
```

**Data flow:** honeypots only ever *write* events. The mesh controller and
anomaly detector *tail* those log files and write their own analysis logs. The
dashboard is strictly *read-only* — it aggregates every log file into its API.
This keeps the components decoupled: any service can restart independently
without breaking the others.

---

## ✨ Features

| Feature | Description | State |
|---|---|---|
| 🔐 SSH Honeypot | Fake OpenSSH server (Paramiko); captures usernames, passwords, pubkey attempts | ✅ Implemented |
| 🌐 HTTP Honeypot | Fake admin login page; captures submitted credentials and request metadata | ✅ Implemented |
| 📁 SMB Honeypot | TCP listener on 4445; logs connections and raw payload hex | ✅ Implemented |
| 🧾 JSON Logging | Structured JSON-lines logging with rotation, node ID and hostname | ✅ Implemented |
| 🔗 Mesh Controller | Counts attempts per IP, quarantines above a configurable threshold | ✅ Implemented |
| 🧠 Anomaly Detection | Rule-based threat scoring (0–100) with LOW/MEDIUM/HIGH levels | ✅ Implemented |
| 🎯 MITRE ATT&CK | Five technique mappings applied to captured events | ✅ Implemented |
| 📊 SOC Dashboard | Flask + Chart.js console with KPIs, live feed, analytics, health | ✅ Implemented |
| 📄 Exports | CSV and JSON server-side; PDF generated client-side (jsPDF) | ✅ Implemented |
| 🔄 Auto Refresh | Dashboard fetches fresh data every 10 seconds (no page reload) | ✅ Implemented |
| 🐳 Docker Compose | Six-service containerised deployment on an isolated bridge network | ✅ Implemented |
| 🛰️ Wazuh / SIEM | `siem/wazuh_forwarder.py` is an empty scaffold — no forwarding logic yet | ⚠️ Not implemented |
| ☁️ Cloudflare Tunnel | Documented as an optional external step; no config in this repo | ℹ️ Optional / external |

---

## 📁 Project Structure

```
zt-honeypot-mesh/
├── ai/
│   ├── __init__.py
│   └── anomaly_detector.py      # Rule-based threat scoring + MITRE mapping
├── config/
│   ├── __init__.py
│   └── settings.py              # Central configuration (env-var driven)
├── core_logging/
│   ├── __init__.py
│   └── logger.py                # JSON-lines logging engine with rotation
├── dashboard/
│   ├── __init__.py
│   ├── app.py                   # Flask app: REST API + dashboard (port 8888)
│   ├── templates/
│   │   └── index.html           # SOC Command Center markup
│   └── static/
│       ├── style.css            # Dark SOC theme
│       └── script.js            # Data fetching, charts, filters, PDF export
├── honeypots/
│   ├── __init__.py
│   ├── ssh/
│   │   ├── __init__.py
│   │   └── ssh_honeypot.py      # Paramiko-based fake SSH server (2222)
│   ├── http/
│   │   ├── __init__.py
│   │   └── http_honeypot.py     # Fake admin login page (8080)
│   └── smb/
│       ├── __init__.py
│       └── smb_honeypot.py      # SMB-style TCP listener (4445)
├── mesh/
│   ├── __init__.py
│   └── controller.py            # Attempt counting + IP quarantine
├── siem/
│   ├── __init__.py
│   └── wazuh_forwarder.py       # Empty scaffold — Wazuh forwarding not built
├── Dockerfile                   # SSH honeypot image
├── Dockerfile.http              # HTTP honeypot image
├── Dockerfile.smb               # SMB honeypot image
├── Dockerfile.analytics         # Shared image for AI detector + mesh controller
├── Dockerfile.dashboard         # Dashboard image
├── docker-compose.yml           # Six-service mesh deployment
├── requirements.txt             # Python dependencies
├── .gitignore
└── README.md
```

> Note: captured logs are **not** committed. `logs/` is git-ignored and, in the
> Docker deployment, lives in the `honeypot-logs` volume.

---

## 🚀 Quick Start

### Prerequisites

- Docker Engine with the Compose plugin (`docker compose`)
- Linux host (developed and tested on Ubuntu)
- Ports 2222, 8080, 4445 and 8888 free on the host

### Clone and run

```bash
git clone https://github.com/alsaif26/zt-honeypot-mesh.git
cd zt-honeypot-mesh
docker compose up -d --build
docker compose ps
```

The first build takes a few minutes while the images are created. Subsequent
starts take seconds.

`docker compose ps` should list six services in the `Up` state:

```
ai-detector       Up
dashboard         Up   0.0.0.0:8888->8888/tcp
http-honeypot     Up   0.0.0.0:8080->8080/tcp
mesh-controller   Up
smb-honeypot      Up   0.0.0.0:4445->4445/tcp
ssh-honeypot      Up   0.0.0.0:2222->2222/tcp
```

### Open the dashboard

```
http://localhost:8888
```

The dashboard starts empty by design — it only ever displays real captured
events. Run the tests in [Testing the Honeypots](#-testing-the-honeypots) to
populate it.

---

## 🛠️ Operating the Mesh

| Task | Command |
|---|---|
| Start (build if needed) | `docker compose up -d --build` |
| Check service status | `docker compose ps` |
| Follow live logs (all services) | `docker compose logs -f` |
| Follow one service | `docker compose logs -f ssh-honeypot` |
| Last 50 lines of a service | `docker compose logs --tail=50 dashboard` |
| Restart one service | `docker compose restart dashboard` |
| Stop everything | `docker compose down` |
| Stop and delete captured logs | `docker compose down -v` |

`docker compose down` preserves the `honeypot-logs` volume, so captured attack
data survives a restart. Add `-v` only when you deliberately want a clean slate.

### Troubleshooting

| Symptom | Check |
|---|---|
| Dashboard unreachable | `docker compose ps` — is `dashboard` up? Then `docker compose logs --tail=50 dashboard` |
| Port already in use | `ss -ltnp \| grep -E '2222\|8080\|4445\|8888'` and free the port or change the mapping in `docker-compose.yml` |
| Dashboard shows no data | Generate traffic (see testing below); confirm with `docker compose logs --tail=20 ssh-honeypot` |
| No AI scores / quarantine data | `docker compose logs --tail=20 ai-detector mesh-controller` — both must be `Up` |
| API sanity check | `curl -s http://localhost:8888/api/health` |
| Rebuild after code changes | `docker compose up -d --build` |

---

## 🧪 Testing the Honeypots

These are safe tests against your own local containers.

### HTTP honeypot

```bash
curl http://127.0.0.1:8080
```

Returns the fake **Admin Login** page and logs an `HTTP_GET` event. To capture
credentials, submit the form:

```bash
curl -X POST -d "username=admin&password=admin123" http://127.0.0.1:8080/login
```

This logs an `HTTP_LOGIN_ATTEMPT` event containing the submitted username and
password, mapped to **T1190**.

### SSH honeypot

```bash
ssh -p 2222 test@127.0.0.1
```

Enter any password. **Authentication will always fail — that is the intended
behaviour.** The honeypot never grants access; it exists only to record the
attempt. Each try logs an `AUTH_ATTEMPT_PASSWORD` event with the username,
password attempt, source IP, timestamp, attempt number and MITRE technique
**T1110**.

Repeat the attempt several times to watch the threat score rise, and exceed the
quarantine threshold (default 10 attempts) to see the IP appear in the
dashboard's Quarantine panel.

### SMB honeypot

```bash
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/4445 && echo probe >&3'
```

Logs an `SMB_CONNECTION_OPEN` event mapped to **T1021.002**.

### Inspect captured events

```bash
docker compose logs --tail=50 ssh-honeypot
docker compose logs --tail=50 http-honeypot
docker compose logs --tail=50 smb-honeypot
docker compose logs --tail=50 ai-detector
```

Every line is a JSON object, so you can pipe it into `jq` for readability.

### Verify via the API

```bash
curl -s http://localhost:8888/api/stats | head -c 400
curl -s http://localhost:8888/api/health
```

---

## 📊 Dashboard

Available at **http://localhost:8888** once the stack is running.

Served by Flask (`dashboard/app.py`), rendered with vanilla HTML/CSS/JS and
Chart.js. All figures are derived from the JSON logs at request time — where a
value cannot be derived, the UI renders `N/A` or an explicit empty state rather
than a placeholder number.

### Implemented sections

| Section | Contents |
|---|---|
| Security Overview | KPI cards: total / SSH / HTTP / SMB attacks, high-severity IPs, quarantined IPs |
| Attack Analytics | Service distribution, hourly activity, severity distribution, MITRE frequency charts |
| Top Attacker IPs | Ranked table with event count, services touched, threat score, severity, first/last seen |
| Live Attack Feed | Event table with sortable columns, pagination, and filters for IP, service, severity, event type and technique |
| MITRE ATT&CK | Technique cards plus a table of ID, name, tactic, occurrence count and observed severity |
| AI Threat Analysis | Detector status, analyses logged, peak score, and a table of per-detection scores, techniques and reasons |
| Honeypot Health | Per-service status (verified by live TCP probe), port, node ID, event counts and last-event times |
| Quarantine / Blocklist | Quarantined IPs with reason, attempt count, threat score and detection time |
| Reports | PDF, CSV and JSON export buttons |
| Settings | Refresh-interval control and backend runtime values |

Also implemented: a sticky header with global search, live/auto-refresh
indicator and last-updated time; an alert panel driven by real high-threat,
quarantine and service-outage conditions; auto-refresh every 10 seconds via
async fetch; responsive layout; and accessibility support (skip link, ARIA
labels, keyboard-sortable table headers).

### REST API

| Endpoint | Returns |
|---|---|
| `GET /api/stats` | Full aggregated payload: KPIs, attack feed, analytics, AI, quarantine, health, alerts |
| `GET /api/health` | Honeypot status with live TCP reachability probe |
| `GET /api/mitre` | Observed MITRE technique frequency |
| `GET /api/ai` | Anomaly detector analyses |
| `GET /api/quarantine` | Mesh controller quarantine state |
| `GET /api/alerts` | Derived alert conditions |
| `GET /api/export/csv` | Attack events as a CSV download |
| `GET /api/export/json` | Full snapshot as a JSON download |

PDF export is generated in the browser with jsPDF (loaded from a CDN, so it
requires internet access); CSV and JSON are produced server-side and work
offline.

---

## 🔒 Threat Scoring

Implemented in `ai/anomaly_detector.py`. This is **rule-based scoring, not a
machine-learning model** — the "AI" component is a deterministic heuristic
engine, and the dashboard states this explicitly.

Each source IP accumulates a score from 0 to 100:

| Attempts observed | Points |
|---|---|
| 1–4 | `count × 2` |
| 5–9 | +15 |
| 10–19 | +30 |
| 20+ | +50 |

Plus **+10 for each unique event type** from that IP — so an attacker probing
SSH *and* HTTP scores higher than one hammering a single service. The total is
capped at 100.

| Score | Level |
|---|---|
| 0 – 30 | 🟢 LOW |
| 31 – 60 | 🟡 MEDIUM |
| 61 – 100 | 🔴 HIGH |

Separately, `mesh/controller.py` quarantines any IP exceeding
`MAX_ATTEMPTS_PER_IP` (default **10**, configurable via environment variable).
Quarantine is a **logging and visibility action** — it records and displays the
blocklist entry. It does not modify host firewall rules.

---

## 🎯 MITRE ATT&CK Mapping

These five techniques are the complete set implemented in the code. No broader
coverage is claimed.

| Trigger | Technique ID | Technique Name | Tactic | Source |
|---|---|---|---|---|
| SSH password attempt | T1110 / T1110.001 | Brute Force: Password Guessing | Credential Access | `ssh_honeypot.py`, `anomaly_detector.py` |
| SSH public-key attempt | T1110.004 | Brute Force: Credential Stuffing | Credential Access | `ssh_honeypot.py`, `anomaly_detector.py` |
| HTTP login attempt | T1190 | Exploit Public-Facing Application | Initial Access | `anomaly_detector.py` |
| SMB connection / data | T1021.002 | Remote Services: SMB | Lateral Movement | `smb_honeypot.py`, `anomaly_detector.py` |
| IP quarantined | T1110 | Brute Force | Credential Access | `mesh/controller.py` |

The honeypots tag raw events with a technique at capture time; the anomaly
detector applies the fuller mapping (ID, name and tactic) during analysis.

---

## 🗂️ Logging

`core_logging/logger.py` writes newline-delimited JSON, one object per event,
with rotation (5 MB per file, 5 backups by default).

Every record includes a UTC ISO-8601 timestamp, log level, node ID, node role,
hostname and logger name, plus event-specific fields such as `event_type`,
`src_ip`, `src_port`, `username`, `password` and `mitre_technique`.

| File | Written by |
|---|---|
| `ssh_honeypot.json` | SSH honeypot |
| `http_honeypot.json` | HTTP honeypot |
| `smb_honeypot.json` | SMB honeypot |
| `mesh_controller.json` | Mesh controller |
| `ai_detector.json` | Anomaly detector |

In Docker these live in the shared `honeypot-logs` volume mounted at
`/app/logs`. Locally they default to `./logs/`, controlled by the `LOG_DIR`
environment variable.

> ⚠️ Honeypot logs contain real credentials submitted by attackers. `logs/` is
> git-ignored — keep it that way and never publish raw captures.

---

## 🐍 Local Python Development (Optional)

Docker Compose is the intended deployment method. Running components directly
is useful for development and debugging only.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Each component is a standalone entry point:

```bash
python honeypots/ssh/ssh_honeypot.py     # binds 0.0.0.0:2222
python honeypots/http/http_honeypot.py   # binds 0.0.0.0:8080
python honeypots/smb/smb_honeypot.py     # binds 0.0.0.0:4445
python mesh/controller.py                # tails logs, no port
python ai/anomaly_detector.py            # tails logs, no port
python dashboard/app.py                  # binds 0.0.0.0:8888
```

`dashboard/app.py` reads logs from `LOG_DIR` (default `logs/`) and serves on
port **8888**. Because the analysis services *tail* log files, run the
honeypots first, or start them in any order — as of the current code they wait
for their input files to appear instead of exiting.

If you run the dashboard on the host while the honeypots run in Docker, point
it at the volume or set `LOG_DIR` accordingly; otherwise it will find no logs.
Running the whole stack in Compose avoids this entirely.

---

## ☁️ Public Access via Cloudflare Tunnel (Optional)

**This is an optional external step. No Cloudflare configuration, credentials
or tunnel definitions exist in this repository** — the application does not
deploy through Cloudflare automatically.

If you want to expose the dashboard for a demo, `cloudflared` can tunnel it:

```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
cloudflared tunnel --url http://localhost:8888
```

You will receive a temporary public `https://<random>.trycloudflare.com` URL.

> ⚠️ The dashboard has **no authentication**. Exposing it publicly makes your
> captured data — including harvested credentials — world-readable. Prefer
> screenshots or a recorded walkthrough for portfolio purposes, and take the
> tunnel down when you are finished.

---

## 🛡️ Security & Responsible Use

This project is for **defensive cybersecurity** purposes:

- defensive security research
- SOC analyst training and practice
- honeypot experimentation
- security monitoring exercises
- portfolio demonstration

**Design safeguards**

- ✅ No honeypot ever grants access to a real system
- ✅ Authentication always fails by design
- ✅ Services only observe and log
- ✅ Containers run as a non-root `honeypot` user
- ✅ Isolated Docker bridge network (`172.20.0.0/24`)
- ✅ Rotating log files to prevent disk exhaustion

**Before exposing this to the internet**

- Run it on isolated infrastructure — never on a host that holds real data,
  credentials or production services, and never on your primary workstation
- Keep honeypot networks segmented from internal/corporate networks
- Remember the dashboard is unauthenticated; do not leave it publicly reachable
- Treat captured logs as sensitive: they contain real credentials
- Check that running honeypot services is permitted by your hosting provider,
  your ISP and any applicable local law

Deploy only against systems and networks you own or have explicit written
permission to operate.

---

## 📈 Project Status

Verified against the current codebase and a running Docker Compose deployment.

| Component | Implementation | Status |
|---|---|---|
| SSH Honeypot | `honeypots/ssh/ssh_honeypot.py` | ✅ Working — tested, captures credentials |
| HTTP Honeypot | `honeypots/http/http_honeypot.py` | ✅ Working — tested, serves fake login page |
| SMB Honeypot | `honeypots/smb/smb_honeypot.py` | ✅ Working — logs connections and payloads |
| JSON Logging | `core_logging/logger.py` | ✅ Working — rotating JSON-lines output |
| Mesh Controller | `mesh/controller.py` | ✅ Working — quarantine by attempt threshold |
| Anomaly Detection | `ai/anomaly_detector.py` | ✅ Working — rule-based scoring (not ML) |
| MITRE Mapping | `ai/anomaly_detector.py` + honeypots | ✅ Working — 5 techniques |
| SOC Dashboard | `dashboard/` | ✅ Working — served on port 8888 |
| CSV / JSON Export | `dashboard/app.py` | ✅ Working — server-side endpoints |
| PDF Export | `dashboard/static/script.js` | ✅ Working — client-side jsPDF, needs CDN access |
| Docker Deployment | `docker-compose.yml` + 5 Dockerfiles | ✅ Working — six services |
| Wazuh / SIEM Forwarding | `siem/wazuh_forwarder.py` | ⚠️ **Not implemented** — empty file, scaffold only |
| Cloudflare Tunnel | — | ℹ️ Optional external tooling, not part of the codebase |
| Authentication | — | ❌ Not implemented — dashboard is unauthenticated |
| Automated Tests | — | ❌ Not implemented — testing is currently manual |
| Firewall Enforcement | — | ❌ Not implemented — quarantine is log-only, by design |

---

## 📦 Requirements

```
paramiko==3.4.0
cryptography==42.0.5
bcrypt==4.1.3
flask==3.0.3
```

Chart.js and jsPDF are loaded in the browser from a CDN and are not Python
dependencies.

---

## 🗺️ Roadmap

Honest next steps, in rough priority order:

- [ ] Implement `siem/wazuh_forwarder.py` to ship events to a Wazuh manager
- [ ] Add authentication to the dashboard before any public exposure
- [ ] Add automated tests for the scoring and aggregation logic
- [ ] Add optional GeoIP / ASN enrichment for source IPs
- [ ] Persist analysis state so scores survive an analyser restart

---

## 👤 Author

**Mohammed Saif Al Sabah**

- 🐙 GitHub: [@alsaif26](https://github.com/alsaif26)
- 📧 Email: mohammedsaifalsabah@gmail.com

---

## 📄 License

MIT License — free to use for educational and research purposes.

---

<div align="center">

⭐ **Star this repo if you found it useful!** ⭐

</div>
