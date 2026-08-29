"""Flask API + SOC Command Center dashboard for the Zero-Trust Honeypot Mesh.

All data served here is derived from the JSON logs written by the honeypots,
the mesh controller and the AI anomaly detector. Nothing is synthetic: when a
value cannot be derived from real data it is returned as null/0 and the UI
renders "N/A" or an empty state.
"""

import os
import socket
import sys
import json
from collections import defaultdict
from datetime import datetime, timezone

from flask import Flask, render_template, jsonify, Response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Reuse the project's real threat-scoring / MITRE logic instead of duplicating it.
try:
    from ai.anomaly_detector import (
        MITRE_MAP,
        calculate_threat_score,
        get_threat_level,
    )
    _AI_AVAILABLE = True
except Exception:  # pragma: no cover - dashboard must never hard-fail on import
    MITRE_MAP = {}
    _AI_AVAILABLE = False

    def calculate_threat_score(ip_data):
        return 0

    def get_threat_level(score):
        return "LOW"

try:
    from config.settings import MAX_ATTEMPTS_PER_IP
except Exception:
    MAX_ATTEMPTS_PER_IP = int(os.environ.get("MAX_ATTEMPTS_PER_IP", 10))

app = Flask(__name__)

LOG_DIR = os.environ.get("LOG_DIR", "logs")

LOG_FILES = {
    "ssh":  os.path.join(LOG_DIR, "ssh_honeypot.json"),
    "http": os.path.join(LOG_DIR, "http_honeypot.json"),
    "smb":  os.path.join(LOG_DIR, "smb_honeypot.json"),
    "ai":   os.path.join(LOG_DIR, "ai_detector.json"),
    "mesh": os.path.join(LOG_DIR, "mesh_controller.json"),
}

# Attack events per service (the events that represent adversary activity).
ATTACK_EVENTS = {
    "ssh":  {"AUTH_ATTEMPT_PASSWORD", "AUTH_ATTEMPT_PUBKEY"},
    "http": {"HTTP_LOGIN_ATTEMPT"},
    "smb":  {"SMB_CONNECTION_OPEN", "SMB_DATA"},
}

# Service reachability probe targets (host:port), overridable via environment.
SERVICES = {
    "ssh": {
        "label": "SSH Honeypot",
        "host": os.environ.get("SSH_PROBE_HOST", "ssh-honeypot"),
        "port": int(os.environ.get("SSH_PROBE_PORT", 2222)),
    },
    "http": {
        "label": "HTTP Honeypot",
        "host": os.environ.get("HTTP_PROBE_HOST", "http-honeypot"),
        "port": int(os.environ.get("HTTP_PROBE_PORT", 8080)),
    },
    "smb": {
        "label": "SMB Honeypot",
        "host": os.environ.get("SMB_PROBE_HOST", "smb-honeypot"),
        "port": int(os.environ.get("SMB_PROBE_PORT", 4445)),
    },
}

PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", 1.0))


def _own_addresses():
    """IPs belonging to this dashboard process.

    The health probes below open real TCP connections to the honeypots, which
    the honeypots dutifully log. Those are internal health checks, not attacks,
    so their source IPs are excluded from attack analytics.
    """
    addresses = {"127.0.0.1", "::1"}
    for extra in os.environ.get("EXCLUDE_IPS", "").split(","):
        extra = extra.strip()
        if extra:
            addresses.add(extra)
    try:
        addresses.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return addresses


EXCLUDED_IPS = _own_addresses()


# --------------------------------------------------------------------------- #
# Log access
# --------------------------------------------------------------------------- #

def read_log(filepath):
    events = []
    if not os.path.exists(filepath):
        return events
    with open(filepath, "r") as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass
    return events


def read_all():
    return {key: read_log(path) for key, path in LOG_FILES.items()}


def _service_of(event_type):
    for service, types in ATTACK_EVENTS.items():
        if event_type in types:
            return service
    return None


def mitre_for(event):
    """Resolve MITRE metadata for an event, preferring the AI detector's map."""
    event_type = event.get("event_type", "")
    mapped = MITRE_MAP.get(event_type)
    if mapped:
        return {
            "technique_id": mapped["technique_id"],
            "technique_name": mapped["technique_name"],
            "tactic": mapped["tactic"],
        }
    # Fall back to the technique the honeypot itself recorded, if any.
    raw = event.get("mitre_technique")
    if raw:
        return {"technique_id": raw, "technique_name": None, "tactic": None}
    return {"technique_id": None, "technique_name": None, "tactic": None}


# --------------------------------------------------------------------------- #
# Derived analytics
# --------------------------------------------------------------------------- #

def build_ip_profiles(attacks):
    """Per-IP activity profile scored with the project's own AI scoring rules."""
    profiles = {}
    for e in attacks:
        ip = e.get("src_ip")
        if not ip:
            continue
        p = profiles.setdefault(ip, {
            "ip": ip,
            "count": 0,
            "event_types": [],
            "services": set(),
            "first_seen": None,
            "last_seen": None,
        })
        p["count"] += 1
        p["event_types"].append(e.get("event_type", ""))
        service = _service_of(e.get("event_type", ""))
        if service:
            p["services"].add(service)
        ts = e.get("timestamp")
        if ts:
            if not p["first_seen"] or ts < p["first_seen"]:
                p["first_seen"] = ts
            if not p["last_seen"] or ts > p["last_seen"]:
                p["last_seen"] = ts

    for p in profiles.values():
        score = calculate_threat_score({
            "count": p["count"],
            "event_types": p["event_types"],
        })
        p["threat_score"] = score
        p["threat_level"] = get_threat_level(score)
        p["services"] = sorted(p["services"])
        p.pop("event_types", None)
    return profiles


def build_timeline(attacks, buckets=24):
    """Attack activity grouped per hour (UTC), oldest bucket first."""
    counts = defaultdict(lambda: defaultdict(int))
    for e in attacks:
        ts = e.get("timestamp") or ""
        if len(ts) < 13:
            continue
        hour = ts[:13]  # YYYY-MM-DDTHH
        service = _service_of(e.get("event_type", "")) or "other"
        counts[hour]["total"] += 1
        counts[hour][service] += 1

    ordered = sorted(counts.keys())[-buckets:]
    return [{
        "bucket": h,
        "label": h[11:13] + ":00",
        "date": h[:10],
        "total": counts[h]["total"],
        "ssh": counts[h]["ssh"],
        "http": counts[h]["http"],
        "smb": counts[h]["smb"],
    } for h in ordered]


def quarantine_from_logs(mesh_events, profiles):
    """Quarantined IPs as recorded by mesh/controller.py (IP_QUARANTINED)."""
    entries = {}
    for e in mesh_events:
        if e.get("event_type") != "IP_QUARANTINED":
            continue
        ip = e.get("src_ip")
        if not ip:
            continue
        profile = profiles.get(ip, {})
        entries[ip] = {
            "ip": ip,
            "reason": e.get("message") or "Attempt threshold exceeded",
            "attempts": e.get("total_attempts"),
            "threshold": e.get("threshold", MAX_ATTEMPTS_PER_IP),
            "detected_at": e.get("timestamp"),
            "mitre_technique": e.get("mitre_technique"),
            "threat_score": profile.get("threat_score"),
            "threat_level": profile.get("threat_level"),
            "status": "QUARANTINED",
        }
    return sorted(entries.values(), key=lambda x: x["detected_at"] or "", reverse=True)


def ai_analyses(ai_events, limit=50):
    """Most recent AI anomaly analyses, newest first."""
    rows = [e for e in ai_events if e.get("event_type") == "AI_ANALYSIS"]
    rows.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return [{
        "timestamp": e.get("timestamp"),
        "src_ip": e.get("src_ip"),
        "threat_score": e.get("threat_score"),
        "threat_level": e.get("threat_level"),
        "total_attempts": e.get("total_attempts"),
        "technique_id": e.get("mitre_technique_id"),
        "technique_name": e.get("mitre_technique_name"),
        "tactic": e.get("mitre_tactic"),
        "first_seen": e.get("first_seen"),
        "last_seen": e.get("last_seen"),
        "node_id": e.get("node_id"),
        "message": e.get("message"),
    } for e in rows[:limit]]


def probe(host, port):
    """TCP reachability probe. Returns True/False, or None if not resolvable."""
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return None


def honeypot_health(logs):
    """Per-honeypot status built from real log data plus a live TCP probe."""
    health = []
    for key, meta in SERVICES.items():
        events = logs.get(key, [])
        attacks = [e for e in events if e.get("event_type") in ATTACK_EVENTS[key]
                   and e.get("src_ip") not in EXCLUDED_IPS]
        starts = [e for e in events if e.get("event_type") == "HONEYPOT_START"]
        last_event = max((e.get("timestamp", "") for e in events), default="") or None
        last_attack = max((e.get("timestamp", "") for e in attacks), default="") or None
        reachable = probe(meta["host"], meta["port"])
        health.append({
            "service": key,
            "label": meta["label"],
            "port": meta["port"],
            "reachable": reachable,
            "status": "ONLINE" if reachable else ("OFFLINE" if reachable is False else "UNKNOWN"),
            "event_count": len(events),
            "attack_count": len(attacks),
            "last_event": last_event,
            "last_attack": last_attack,
            "started_at": starts[-1].get("timestamp") if starts else None,
            "node_id": starts[-1].get("node_id") if starts else None,
            "log_present": os.path.exists(LOG_FILES[key]),
        })
    return health


def build_alerts(profiles, quarantine, health, ai_rows):
    """Alerts derived strictly from observed conditions. No synthetic alerts."""
    alerts = []
    for row in sorted(ai_rows, key=lambda r: r.get("timestamp") or "", reverse=True):
        if row.get("threat_level") in ("HIGH", "CRITICAL"):
            alerts.append({
                "severity": row["threat_level"],
                "title": f"High threat activity from {row.get('src_ip')}",
                "detail": f"Threat score {row.get('threat_score')}/100 · {row.get('technique_id') or 'N/A'}",
                "timestamp": row.get("timestamp"),
            })
        if len(alerts) >= 10:
            break

    for q in quarantine[:5]:
        alerts.append({
            "severity": "HIGH",
            "title": f"IP quarantined: {q['ip']}",
            "detail": f"{q.get('attempts') or 'N/A'} attempts (threshold {q.get('threshold')})",
            "timestamp": q.get("detected_at"),
        })

    for h in health:
        if h["status"] == "OFFLINE":
            alerts.append({
                "severity": "CRITICAL",
                "title": f"{h['label']} unavailable",
                "detail": f"TCP probe failed on port {h['port']}",
                "timestamp": None,
            })

    alerts.sort(key=lambda a: a.get("timestamp") or "", reverse=True)
    return alerts[:20]


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

def get_stats():
    logs = read_all()
    ssh, http, smb = logs["ssh"], logs["http"], logs["smb"]
    ai, mesh = logs["ai"], logs["mesh"]

    ssh_attacks  = [e for e in ssh  if e.get("event_type") in ATTACK_EVENTS["ssh"]
                    and e.get("src_ip") not in EXCLUDED_IPS]
    http_attacks = [e for e in http if e.get("event_type") in ATTACK_EVENTS["http"]
                    and e.get("src_ip") not in EXCLUDED_IPS]
    smb_attacks  = [e for e in smb  if e.get("event_type") in ATTACK_EVENTS["smb"]
                    and e.get("src_ip") not in EXCLUDED_IPS]

    all_attacks = ssh_attacks + http_attacks + smb_attacks
    all_attacks.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    profiles = build_ip_profiles(all_attacks)

    top_ips = sorted(
        [{
            "ip": p["ip"],
            "count": p["count"],
            "threat_score": p["threat_score"],
            "threat_level": p["threat_level"],
            "services": p["services"],
            "first_seen": p["first_seen"],
            "last_seen": p["last_seen"],
        } for p in profiles.values()],
        key=lambda x: (x["count"], x["threat_score"]), reverse=True
    )[:10]

    # MITRE technique frequency, enriched with names/tactics where known.
    mitre_counts = defaultdict(int)
    mitre_meta = {}
    for e in all_attacks:
        info = mitre_for(e)
        tid = info["technique_id"]
        if not tid:
            continue
        mitre_counts[tid] += 1
        existing = mitre_meta.get(tid) or {}
        if not existing.get("technique_name"):
            mitre_meta[tid] = info
    for e in mesh:
        if e.get("event_type") == "IP_QUARANTINED" and e.get("mitre_technique"):
            tid = e["mitre_technique"]
            mitre_counts[tid] += 1
            mitre_meta.setdefault(tid, {
                "technique_id": tid, "technique_name": "Brute Force",
                "tactic": "Credential Access",
            })

    mitre = []
    for tid, count in sorted(mitre_counts.items(), key=lambda kv: kv[1], reverse=True):
        meta = mitre_meta.get(tid, {})
        mitre.append({
            "technique": tid,                      # legacy key (backward compatible)
            "count": count,
            "technique_id": tid,
            "technique_name": meta.get("technique_name"),
            "tactic": meta.get("tactic"),
        })

    ai_rows = ai_analyses(ai)
    quarantine = quarantine_from_logs(mesh, profiles)
    health = honeypot_health(logs)

    # Severity distribution across per-IP profiles (real threat scoring output).
    severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for p in profiles.values():
        severity[p["threat_level"]] = severity.get(p["threat_level"], 0) + 1

    # Enrich the attack feed rows the UI renders.
    feed = []
    for e in all_attacks[:200]:
        ip = e.get("src_ip")
        profile = profiles.get(ip, {})
        info = mitre_for(e)
        feed.append({
            "timestamp": e.get("timestamp"),
            "event_type": e.get("event_type"),
            "service": _service_of(e.get("event_type", "")),
            "src_ip": ip,
            "src_port": e.get("src_port"),
            "username": e.get("username"),
            "password": e.get("password"),
            "path": e.get("path"),
            "user_agent": e.get("user_agent"),
            "node_id": e.get("node_id"),
            "mitre_technique": info["technique_id"],
            "mitre_technique_name": info["technique_name"],
            "mitre_tactic": info["tactic"],
            "threat_score": profile.get("threat_score"),
            "severity": profile.get("threat_level"),
            "status": "QUARANTINED" if any(q["ip"] == ip for q in quarantine) else "MONITORED",
        })

    return {
        # ---- legacy keys (kept for backward compatibility) ----
        "ssh":     len(ssh_attacks),
        "http":    len(http_attacks),
        "smb":     len(smb_attacks),
        "total":   len(all_attacks),
        "high":    len([e for e in ai if e.get("threat_level") == "HIGH"]),
        "medium":  len([e for e in ai if e.get("threat_level") == "MEDIUM"]),
        "top_ips": top_ips,
        "mitre":   mitre,
        "attacks": feed,
        # ---- extended keys ----
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "severity":        severity,
        "high_profiles":   severity.get("HIGH", 0) + severity.get("CRITICAL", 0),
        "unique_ips":      len(profiles),
        "timeline":        build_timeline(all_attacks),
        "ai": {
            "available": _AI_AVAILABLE,
            "engine": "Rule-based anomaly scoring (ai/anomaly_detector.py)",
            "log_present": os.path.exists(LOG_FILES["ai"]),
            "analyses": ai_rows,
        },
        "quarantine": {
            "threshold": MAX_ATTEMPTS_PER_IP,
            "log_present": os.path.exists(LOG_FILES["mesh"]),
            "count": len(quarantine),
            "entries": quarantine,
        },
        "health":     health,
        "alerts":     build_alerts(profiles, quarantine, health, ai_rows),
        "refresh_interval_s": int(os.environ.get("REFRESH_INTERVAL", 10)),
    }


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify(get_stats())


@app.route("/api/health")
def api_health():
    logs = read_all()
    return jsonify({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "honeypots": honeypot_health(logs),
        "log_dir": LOG_DIR,
        "ai_detector_active": os.path.exists(LOG_FILES["ai"]),
        "mesh_controller_active": os.path.exists(LOG_FILES["mesh"]),
    })


@app.route("/api/mitre")
def api_mitre():
    data = get_stats()
    return jsonify({"techniques": data["mitre"], "generated_at": data["generated_at"]})


@app.route("/api/ai")
def api_ai():
    data = get_stats()
    return jsonify(data["ai"])


@app.route("/api/quarantine")
def api_quarantine():
    data = get_stats()
    return jsonify(data["quarantine"])


@app.route("/api/alerts")
def api_alerts():
    data = get_stats()
    return jsonify({"alerts": data["alerts"], "generated_at": data["generated_at"]})


@app.route("/api/export/csv")
def export_csv():
    data = get_stats()
    columns = [
        "timestamp", "service", "event_type", "src_ip", "src_port",
        "username", "password", "mitre_technique", "mitre_tactic",
        "threat_score", "severity", "status",
    ]

    def cell(value):
        if value is None:
            return ""
        text = str(value).replace('"', '""')
        return f'"{text}"' if any(c in text for c in ',"\n') else text

    lines = [",".join(columns)]
    for e in data["attacks"]:
        lines.append(",".join(cell(e.get(c)) for c in columns))
    return Response(
        "\n".join(lines),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=attacks.csv"}
    )


@app.route("/api/export/json")
def export_json():
    return Response(
        json.dumps(get_stats(), indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=honeypot_report.json"}
    )


if __name__ == "__main__":
    print("\nDashboard: http://localhost:8888")
    app.run(host="0.0.0.0", port=8888, debug=False)
