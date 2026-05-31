import os
import sys
import json
from flask import Flask, render_template, jsonify, Response
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

app = Flask(__name__)

LOG_DIR = os.environ.get("LOG_DIR", "logs")

LOG_FILES = {
    "ssh":  os.path.join(LOG_DIR, "ssh_honeypot.json"),
    "http": os.path.join(LOG_DIR, "http_honeypot.json"),
    "smb":  os.path.join(LOG_DIR, "smb_honeypot.json"),
    "ai":   os.path.join(LOG_DIR, "ai_detector.json"),
}


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


def get_stats():
    ssh   = read_log(LOG_FILES["ssh"])
    http  = read_log(LOG_FILES["http"])
    smb   = read_log(LOG_FILES["smb"])
    ai    = read_log(LOG_FILES["ai"])

    ssh_attacks  = [e for e in ssh  if e.get("event_type") == "AUTH_ATTEMPT_PASSWORD"]
    http_attacks = [e for e in http if e.get("event_type") == "HTTP_LOGIN_ATTEMPT"]
    smb_attacks  = [e for e in smb  if e.get("event_type") == "SMB_CONNECTION_OPEN"]

    ip_counts = defaultdict(int)
    for e in ssh_attacks + http_attacks + smb_attacks:
        ip = e.get("src_ip")
        if ip:
            ip_counts[ip] += 1

    top_ips = sorted(
        [{"ip": ip, "count": count} for ip, count in ip_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:10]

    mitre_counts = defaultdict(int)
    for e in ssh_attacks + http_attacks + smb_attacks:
        mitre = e.get("mitre_technique")
        if mitre:
            mitre_counts[mitre] += 1

    all_attacks = ssh_attacks + http_attacks + smb_attacks
    all_attacks.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "ssh":    len(ssh_attacks),
        "http":   len(http_attacks),
        "smb":    len(smb_attacks),
        "total":  len(all_attacks),
        "high":   len([e for e in ai if e.get("threat_level") == "HIGH"]),
        "medium": len([e for e in ai if e.get("threat_level") == "MEDIUM"]),
        "top_ips": top_ips,
        "mitre":  [{"technique": k, "count": v} for k, v in mitre_counts.items()],
        "attacks": all_attacks[:50],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify(get_stats())


@app.route("/api/export/csv")
def export_csv():
    data = get_stats()
    lines = ["timestamp,event_type,src_ip,username,password,mitre_technique"]
    for e in data["attacks"]:
        lines.append(
            f"{e.get('timestamp','')},{e.get('event_type','')},{e.get('src_ip','')},{e.get('username','')},{e.get('password','')},{e.get('mitre_technique','')}"
        )
    return Response(
        "\n".join(lines),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=attacks.csv"}
    )


if __name__ == "__main__":
    print("\nDashboard: http://localhost:8888")
    app.run(host="0.0.0.0", port=8888, debug=False)