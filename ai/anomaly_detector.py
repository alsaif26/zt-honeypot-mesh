import os
import sys
import json
import time
import threading
from datetime import datetime, timezone
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config.settings import NODE_ID
from core_logging.logger import get_logger, log_event

LOG_DIR = os.environ.get("LOG_DIR", "logs")
LOG_FILE_AI = os.path.join(LOG_DIR, "ai_detector.json")

logger = get_logger("ai_detector", LOG_FILE_AI)

MITRE_MAP = {
    "AUTH_ATTEMPT_PASSWORD": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "AUTH_ATTEMPT_PUBKEY": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
    },
    "HTTP_LOGIN_ATTEMPT": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "SMB_CONNECTION_OPEN": {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB",
        "tactic": "Lateral Movement",
    },
}

ip_activity = defaultdict(lambda: {
    "count": 0,
    "first_seen": None,
    "last_seen": None,
    "event_types": [],
})

lock = threading.Lock()


def calculate_threat_score(ip_data: dict) -> int:
    score = 0
    count = ip_data["count"]
    if count >= 20:
        score += 50
    elif count >= 10:
        score += 30
    elif count >= 5:
        score += 15
    else:
        score += count * 2
    unique_events = len(set(ip_data["event_types"]))
    score += unique_events * 10
    return min(score, 100)


def get_threat_level(score: int) -> str:
    if score >= 61:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    else:
        return "LOW"


def analyze_event(event: dict):
    src_ip = event.get("src_ip")
    event_type = event.get("event_type", "")

    if not src_ip or event_type not in MITRE_MAP:
        return

    now = datetime.now(timezone.utc).isoformat()

    with lock:
        ip_data = ip_activity[src_ip]
        ip_data["count"] += 1
        ip_data["event_types"].append(event_type)

        if not ip_data["first_seen"]:
            ip_data["first_seen"] = now
        ip_data["last_seen"] = now

        mitre = MITRE_MAP[event_type]
        score = calculate_threat_score(ip_data)
        level = get_threat_level(score)

        log_event(logger, "warning" if level != "LOW" else "info",
                  "Anomaly analysis complete", {
            "event_type": "AI_ANALYSIS",
            "src_ip": src_ip,
            "threat_score": score,
            "threat_level": level,
            "total_attempts": ip_data["count"],
            "mitre_technique_id": mitre["technique_id"],
            "mitre_technique_name": mitre["technique_name"],
            "mitre_tactic": mitre["tactic"],
            "first_seen": ip_data["first_seen"],
            "last_seen": now,
            "node_id": NODE_ID,
        })

        if level == "HIGH":
            print(f"\nHIGH THREAT: {src_ip}")
            print(f"   Score   : {score}/100")
            print(f"   MITRE   : {mitre['technique_id']}")
            print(f"   Tactic  : {mitre['tactic']}")
            print(f"   Attempts: {ip_data['count']}\n")
        elif level == "MEDIUM":
            print(f"\nMEDIUM THREAT: {src_ip} — Score: {score}/100")


def watch_log_file(log_file: str):
    if not os.path.exists(log_file):
        return
    with open(log_file, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                try:
                    event = json.loads(line.strip())
                    analyze_event(event)
                except json.JSONDecodeError:
                    pass
            else:
                time.sleep(0.5)


def run_ai_detector():
    os.makedirs(LOG_DIR, exist_ok=True)

    log_files = [
        os.path.join(LOG_DIR, "ssh_honeypot.json"),
        os.path.join(LOG_DIR, "http_honeypot.json"),
        os.path.join(LOG_DIR, "smb_honeypot.json"),
        os.path.join(LOG_DIR, "mesh_controller.json"),
    ]

    log_event(logger, "info", "AI Detector started", {
        "event_type": "AI_START",
        "node_id": NODE_ID,
        "watching_files": log_files,
    })

    print(f"\nAI Anomaly Detector started")
    print(f"Watching : {len(log_files)} log files")
    print(f"Log file : {LOG_FILE_AI}")
    print("Press Ctrl+C to stop\n")

    threads = []
    for log_file in log_files:
        thread = threading.Thread(
            target=watch_log_file,
            args=(log_file,),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping AI Detector...")
        log_event(logger, "info", "AI Detector stopped", {
            "event_type": "AI_STOP",
            "node_id": NODE_ID,
        })


if __name__ == "__main__":
    run_ai_detector()