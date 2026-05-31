import os
import sys
import json
import time
import threading
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config.settings import NODE_ID, MAX_ATTEMPTS_PER_IP
from core_logging.logger import get_logger, log_event

LOG_DIR = os.environ.get("LOG_DIR", "logs")
LOG_FILE_MESH = os.path.join(LOG_DIR, "mesh_controller.json")

logger = get_logger("mesh_controller", LOG_FILE_MESH)

ip_attempt_counts = defaultdict(int)
quarantine_list = set()
lock = threading.Lock()


def process_event(event: dict):
    src_ip = event.get("src_ip")
    event_type = event.get("event_type", "")

    if not src_ip:
        return

    attack_events = [
        "AUTH_ATTEMPT_PASSWORD",
        "AUTH_ATTEMPT_PUBKEY",
        "HTTP_LOGIN_ATTEMPT",
        "SMB_CONNECTION_OPEN",
    ]

    if event_type not in attack_events:
        return

    with lock:
        ip_attempt_counts[src_ip] += 1
        count = ip_attempt_counts[src_ip]

        log_event(logger, "info", "Event processed", {
            "event_type": "MESH_EVENT_RECEIVED",
            "src_ip": src_ip,
            "attack_event": event_type,
            "total_attempts": count,
            "node_id": NODE_ID,
        })

        if count >= MAX_ATTEMPTS_PER_IP and src_ip not in quarantine_list:
            quarantine_list.add(src_ip)
            log_event(logger, "warning", "IP quarantined", {
                "event_type": "IP_QUARANTINED",
                "src_ip": src_ip,
                "total_attempts": count,
                "threshold": MAX_ATTEMPTS_PER_IP,
                "node_id": NODE_ID,
                "mitre_technique": "T1110",
            })
            print(f"\nQUARANTINE: {src_ip} — {count} attempts detected!\n")


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
                    process_event(event)
                except json.JSONDecodeError:
                    pass
            else:
                time.sleep(0.5)


def run_mesh_controller():
    os.makedirs(LOG_DIR, exist_ok=True)

    log_files = [
        os.path.join(LOG_DIR, "ssh_honeypot.json"),
        os.path.join(LOG_DIR, "http_honeypot.json"),
        os.path.join(LOG_DIR, "smb_honeypot.json"),
    ]

    log_event(logger, "info", "Mesh Controller started", {
        "event_type": "MESH_START",
        "watching_files": log_files,
        "node_id": NODE_ID,
        "threshold": MAX_ATTEMPTS_PER_IP,
    })

    print(f"\nMesh Controller started")
    print(f"Watching : {len(log_files)} log files")
    print(f"Threshold: {MAX_ATTEMPTS_PER_IP} attempts = quarantine")
    print(f"Log file : {LOG_FILE_MESH}")
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
        print("\nStopping Mesh Controller...")
        log_event(logger, "info", "Mesh Controller stopped", {
            "event_type": "MESH_STOP",
            "node_id": NODE_ID,
            "quarantined_ips": list(quarantine_list),
        })


if __name__ == "__main__":
    run_mesh_controller()