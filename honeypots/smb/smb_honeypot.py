import os
import sys
import socket
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from config.settings import NODE_ID
from core_logging.logger import get_logger, log_event

LOG_DIR = os.environ.get("LOG_DIR", "logs")
LOG_FILE_SMB = os.path.join(LOG_DIR, "smb_honeypot.json")
SMB_PORT = int(os.environ.get("SMB_PORT", 4445))

logger = get_logger("smb_honeypot", LOG_FILE_SMB)


def handle_client(client_socket, client_address):
    client_ip = client_address[0]
    client_port = client_address[1]
    log_event(logger, "info", "SMB connection received", {
        "event_type": "SMB_CONNECTION_OPEN",
        "src_ip": client_ip,
        "src_port": client_port,
        "node_id": NODE_ID,
        "mitre_technique": "T1021.002",
    })
    try:
        client_socket.settimeout(10)
        data = client_socket.recv(1024)
        if data:
            log_event(logger, "warning", "SMB data received", {
                "event_type": "SMB_DATA",
                "src_ip": client_ip,
                "src_port": client_port,
                "data_length": len(data),
                "data_hex": data[:50].hex(),
                "node_id": NODE_ID,
                "mitre_technique": "T1021.002",
            })
    except socket.timeout:
        log_event(logger, "debug", "SMB connection timeout", {
            "event_type": "SMB_TIMEOUT",
            "src_ip": client_ip,
        })
    except Exception as e:
        log_event(logger, "error", "SMB error", {
            "event_type": "SMB_ERROR",
            "src_ip": client_ip,
            "error": str(e),
        })
    finally:
        client_socket.close()
        log_event(logger, "info", "SMB connection closed", {
            "event_type": "SMB_CONNECTION_CLOSE",
            "src_ip": client_ip,
        })


def run_smb_honeypot():
    os.makedirs(LOG_DIR, exist_ok=True)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", SMB_PORT))
    server_socket.listen(50)
    log_event(logger, "info", "SMB Honeypot started", {
        "event_type": "HONEYPOT_START",
        "bind_port": SMB_PORT,
        "node_id": NODE_ID,
    })
    print(f"\nSMB Honeypot started on port {SMB_PORT}")
    print(f"Node ID  : {NODE_ID}")
    print(f"Log file : {LOG_FILE_SMB}")
    print("Press Ctrl+C to stop\n")
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\nStopping SMB honeypot...")
        log_event(logger, "info", "SMB Honeypot stopped", {
            "event_type": "HONEYPOT_STOP",
            "node_id": NODE_ID,
        })
    finally:
        server_socket.close()


if __name__ == "__main__":
    run_smb_honeypot()