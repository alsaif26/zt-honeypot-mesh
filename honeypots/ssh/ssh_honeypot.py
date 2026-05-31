import os
import socket
import sys
import threading
import time

import paramiko

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from config.settings import (
    LOG_FILE_SSH, NODE_ID, SSH_AUTH_TIMEOUT,
    SSH_BANNER, SSH_HOST, SSH_MAX_CONNECTIONS, SSH_PORT,
)
from core_logging.logger import get_logger, log_event

logger = get_logger("ssh_honeypot", LOG_FILE_SSH)


def generate_host_key():
    key = paramiko.RSAKey.generate(2048)
    log_event(logger, "info", "RSA host key generated", {
        "event_type": "KEY_GENERATED",
        "node_id": NODE_ID,
    })
    return key


class HoneypotSSHInterface(paramiko.ServerInterface):

    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.attempt_count = 0
        self.session_start = time.time()

    def check_channel_request(self, kind, chanid):
        log_event(logger, "warning", "Channel request blocked", {
            "event_type": "CHANNEL_REQUEST",
            "src_ip": self.client_ip,
            "channel_type": kind,
        })
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.attempt_count += 1
        elapsed = round(time.time() - self.session_start, 3)
        log_event(logger, "warning", "Login attempt captured", {
            "event_type": "AUTH_ATTEMPT_PASSWORD",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "username": username,
            "password": password,
            "attempt_number": self.attempt_count,
            "session_elapsed_s": elapsed,
            "node_id": NODE_ID,
            "mitre_technique": "T1110",
        })
        time.sleep(1.5)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_event(logger, "info", "Public key attempt captured", {
            "event_type": "AUTH_ATTEMPT_PUBKEY",
            "src_ip": self.client_ip,
            "username": username,
            "key_type": key.get_name(),
            "node_id": NODE_ID,
            "mitre_technique": "T1110.004",
        })
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"


def handle_client(client_socket, client_address, host_key):
    client_ip = client_address[0]
    client_port = client_address[1]
    log_event(logger, "info", "New connection", {
        "event_type": "CONNECTION_OPEN",
        "src_ip": client_ip,
        "src_port": client_port,
        "node_id": NODE_ID,
    })
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)
        server_interface = HoneypotSSHInterface(client_ip, client_port)
        transport.start_server(server=server_interface)
        deadline = time.time() + SSH_AUTH_TIMEOUT
        while transport.is_active() and time.time() < deadline:
            time.sleep(0.5)
    except paramiko.SSHException as e:
        log_event(logger, "debug", "SSH protocol error", {
            "event_type": "PROTOCOL_ERROR",
            "src_ip": client_ip,
            "error": str(e),
        })
    except EOFError:
        log_event(logger, "debug", "Client disconnected", {
            "event_type": "CONNECTION_RESET",
            "src_ip": client_ip,
        })
    except Exception as e:
        log_event(logger, "error", "Unexpected error", {
            "event_type": "HANDLER_ERROR",
            "src_ip": client_ip,
            "error": str(e),
        })
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass
        log_event(logger, "info", "Connection closed", {
            "event_type": "CONNECTION_CLOSE",
            "src_ip": client_ip,
        })


def run_ssh_honeypot():
    host_key = generate_host_key()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((SSH_HOST, SSH_PORT))
    except Exception as e:
        logger.critical(f"Cannot bind to port {SSH_PORT}: {e}")
        sys.exit(1)
    server_socket.listen(SSH_MAX_CONNECTIONS)
    log_event(logger, "info", "SSH Honeypot started", {
        "event_type": "HONEYPOT_START",
        "bind_host": SSH_HOST,
        "bind_port": SSH_PORT,
        "node_id": NODE_ID,
    })
    print(f"\nSSH Honeypot started on port {SSH_PORT}")
    print(f"Node ID  : {NODE_ID}")
    print(f"Log file : {LOG_FILE_SSH}")
    print("Press Ctrl+C to stop\n")
    active_threads = []
    try:
        while True:
            try:
                client_socket, client_address = server_socket.accept()
            except OSError:
                break
            active_threads = [t for t in active_threads if t.is_alive()]
            if len(active_threads) >= SSH_MAX_CONNECTIONS:
                client_socket.close()
                continue
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, host_key),
                daemon=True,
            )
            thread.start()
            active_threads.append(thread)
    except KeyboardInterrupt:
        print("\nStopping honeypot...")
        log_event(logger, "info", "Honeypot stopped", {
            "event_type": "HONEYPOT_STOP",
            "node_id": NODE_ID,
        })
    finally:
        server_socket.close()


if __name__ == "__main__":
    run_ssh_honeypot()