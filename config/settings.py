import os

SSH_HOST = os.environ.get("SSH_HOST", "0.0.0.0")
SSH_PORT = int(os.environ.get("SSH_PORT", 2222))
SSH_BANNER = os.environ.get("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
SSH_MAX_CONNECTIONS = int(os.environ.get("SSH_MAX_CONNECTIONS", 50))
SSH_AUTH_TIMEOUT = int(os.environ.get("SSH_AUTH_TIMEOUT", 30))

LOG_DIR = os.environ.get("LOG_DIR", "logs")
LOG_FILE_SSH = os.path.join(LOG_DIR, "ssh_honeypot.json")
LOG_FILE_SYSTEM = os.path.join(LOG_DIR, "system.json")
LOG_ROTATION_BYTES = int(os.environ.get("LOG_ROTATION_BYTES", 5_000_000))
LOG_ROTATION_COUNT = int(os.environ.get("LOG_ROTATION_COUNT", 5))

NODE_ID = os.environ.get("NODE_ID", "node-ssh-01")
NODE_ROLE = os.environ.get("NODE_ROLE", "ssh-honeypot")

MAX_ATTEMPTS_PER_IP = int(os.environ.get("MAX_ATTEMPTS_PER_IP", 10))