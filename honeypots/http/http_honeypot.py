import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from config.settings import NODE_ID
from core_logging.logger import get_logger, log_event

LOG_DIR = os.environ.get("LOG_DIR", "logs")
LOG_FILE_HTTP = os.path.join(LOG_DIR, "http_honeypot.json")
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))

logger = get_logger("http_honeypot", LOG_FILE_HTTP)

FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
<h2>Admin Panel</h2>
<form method="POST" action="/login">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
</body>
</html>"""

FAKE_FAIL_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
<h2>Admin Panel</h2>
<p style="color:red">Invalid username or password.</p>
<form method="POST" action="/login">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
</body>
</html>"""


class HoneypotHTTPHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        log_event(logger, "info", "HTTP GET request", {
            "event_type": "HTTP_GET",
            "src_ip": self.client_address[0],
            "src_port": self.client_address[1],
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "node_id": NODE_ID,
        })
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(FAKE_LOGIN_PAGE.encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        log_event(logger, "warning", "HTTP login attempt captured", {
            "event_type": "HTTP_LOGIN_ATTEMPT",
            "src_ip": self.client_address[0],
            "src_port": self.client_address[1],
            "username": username,
            "password": password,
            "user_agent": self.headers.get("User-Agent", ""),
            "node_id": NODE_ID,
            "mitre_technique": "T1110",
        })
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(FAKE_FAIL_PAGE.encode())


def run_http_honeypot():
    os.makedirs(LOG_DIR, exist_ok=True)
    server = HTTPServer(("0.0.0.0", HTTP_PORT), HoneypotHTTPHandler)
    log_event(logger, "info", "HTTP Honeypot started", {
        "event_type": "HONEYPOT_START",
        "bind_port": HTTP_PORT,
        "node_id": NODE_ID,
    })
    print(f"\nHTTP Honeypot started on port {HTTP_PORT}")
    print(f"Node ID  : {NODE_ID}")
    print(f"Log file : {LOG_FILE_HTTP}")
    print("Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping HTTP honeypot...")
        log_event(logger, "info", "HTTP Honeypot stopped", {
            "event_type": "HONEYPOT_STOP",
            "node_id": NODE_ID,
        })
    finally:
        server.server_close()


if __name__ == "__main__":
    run_http_honeypot()