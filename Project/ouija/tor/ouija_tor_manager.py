#!/usr/bin/env python3
"""
OUIJA Tor Manager & Onion Routing Daemon
Controls Tor Hidden Services (v3 Onion), SOCKS5 Proxy Dispatcher, and Message Forwarding.
"""

import sys
import os
import time
import json
import socket
import tempfile
import subprocess
import shutil
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

# SOCKS5 support via python socks/socket
try:
    import socks
    HAVE_SOCKS = True
except ImportError:
    HAVE_SOCKS = False

TOR_CONTROL_PORT = int(os.environ.get("OUIJA_TOR_CONTROL_PORT", 9051))
TOR_SOCKS_PORT = int(os.environ.get("OUIJA_TOR_SOCKS_PORT", 9050))
OUIJA_BRIDGE_PORT = int(os.environ.get("OUIJA_BRIDGE_PORT", 9058))
OUIJA_HTTP_PORT = int(os.environ.get("OUIJA_HTTP_PORT", 8765))

class TorBridgeHandler(BaseHTTPRequestHandler):
    """Internal HTTP/JSON IPC handler for the Rust Ouija backend."""

    def log_message(self, format, *args):
        # Quiet logging
        pass

    def do_GET(self):
        if self.path == "/status":
            onion = self.server.tor_manager.get_onion_address()
            resp = {
                "status": "online" if onion else "starting",
                "onion_address": onion or "initializing.onion",
                "socks_port": self.server.tor_manager.socks_port,
                "hidden_service_port": 80,
                "target_port": OUIJA_HTTP_PORT
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/send_onion":
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body.decode('utf-8'))
                target_onion = data.get("target_onion")
                payload = data.get("payload") # Encrypted XMPP + OTP blob
                
                success, msg = self.server.tor_manager.send_to_onion(target_onion, payload)
                resp = {"success": success, "message": msg}
                status_code = 200 if success else 502
            except Exception as e:
                resp = {"success": False, "error": str(e)}
                status_code = 400

            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()


class TorManager:
    def __init__(self):
        self.tor_proc = None
        self.temp_dir = None
        self.onion_address = None
        self.socks_port = TOR_SOCKS_PORT
        self.control_port = TOR_CONTROL_PORT

    def is_port_open(self, host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            return s.connect_ex((host, port)) == 0

    def start(self):
        """Start or attach to Tor instance with Hidden Service."""
        print(f"[OUIJA-TOR] Initializing Tor integration on bridge port {OUIJA_BRIDGE_PORT}...")
        
        # Check if system tor or local tor is running
        self.temp_dir = tempfile.mkdtemp(prefix="ouija_tor_")
        hs_dir = os.path.join(self.temp_dir, "hs")
        os.makedirs(hs_dir, mode=0o700)

        # Generate minimal torrc for ephemeral hidden service
        torrc_path = os.path.join(self.temp_dir, "torrc")
        with open(torrc_path, "w") as f:
            f.write(f"""
DataDirectory {self.temp_dir}
SocksPort {self.socks_port}
ControlPort {self.control_port}
HiddenServiceDir {hs_dir}
HiddenServicePort 80 127.0.0.1:{OUIJA_HTTP_PORT}
HiddenServiceVersion 3
Log notice stdout
""")

        try:
            # Check if tor executable exists
            if shutil.which("tor"):
                print(f"[OUIJA-TOR] Launching ephemeral Tor instance (v3 hidden service)...")
                self.tor_proc = subprocess.Popen(
                    ["tor", "-f", torrc_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )

                # Read stdout in thread to monitor bootstrap & hostname
                def monitor_tor():
                    hostname_file = os.path.join(hs_dir, "hostname")
                    while True:
                        if self.tor_proc and self.tor_proc.poll() is not None:
                            break
                        if os.path.exists(hostname_file):
                            try:
                                with open(hostname_file, "r") as hf:
                                    addr = hf.read().strip()
                                    if addr:
                                        self.onion_address = addr
                                        print(f"[OUIJA-TOR] SUCCESS: Onion Address active: {self.onion_address}")
                                        break
                            except Exception:
                                pass
                        time.sleep(0.5)

                t = Thread(target=monitor_tor, daemon=True)
                t.start()
            else:
                print("[OUIJA-TOR] Warning: 'tor' binary not found in system PATH. Fallback to simulated Tor network bridge.")
                self.onion_address = "ouija777777777777777777777777777777777777777777777777777.onion"

        except Exception as e:
            print(f"[OUIJA-TOR] Tor startup warning: {e}. Running in local relay mode.")
            self.onion_address = "ouijalocalrelay777777777777777777777777777777777777777.onion"

    def get_onion_address(self):
        if self.onion_address:
            return self.onion_address
        # Check hostname file
        if self.temp_dir:
            hf = os.path.join(self.temp_dir, "hs", "hostname")
            if os.path.exists(hf):
                try:
                    with open(hf, "r") as f:
                        self.onion_address = f.read().strip()
                        return self.onion_address
                except Exception:
                    pass
        return self.onion_address or "connecting.onion"

    def send_to_onion(self, target_onion, payload_dict):
        """Send message through Tor SOCKS5 proxy to target onion address."""
        if not target_onion.endswith(".onion") and not target_onion.startswith("http"):
            target_onion = f"http://{target_onion}"
        elif not target_onion.startswith("http://") and not target_onion.startswith("https://"):
            target_onion = f"http://{target_onion}"

        target_url = f"{target_onion}/api/inbox"
        data_bytes = json.dumps(payload_dict).encode('utf-8')

        print(f"[OUIJA-TOR] Routing encrypted packet to: {target_url} (size={len(data_bytes)} bytes)")

        # If direct local target or simulated onion
        if "127.0.0.1" in target_onion or "localhost" in target_onion or target_onion.startswith("http://ouija"):
            # Direct post for local testbed or simulation
            try:
                # If target is local test port
                req = urllib.request.Request(
                    f"http://127.0.0.1:{OUIJA_HTTP_PORT}/api/inbox",
                    data=data_bytes,
                    headers={"Content-Type": "application/json", "User-Agent": "Ouija-Tor-Client/1.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    return True, f"Delivered via local loopback relay (status: {response.status})"
            except Exception as e:
                return False, f"Delivery error: {e}"

        # Real Tor Onion routing via SOCKS5
        if HAVE_SOCKS:
            try:
                # Configure SOCKS socket
                s = socks.socksocket()
                s.set_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
                s.settimeout(30)
                
                # Parse host and port
                parsed = urllib.parse.urlparse(target_url)
                host = parsed.hostname
                port = parsed.port or 80
                path = parsed.path or "/api/inbox"

                s.connect((host, port))
                http_req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: Ouija-Tor-Node/1.0\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(data_bytes)}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode('utf-8') + data_bytes

                s.sendall(http_req)
                response = s.recv(4096)
                s.close()
                return True, f"Delivered through Tor circuit to {host}"
            except Exception as e:
                return False, f"Tor SOCKS5 routing failed: {e}"
        else:
            return False, "Python SOCKS module not available for Tor socket routing"

    def cleanup(self):
        if self.tor_proc:
            print("[OUIJA-TOR] Terminating Tor process...")
            self.tor_proc.terminate()
            try:
                self.tor_proc.wait(timeout=3)
            except Exception:
                self.tor_proc.kill()
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception:
                pass


def run_bridge_server():
    mgr = TorManager()
    mgr.start()

    server = HTTPServer(("127.0.0.1", OUIJA_BRIDGE_PORT), TorBridgeHandler)
    server.tor_manager = mgr
    print(f"[OUIJA-TOR] Bridge server listening on http://127.0.0.1:{OUIJA_BRIDGE_PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        mgr.cleanup()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        run_bridge_server()
    else:
        run_bridge_server()
