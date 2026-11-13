"""
Lightweight Minimalist UI Server (Standard Library).
Serves the ATLAS Red-Team Console on http://localhost:8000/
"""
import http.server
import socketserver
import os
import sys
from pathlib import Path

DEFAULT_PORT = 8000
UI_DIR = Path(__file__).resolve().parent.parent.parent / "ui"

class ConsoleRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def log_message(self, format, *args):
        # Clean, minimal log output
        sys.stdout.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")

def run(port: int = DEFAULT_PORT):
    server_address = ("", port)
    # Enable address reuse so fast restarts don't hit Address already in use
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(server_address, ConsoleRequestHandler) as httpd:
        print(f"=======================================================")
        print(f"  ATLAS RED-TEAM CONSOLE RUNNING")
        print(f"  URL: http://localhost:{port}/")
        print(f"  Root: {UI_DIR}")
        print(f"  Press Ctrl+C to terminate.")
        print(f"=======================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run(port)
