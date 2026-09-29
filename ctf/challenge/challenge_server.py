#!/usr/bin/env python3
"""
challenge_server.py
Background web service running on port 9191 for Stage 5 of the 5-in-1 CTF challenge.
"""

import http.server
import socketserver
import os
import sys

PORT = 9191

# Layered cipher flag: Base64 -> ROT13
# Plain flag: CTF{5_t00l5_1_m45t3r_ch41n_c0mpl3t3}
# ROT13:      PGF{5_g00y5_1_z45g3e_pu41a_p0zcy3g3}
# Base64:     UEdTezVfZzAweTVfMV96NDVnM2VfcHU0MWFfcDB6Y3kzZzN9
LAYERED_FLAG_PAYLOAD = "UEdTezVfZzAweTVfMV96NDVnM2VfcHU0MWFfcDB6Y3kzZzN9"

class ChallengeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "CTF-Vault-Gateway/2.1")
            self.end_headers()
            body = """<!DOCTYPE html>
<html>
<head><title>Internal CTF Vault</title></head>
<body>
<h1>Internal CTF Secure Vault Gateway</h1>
<p>Authentication node active. Public routes are restricted.</p>
<!-- Hint: Check standard directories for sensitive exports -->
</body>
</html>"""
            self.wfile.write(body.encode())

        elif self.path == "/vault" or self.path == "/vault/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = f'{{"status": "success", "vault_access": "granted", "encrypted_flag": "{LAYERED_FLAG_PAYLOAD}"}}\n'
            self.wfile.write(response.encode())

        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /vault\n")

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found\n")

    def log_message(self, format, *args):
        # Suppress noisy request logs to keep terminal clean
        pass

def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), ChallengeHandler) as httpd:
        print(f"[*] Challenge server listening on 127.0.0.1:{PORT}...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down challenge server.")

if __name__ == "__main__":
    main()
