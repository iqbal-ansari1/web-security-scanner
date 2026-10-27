#!/usr/bin/env python3
"""
Local demo server for testing scanner.py without touching anyone else's site.

    python demo_server.py             # deliberately INSECURE (reflects any Origin)
    python demo_server.py --secure    # hardened headers + strict CORS allow-list

Binds to 127.0.0.1 only. Never expose this to a network.
"""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

TRUSTED_ORIGIN = "https://trusted.example"
SECURE = False


class Handler(BaseHTTPRequestHandler):
    def version_string(self):  # controls the Server header
        return "web" if SECURE else "DemoServer/1.0.3"

    def _respond(self, body: bytes):
        origin = self.headers.get("Origin")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")

        if SECURE:
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Set-Cookie", "session=abc123; Path=/; HttpOnly; SameSite=Lax")
            if origin == TRUSTED_ORIGIN:  # exact allow-list match only
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
        else:
            self.send_header("X-Powered-By", "PythonHTTP")
            self.send_header("Set-Cookie", "session=abc123; Path=/")
            if origin:  # BAD: reflects any origin and allows credentials
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._respond(b'{"secret": "demo data"}')

    def do_OPTIONS(self):
        self._respond(b"")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--secure", action="store_true", help="serve hardened headers")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    SECURE = args.secure
    mode = "SECURE" if SECURE else "INSECURE"
    print(f"Demo server ({mode}) on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
