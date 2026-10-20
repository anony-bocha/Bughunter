"""Deliberately vulnerable local server for the bughunter demo.

Run it on 127.0.0.1:8000, then point bughunter at the local_demo policy.
It serves fake data and intentionally bad configuration so the safe checks
have something to find. Do not deploy this anywhere public.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8000

_INDEX = """<!doctype html>
<html><head>
<title>Local Demo App</title>
<meta name="generator" content="DemoGen 1.0">
<script src="/app.js"></script>
</head><body>
<h1>Local Demo</h1>
<a href="/api/v1/users">Users API</a>
<a href="/admin/settings">Admin settings</a>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
<!-- build: staging branch, contact dev@example.com -->
</body></html>
"""

_APP_JS = """
const API = "/api/v1/users";
const token = "AKIA1234567890ABCDEF";
const bucket = "https://demo-bucket.s3.amazonaws.com/exports/";
fetch(API).then(r => r.json());
function load() { return fetch("/graphql").then(r => r.json()); }
//# sourceMappingURL=app.js.map
"""

_GRAPHQL = json.dumps(
    {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}}}}
).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.25.1"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:  # keep the demo quiet
        return

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/html", extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.25.1")
        self.send_header("X-Powered-By", "PHP/8.2.1")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        origin = self.headers.get("Origin", "")
        if path == "/robots.txt":
            self._send(200, b"User-agent: *\nAllow: /\n", "text/plain")
        elif path == "/":
            self._send(
                200,
                _INDEX.encode("utf-8"),
                "text/html; charset=utf-8",
                {"Set-Cookie": "sid=abc123; Path=/"},
            )
        elif path == "/app.js":
            self._send(200, _APP_JS.encode("utf-8"), "application/javascript")
        elif path == "/api/v1/users":
            extra = {"Vary": "Origin"}
            if origin:
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            self._send(200, b'[{"id": 1, "email": "user@example.com"}]', "application/json", extra)
        elif path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n", "text/plain")
        elif path == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n", "text/plain")
        elif path == "/.env":
            self._send(200, b"APP_ENV=production\nDEBUG=true\n", "text/plain")
        elif path == "/backup.zip":
            self._send(200, b"PK\x03\x04demo-backup", "application/zip")
        elif path == "/swagger-ui.html":
            self._send(200, b"<html><title>Swagger UI</title></html>", "text/html")
        elif path == "/openapi.json":
            self._send(200, b'{"openapi": "3.0.0"}', "application/json")
        elif path == "/server-status":
            self._send(200, b"<html>Apache Server Status for localhost</html>", "text/html")
        else:
            self._send(404, b"<html>404 not found</html>", "text/html")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(min(length, 65536))
        if path == "/graphql":
            self._send(200, _GRAPHQL, "application/json")
        else:
            self._send(404, b"<html>404 not found</html>", "text/html")


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Local demo server on http://{HOST}:{PORT} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
