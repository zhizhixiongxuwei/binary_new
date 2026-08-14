"""BinaryScan Python checker HTTP service.

A zero-dependency JSON service built on the standard library (http.server).
The worker submits decompiled Python sources and receives findings plus
diagnostics with a versioned request/response schema.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import rules

SERVER_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

MAX_BODY_BYTES = 64 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "binaryscan-python-checker/0.1.0"

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "name": rules.RESPONSE_SCHEMA})
            return
        self._send(404, {"error": {"code": "not_found",
                                   "message": "unknown endpoint"}})

    def do_POST(self):
        if self.path != "/analyze":
            self._send(404, {"error": {"code": "not_found",
                                       "message": "unknown endpoint"}})
            return
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            self._send(411, {"error": {"code": "length_required",
                                       "message": "Content-Length is required"}})
            return
        size = int(length)
        if size <= 0 or size > MAX_BODY_BYTES:
            self._send(413, {"error": {"code": "too_large",
                                       "message": "request body is too large"}})
            return
        try:
            payload = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": {"code": "invalid_json",
                                       "message": "request body is not JSON"}})
            return
        response, status = rules.analyze_request(payload)
        self._send(status, response)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


def main():
    server = ThreadingHTTPServer(("0.0.0.0", SERVER_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
