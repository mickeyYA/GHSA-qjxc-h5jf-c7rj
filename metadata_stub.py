#!/usr/bin/env python3
"""Fake GCP metadata server.

Enough of the real thing to demo GHSA-qjxc-h5jf-c7rj without spending a real
service account token. Same header check, same 403 when it's missing.
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Length is on purpose. Real GCP access tokens run past 200 characters, and the
# 47 bytes the error message hands over are a rounding error against that. The
# rest has to come out of the oracle one character at a time.
TOKEN = (
    "ya29.c.b0Aaekm1L9xqZ7vN3rKpQ8sT2uW5yA1bC4dE6fG8hJ0kL2mN4pQ6rS8tU0vW2xY4zA6"
    "bD8fH0jK2mP4rT6vX8zB1dF3hJ5lN7pR9tV1xZ3bE5gJ7kM9qS2uW4yA6cF8hK0mQ2sU4wY6a"
    "C9eG1iL3nQ5rU7wZ9bD2fH4jM6pS8vX0zC3eH5kN7qT9wA1dG3jL5nR7tV9yB2eG4iK6mP8s"
    "U0xA2cE4gI6kM8oQ0sU2wY4a"
)

ROUTES = {
    # compact, same as the real endpoint, so the keyword oracle is byte exact
    "/computeMetadata/v1/instance/service-accounts/default/token": json.dumps(
        {"access_token": TOKEN, "expires_in": 3599, "token_type": "Bearer"},
        separators=(",", ":"),
    ),
    "/computeMetadata/v1/instance/service-accounts/default/email": "poc-sa@example-project.iam.gserviceaccount.com",
    "/computeMetadata/v1/project/project-id": "example-project",
    "/computeMetadata/v1/instance/attributes/ssh-keys": "deploy:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC deploy@bastion",
    "/computeMetadata/v1/instance/hostname": "kuma-01.c.example-project.internal",
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Metadata-Flavor") != "Google":
            self.send(403, "Missing Metadata-Flavor:Google header")
            return

        body = ROUTES.get(self.path.rstrip("/"))
        if body is None:
            self.send(404, "not found")
            return

        self.send(200, body)

    def send(self, code, body):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Metadata-Flavor", "Google")
        self.send_header("Content-Type", "application/text")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        print("  %s" % (fmt % args))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8169)
    args = ap.parse_args()

    print("metadata stub on http://%s:%d" % (args.host, args.port))
    for path in ROUTES:
        print("  %s" % path)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
