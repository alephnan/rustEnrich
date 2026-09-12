#!/usr/bin/env python3
"""Exercise the Bash client over loopback HTTP with synthetic credentials only."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).resolve().with_name("test_indicators.sh")
TOKEN = "synthetic-test-token-" + "x" * 32


class SmokeClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rustenrich-client-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input = self.root / "indicators.txt"
        self.token = self.root / "token"
        self.token.write_text(TOKEN + "\r\n", encoding="ascii")
        self.output = self.root / "results"
        self.requests = []
        self.status = 200
        self.body = None
        self.disconnect = False
        self.outcomes = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, self.headers.get("Authorization"), payload))
                if owner.disconnect:
                    self.close_connection = True
                    return
                indicator = payload["indicators"][0]
                duplicate = any(request[2]["indicators"][0] == indicator for request in owner.requests[:-1])
                results = []
                for name in payload.get("providers", ["abuseipdb", "virustotal"]):
                    status = owner.outcomes.get(name, "ok")
                    error = None if status in {"ok", "not_found", "unsupported", "disabled"} else {
                        "code": "quota_exhausted", "retry_after_seconds": 60,
                    }
                    result = {"provider": name, "status": status, "cache": {"hit": duplicate}, "error": error}
                    if payload["include_raw"]:
                        result["raw"] = {"private_report": "synthetic-raw-evidence"}
                    results.append(result)
                body = owner.body if owner.body is not None else {
                    "request_id": "mock-request", "results": [{"index": 0, "input": indicator, "providers": results}],
                }
                content = json.dumps(body).encode()
                self.send_response(owner.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                if owner.status == 302:
                    self.send_header("Location", "/redirect")
                self.end_headers()
                self.wfile.write(content)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)

    def invoke(self, content="ip 8.8.8.8\n", *options):
        self.input.write_bytes(content if isinstance(content, bytes) else content.encode())
        completed = subprocess.run(
            ["bash", str(SCRIPT), str(self.input), "--token-file", str(self.token),
             "--output-dir", str(self.output), "--base-url", f"http://127.0.0.1:{self.server.server_port}",
             "--delay", "0", *options],
            cwd=self.root, capture_output=True, text=True, timeout=10,
            env={**os.environ, "TMPDIR": str(self.root)}, check=False,
        )
        self.assertNotIn(TOKEN, completed.stdout + completed.stderr)
        self.assertEqual(list(self.root.glob("rustenrich-client-*")), [])
        return completed

    def saved_runs(self):
        return list(self.output.glob("run-*"))

    def test_preserves_crlf_urls_hash_case_order_duplicates_and_authentication(self):
        url = 'https://example.com/A%2fb?x=one&x=two#Fragment'
        digest = "D41D8CD98F00B204E9800998ECF8427E"
        content = f"\ufeff# comment\r\n\r\nip 8.8.8.8\r\nurl\t{url}\r\nhash {digest}\r\nip 8.8.8.8"
        completed = self.invoke(content, "--providers", "virustotal,abuseipdb", "--raw")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual([request[2]["indicators"][0]["value"] for request in self.requests], ["8.8.8.8", url, digest, "8.8.8.8"])
        for path, authorization, payload in self.requests:
            self.assertEqual(path, "/v1/enrich")
            self.assertEqual(authorization, f"Bearer {TOKEN}")
            self.assertEqual(payload["providers"], ["virustotal", "abuseipdb"])
            self.assertTrue(payload["include_raw"])
        self.assertIn("cache.hit=true", completed.stdout)
        self.assertNotIn(url, completed.stdout + completed.stderr)
        self.assertNotIn("synthetic-raw-evidence", completed.stdout + completed.stderr)
        run = self.saved_runs()[0]
        self.assertEqual(len(list(run.glob("*.json"))), 4)
        self.assertIn("4\t6\tip\t200\t0004.json", (run / "index.tsv").read_text())
        self.assertEqual((run / "0001.json").stat().st_mode & 0o777, 0o600)

    def test_dry_run_needs_no_token_and_makes_no_requests(self):
        self.token.unlink()
        completed = self.invoke("ip 8.8.8.8\n", "--dry-run")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.requests, [])
        self.assertFalse(self.output.exists())

    def test_rejects_bad_file_before_any_dispatch(self):
        for content in ["ip 8.8.8.8\nhash bad\n", "ip 8.8.8.8\nunknown value\n",
                        b"url https://example.com/\x00hidden\n", b"url https://example.com/\xff\n",
                        "ip 8.8.8.8\n" * 1001, "url https://example.com/" + "x" * 4096,
                        "# empty\n", "x" * 1_048_577]:
            with self.subTest(size=len(content)):
                completed = self.invoke(content)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(self.requests, [])

    def test_stops_on_partial_provider_failure_and_retains_successes(self):
        for status in ["rate_limited", "error", "timeout", "disabled"]:
            with self.subTest(status=status):
                self.requests.clear()
                self.outcomes = {"virustotal": status}
                completed = self.invoke("ip 8.8.8.8\nip 1.1.1.1\n")
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(len(self.requests), 1)
        for run in self.saved_runs():
            body = json.loads((run / "0001.json").read_text())
            self.assertEqual(body["results"][0]["providers"][0]["status"], "ok")

    def test_continues_on_not_found_and_unsupported(self):
        self.outcomes = {"abuseipdb": "unsupported", "virustotal": "not_found"}
        completed = self.invoke("url https://example.com/\nurl https://example.org/\n")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(self.requests), 2)
        self.assertNotIn("providers", self.requests[0][2])

    def test_http_failures_and_redirects_are_not_retried(self):
        for status in [401, 422, 503, 302]:
            with self.subTest(status=status):
                self.requests.clear()
                self.status = status
                completed = self.invoke("ip 8.8.8.8\nip 1.1.1.1\n")
                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertEqual(len(self.requests), 1)

    def test_transport_disconnect_is_not_retried(self):
        self.disconnect = True
        completed = self.invoke("ip 8.8.8.8\nip 1.1.1.1\n")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(len(self.requests), 1)
        self.assertIn("transport_error", (self.saved_runs()[0] / "index.tsv").read_text())

    def test_unexpected_response_cannot_report_success(self):
        self.body = {"request_id": "mock", "results": []}
        completed = self.invoke("ip 8.8.8.8\nip 1.1.1.1\n")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(len(self.requests), 1)

    def test_rejects_invalid_tokens_without_echoing_or_dispatching(self):
        for token in ["", "short", TOKEN + "\nInjected: header", TOKEN + "\n\n"]:
            with self.subTest(length=len(token)):
                self.token.write_text(token)
                completed = self.invoke()
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
