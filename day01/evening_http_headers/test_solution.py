"""Tests for the HTTP security header inspector (localhost only)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import solution


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass  # keep test output quiet


def start_server():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_inspect_case_insensitive():
    report = solution.inspect_headers({"x-frame-options": "DENY"})
    assert report["X-Frame-Options"] == "DENY"
    assert report["Content-Security-Policy"] is None


def test_score_counts_present():
    report = solution.inspect_headers({"Referrer-Policy": "no-referrer"})
    assert solution.score(report) == 1


def test_format_report_marks_missing():
    text = solution.format_report(solution.inspect_headers({}))
    assert "[MISSING] Strict-Transport-Security" in text
    assert "Score: 0/6" in text


def test_fetch_headers_from_local_server():
    server = start_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        headers = solution.fetch_headers(url)
    finally:
        server.shutdown()
        server.server_close()
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_main_reports_failure(capsys):
    assert solution.main(["not-a-valid-url"]) == 1
    assert "Could not fetch" in capsys.readouterr().err
