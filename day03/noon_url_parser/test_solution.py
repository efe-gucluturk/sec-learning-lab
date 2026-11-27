"""Tests for the URL & query parameter inspector (sample strings only, no network)."""

import solution

FULL_URL = "https://alice:s3cret@example.com:8443/login/form?next=/home&lang=en#top"


def test_inspect_url_splits_all_parts():
    info = solution.inspect_url(FULL_URL)
    assert info == {
        "scheme": "https",
        "username": "alice",
        "password": "s3cret",
        "host": "example.com",
        "port": 8443,
        "path": "/login/form",
        "query": "next=/home&lang=en",
        "fragment": "top",
    }


def test_inspect_url_without_optional_parts():
    info = solution.inspect_url("http://example.org")
    assert info["host"] == "example.org"
    assert info["port"] is None
    assert info["path"] == ""
    assert info["query"] == ""
    assert info["username"] is None


def test_invalid_port_does_not_crash():
    info = solution.inspect_url("http://example.com:99999/")
    assert info["port"] is None


def test_list_params_keeps_repeats_and_blanks():
    params = solution.list_params("id=1&id=2&empty=&q=hello%20world")
    assert params == [("id", "1"), ("id", "2"), ("empty", ""), ("q", "hello world")]


def test_list_params_empty_query():
    assert solution.list_params("") == []


def test_security_hints_detects_problems():
    url = "http://bob:pw@example.com/?token=abc&next=https://evil.example"
    info = solution.inspect_url(url)
    hints = solution.security_hints(info, solution.list_params(info["query"]))
    assert any("password" in h for h in hints)
    assert any("Plain HTTP" in h for h in hints)
    assert any("'token'" in h for h in hints)
    assert any("open redirect" in h for h in hints)


def test_security_hints_clean_url():
    info = solution.inspect_url("https://example.com/search?q=python&next=/home")
    assert solution.security_hints(info, solution.list_params(info["query"])) == []


def test_report_masks_password():
    report = solution.format_report(FULL_URL)
    assert "s3cret" not in report
    assert "******" in report
    assert "next = '/home'" in report
    assert "Query parameters (2):" in report


def test_main_cli_prints_report(capsys):
    assert solution.main(["https://example.com/a?x=1"]) == 0
    out = capsys.readouterr().out
    assert "host     : example.com" in out
    assert "x = '1'" in out
