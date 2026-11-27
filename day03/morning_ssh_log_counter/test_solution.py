"""Tests for the SSH failed-login counter (sample log lines only, no network)."""

import solution

SAMPLE_LOG = """\
Nov 27 10:15:01 srv sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
Nov 27 10:15:03 srv sshd[1234]: Failed password for root from 203.0.113.5 port 52212 ssh2
Nov 27 10:15:09 srv sshd[1240]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2
Nov 27 10:15:20 srv sshd[1250]: Accepted password for alice from 192.0.2.10 port 50000 ssh2
Nov 27 10:16:00 srv sshd[1301]: Invalid user test from 192.0.2.44 port 51000
Nov 27 10:16:05 srv sshd[1302]: Failed publickey for bob from 2001:db8::1 port 6000 ssh2
Nov 27 10:17:00 srv CRON[999]: pam_unix(cron:session): session opened for user root
Nov 27 10:18:00 srv sshd[1400]: Failed password for root from 203.0.113.5 port 52299 ssh2
"""


def test_extract_failed_password():
    line = "sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2"
    assert solution.extract_failed_ip(line) == "203.0.113.5"


def test_extract_invalid_user_variants():
    line = "sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 22 ssh2"
    assert solution.extract_failed_ip(line) == "198.51.100.7"
    assert solution.extract_failed_ip("sshd[2]: Invalid user test from 192.0.2.44 port 1") == "192.0.2.44"


def test_extract_ignores_success_and_other_services():
    assert solution.extract_failed_ip("sshd[1]: Accepted password for a from 192.0.2.10 port 1") is None
    assert solution.extract_failed_ip("CRON[1]: Failed password for x from 1.2.3.4 port 1") is None


def test_count_failed_logins():
    counts = solution.count_failed_logins(SAMPLE_LOG.splitlines())
    assert counts == {
        "203.0.113.5": 3,
        "198.51.100.7": 1,
        "192.0.2.44": 1,
        "2001:db8::1": 1,
    }
    assert "192.0.2.10" not in counts


def test_format_report_sorting_top_and_minimum():
    counts = solution.count_failed_logins(SAMPLE_LOG.splitlines())
    report = solution.format_report(counts, top=1)
    assert "203.0.113.5" in report and "198.51.100.7" not in report
    report = solution.format_report(counts, minimum=2)
    assert "203.0.113.5" in report and "192.0.2.44" not in report
    assert solution.format_report(counts, minimum=10) == "No failed SSH logins found."


def test_main_reads_file(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(SAMPLE_LOG, encoding="utf-8")
    assert solution.main([str(log), "--top", "2"]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.5" in out
    assert "3" in out


def test_main_missing_file(tmp_path, capsys):
    assert solution.main([str(tmp_path / "nope.log")]) == 1
    assert "could not read" in capsys.readouterr().err
