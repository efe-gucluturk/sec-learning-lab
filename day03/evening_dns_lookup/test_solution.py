"""Tests for the DNS Record Lookup Tool. No real network access is used."""

import socket

import pytest
import solution

# Sample getaddrinfo output: a duplicate IPv4 address and one IPv6 address.
FAKE_RESULTS = [
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1::1", 0, 0, 0)),
]


def fake_resolver(host, port, family, socktype):
    return FAKE_RESULTS


def failing_resolver(host, port, family, socktype):
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


@pytest.mark.parametrize("name", ["example.com", "a-b.example.org.", "localhost", "10.0.0.1", "::1"])
def test_valid_hostnames(name):
    assert solution.is_valid_hostname(name)


@pytest.mark.parametrize("name", ["", "-bad.com", "bad-.com", "a..b", "x" * 64 + ".com", "evil.com;ls"])
def test_invalid_hostnames(name):
    assert not solution.is_valid_hostname(name)


@pytest.mark.parametrize("ip, kind", [
    ("127.0.0.1", "loopback"),
    ("::1", "loopback"),
    ("10.1.2.3", "private"),
    ("192.168.0.5", "private"),
    ("169.254.1.1", "link-local"),
    ("8.8.8.8", "public"),
])
def test_classify_ip(ip, kind):
    assert solution.classify_ip(ip) == kind


def test_resolve_groups_and_deduplicates():
    records = solution.resolve("example.com", resolver=fake_resolver)
    assert records == {"A": ["93.184.216.34"], "AAAA": ["2606:2800:220:1::1"]}


def test_resolve_passes_family():
    seen = {}

    def spy(host, port, family, socktype):
        seen["family"] = family
        return []

    solution.resolve("example.com", family="6", resolver=spy)
    assert seen["family"] == socket.AF_INET6


def test_resolve_ip_literal_without_network():
    # getaddrinfo handles a numeric address locally, without asking DNS.
    records = solution.resolve("127.0.0.1", family="4")
    assert records["A"] == ["127.0.0.1"]


def test_resolve_rejects_bad_hostname():
    with pytest.raises(ValueError):
        solution.resolve("bad host!", resolver=fake_resolver)


def test_format_records():
    lines = solution.format_records("example.com", {"A": ["10.0.0.1"], "AAAA": []})
    assert lines[0] == "DNS lookup for example.com"
    assert "10.0.0.1" in lines[1] and "(private)" in lines[1]
    empty = solution.format_records("x.com", {"A": [], "AAAA": []})
    assert "no addresses found" in empty[1]


def use_resolver(monkeypatch, resolver):
    """Make main() call resolve() with a fake resolver instead of real DNS."""
    real_resolve = solution.resolve
    monkeypatch.setattr(solution, "resolve",
                        lambda host, family: real_resolve(host, family, resolver=resolver))


def test_main_success(monkeypatch, capsys):
    use_resolver(monkeypatch, fake_resolver)
    assert solution.main(["example.com"]) == 0
    out = capsys.readouterr().out
    assert "93.184.216.34" in out and "(public)" in out


def test_main_errors(monkeypatch, capsys):
    use_resolver(monkeypatch, failing_resolver)
    assert solution.main(["bad host!"]) == 2
    assert solution.main(["nonexistent.invalid"]) == 1
    assert "could not resolve" in capsys.readouterr().err
