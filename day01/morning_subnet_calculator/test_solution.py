"""Tests for the IPv4 subnet calculator (sample strings only, no network)."""

import pytest
from solution import calculate, int_to_ip, ip_to_int, parse_cidr


def test_ip_round_trip():
    assert int_to_ip(ip_to_int("192.168.1.10")) == "192.168.1.10"


def test_parse_cidr():
    assert parse_cidr("10.0.0.1/8") == (ip_to_int("10.0.0.1"), 8)


def test_slash_24():
    info = calculate("192.168.1.10/24")
    assert info["network"] == "192.168.1.0"
    assert info["broadcast"] == "192.168.1.255"
    assert info["mask"] == "255.255.255.0"
    assert info["first_host"] == "192.168.1.1"
    assert info["last_host"] == "192.168.1.254"
    assert info["hosts"] == 254


def test_slash_20_non_octet_boundary():
    info = calculate("172.16.37.5/20")
    assert info["network"] == "172.16.32.0"
    assert info["broadcast"] == "172.16.47.255"
    assert info["mask"] == "255.255.240.0"


def test_slash_32_and_31():
    assert calculate("1.2.3.4/32")["hosts"] == 1
    info = calculate("1.2.3.4/31")
    assert (info["first_host"], info["last_host"]) == ("1.2.3.4", "1.2.3.5")


def test_slash_0():
    info = calculate("8.8.8.8/0")
    assert info["mask"] == "0.0.0.0"
    assert info["broadcast"] == "255.255.255.255"


@pytest.mark.parametrize(
    "bad", ["1.2.3.4", "1.2.3/24", "256.1.1.1/24", "1.2.3.4/33", "a.b.c.d/8", "1.2.3.4/-1"]
)
def test_invalid_input(bad):
    with pytest.raises(ValueError):
        calculate(bad)
