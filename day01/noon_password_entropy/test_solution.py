"""Tests for the password entropy checker."""
import math

from solution import entropy_bits, find_weaknesses, pool_size, rate


def test_pool_size_lowercase_only():
    assert pool_size("abc") == 26


def test_pool_size_mixed():
    assert pool_size("aA1!") == 26 + 26 + 10 + 32


def test_entropy_matches_formula():
    assert math.isclose(entropy_bits("abcd"), 4 * math.log2(26))


def test_empty_password_has_zero_entropy():
    assert entropy_bits("") == 0.0


def test_common_password_flagged():
    assert any("common" in p for p in find_weaknesses("Password"))


def test_sequence_flagged():
    assert any("sequence" in p for p in find_weaknesses("xx1234yy"))


def test_repeats_flagged():
    assert any("repeated" in p for p in find_weaknesses("aaaaaaaa"))


def test_strong_password_has_no_warnings():
    assert find_weaknesses("t7#Kp9!vLq2Z") == []


def test_rate_levels():
    assert rate(10) == "very weak"
    assert rate(100) == "very strong"
