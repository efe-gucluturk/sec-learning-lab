"""Tests for the Caesar & XOR cipher lab (sample strings only, no network)."""

import pytest
import solution


def test_caesar_known_example():
    assert solution.caesar_encrypt("Hello, World!", 3) == "Khoor, Zruog!"
    assert solution.caesar_decrypt("Khoor, Zruog!", 3) == "Hello, World!"


def test_caesar_wraps_around_alphabet():
    assert solution.caesar_encrypt("xyz XYZ", 3) == "abc ABC"
    assert solution.caesar_encrypt("abc", -1) == "zab"
    assert solution.caesar_encrypt("abc", 29) == "def"  # 29 is the same as 3


def test_caesar_rot13_is_its_own_inverse():
    text = "Attack at dawn 123"
    assert solution.caesar_encrypt(solution.caesar_encrypt(text, 13), 13) == text


def test_caesar_bruteforce_contains_plaintext():
    results = solution.caesar_bruteforce("Khoor")
    assert len(results) == 26
    assert (3, "Hello") in results


def test_xor_bytes_known_values():
    assert solution.xor_bytes(b"\x00\xff", b"\x0f") == b"\x0f\xf0"


def test_xor_roundtrip():
    secret = solution.xor_encrypt("attack at dawn", "secret")
    assert secret != b"attack at dawn".hex()
    assert solution.xor_decrypt(secret, "secret") == "attack at dawn"


def test_xor_key_repeats():
    # Key "AB" over 4 bytes uses A, B, A, B.
    assert solution.xor_bytes(b"\x00\x00\x00\x00", b"AB") == b"ABAB"


def test_xor_empty_key_rejected():
    with pytest.raises(ValueError):
        solution.xor_bytes(b"data", b"")


def test_xor_decrypt_bad_hex():
    with pytest.raises(ValueError):
        solution.xor_decrypt("not hex!", "key")


def test_cli_caesar_encrypt(capsys):
    assert solution.main(["caesar", "encrypt", "abc", "--shift", "1"]) == 0
    assert capsys.readouterr().out.strip() == "bcd"


def test_cli_caesar_bruteforce(capsys):
    assert solution.main(["caesar", "bruteforce", "Khoor"]) == 0
    assert " 3: Hello" in capsys.readouterr().out


def test_cli_xor_roundtrip(capsys):
    assert solution.main(["xor", "encrypt", "hi there", "--key", "k"]) == 0
    hex_text = capsys.readouterr().out.strip()
    assert solution.main(["xor", "decrypt", hex_text, "--key", "k"]) == 0
    assert capsys.readouterr().out.strip() == "hi there"


def test_cli_xor_requires_key(capsys):
    assert solution.main(["xor", "encrypt", "hi"]) == 1
    assert "--key" in capsys.readouterr().err


def test_cli_xor_bruteforce_rejected(capsys):
    assert solution.main(["xor", "bruteforce", "00", "--key", "k"]) == 1
