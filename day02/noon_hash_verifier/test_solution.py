"""Tests for the SHA-256 file integrity verifier (local temp files only)."""

import pytest
import solution

# Well-known SHA-256 test vectors.
EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


@pytest.fixture
def abc_file(tmp_path):
    path = tmp_path / "abc.txt"
    path.write_bytes(b"abc")
    return path


def test_sha256_of_bytes_known_vectors():
    assert solution.sha256_of_bytes(b"") == EMPTY_HASH
    assert solution.sha256_of_bytes(b"abc") == ABC_HASH


def test_sha256_of_file(abc_file):
    assert solution.sha256_of_file(abc_file) == ABC_HASH


def test_small_chunks_give_same_hash(tmp_path):
    path = tmp_path / "big.bin"
    data = bytes(range(256)) * 1000
    path.write_bytes(data)
    assert solution.sha256_of_file(path, chunk_size=7) == solution.sha256_of_bytes(data)


def test_one_byte_change_changes_hash(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"abd")
    assert solution.sha256_of_file(path) != ABC_HASH


def test_normalize_hash_accepts_upper_case_and_spaces():
    assert solution.normalize_hash(f"  {ABC_HASH.upper()}\n") == ABC_HASH


@pytest.mark.parametrize("bad", ["abc", ABC_HASH[:-1] + "z", ABC_HASH + "0"])
def test_normalize_hash_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        solution.normalize_hash(bad)


def test_hashes_match():
    assert solution.hashes_match(ABC_HASH, ABC_HASH.upper())
    assert not solution.hashes_match(ABC_HASH, EMPTY_HASH)


def test_read_checksum_file(tmp_path):
    path = tmp_path / "abc.txt.sha256"
    path.write_text(f"\n{ABC_HASH}  abc.txt\n", encoding="utf-8")
    assert solution.read_checksum_file(path) == ABC_HASH


def test_read_checksum_file_empty(tmp_path):
    path = tmp_path / "empty.sha256"
    path.write_text("\n\n", encoding="utf-8")
    with pytest.raises(ValueError):
        solution.read_checksum_file(path)


def test_main_prints_hash_without_expected(abc_file, capsys):
    assert solution.main([str(abc_file)]) == 0
    assert ABC_HASH in capsys.readouterr().out


def test_main_match_and_mismatch(abc_file, capsys):
    assert solution.main([str(abc_file), ABC_HASH]) == 0
    assert "OK" in capsys.readouterr().out
    assert solution.main([str(abc_file), EMPTY_HASH]) == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_main_with_checksum_file(abc_file, tmp_path):
    checksum = tmp_path / "abc.sha256"
    checksum.write_text(f"{ABC_HASH}  abc.txt\n", encoding="utf-8")
    assert solution.main([str(abc_file), "--checksum-file", str(checksum)]) == 0


def test_main_errors(tmp_path, abc_file, capsys):
    assert solution.main([str(tmp_path / "missing.txt")]) == 1
    assert solution.main([str(abc_file), "not-a-hash"]) == 1
    assert "Error" in capsys.readouterr().err
