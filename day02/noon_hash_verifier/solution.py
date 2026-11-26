"""SHA-256 File Integrity Verifier.

Computes the SHA-256 hash of a file and, optionally, compares it with an
expected value (for example the checksum published next to a download).
If even one byte of the file changes, the hash changes completely, so a
match means the file is (almost certainly) exactly what the publisher made.

Usage:
    python solution.py installer.iso
    python solution.py installer.iso 9f86d081884c7d65...
    python solution.py installer.iso --checksum-file installer.iso.sha256
"""

import argparse
import hashlib
import hmac
import string
import sys

CHUNK_SIZE = 64 * 1024  # read 64 KiB at a time so big files fit in memory
SHA256_HEX_LENGTH = 64  # 256 bits = 32 bytes = 64 hex characters


def sha256_of_bytes(data):
    """Return the SHA-256 hex digest of a bytes object."""
    return hashlib.sha256(data).hexdigest()


def sha256_of_file(path, chunk_size=CHUNK_SIZE):
    """Return the SHA-256 hex digest of a file, reading it in chunks."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        # iter() with a sentinel keeps calling read() until it returns b"".
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def normalize_hash(text):
    """Clean up a user-supplied hash and check that it looks valid.

    Accepts upper/lower case and surrounding spaces. Raises ValueError if
    the value is not exactly 64 hexadecimal characters.
    """
    cleaned = text.strip().lower()
    if len(cleaned) != SHA256_HEX_LENGTH:
        raise ValueError(
            f"Expected {SHA256_HEX_LENGTH} hex characters, got {len(cleaned)}"
        )
    if any(ch not in string.hexdigits for ch in cleaned):
        raise ValueError("Hash contains non-hexadecimal characters")
    return cleaned


def read_checksum_file(path):
    """Read the hash from a checksum file like 'abc123...  filename'.

    This is the format produced by the `sha256sum` tool: the hash comes
    first, followed by whitespace and the file name. Only the first
    non-empty line is used.
    """
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                return normalize_hash(line.split()[0])
    raise ValueError(f"No checksum found in {path}")


def hashes_match(actual, expected):
    """Compare two hex digests safely.

    hmac.compare_digest takes the same time no matter where the strings
    differ, which is a good habit when comparing secrets or digests.
    """
    return hmac.compare_digest(actual.lower(), normalize_hash(expected))


def main(argv=None):
    """Command-line entry point. Returns 0 on success/match, 1 otherwise."""
    parser = argparse.ArgumentParser(description="Compute/verify a SHA-256 hash.")
    parser.add_argument("file", help="file to hash")
    parser.add_argument("expected", nargs="?", help="expected SHA-256 hex digest")
    parser.add_argument("--checksum-file", help="read expected hash from file")
    args = parser.parse_args(argv)

    try:
        actual = sha256_of_file(args.file)
        expected = args.expected
        if args.checksum_file:
            expected = read_checksum_file(args.checksum_file)
        if expected is None:
            # No expected value: just print the hash like sha256sum does.
            print(f"{actual}  {args.file}")
            return 0
        match = hashes_match(actual, expected)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Computed: {actual}")
    print(f"Expected: {normalize_hash(expected)}")
    print("Result:   OK - file is intact" if match else "Result:   MISMATCH!")
    return 0 if match else 1


if __name__ == "__main__":
    sys.exit(main())
