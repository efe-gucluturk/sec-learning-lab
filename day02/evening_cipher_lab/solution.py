"""Caesar & XOR Cipher Lab.

Two classic (and very insecure!) ciphers, useful for learning the basics:

* Caesar cipher - shifts every letter by a fixed amount (A -> D with shift 3).
  Only 26 possible keys, so it can be brute-forced instantly.
* Repeating-key XOR - XORs each byte of the message with a byte of the key,
  cycling through the key. XOR-ing twice with the same key undoes it.
  The ciphertext is printed as hex because it may contain unprintable bytes.

Usage:
    python solution.py caesar encrypt "Hello, World" --shift 3
    python solution.py caesar decrypt "Khoor, Zruog" --shift 3
    python solution.py caesar bruteforce "Khoor, Zruog"
    python solution.py xor encrypt "attack at dawn" --key secret
    python solution.py xor decrypt 1211171308... --key secret
"""

import argparse
import string
import sys

ALPHABET_SIZE = 26


def caesar_shift(text, shift):
    """Shift letters in text by `shift` places; other characters stay the same."""
    result = []
    for char in text:
        if char in string.ascii_uppercase:
            base = ord("A")
        elif char in string.ascii_lowercase:
            base = ord("a")
        else:
            result.append(char)  # digits, spaces, punctuation are unchanged
            continue
        # Move to 0-25, shift, wrap around with modulo, move back to a letter.
        offset = (ord(char) - base + shift) % ALPHABET_SIZE
        result.append(chr(base + offset))
    return "".join(result)


def caesar_encrypt(text, shift):
    """Encrypt with a Caesar shift."""
    return caesar_shift(text, shift)


def caesar_decrypt(text, shift):
    """Decrypt a Caesar ciphertext by shifting the other way."""
    return caesar_shift(text, -shift)


def caesar_bruteforce(ciphertext):
    """Return every possible (shift, plaintext) pair - shows why Caesar is weak."""
    return [(shift, caesar_decrypt(ciphertext, shift)) for shift in range(ALPHABET_SIZE)]


def xor_bytes(data, key):
    """XOR each byte of data with the key, repeating the key as needed."""
    if not key:
        raise ValueError("XOR key must not be empty")
    # data[i] is paired with key[i % len(key)], so the key "wraps around".
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def xor_encrypt(text, key):
    """Encrypt text with a repeating-key XOR and return the result as hex."""
    return xor_bytes(text.encode("utf-8"), key.encode("utf-8")).hex()


def xor_decrypt(hex_ciphertext, key):
    """Decrypt hex ciphertext produced by xor_encrypt back into text."""
    try:
        data = bytes.fromhex(hex_ciphertext)
    except ValueError:
        raise ValueError("ciphertext must be a hex string") from None
    return xor_bytes(data, key.encode("utf-8")).decode("utf-8", errors="replace")


def main(argv=None):
    """Command-line entry point. Returns 0 on success, 1 on error."""
    parser = argparse.ArgumentParser(description="Play with Caesar and XOR ciphers.")
    parser.add_argument("cipher", choices=["caesar", "xor"])
    parser.add_argument("action", choices=["encrypt", "decrypt", "bruteforce"])
    parser.add_argument("text", help="plaintext, or ciphertext (hex for XOR)")
    parser.add_argument("--shift", type=int, default=3, help="Caesar shift (default 3)")
    parser.add_argument("--key", help="XOR key (required for xor)")
    args = parser.parse_args(argv)

    try:
        if args.cipher == "caesar":
            if args.action == "encrypt":
                print(caesar_encrypt(args.text, args.shift))
            elif args.action == "decrypt":
                print(caesar_decrypt(args.text, args.shift))
            else:
                for shift, guess in caesar_bruteforce(args.text):
                    print(f"{shift:2d}: {guess}")
        else:
            if args.action == "bruteforce":
                raise ValueError("bruteforce is only supported for caesar")
            if args.key is None:
                raise ValueError("--key is required for xor")
            func = xor_encrypt if args.action == "encrypt" else xor_decrypt
            print(func(args.text, args.key))
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
