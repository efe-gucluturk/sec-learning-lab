"""Password Strength & Entropy Checker.

Estimates entropy (in bits) from the size of the character pool and
flags common weak patterns. Usage: python solution.py "MyP@ssw0rd"
"""
import argparse
import math
import string

# A tiny sample of very common passwords (real lists have millions).
COMMON_PASSWORDS = {"password", "123456", "12345678", "qwerty", "letmein",
                    "admin", "welcome", "iloveyou", "abc123", "monkey"}

# Keyboard / alphabet runs that are easy to guess.
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop",
             "asdfghjkl", "zxcvbnm"]


def pool_size(password):
    """Return how many different characters an attacker must consider."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    if any(c not in string.printable for c in password):
        size += 100  # rough allowance for non-ASCII characters
    return size


def entropy_bits(password):
    """Entropy = length * log2(pool size)."""
    size = pool_size(password)
    if size == 0:
        return 0.0
    return len(password) * math.log2(size)


def find_weaknesses(password):
    """Return a list of human-readable weakness warnings."""
    problems = []
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        problems.append("is a very common password")
    if len(password) < 8:
        problems.append("is shorter than 8 characters")
    if password and len(set(password)) == 1:
        problems.append("is one repeated character")
    elif any(ch * 3 in password for ch in set(password)):
        problems.append("has a character repeated 3+ times in a row")
    for seq in SEQUENCES:
        # Check every 4-character window, forwards and backwards.
        for i in range(len(seq) - 3):
            chunk = seq[i:i + 4]
            if chunk in lower or chunk[::-1] in lower:
                problems.append(f"contains a sequence like '{chunk}'")
                break
    return problems


def rate(bits):
    """Turn a bit count into a simple label."""
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "reasonable"
    if bits < 80:
        return "strong"
    return "very strong"


def main():
    parser = argparse.ArgumentParser(description="Password entropy checker")
    parser.add_argument("password", help="password to analyse")
    args = parser.parse_args()
    bits = entropy_bits(args.password)
    print(f"Entropy: {bits:.1f} bits ({rate(bits)})")
    for problem in find_weaknesses(args.password):
        print("Warning: password " + problem)


if __name__ == "__main__":
    main()
