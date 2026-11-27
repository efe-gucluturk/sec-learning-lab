"""SSH Auth Log Failed-Login Counter.

Reads an SSH authentication log (for example /var/log/auth.log on Debian/Ubuntu)
and counts how many failed login attempts came from each source IP address.

Typical log lines we care about look like this:

    Nov 27 10:15:01 server sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
    Nov 27 10:15:09 server sshd[1240]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2
    Nov 27 10:16:00 server sshd[1301]: Invalid user test from 192.0.2.44 port 51000

Usage:
    python solution.py /var/log/auth.log
    python solution.py auth.log --top 5 --min 3
"""

import argparse
import re
import sys
from collections import Counter
from collections.abc import Iterable

# One regular expression per "failure" message that sshd writes.
# Each pattern captures the source IP in a group called "ip".
# The IP part accepts IPv4 (digits and dots) and IPv6 (hex digits and colons).
IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
FAILED_PATTERNS = [
    re.compile(r"Failed (?:password|publickey) for (?:invalid user )?\S+ from " + IP),
    re.compile(r"Invalid user \S* ?from " + IP),
]


def extract_failed_ip(line: str) -> str | None:
    """Return the source IP if this log line is a failed SSH login, else None."""
    # Only look at lines written by the SSH daemon.
    if "sshd" not in line:
        return None
    for pattern in FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group("ip")
    return None


def count_failed_logins(lines: Iterable[str]) -> Counter:
    """Count failed login attempts per source IP from an iterable of log lines."""
    counts: Counter = Counter()
    for line in lines:
        ip = extract_failed_ip(line)
        if ip is not None:
            counts[ip] += 1
    return counts


def format_report(counts: Counter, top: int | None = None, minimum: int = 1) -> str:
    """Build a readable table of IPs sorted by number of failures (highest first)."""
    # Keep only IPs that reached the minimum number of failures.
    rows = [(ip, n) for ip, n in counts.most_common() if n >= minimum]
    if top is not None:
        rows = rows[:top]
    if not rows:
        return "No failed SSH logins found."

    lines = [f"{'Source IP':<40} {'Failures':>8}", "-" * 49]
    for ip, n in rows:
        lines.append(f"{ip:<40} {n:>8}")
    lines.append("-" * 49)
    lines.append(f"{'Total (shown)':<40} {sum(n for _, n in rows):>8}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Count failed SSH logins per source IP from an auth log."
    )
    parser.add_argument("logfile", help="path to the auth log file (e.g. /var/log/auth.log)")
    parser.add_argument("--top", type=int, default=None, help="show only the N worst IPs")
    parser.add_argument(
        "--min", dest="minimum", type=int, default=1,
        help="only show IPs with at least this many failures (default: 1)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CLI. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    try:
        # errors="replace" so odd bytes in a log file don't crash the program.
        with open(args.logfile, encoding="utf-8", errors="replace") as handle:
            counts = count_failed_logins(handle)
    except OSError as exc:
        print(f"Error: could not read {args.logfile}: {exc}", file=sys.stderr)
        return 1

    print(format_report(counts, top=args.top, minimum=args.minimum))
    return 0


if __name__ == "__main__":
    sys.exit(main())
