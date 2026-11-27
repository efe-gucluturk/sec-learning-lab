"""DNS Record Lookup Tool.

Resolves a hostname to its IPv4 (A) and IPv6 (AAAA) addresses using only
the standard library (socket.getaddrinfo), and labels each address as
public, private, loopback, etc. That label is handy in security work: a
public hostname that resolves to 127.0.0.1 or 10.x.x.x can be a sign of
DNS rebinding or of an SSRF attempt.

Usage:
    python solution.py example.com
    python solution.py localhost --family 4
"""

import argparse
import ipaddress
import re
import socket
import sys

# One DNS label: 1-63 letters, digits or hyphens, not starting/ending with "-".
LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# Map the --family option to the socket constants getaddrinfo expects.
FAMILIES = {"any": socket.AF_UNSPEC, "4": socket.AF_INET, "6": socket.AF_INET6}


def is_valid_hostname(hostname):
    """Return True if hostname looks like a valid DNS name (or an IP address)."""
    try:
        ipaddress.ip_address(hostname)
        return True  # a literal IP address is fine too
    except ValueError:
        pass
    name = hostname.rstrip(".")  # a trailing dot means "fully qualified"
    if not name or len(name) > 253:
        return False
    return all(LABEL_RE.match(label) for label in name.split("."))


def classify_ip(ip):
    """Describe what kind of address ip is (loopback, private, public...)."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "private"
    if addr.is_multicast:
        return "multicast"
    return "public"


def resolve(hostname, family="any", resolver=socket.getaddrinfo):
    """Resolve hostname and return {"A": [...], "AAAA": [...]} with unique IPs.

    The resolver argument lets tests pass in a fake getaddrinfo so that no
    real network access is needed.
    """
    if not is_valid_hostname(hostname):
        raise ValueError(f"invalid hostname: {hostname!r}")
    # SOCK_STREAM avoids getting each address three times (TCP/UDP/raw).
    results = resolver(hostname, None, FAMILIES[family], socket.SOCK_STREAM)
    records = {"A": [], "AAAA": []}
    for fam, _type, _proto, _canon, sockaddr in results:
        ip = sockaddr[0]  # sockaddr is (ip, port) or (ip, port, flow, scope)
        key = "A" if fam == socket.AF_INET else "AAAA"
        if ip not in records[key]:
            records[key].append(ip)
    return records


def format_records(hostname, records):
    """Turn the resolve() result into printable lines."""
    lines = [f"DNS lookup for {hostname}"]
    for rtype in ("A", "AAAA"):
        for ip in records[rtype]:
            lines.append(f"  {rtype:<4} {ip:<40} ({classify_ip(ip)})")
    if len(lines) == 1:
        lines.append("  (no addresses found)")
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser(description="Resolve a hostname to its IP addresses.")
    parser.add_argument("hostname", help="hostname to look up, e.g. example.com")
    parser.add_argument("--family", choices=FAMILIES, default="any",
                        help="only IPv4 (4), only IPv6 (6) or both (any)")
    args = parser.parse_args(argv)

    try:
        records = resolve(args.hostname, args.family)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except socket.gaierror as exc:  # name not found, no network, etc.
        print(f"Error: could not resolve {args.hostname}: {exc}", file=sys.stderr)
        return 1

    print("\n".join(format_records(args.hostname, records)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
