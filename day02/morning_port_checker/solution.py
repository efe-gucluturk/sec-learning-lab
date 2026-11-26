"""Single-Host TCP Port & Banner Checker.

Tries to open a TCP connection to each requested port on ONE host and,
if the port is open, waits briefly to see whether the service sends a
greeting ("banner"), e.g. "SSH-2.0-OpenSSH_9.6" or "220 mail ESMTP".

Only scan hosts you own or are explicitly allowed to test.

Usage:
    python solution.py 127.0.0.1 22,80,443
    python solution.py scanme.example 20-25 --timeout 0.5
"""

import argparse
import socket
import sys

MAX_BANNER_BYTES = 1024


def parse_ports(text):
    """Turn "22,80,8000-8002" into a sorted list of unique port numbers."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Bad range (start > end): {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range 1-65535: {port}")
    if not ports:
        raise ValueError("No ports given")
    return sorted(ports)


def clean_banner(raw):
    """Decode banner bytes safely and keep only the first printable line."""
    text = raw.decode("utf-8", errors="replace").strip()
    first_line = text.splitlines()[0] if text else ""
    # Drop control characters so a hostile banner cannot mess up the terminal.
    return "".join(ch for ch in first_line if ch.isprintable())


def check_port(host, port, timeout=1.0):
    """Return a dict like {"port": 22, "open": True, "banner": "SSH-2.0..."}."""
    result = {"port": port, "open": False, "banner": ""}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result["open"] = True
            try:
                # Many services (SSH, FTP, SMTP) speak first; HTTP does not.
                data = sock.recv(MAX_BANNER_BYTES)
                result["banner"] = clean_banner(data)
            except OSError:  # TimeoutError is a subclass of OSError
                pass  # open, but no banner within the timeout
    except OSError:  # TimeoutError is a subclass of OSError
        pass  # refused, filtered, or unreachable -> treat as closed
    return result


def scan(host, ports, timeout=1.0):
    """Check every port in order and return a list of result dicts."""
    return [check_port(host, port, timeout) for port in ports]


def format_result(result):
    """Build one human-readable line for a result."""
    state = "open" if result["open"] else "closed"
    line = f"{result['port']:>5}/tcp  {state:<6}"
    if result["banner"]:
        line += f"  {result['banner']}"
    return line


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check TCP ports on one host.")
    parser.add_argument("host", help="hostname or IP address to check")
    parser.add_argument("ports", help='ports, e.g. "22,80,8000-8010"')
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="seconds to wait per port (default 1.0)")
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print(f"Checking {len(ports)} port(s) on {args.host}")
    results = scan(args.host, ports, args.timeout)
    for result in results:
        print(format_result(result))
    open_count = sum(1 for r in results if r["open"])
    print(f"{open_count} open, {len(results) - open_count} closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
