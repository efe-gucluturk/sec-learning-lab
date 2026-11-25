"""HTTP Security Header Inspector.

Fetches a URL and reports which common security response headers are
present or missing.

Usage:
    python solution.py https://example.com
"""

import argparse
import sys
import urllib.request

# Header name -> short explanation of why it matters.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces browsers to use HTTPS.",
    "Content-Security-Policy": "Limits where scripts and resources may load from.",
    "X-Content-Type-Options": "Stops browsers from guessing content types.",
    "X-Frame-Options": "Protects against clickjacking.",
    "Referrer-Policy": "Controls how much referrer info is leaked.",
    "Permissions-Policy": "Restricts powerful browser features.",
}


def fetch_headers(url, timeout=10):
    """Request the URL and return the response headers as a dict."""
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return dict(response.headers.items())


def inspect_headers(headers):
    """Compare headers to SECURITY_HEADERS.

    Returns a dict mapping each security header name to its value,
    or to None when it is missing.
    """
    # HTTP header names are case-insensitive, so lowercase them first.
    lowered = {name.lower(): value for name, value in headers.items()}
    return {name: lowered.get(name.lower()) for name in SECURITY_HEADERS}


def score(report):
    """Return how many security headers are present."""
    return sum(1 for value in report.values() if value is not None)


def format_report(report):
    """Turn a report into printable text."""
    lines = []
    for name, value in report.items():
        if value is None:
            lines.append(f"[MISSING] {name} - {SECURITY_HEADERS[name]}")
        else:
            lines.append(f"[OK]      {name}: {value}")
    lines.append(f"Score: {score(report)}/{len(report)}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check HTTP security headers.")
    parser.add_argument("url", help="URL to inspect, e.g. https://example.com")
    args = parser.parse_args(argv)

    try:
        headers = fetch_headers(args.url)
    except (OSError, ValueError) as error:
        print(f"Could not fetch {args.url}: {error}", file=sys.stderr)
        return 1

    print(format_report(inspect_headers(headers)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
