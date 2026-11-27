"""URL & Query Parameter Inspector.

Splits a URL into its parts (scheme, host, port, path, ...) and lists its
query parameters. It also prints a few simple security hints, such as
credentials embedded in the URL or parameters that often carry secrets.

Usage:
    python solution.py "https://user@example.com:8443/login?next=/home&token=abc#top"

Only the standard library is used and no network requests are made:
the URL is just parsed as text.
"""

import argparse
import sys
from urllib.parse import parse_qsl, urlsplit

# Parameter names that often hold secrets and should not appear in URLs
# (URLs end up in browser history, proxy logs and Referer headers).
SENSITIVE_PARAMS = {"password", "passwd", "pwd", "token", "api_key", "apikey",
                    "secret", "session", "sessionid", "auth", "access_token"}

# Parameter names often abused for open redirects.
REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_uri", "return", "returnto", "goto"}


def inspect_url(url):
    """Split a URL into a dictionary of its parts."""
    parts = urlsplit(url.strip())
    try:
        port = parts.port  # raises ValueError for a non-numeric/out-of-range port
    except ValueError:
        port = None
    return {
        "scheme": parts.scheme,
        "username": parts.username,
        "password": parts.password,
        "host": parts.hostname,
        "port": port,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
    }


def list_params(query):
    """Return query parameters as a list of (name, value) pairs.

    A list (not a dict) is used so repeated names like ?id=1&id=2 are kept.
    """
    return parse_qsl(query, keep_blank_values=True)


def security_hints(info, params):
    """Return a list of human-readable warnings about the URL."""
    hints = []
    if info["password"] is not None:
        hints.append("URL contains a password in the user-info part")
    if info["scheme"] == "http":
        hints.append("Plain HTTP: traffic is not encrypted")
    for name, value in params:
        lowered = name.lower()
        if lowered in SENSITIVE_PARAMS:
            hints.append(f"Parameter '{name}' may expose a secret")
        if lowered in REDIRECT_PARAMS and value.lower().startswith(("http://", "https://", "//")):
            hints.append(f"Parameter '{name}' points to an external URL (open redirect?)")
    return hints


def format_report(url):
    """Build the full text report for one URL."""
    info = inspect_url(url)
    params = list_params(info["query"])
    shown = url
    if info["password"]:
        shown = url.replace(":" + info["password"] + "@", ":***@", 1)  # hide secret
    lines = [f"URL: {shown}"]
    for key, value in info.items():
        if key == "password" and value is not None:
            value = "*" * len(value)  # never echo the secret itself
        lines.append(f"  {key:<9}: {value if value not in (None, '') else '-'}")
    lines.append(f"Query parameters ({len(params)}):")
    for name, value in params:
        lines.append(f"  {name} = {value!r}")
    hints = security_hints(info, params)
    if hints:
        lines.append("Security hints:")
        lines.extend(f"  [!] {hint}" for hint in hints)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Split URLs into parts and list query parameters.")
    parser.add_argument("urls", nargs="+", help="one or more URLs to inspect")
    args = parser.parse_args(argv)
    for url in args.urls:
        print(format_report(url))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
