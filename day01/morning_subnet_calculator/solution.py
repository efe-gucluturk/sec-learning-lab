"""IPv4 Subnet & CIDR Calculator.

Given an address in CIDR notation (for example 192.168.1.10/24) this tool
prints the network address, broadcast address, subnet mask and host range.
Only the standard library is used.
"""

import argparse


def ip_to_int(ip):
    """Convert dotted-decimal text like '10.0.0.1' to a 32-bit integer."""
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IPv4 address: {ip!r}")
    value = 0
    for part in parts:
        # isdigit() rejects empty strings, signs and letters.
        if not part.isdigit() or not 0 <= int(part) <= 255:
            raise ValueError(f"Invalid IPv4 address: {ip!r}")
        value = (value << 8) | int(part)  # shift left 8 bits, add octet
    return value


def int_to_ip(value):
    """Convert a 32-bit integer back to dotted-decimal text."""
    octets = [(value >> shift) & 0xFF for shift in (24, 16, 8, 0)]
    return ".".join(str(o) for o in octets)


def parse_cidr(text):
    """Split '1.2.3.4/24' into (address_int, prefix_length)."""
    if "/" not in text:
        raise ValueError("Expected CIDR notation like 192.168.1.10/24")
    ip, _, prefix_text = text.partition("/")
    if not prefix_text.isdigit() or not 0 <= int(prefix_text) <= 32:
        raise ValueError(f"Invalid prefix length: {prefix_text!r}")
    return ip_to_int(ip), int(prefix_text)


def calculate(cidr):
    """Return a dictionary describing the subnet for the given CIDR text."""
    address, prefix = parse_cidr(cidr)

    # A mask is `prefix` one-bits followed by zeros, e.g. /24 -> 255.255.255.0
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = address & mask
    broadcast = network | (~mask & 0xFFFFFFFF)

    total = 2 ** (32 - prefix)
    if prefix >= 31:
        # /32 is a single host; /31 is a point-to-point link (RFC 3021).
        first, last, hosts = network, broadcast, total
    else:
        first, last, hosts = network + 1, broadcast - 1, total - 2

    return {
        "network": int_to_ip(network),
        "broadcast": int_to_ip(broadcast),
        "mask": int_to_ip(mask),
        "first_host": int_to_ip(first),
        "last_host": int_to_ip(last),
        "hosts": hosts,
    }


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="IPv4 subnet calculator")
    parser.add_argument("cidr", help="address with prefix, e.g. 192.168.1.10/24")
    args = parser.parse_args()
    try:
        info = calculate(args.cidr)
    except ValueError as error:
        parser.error(str(error))  # prints message and exits with code 2
    for key, value in info.items():
        print(f"{key:>10}: {value}")


if __name__ == "__main__":
    main()
