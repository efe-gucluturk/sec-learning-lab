"""Tests for the TCP port & banner checker (localhost sockets only)."""

import socket
import threading

import pytest
import solution


def start_listener(banner=None):
    """Listen on a free localhost port; optionally send a banner on connect."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        with conn:
            if banner is not None:
                conn.sendall(banner)
            conn.recv(1)  # wait until the client closes

    threading.Thread(target=serve, daemon=True).start()
    return server


def free_closed_port():
    """Grab a port number that nothing is listening on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_parse_ports_list_and_range():
    assert solution.parse_ports("80, 22,8000-8002,22") == [22, 80, 8000, 8001, 8002]


@pytest.mark.parametrize("bad", ["0", "70000", "10-5", "abc", ""])
def test_parse_ports_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        solution.parse_ports(bad)


def test_clean_banner_strips_control_chars_and_extra_lines():
    raw = b"SSH-2.0-Test\x1b[31m\r\nsecond line\r\n"
    assert solution.clean_banner(raw) == "SSH-2.0-Test[31m"
    assert solution.clean_banner(b"") == ""


def test_open_port_with_banner():
    server = start_listener(b"220 test FTP ready\r\n")
    port = server.getsockname()[1]
    result = solution.check_port("127.0.0.1", port, timeout=2)
    server.close()
    assert result == {"port": port, "open": True, "banner": "220 test FTP ready"}


def test_open_port_without_banner():
    server = start_listener()
    port = server.getsockname()[1]
    result = solution.check_port("127.0.0.1", port, timeout=0.3)
    server.close()
    assert result["open"] is True
    assert result["banner"] == ""


def test_closed_port():
    port = free_closed_port()
    result = solution.check_port("127.0.0.1", port, timeout=0.5)
    assert result == {"port": port, "open": False, "banner": ""}


def test_format_result():
    line = solution.format_result({"port": 22, "open": True, "banner": "SSH-2.0"})
    assert line == "   22/tcp  open    SSH-2.0"
    assert "closed" in solution.format_result({"port": 9, "open": False, "banner": ""})


def test_main_cli(capsys):
    server = start_listener(b"hello\n")
    port = server.getsockname()[1]
    exit_code = solution.main(["127.0.0.1", str(port), "--timeout", "2"])
    server.close()
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "open" in output and "hello" in output
    assert "1 open, 0 closed" in output


def test_main_bad_ports(capsys):
    assert solution.main(["127.0.0.1", "99999"]) == 2
    assert "Error" in capsys.readouterr().err
