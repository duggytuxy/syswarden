#!/usr/bin/env python3
"""Serve deterministic HTTPS origins for SysWarden OSINT qualification.

This fixture is lab and CI infrastructure. It does not provide a product URL,
trust, validation, or downloader override. An outer disposable-lab harness must
map the supported origin names to the bind address, trust its temporary CA,
start this server, and remove those harness-owned resources afterward.
The server certificate SAN set must cover cinsscore.com, lists.blocklist.de,
raw.githubusercontent.com, gitlab.com, cdn.jsdelivr.net, bitbucket.org, and
codeberg.org. The product-facing qualification path uses HTTPS port 443.

The protected ASCII mode file selects one response matrix:

* ``success`` serves four public addresses plus one valid 6to4 address.
* ``malformed`` adds a malformed fifth line.
* ``below-minimum`` serves three public addresses plus one valid 6to4 address.
* ``safe`` serves only the four common public addresses.

Use ``osint_tls_qualification_lab.sh`` to exercise the real installed
``syswarden update-feeds`` command and collect qualification evidence.
"""

from __future__ import annotations

import argparse
import http.server
import os
import ssl
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit


OSINT_COMMON = b"1.0.0.1\n1.1.1.1\n8.8.4.4\n8.8.8.8\n"
SIX_TO_FOUR = b"2002:982a:b983::982a:b983\n"
MALFORMED = b"this-is-not-an-address\n"
BELOW_MINIMUM = b"1.0.0.1\n1.1.1.1\n8.8.4.4\n" + SIX_TO_FOUR

DATA_SHIELD = (
    b"1.0.0.1\n1.1.1.1\n8.8.4.4\n8.8.8.8\n9.9.9.9\n"
    b"149.112.112.112\n208.67.222.222\n208.67.220.220\n"
    b"64.6.64.6\n64.6.65.6\n94.140.14.14\n94.140.15.15\n"
    b"76.76.2.0\n76.76.10.0\n185.228.168.9\n185.228.169.9\n"
)

DATA_SHIELD_PATHS = {
    "/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
    "/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt",
    "/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt",
    "/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_critical_data-shield_ipv4_blocklist.txt",
    "/gh/duggytuxy/Data-Shield_IPv4_Blocklist@refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
    "/gh/duggytuxy/Data-Shield_IPv4_Blocklist@refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt",
    "/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt",
    "/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_critical_data-shield_ipv4_blocklist.txt",
    "/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt",
    "/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_critical_data-shield_ipv4_blocklist.txt",
}

DATA_SHIELD_HOSTS = {
    "raw.githubusercontent.com",
    "gitlab.com",
    "cdn.jsdelivr.net",
    "bitbucket.org",
    "codeberg.org",
}

SUPPORTED_MODES = frozenset({"safe", "success", "malformed", "below-minimum"})


def read_mode(path: Path) -> str:
    """Read one small regular mode file without following a final symlink."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("fixture mode must be one regular single-link file")
        if not 1 <= info.st_size <= 64:
            raise ValueError("fixture mode has an invalid size")
        wire = os.read(descriptor, 65)
    finally:
        os.close(descriptor)
    try:
        mode = wire.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError("fixture mode must be ASCII") from error
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"unsupported fixture mode: {mode!r}")
    return mode


def fixture_response(host: str, path: str, mode: str) -> tuple[int, bytes]:
    """Return the exact response for one normalized fixture request."""

    if mode not in SUPPORTED_MODES:
        return 503, b"invalid fixture mode\n"
    if host == "cinsscore.com" and path == "/list/ci-badguys.txt":
        return 200, OSINT_COMMON
    if host == "lists.blocklist.de" and path == "/lists/all.txt":
        responses = {
            "safe": OSINT_COMMON,
            "success": OSINT_COMMON + SIX_TO_FOUR,
            "malformed": OSINT_COMMON + MALFORMED,
            "below-minimum": BELOW_MINIMUM,
        }
        return 200, responses[mode]
    if host in DATA_SHIELD_HOSTS and path in DATA_SHIELD_PATHS:
        return 200, DATA_SHIELD
    if host in {"raw.githubusercontent.com", "codeberg.org"} and path == "/":
        return 200, b"fixture-ready\n"
    return 404, b"not found\n"


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SysWardenOSINTQualificationFixture/1"
    sys_version = ""

    def log_message(self, format_string: str, *args: object) -> None:
        del format_string
        sys.stderr.write(
            "fixture client=%s host=%s path=%s status=%s\n"
            % (
                self.client_address[0],
                self.headers.get("Host", ""),
                urlsplit(self.path).path,
                args[1] if len(args) > 1 else "unknown",
            )
        )

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(head_only=True)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(head_only=False)

    def _serve(self, *, head_only: bool) -> None:
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        path = urlsplit(self.path).path
        try:
            mode = read_mode(self.server.mode_path)
            status_code, body = fixture_response(host, path, mode)
        except (OSError, ValueError) as error:
            sys.stderr.write(f"fixture mode error: {error}\n")
            status_code, body = 503, b"fixture mode unavailable\n"
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if not head_only and body:
            self.wfile.write(body)


class FixtureServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, address: tuple[str, int], mode_path: Path):
        super().__init__(address, FixtureHandler)
        self.mode_path = mode_path


def bounded_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535 or str(port) != value:
        raise argparse.ArgumentTypeError("port must be canonical and inside 1..65535")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--mode", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=bounded_port, default=443)
    args = parser.parse_args()

    read_mode(args.mode)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)

    server = FixtureServer((args.bind, args.port), args.mode)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
