#!/usr/bin/env python3
"""Contract tests for the deterministic OSINT TLS lab fixture."""

from __future__ import annotations

import importlib.util
import ipaddress
import unittest
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = SCRIPT_ROOT / "osint_tls_fixture.py"
RUNNER_PATH = SCRIPT_ROOT / "osint_tls_qualification_lab.sh"

SPEC = importlib.util.spec_from_file_location("osint_tls_fixture", FIXTURE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import OSINT TLS fixture")
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class OSINTTLSFixtureContractTest(unittest.TestCase):
    def blocklist(self, mode: str) -> bytes:
        status, body = FIXTURE.fixture_response(
            "lists.blocklist.de", "/lists/all.txt", mode
        )
        self.assertEqual(status, 200)
        return body

    def test_positive_contains_four_public_entries_and_one_6to4(self) -> None:
        lines = self.blocklist("success").decode("ascii").splitlines()
        addresses = [ipaddress.ip_address(line) for line in lines]
        six_to_four = ipaddress.ip_address("2002:982a:b983::982a:b983")
        self.assertEqual(len(addresses), 5)
        self.assertEqual(addresses.count(six_to_four), 1)
        self.assertIn(six_to_four, ipaddress.ip_network("2002::/16"))
        self.assertEqual(sum(address.is_global for address in addresses[:4]), 4)

    def test_malformed_case_fails_at_fifth_line(self) -> None:
        lines = self.blocklist("malformed").decode("ascii").splitlines()
        self.assertEqual(len(lines), 5)
        for line in lines[:4]:
            ipaddress.ip_address(line)
        with self.assertRaises(ValueError):
            ipaddress.ip_address(lines[4])

    def test_below_minimum_case_is_all_valid_syntax(self) -> None:
        lines = self.blocklist("below-minimum").decode("ascii").splitlines()
        addresses = [ipaddress.ip_address(line) for line in lines]
        six_to_four = ipaddress.ip_address("2002:982a:b983::982a:b983")
        self.assertEqual(len(addresses), 4)
        self.assertEqual(addresses.count(six_to_four), 1)
        self.assertEqual(
            len([address for address in addresses if address != six_to_four]), 3
        )

    def test_unknown_route_and_mode_fail_closed(self) -> None:
        self.assertEqual(
            FIXTURE.fixture_response("lists.blocklist.de", "/unknown", "success")[0],
            404,
        )
        self.assertEqual(
            FIXTURE.fixture_response(
                "lists.blocklist.de", "/lists/all.txt", "unexpected"
            )[0],
            503,
        )

    def test_runner_locks_exact_product_contract_and_cleanup(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        exact_warning = (
            "[WARNING] OSINT source https://lists.blocklist.de ignored 1 "
            "non-public or special-use CIDR entry."
        )
        self.assertIn(exact_warning, runner)
        self.assertIn("invalid CIDR at line 5", runner)
        self.assertIn(
            "feed contains 3 canonical entries after ignoring 1 non-public or "
            "special-use entries, minimum is 4",
            runner,
        )
        self.assertLess(
            runner.index("write_fixture_mode success"),
            runner.index("write_fixture_mode malformed"),
        )
        self.assertLess(
            runner.index("write_fixture_mode malformed"),
            runner.index("write_fixture_mode below-minimum"),
        )
        self.assertIn('command+=(update-feeds)', runner)
        self.assertIn('trap finish EXIT', runner)
        self.assertIn('write_fixture_mode "${ORIGINAL_MODE}"', runner)
        self.assertNotIn("custom-url", runner.lower())

    def test_assets_are_english_ascii_without_em_dash(self) -> None:
        for path in (FIXTURE_PATH, RUNNER_PATH, Path(__file__)):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("\N{EM DASH}", content, path.name)


if __name__ == "__main__":
    unittest.main()
