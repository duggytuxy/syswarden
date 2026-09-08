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
        self.assertIn('trap restore_runtime EXIT INT TERM', runner)
        self.assertIn('write_fixture_mode "${ORIGINAL_MODE}"', runner)
        for binding in (
            "--candidate-sha",
            "--deb-package",
            "--deb-signature",
            "--signature-policy",
            "--signature-inventory",
            "--deb-key-id",
            "--deb-signature-date",
            "--node02-ssh-host-key-sha256",
            "--campaign-id",
            "native_feed_contract_v4.10.0.json",
            'python3 "${EVIDENCE_TOOL}" assemble',
            "native_package_signature_gate.py",
            "readonly CLI_PATH=/opt/syswarden/bin/syswarden-cli",
            "readonly LIST_ROOT=/etc/syswarden/lists",
            "readonly HOSTS_PATH=/etc/hosts",
            "readonly QUALIFICATION_CA=/usr/local/share/ca-certificates/syswarden-native-feed-qualification.crt",
            "configure_fixture_hosts",
            "restore_fixture_hosts",
            "install_quarantine_barrier",
            "capture_quarantine_barrier",
            "snapshot_restore_required",
            "service-quarantined.txt",
            "product/disposition.json",
            "readonly CAMPAIGN_LOCK=/run/lock/syswarden-native-feed-qualification.lock",
            "os.mkdir(name, 0o700, dir_fd=directory)",
            "follow_symlinks=False",
            "os.fsync(systemd_root)",
            "systemctl kill --kill-whom=main --signal=SIGSTOP cron.service",
            "systemctl kill --kill-whom=main --signal=SIGSTOP syswarden-core.service",
            'exec 7<>"${FIREWALL_LOCK}"',
            "dpkg-query --control-show syswarden md5sums",
            'dpkg-query --search "${CLI_PATH}"',
            ".syswarden_threatintel.ipv4.syswarden-snapshot-",
            "nft --json list set inet syswarden syswarden_blacklist",
            "nft --json list set inet syswarden syswarden_blacklist6",
            "syswarden_blacklist6",
            "capture_scenario reject-malformed-syntax 2 malformed",
            "capture_scenario reject-valid-volume-below-minimum 3 below-minimum",
        ):
            self.assertIn(binding, runner)
        self.assertEqual(runner.count('command+=(update-feeds)'), 1)
        self.assertEqual(runner.count("write_fixture_mode malformed"), 1)
        self.assertEqual(runner.count("write_fixture_mode below-minimum"), 1)
        self.assertNotIn('"timeout"}', runner)
        self.assertNotIn("custom-url", runner.lower())
        self.assertNotIn('install -m 0600 -- "${FIXTURE_KEY}" "${RAW_ROOT}', runner)
        self.assertNotIn("SIGCONT", runner)
        self.assertNotIn("reload --no-restart", runner)
        self.assertNotIn("restore_product_state", runner)
        self.assertNotIn("exec 9>", runner)
        self.assertNotIn("os.O_TRUNC", runner)

    def test_runner_lock_and_quarantine_durability_are_fail_closed(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        lock_start = runner.index("# Claim a root-private directory atomically.")
        lock_end = runner.index("readonly -a UNTRUSTED_ENV", lock_start)
        lock_contract = runner[lock_start:lock_end]
        required_lock_tokens = (
            "os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
            "os.mkdir(name, 0o700, dir_fd=directory)",
            "os.fstat(descriptor)",
            "follow_symlinks=False",
            "identity(opened) != identity(resolved)",
            "opened.st_uid != 0",
            "opened.st_gid != 0",
            "stat.S_IMODE(opened.st_mode) != 0o700",
            "opened.st_nlink != 2",
            "os.fsync(directory)",
        )
        for required in required_lock_tokens:
            self.assertIn(required, lock_contract)
        for unsafe in ("exec 9>", "os.O_TRUNC", "follow_symlinks=True"):
            self.assertNotIn(unsafe, lock_contract)

        barrier_start = runner.index("install_quarantine_barrier() {")
        barrier_end = runner.index("capture_quarantine_barrier() {", barrier_start)
        barrier = runner[barrier_start:barrier_end]
        mkdir_index = barrier.index("os.mkdir(name, 0o755, dir_fd=systemd_root)")
        parent_fsync_index = barrier.index("os.fsync(systemd_root)", mkdir_index)
        daemon_reload_index = barrier.index("systemctl daemon-reload")
        marker_index = barrier.index(
            'python3 - "${QUARANTINE_MARKER}"', daemon_reload_index
        )
        self.assertLess(mkdir_index, parent_fsync_index)
        self.assertLess(parent_fsync_index, daemon_reload_index)
        self.assertLess(daemon_reload_index, marker_index)

        for token in required_lock_tokens[:5]:
            mutation = lock_contract.replace(token, "removed")
            with self.subTest(token=token):
                self.assertFalse(all(item in mutation for item in required_lock_tokens))

    def test_assets_are_english_ascii_without_em_dash(self) -> None:
        for path in (FIXTURE_PATH, RUNNER_PATH, Path(__file__)):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("\N{EM DASH}", content, path.name)


if __name__ == "__main__":
    unittest.main()
