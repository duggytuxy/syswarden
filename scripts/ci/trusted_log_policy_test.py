"""Prevent drift between independently built producer-policy consumers."""
from pathlib import Path
import unittest
import re


class TrustedLogPolicyParityTests(unittest.TestCase):
    def test_cli_and_core_share_exact_authorization_contract(self):
        root = Path(__file__).resolve().parents[2] / "src" / "core"
        for name in ("trusted_log_producers.go", "trusted_log_files_linux.go"):
            with self.subTest(name=name):
                self.assertEqual(
                    (root / "syswarden-cli" / "config" / name).read_bytes(),
                    (root / "syswarden-core" / "config" / name).read_bytes(),
                )


    def test_direct_handoff_keeps_every_historical_bridge_input(self):
        root = Path(__file__).resolve().parents[2] / "src" / "core"
        bridge = (root / "syswarden-cli/pkg/integration/waf_logs_linux.go").read_text()
        historical = bridge.split("const rsyslogWAFBase = `", 1)[1].split("`", 1)[0]
        expected = re.findall(r'File="([^"\n]+)"', historical)
        policy = (root / "syswarden-core/config/trusted_log_producers.go").read_text()
        declaration = policy.split("patterns := []string{", 1)[1].split("}", 1)[0]
        actual = re.findall(r'"([^"\n]+)"', declaration)
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
