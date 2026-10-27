#!/usr/bin/env python3
"""Regression coverage for protected-path evidence completeness and meaning."""
import unittest

import apk_protected_path_probe as probe


class ProtectedPathEvidenceTests(unittest.TestCase):
    def output(self):
        lines = []
        for package in probe.PACKAGE_NAMES:
            for case in probe.CASES:
                for removal in probe.REMOVALS:
                    preserved = case in ("fresh-directory", "same-directory", "omit-directory")
                    owned = case not in ("omit-directory", "omit-exact")
                    retained = case == "omit-directory" or removal == "remove" and case in ("fresh-directory", "same-directory")
                    lines.append(f"OBSERVATION={package}:{case}:{removal}:{int(preserved)}:{int(owned)}:{int(retained)}")
        return ("\n".join(lines + [probe.PASS_MARKER]) + "\n").encode()

    def test_complete_matrix_distinguishes_upgrade_ownership_and_purge(self):
        records = probe.parse_result(self.output())
        self.assertEqual(len(records), 28)
        for package in probe.PACKAGE_NAMES:
            relevant = {record["case"]: record for record in records if record["package_name"] == package and record["removal"] == "purge"}
            self.assertTrue(relevant["same-directory"]["launcher_identity_and_effect_preserved"])
            self.assertTrue(relevant["same-directory"]["launcher_owned_after_upgrade"])
            self.assertFalse(relevant["same-directory"]["launcher_identity_and_effect_preserved_after_removal"])
            self.assertTrue(relevant["omit-directory"]["launcher_identity_and_effect_preserved_after_removal"])
            self.assertFalse(relevant["omit-directory"]["launcher_owned_after_upgrade"])

    def test_each_missing_duplicate_reordered_or_changed_observation_fails(self):
        lines = self.output().decode().splitlines()
        for index in range(28):
            for altered in (lines[:index] + lines[index + 1:],
                            lines[:index] + [lines[index]] + lines[index:],
                            lines[:index] + [lines[index][:-1] + str(1 - int(lines[index][-1]))] + lines[index + 1:]):
                with self.subTest(index=index, count=len(altered)), self.assertRaises(ValueError):
                    probe.parse_result(("\n".join(altered) + "\n").encode())
        lines[0], lines[1] = lines[1], lines[0]
        with self.assertRaises(ValueError):
            probe.parse_result(("\n".join(lines) + "\n").encode())

    def test_completion_output_and_coordinate_boundaries(self):
        for output in (b"", self.output().replace(probe.PASS_MARKER.encode(), b""),
                       self.output() + probe.PASS_MARKER.encode() + b"\n", self.output() + b"trailing\n",
                       b"x" * ((1 << 20) + 1), self.output().replace(b"syswarden:", b"other:", 1), b"\xff\n"):
            with self.subTest(size=len(output)), self.assertRaises((ValueError, UnicodeError)):
                probe.parse_result(output)
        for coordinate in (("other", "same-directory", "remove"), ("syswarden", "other", "remove"),
                           ("syswarden", "same-directory", "reboot")):
            with self.assertRaises(ValueError):
                probe.expected_observation(*coordinate)


if __name__ == "__main__":
    unittest.main()
