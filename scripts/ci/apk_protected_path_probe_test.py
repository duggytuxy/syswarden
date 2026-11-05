#!/usr/bin/env python3
"""Regression coverage for protected-path evidence completeness and meaning."""
import unittest
import subprocess
import tempfile
from pathlib import Path
from unittest import mock
import tarfile
import io
import json
from types import SimpleNamespace

import apk_protected_path_probe as probe


class ProtectedPathEvidenceTests(unittest.TestCase):
    # Identity, combined identity/effect, ownership, then remove and purge pairs.
    outcomes = {
        "fresh-directory": (1, 1, 1, 1, 1, 0, 0),
        "same-directory": (1, 1, 1, 1, 1, 0, 0),
        "omit-directory": (1, 1, 0, 1, 1, 1, 1),
        "same-exact": (0, 0, 1, 0, 0, 0, 0),
        "omit-exact": (0, 0, 0, 0, 0, 0, 0),
        "incoming-rule": (0, 0, 1, 0, 0, 0, 0),
        "preupgrade-rule": (0, 0, 1, 0, 0, 0, 0),
        "omit-metadata-link-directory": (1, 0, 0, 1, 0, 1, 0),
        "omit-metadata-regular-directory": (0, 0, 0, 0, 0, 0, 0),
        "omit-overlay": (1, 1, 0, 1, 1, 1, 1),
        "omit-metadata-regular-overlay": (1, 1, 0, 1, 1, 1, 1),
        "omit-metadata-link-overlay": (1, 0, 0, 1, 0, 1, 0),
    }

    def output(self):
        lines = []
        for package in probe.PACKAGE_NAMES:
            for case in probe.CASES:
                for removal in probe.REMOVALS:
                    identity, effect, owned, remove_identity, remove_effect, purge_identity, purge_effect = self.outcomes[case]
                    retained_identity, retained_effect = (remove_identity, remove_effect) if removal == "remove" else (purge_identity, purge_effect)
                    coordinate = f"{package}:{case}:{removal}"
                    for stage_index, stage in enumerate(("before", "after", "removed")):
                        for parent_index, parent in enumerate(probe.PARENTS):
                            # Directory entry changes can update size/times without
                            # changing the parent's identity or access permissions.
                            metadata = f"1:{parent_index + 2}:41ed:0:0:2:{4096 + stage_index}:100:{100 + stage_index}"
                            lines.append(f"PARENT_METADATA={coordinate}:{stage}:{parent}:{metadata}")
                    for alias_index, alias in enumerate(probe.ALIASES):
                        ownership = "owned" if owned else "unowned"
                        if "metadata-link" in case and alias_index == 0:
                            ownership = "target-owned"
                        lines.append(f"OWNERSHIP_OBSERVATION={coordinate}:{alias}:{ownership}")
                    lines.append(f"IDENTITY_OBSERVATION={coordinate}:{identity}:{retained_identity}")
                    lines.append(f"PARENT_OBSERVATION={coordinate}:1:1")
                    lines.append(f"OBSERVATION={coordinate}:{effect}:{owned}:{retained_effect}")
        return ("\n".join(lines + [probe.PASS_MARKER]) + "\n").encode()

    def test_complete_matrix_distinguishes_upgrade_ownership_and_purge(self):
        records = probe.parse_result(self.output())
        self.assertEqual(set(self.outcomes), set(probe.CASES))
        self.assertEqual(len(records), 48)
        for package in probe.PACKAGE_NAMES:
            relevant = {record["case"]: record for record in records if record["package_name"] == package and record["removal"] == "purge"}
            self.assertTrue(relevant["same-directory"]["launcher_identity_and_effect_preserved"])
            self.assertTrue(relevant["same-directory"]["launcher_owned_after_upgrade"])
            self.assertFalse(relevant["same-directory"]["launcher_identity_and_effect_preserved_after_removal"])
            self.assertTrue(relevant["omit-directory"]["launcher_identity_and_effect_preserved_after_removal"])
            self.assertFalse(relevant["omit-directory"]["launcher_owned_after_upgrade"])
            for case in ("omit-metadata-link-directory", "omit-metadata-regular-directory"):
                self.assertFalse(relevant[case]["launcher_identity_and_effect_preserved"])
                self.assertFalse(relevant[case]["launcher_owned_after_upgrade"])
                self.assertFalse(relevant[case]["launcher_identity_and_effect_preserved_after_removal"])
            self.assertTrue(relevant["omit-metadata-link-directory"]["launcher_identity_preserved_after_removal"])
            self.assertFalse(relevant["omit-metadata-regular-directory"]["launcher_identity_preserved_after_removal"])
            for case in ("omit-overlay", "omit-metadata-regular-overlay"):
                self.assertTrue(relevant[case]["launcher_identity_and_effect_preserved_after_removal"])
                self.assertFalse(relevant[case]["launcher_owned_after_upgrade"])
            self.assertTrue(relevant["omit-metadata-link-overlay"]["launcher_identity_preserved_after_removal"])
            self.assertFalse(relevant["omit-metadata-link-overlay"]["launcher_identity_and_effect_preserved_after_removal"])
            self.assertEqual(relevant["omit-metadata-link-overlay"]["native_ownership_observations"]["syswarden"], "target-owned")
            for record in relevant.values():
                self.assertTrue(record["parent_identity_and_permissions_preserved_after_removal"])
                self.assertEqual(set(record["parent_metadata"]), {"before", "after", "removed"})

    def test_each_missing_duplicate_reordered_or_changed_observation_fails(self):
        lines = self.output().decode().splitlines()
        for index in range(len(lines) - 1):
            changed = lines[index].replace("syswarden:", "foreign:", 1)
            for altered in (lines[:index] + lines[index + 1:],
                            lines[:index] + [lines[index]] + lines[index:],
                            lines[:index] + [changed] + lines[index + 1:]):
                if altered == lines:
                    altered[index] = lines[index].replace("syswarden-base:", "foreign:", 1)
                with self.subTest(index=index, count=len(altered)), self.assertRaises(ValueError):
                    probe.parse_result(("\n".join(altered) + "\n").encode())
        lines[0], lines[1] = lines[1], lines[0]
        with self.assertRaises(ValueError):
            probe.parse_result(("\n".join(lines) + "\n").encode())

    def test_old_evidence_cannot_downgrade_required_identity_or_parent_checks(self):
        lines = self.output().decode().splitlines()
        for prefix in ("IDENTITY_OBSERVATION=", "PARENT_OBSERVATION=", "PARENT_METADATA=", "OWNERSHIP_OBSERVATION="):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                probe.parse_result(("\n".join(line for line in lines if not line.startswith(prefix)) + "\n").encode())
        for prefix in ("IDENTITY_OBSERVATION", "OBSERVATION", "PARENT_OBSERVATION"):
            index = next(index for index, line in enumerate(lines) if line.startswith(prefix + "="))
            changed = lines.copy()
            changed[index] = changed[index][:-1] + str(1 - int(changed[index][-1]))
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                probe.parse_result(("\n".join(changed) + "\n").encode())

    def test_parent_permission_or_type_drift_cannot_hide_behind_success_boolean(self):
        output = self.output()
        prefix = b"PARENT_METADATA=syswarden:fresh-directory:remove:after:/usr:1:2:"
        for metadata in (b"41e8:0:0", b"41ed:1:0", b"81ed:0:0", b"bad:0:0"):
            changed = output.replace(prefix + b"41ed:0:0", prefix + metadata, 1)
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                probe.parse_result(changed)

    def test_target_ownership_is_never_promoted_to_alias_ownership(self):
        output = self.output()
        metadata_link = b"OWNERSHIP_OBSERVATION=syswarden:omit-metadata-link-overlay:purge:syswarden:target-owned"
        for changed in (output.replace(metadata_link, metadata_link.replace(b":target-owned", b":owned")),
                        output.replace(b"OWNERSHIP_OBSERVATION=syswarden:omit-overlay:purge:syswarden:unowned",
                                       b"OWNERSHIP_OBSERVATION=syswarden:omit-overlay:purge:syswarden:target-owned"),
                        output.replace(b"OBSERVATION=syswarden:omit-metadata-link-overlay:purge:0:0:0",
                                       b"OBSERVATION=syswarden:omit-metadata-link-overlay:purge:1:0:1")):
            with self.assertRaises(ValueError):
                probe.parse_result(changed)

    def test_native_ownership_fallback_requires_exact_package_and_symlink_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular, linked, foreign = root / "regular", root / "linked", root / "foreign"
            regular.write_bytes(b"inert")
            linked.symlink_to("/opt/sw-apk-protection/vendor")
            foreign.symlink_to("/different-target")
            registration = "syswarden-3.00.0-r0"
            cases = [
                (regular, f"{regular} is owned by {registration}", 0, "owned"),
                (linked, f"{linked} symlink target is owned by {registration}", 0, "target-owned"),
                (linked, "", 1, "unowned"),
                (regular, f"{regular} symlink target is owned by {registration}", 0, None),
                (foreign, f"{foreign} symlink target is owned by {registration}", 0, None),
                (linked, f"{linked} symlink target is owned by another-package", 0, None),
                (linked, f"{linked} is owned by {registration}\nextra", 0, None),
                (linked, "", 2, None),
            ]
            script = 'set -eu\napk() { printf "%s\\n" "$OWNER_OUTPUT"; return "$OWNER_STATUS"; }\n' + probe.OWNERSHIP_SCRIPT
            script += '\nlauncher_ownership "$TEST_ALIAS" "$EXPECTED_PACKAGE"\n'
            for alias, output, status, expected in cases:
                result = subprocess.run(["/bin/sh", "-c", script], cwd=root, timeout=3, check=False,
                                        env={"PATH": "/usr/bin:/bin", "OWNER_OUTPUT": output, "OWNER_STATUS": str(status),
                                             "TEST_ALIAS": str(alias), "EXPECTED_PACKAGE": registration},
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with self.subTest(alias=alias.name, status=status, expected=expected):
                    self.assertEqual(result.returncode, 0 if expected is not None else 83)
                    self.assertEqual(result.stdout, (expected + "\n").encode() if expected is not None else b"")

    def test_full_success_remains_synthetic_and_unqualified(self):
        image, cid = "1" * 64, "2" * 64
        def execute(arguments, **kwargs):
            if "info" in arguments:
                output = b"true\n"
            elif "image" in arguments:
                output = json.dumps([{"Id": image, "Os": "linux", "Architecture": "amd64"}]).encode()
            elif "create" in arguments:
                output = (cid + "\n").encode()
            elif "inspect" in arguments:
                output = b"[{}]"
            elif "start" in arguments:
                output = self.output()
            else:
                self.fail(f"unexpected mock command: {arguments}")
            return subprocess.CompletedProcess(arguments, 0, output)
        helpers = SimpleNamespace(execute_local=execute, podman_command=lambda *args: list(args),
                                  CONTAINER_PREFIX="sw-fixture-", ContainerIdentity=lambda name, token, cidfile: SimpleNamespace(name=name, token=token, cidfile=cidfile),
                                  container_exists=lambda *args: False, read_container_id=lambda *args: cid)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nfpm = root / "nfpm"
            nfpm.write_bytes(b"inert caller-trusted fixture")
            nfpm.chmod(0o700)
            with mock.patch.object(probe.os, "geteuid", return_value=1000), \
                 mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                 mock.patch.object(probe.isolation, "isolation_helpers", return_value=helpers), \
                 mock.patch.object(probe.isolation, "sandbox_command", return_value=["podman", "create"]), \
                 mock.patch.object(probe.isolation, "validate_isolation"), \
                 mock.patch.object(probe.isolation, "cleanup_owned_container", return_value={"verified": True}), \
                 mock.patch.object(probe, "payload", return_value=b"inert payload"), \
                 mock.patch("builtins.print"):
                probe.run(nfpm, image, root / "output")
            summary = json.loads((root / "output" / "results.json").read_text())
            self.assertTrue(summary["passed"])
            self.assertTrue(summary["synthetic_only"])
            self.assertIs(summary["product_accepted"], False)
            self.assertIs(summary["direct_native_upgrade_qualified"], False)
            self.assertEqual(len(summary["observations"]), 48)

    def test_payload_builds_both_metadata_kinds_without_reusing_private_paths(self):
        def build(arguments, **kwargs):
            Path(arguments[-1]).write_bytes(b"inert-package-fixture")
            return subprocess.CompletedProcess(arguments, 0, b"")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(probe.subprocess, "run", side_effect=build):
            root = Path(temporary)
            content = probe.payload(root, root / "nfpm")
            with tarfile.open(fileobj=io.BytesIO(content)) as archive:
                self.assertEqual(len(archive.getnames()), 13)
                self.assertEqual(len(set(archive.getnames())), 13)
            for name in probe.PACKAGE_NAMES:
                regular = json.loads((root / f"{name}-1-regular.json").read_text())
                linked = json.loads((root / f"{name}-1.json").read_text())
                self.assertEqual(regular["version"], linked["version"])
                self.assertTrue(all(entry.get("type") != "symlink" for entry in regular["contents"]))
                self.assertEqual(sum(entry.get("type") == "symlink" for entry in linked["contents"]), 2)

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
