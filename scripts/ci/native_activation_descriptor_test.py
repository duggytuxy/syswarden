#!/usr/bin/env python3
"""Focused tests for byte-bound native runtime capability generation."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import native_activation_descriptor as descriptor


class NativeActivationDescriptorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "opt/syswarden/bin"
        self.binary.mkdir(parents=True, mode=0o755)
        for name in ("syswarden-cli", "syswarden-core"):
            path = self.binary / name
            path.write_bytes(("synthetic " + name + "\n").encode())
            path.chmod(0o750)

    def test_binds_both_binaries_and_is_canonical(self):
        descriptor.generate(self.root)
        descriptor.validate(self.root)
        raw = (self.root / descriptor.DESCRIPTOR_PATH).read_bytes()
        record = json.loads(raw)
        self.assertEqual(record["schema"], "syswarden-native-activation-v2")
        self.assertEqual(record["publication_exclusion"], "config-directory-flock-and-native-debt-v1")
        for component in ("cli", "core"):
            self.assertEqual(record[component + "_sha256"], hashlib.sha256(
                (self.binary / ("syswarden-" + component)).read_bytes()).hexdigest())
        self.assertEqual(raw, (json.dumps(record, separators=(",", ":")) + "\n").encode())
        with self.assertRaises(FileExistsError):
            descriptor.generate(self.root)

    def test_rejects_runtime_or_descriptor_drift(self):
        descriptor.generate(self.root)
        output = self.root / descriptor.DESCRIPTOR_PATH
        original = output.read_bytes()
        for content in (b" " + original, original.replace(b"approval-v1", b"approval-v9"), b"x" * 4097):
            output.write_bytes(content)
            with self.assertRaises(ValueError):
                descriptor.validate(self.root)
        output.write_bytes(original)
        (self.binary / "syswarden-core").write_bytes(b"changed core")
        with self.assertRaises(ValueError):
            descriptor.validate(self.root)

    def test_legacy_bytes_remain_explicit_and_cannot_validate_a_new_stage(self):
        cli = hashlib.sha256((self.binary / "syswarden-cli").read_bytes()).hexdigest()
        core = hashlib.sha256((self.binary / "syswarden-core").read_bytes()).hexdigest()
        legacy = descriptor.descriptor_for_digests(cli, core, legacy=True)
        document = json.loads(legacy)
        self.assertEqual(document["schema"], "syswarden-native-activation-v1")
        self.assertNotIn("publication_exclusion", document)
        descriptor.generate(self.root)
        output = self.root / descriptor.DESCRIPTOR_PATH
        output.write_bytes(legacy)
        with self.assertRaises(ValueError):
            descriptor.validate(self.root)
        self.assertEqual(output.read_bytes(), legacy)

    def test_refuses_symlink_fifo_hardlink_and_writable_payload(self):
        core = self.binary / "syswarden-core"
        original = core.read_bytes()
        for kind in ("symlink", "fifo", "hardlink", "writable"):
            with self.subTest(kind=kind):
                core.unlink()
                if kind == "symlink":
                    core.symlink_to("syswarden-cli")
                elif kind == "fifo":
                    os.mkfifo(core, 0o750)
                elif kind == "hardlink":
                    os.link(self.binary / "syswarden-cli", core)
                else:
                    core.write_bytes(original)
                    core.chmod(0o770)
                with self.assertRaises(ValueError):
                    descriptor.generate(self.root)
                self.assertFalse((self.root / descriptor.DESCRIPTOR_PATH).exists())
                core.unlink()
                core.write_bytes(original)
                core.chmod(0o750)

    def test_rejects_cli_drift_while_capturing_core(self):
        original = descriptor.Capture.read

        def changing(capture, relative, *args, **kwargs):
            result = original(capture, relative, *args, **kwargs)
            if relative.endswith("syswarden-core"):
                (self.binary / "syswarden-cli").write_bytes(b"changed during core capture")
            return result

        with mock.patch.object(descriptor.Capture, "read", changing):
            with self.assertRaises(ValueError):
                descriptor.generate(self.root)
        self.assertFalse((self.root / descriptor.DESCRIPTOR_PATH).exists())

    def test_output_parent_replacement_cannot_redirect_creation(self):
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o755)
        original_open = os.open
        parent = self.root / "opt/syswarden"
        retained = self.root / "opt/retained"

        def replacing(path, flags, mode=0o777, **kwargs):
            if path == "activation-contract-v1.json" and flags & os.O_CREAT:
                parent.rename(retained)
                parent.symlink_to(foreign, target_is_directory=True)
            return original_open(path, flags, mode, **kwargs)

        with mock.patch.object(descriptor.os, "open", replacing):
            with self.assertRaises(ValueError):
                descriptor.generate(self.root)
        self.assertFalse((foreign / "activation-contract-v1.json").exists())
        self.assertTrue((retained / "activation-contract-v1.json").is_file())


if __name__ == "__main__":
    unittest.main()
