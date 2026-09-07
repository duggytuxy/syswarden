#!/usr/bin/env python3
"""Adversarial contracts for the opt-in RHEL package-owned RPM profile."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EXTENSION_ROOT = REPOSITORY_ROOT / "extensions/rhel-package-owned"
STAGER = EXTENSION_ROOT / "stage.py"
VERIFIER = EXTENSION_ROOT / "verify-rpm.py"
INVENTORY = EXTENSION_ROOT / "inventory.json"
PROFILE = EXTENSION_ROOT / "profile.json"
BUILD_SCRIPT = REPOSITORY_ROOT / "build_packages.sh"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


stage_contract = load_module("syswarden_rhel_profile_stage", STAGER)
verify_contract = load_module("syswarden_rhel_profile_verify", VERIFIER)


class RHELPackageOwnedStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        cls.profile = json.loads(PROFILE.read_text(encoding="utf-8"))

    def run_stager(
        self,
        output: Path,
        *,
        opt_in: bool = True,
        shared_base_payload: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = ["python3", str(STAGER), "--output", str(output)]
        if opt_in:
            command.append("--enable-rhel-package-owned-profile")
        if shared_base_payload is not None:
            command.extend(("--shared-base-payload", str(shared_base_payload)))
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def isolated_contract(self, raw: str) -> tuple[Path, dict, object, object]:
        repository = Path(raw) / "repository"
        inventory = json.loads(json.dumps(self.inventory))
        for entry in inventory["entries"]:
            source = entry["source"]
            if source is None:
                continue
            destination = repository / source
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY_ROOT / source, destination)
        inventory_path = repository / "extensions/rhel-package-owned/inventory.json"
        inventory_path.write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )
        old_repository = stage_contract.REPOSITORY_ROOT
        old_inventory = stage_contract.INVENTORY_PATH
        stage_contract.REPOSITORY_ROOT = repository
        stage_contract.INVENTORY_PATH = inventory_path
        return repository, inventory, old_repository, old_inventory

    def restore_contract(self, old_repository: object, old_inventory: object) -> None:
        stage_contract.REPOSITORY_ROOT = old_repository
        stage_contract.INVENTORY_PATH = old_inventory

    def test_inventory_is_exact_ordered_and_digest_bound(self) -> None:
        entries = self.inventory["entries"]
        self.assertEqual(self.inventory["schema_version"], 2)
        self.assertEqual(self.inventory["profile"], "rhel-package-owned-runtime/v2")
        self.assertEqual(len(entries), 19)
        self.assertEqual([entry["role"] for entry in entries], list(stage_contract.EXPECTED_ROLES))
        self.assertEqual(
            set(entries[0]),
            {
                "source",
                "destination",
                "type",
                "mode",
                "uid",
                "gid",
                "link_target",
                "sha256",
                "rpm_ownership",
                "rpm_package",
                "role",
            },
        )
        self.assertEqual(len({entry["destination"] for entry in entries}), len(entries))
        for entry in entries:
            self.assertEqual((entry["uid"], entry["gid"]), (0, 0))
            self.assertIsNone(entry["link_target"])
            if entry["type"] == "directory":
                self.assertIsNone(entry["source"])
                self.assertIsNone(entry["sha256"])
            else:
                source = REPOSITORY_ROOT / entry["source"]
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), entry["sha256"])
            if entry["rpm_ownership"] in {"payload", "scriptlet"}:
                self.assertEqual(entry["rpm_package"], "syswarden")
            else:
                self.assertIsNone(entry["rpm_package"])

    def test_explicit_opt_in_is_required_and_default_is_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "profile"
            result = self.run_stager(output, opt_in=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("explicit profile opt-in is required", result.stderr)
            self.assertFalse(output.exists())

    def test_staged_files_match_sources_modes_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "profile"
            result = self.run_stager(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            for entry in self.inventory["entries"]:
                destination = output / entry["destination"]
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), int(entry["mode"], 8))
                if entry["type"] == "regular":
                    self.assertEqual(destination.read_bytes(), (REPOSITORY_ROOT / entry["source"]).read_bytes())
                    self.assertEqual(destination.stat().st_nlink, 1)
            manifest = json.loads((output / "assembly-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["profile"], "rhel-package-owned-runtime/v2")
            self.assertEqual(manifest["status"], "staged-not-installed")
            self.assertEqual(manifest["managed_entry_count"], 19)
            self.assertEqual(manifest["rpm_payload_entry_count"], 13)
            self.assertEqual(
                manifest["inventory_sha256"], hashlib.sha256(INVENTORY.read_bytes()).hexdigest()
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "assembly-manifest.json").stat().st_mode), 0o600)

    def test_existing_output_fails_closed_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "profile"
            output.mkdir()
            sentinel = output / "operator-file"
            sentinel.write_text("retain\n", encoding="utf-8")
            result = self.run_stager(output)
            self.assertEqual(result.returncode, 1)
            self.assertIn("must not already exist", result.stderr)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "retain\n")

    def test_destination_race_fails_closed_without_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "profile"
            sentinel = output / "operator-file"
            original_verify = stage_contract.verify_staged

            def create_racing_destination(root, entries, prepared):
                original_verify(root, entries, prepared)
                output.mkdir()
                sentinel.write_text("retain\n", encoding="utf-8")

            with mock.patch.object(
                stage_contract,
                "verify_staged",
                side_effect=create_racing_destination,
            ):
                with self.assertRaisesRegex(
                    stage_contract.StageError,
                    "atomic no-replace publication failed",
                ):
                    stage_contract.stage(output)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "retain\n")
            self.assertEqual(
                list(Path(raw).glob(".syswarden-rhel-profile.*")),
                [],
            )

    def test_relative_output_is_rejected(self) -> None:
        result = self.run_stager(Path("relative-profile"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("output must be an absolute path", result.stderr)
        self.assertFalse((REPOSITORY_ROOT / "relative-profile").exists())

    def test_digest_tamper_fails_before_output_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repository, inventory, old_repository, old_inventory = self.isolated_contract(raw)
            try:
                inventory["entries"][-1]["sha256"] = "0" * 64
                Path(stage_contract.INVENTORY_PATH).write_text(
                    json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
                )
                output = Path(raw) / "profile"
                with self.assertRaisesRegex(stage_contract.StageError, "source digest mismatch"):
                    stage_contract.stage(output)
                self.assertFalse(output.exists())
            finally:
                self.restore_contract(old_repository, old_inventory)

    def test_symlinked_source_is_rejected_before_output_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repository, inventory, old_repository, old_inventory = self.isolated_contract(raw)
            try:
                source = repository / inventory["entries"][8]["source"]
                replacement = source.with_name("replacement.service")
                source.rename(replacement)
                source.symlink_to(replacement.name)
                output = Path(raw) / "profile"
                with self.assertRaisesRegex(stage_contract.StageError, "canonical repository path"):
                    stage_contract.stage(output)
                self.assertFalse(output.exists())
            finally:
                self.restore_contract(old_repository, old_inventory)

    def test_hardlinked_source_is_rejected_before_output_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repository, inventory, old_repository, old_inventory = self.isolated_contract(raw)
            try:
                source = repository / inventory["entries"][8]["source"]
                os.link(source, source.with_name("second-link.service"))
                output = Path(raw) / "profile"
                with self.assertRaisesRegex(stage_contract.StageError, "protected singly-linked"):
                    stage_contract.stage(output)
                self.assertFalse(output.exists())
            finally:
                self.restore_contract(old_repository, old_inventory)

    def test_path_traversal_inventory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            _, inventory, old_repository, old_inventory = self.isolated_contract(raw)
            try:
                inventory["entries"][8]["destination"] = "payload/../escape"
                Path(stage_contract.INVENTORY_PATH).write_text(
                    json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(stage_contract.StageError, "safe relative path"):
                    stage_contract.stage(Path(raw) / "profile")
            finally:
                self.restore_contract(old_repository, old_inventory)

    def test_rpm_lifecycle_keeps_go_runtime_only_and_preserves_frontend(self) -> None:
        self.assertEqual(self.profile["status"], "implemented-native-qualification-pending")
        self.assertEqual(self.profile["activation"], "explicit-opt-in-only")
        self.assertEqual(
            self.profile["go_runtime_boundary"],
            {
                "systemd_integration_ownership": "rpm",
                "firewall_integration_ownership": "rpm",
                "firewall_frontend_selection": "operator",
                "dynamic_policy_compilation_and_enforcement": "go-runtime",
                "product_binary_role": "runtime-only",
                "package_scriptlet_product_binary_calls": "forbidden",
            },
        )
        self.assertEqual(
            self.profile["build_integration"],
            {
                "entrypoint": "build_packages.sh --rhel-package-owned-profile",
                "default_builder_behavior": "unchanged",
                "activation": "explicit-command-line-flag",
            },
        )
        self.assertEqual(
            self.profile["image_build_contract"],
            {
                "supported_build_roots": ["mock", "chroot"],
                "running_systemd_required_during_transaction": False,
                "service_start_during_transaction": "forbidden",
                "first_real_boot_activation": "systemd-preset",
                "upgrade_preset_reapplication": "forbidden",
                "operator_configuration_replacement": "forbidden",
            },
        )
        self.assertEqual(
            {
                key: self.profile["rpm"][key]
                for key in (
                    "package_name",
                    "package_release",
                    "nevra_template",
                    "filename_template",
                    "mutual_exclusion",
                )
            },
            {
                "package_name": "syswarden",
                "package_release": "1.rhelpo",
                "nevra_template": "syswarden-{version}-1.rhelpo.x86_64",
                "filename_template": "syswarden-{version}-1.rhelpo.x86_64.rpm",
                "mutual_exclusion": "same-rpm-name",
            },
        )
        scriptlets = "\n".join(
            (EXTENSION_ROOT / relative).read_text(encoding="utf-8")
            for relative in self.profile["rpm"]["lifecycle"].values()
        )
        for forbidden in (
            "/opt/syswarden/bin",
            "syswarden-cli",
            "firewall-cmd",
            "firewalld.service",
            "nftables.service",
            "/usr/bin/nft",
            "/usr/sbin/nft",
            "/usr/bin/curl",
            "/usr/bin/wget",
        ):
            self.assertNotIn(forbidden, scriptlets)
        post_install = (EXTENSION_ROOT / "scriptlets/post-install.sh").read_text(
            encoding="utf-8"
        )
        pre_uninstall = (EXTENSION_ROOT / "scriptlets/pre-uninstall.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('if [ "$1" -eq 1 ]', post_install)
        self.assertIn("/usr/bin/systemctl preset", post_install)
        self.assertNotIn("systemctl start", post_install)
        self.assertNotIn("--now", pre_uninstall)
        self.assertIn("/usr/bin/systemctl disable", pre_uninstall)
        self.assertIn("if [ -d /run/systemd/system ]", pre_uninstall)
        self.assertIn("/usr/bin/systemctl stop", pre_uninstall)
        preset = (REPOSITORY_ROOT / "src/init/systemd/90-syswarden-rhel-image.preset").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            preset,
            "enable syswarden-firewall.service\nenable syswarden-core.service\n",
        )

    def test_flat_init_sources_match_current_runtime_templates_byte_for_byte(self) -> None:
        go_source = (
            REPOSITORY_ROOT / "src/core/syswarden-cli/pkg/system/service_linux.go"
        ).read_text(encoding="utf-8")
        sources = {
            "systemdCoreService": "src/init/systemd/syswarden-core.service",
            "systemdFirewallService": "src/init/systemd/syswarden-firewall.service",
            "openRCCoreService": "src/init/openrc/syswarden-core",
            "openRCFirewallService": "src/init/openrc/syswarden-firewall",
        }
        for constant, relative in sources.items():
            match = re.search(
                rf"^[ \t]*{constant}[ \t]*=[ \t]*`(.*?)`$",
                go_source,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(match, constant)
            self.assertEqual(
                (REPOSITORY_ROOT / relative).read_text(encoding="utf-8"),
                match.group(1),
                relative,
            )

    def test_local_builder_is_explicit_and_default_sources_remain_present(self) -> None:
        builder = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('1:--rhel-package-owned-profile)', builder)
        self.assertIn('if [ "${RHEL_PACKAGE_OWNED_PROFILE}" -eq 1 ]; then', builder)
        self.assertIn('RPM_EXPECTED_PREIN="${PACKAGE_WORKSPACE}/preinst.sh"', builder)
        self.assertIn('RPM_EXPECTED_POSTIN="${PACKAGE_WORKSPACE}/postinst.sh"', builder)
        self.assertIn('RPM_EXPECTED_PREUN="${PACKAGE_WORKSPACE}/prerm.sh"', builder)
        self.assertIn('RPM_EXPECTED_POSTUN="${PACKAGE_WORKSPACE}/postrm.sh"', builder)
        self.assertIn("--rpm-digest sha256", builder)
        self.assertIn("verify-rpm.py", builder)
        self.assertIn('RPM_PACKAGE_RELEASE="1.rhelpo"', builder)
        self.assertIn('--iteration "${RPM_PACKAGE_RELEASE}"', builder)
        self.assertIn('--shared-base-payload "${PACKAGE_WORKSPACE}/staging-rpm"', builder)

    def test_shared_drop_in_must_match_bytes_mode_and_owner(self) -> None:
        relative = stage_contract.SHARED_PAYLOADS[0]
        source_entry = next(
            entry for entry in self.inventory["entries"]
            if entry["destination"] == "payload/" + str(relative)
        )
        source = (REPOSITORY_ROOT / source_entry["source"]).read_bytes()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = root / "base"
            shared = base.joinpath(*relative.parts)
            shared.parent.mkdir(parents=True)
            shared.write_bytes(source)
            shared.chmod(0o644)
            output = root / "profile"
            result = self.run_stager(output, shared_base_payload=base)
            self.assertEqual(result.returncode, 0, result.stderr)

        for mutation in ("bytes", "mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base = root / "base"
                shared = base.joinpath(*relative.parts)
                shared.parent.mkdir(parents=True)
                shared.write_bytes(source)
                shared.chmod(0o644)
                if mutation == "bytes":
                    shared.write_bytes(source + b"# divergence\n")
                else:
                    shared.chmod(0o600)
                output = root / "profile"
                result = self.run_stager(output, shared_base_payload=base)
                self.assertEqual(result.returncode, 1)
                self.assertIn("differs in bytes, mode or owner", result.stderr)
                self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base = root / "base"
            shared = base.joinpath(*relative.parts)
            shared.parent.mkdir(parents=True)
            shared.write_bytes(source)
            shared.chmod(0o644)
            output = root / "profile"
            original_identity = stage_contract.protected_file_identity

            def diverged_owner(path: Path, identity_root: Path, label: str):
                identity = original_identity(path, identity_root, label)
                if label.startswith("base shared payload"):
                    return identity[0], identity[1], identity[2] + 1, identity[3]
                return identity

            with mock.patch.object(
                stage_contract,
                "protected_file_identity",
                side_effect=diverged_owner,
            ):
                with self.assertRaisesRegex(
                    stage_contract.StageError,
                    "differs in bytes, mode or owner",
                ):
                    stage_contract.stage(output, base)
            self.assertFalse(output.exists())

    def test_verifier_accepts_exact_payload_and_rejects_tampering(self) -> None:
        records: dict[str, tuple[str, str, str, str, str, str]] = {
            "/opt/syswarden/bin/syswarden-core": ("-rwxr-x---", "root", "root", "", "1" * 64, "1")
        }
        for entry in self.inventory["entries"]:
            if entry["rpm_ownership"] != "payload":
                continue
            path = "/" + entry["destination"].removeprefix("payload/")
            records[path] = (
                verify_contract.expected_permissions(entry),
                "root",
                "root",
                "",
                entry["sha256"] or "",
                "1",
            )
        verify_contract.validate_payload(self.inventory["entries"], records, "8")
        unit = "/usr/lib/systemd/system/syswarden-core.service"
        original = records[unit]
        records[unit] = ("-rw-rw-rw-", *original[1:])
        with self.assertRaisesRegex(verify_contract.VerificationError, "mode or type mismatch"):
            verify_contract.validate_payload(self.inventory["entries"], records, "8")
        records[unit] = original
        records["/etc/init.d/syswarden-core"] = ("-rwxr-xr-x", "root", "root", "", "2" * 64, "1")
        with self.assertRaisesRegex(verify_contract.VerificationError, "OpenRC"):
            verify_contract.validate_payload(self.inventory["entries"], records, "8")
        del records["/etc/init.d/syswarden-core"]
        records["/usr/lib/systemd/system/syswarden-extra.service"] = (
            "-rw-r--r--",
            "root",
            "root",
            "",
            "3" * 64,
            "1",
        )
        with self.assertRaisesRegex(
            verify_contract.VerificationError, "undeclared package-owned path"
        ):
            verify_contract.validate_payload(self.inventory["entries"], records, "8")

        del records["/usr/lib/systemd/system/syswarden-extra.service"]
        records[unit] = (*original[:-1], "2")
        with self.assertRaisesRegex(verify_contract.VerificationError, "hard-linked"):
            verify_contract.validate_payload(self.inventory["entries"], records, "8")

        records[unit] = original
        records["/usr/lib/systemd/system"] = (
            "lrwxrwxrwx",
            "root",
            "root",
            "/tmp/systemd",
            "",
            "1",
        )
        with self.assertRaisesRegex(
            verify_contract.VerificationError, "unsafe integration parent"
        ):
            verify_contract.validate_payload(self.inventory["entries"], records, "8")

        del records["/usr/lib/systemd/system"]
        records["/usr/lib/systemd/system/syswarden-core.service.d"] = (
            "drwxr-xr-x",
            "root",
            "root",
            "",
            "",
            "1",
        )
        with self.assertRaisesRegex(
            verify_contract.VerificationError, "undeclared package-owned path"
        ):
            verify_contract.validate_payload(self.inventory["entries"], records, "8")

        del records["/usr/lib/systemd/system/syswarden-core.service.d"]
        records["/etc/syswarden/config/modules/99-user.toml"] = (
            "-rw-r-----",
            "root",
            "root",
            "",
            "4" * 64,
            "1",
        )
        with self.assertRaisesRegex(
            verify_contract.VerificationError, "undeclared package-owned path"
        ):
            verify_contract.validate_payload(self.inventory["entries"], records, "8")

    def test_verifier_rejects_legacy_digest_algorithm_and_malformed_records(self) -> None:
        with self.assertRaisesRegex(verify_contract.VerificationError, "not SHA-256"):
            verify_contract.validate_payload(self.inventory["entries"], {}, "1")
        with self.assertRaisesRegex(verify_contract.VerificationError, "malformed"):
            verify_contract.parse_file_inventory("/path\t-rw-r--r--\troot\n")
        with self.assertRaisesRegex(verify_contract.VerificationError, "unsafe"):
            verify_contract.parse_file_inventory("/path\t-rw-r--r--\troot\troot\t\tabc\t1\n/path\t-rw-r--r--\troot\troot\t\tabc\t1\n")

    def test_verifier_rejects_symlinked_and_hardlinked_rpm_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "candidate.rpm"
            package.write_bytes(b"not-an-rpm")
            package.chmod(0o600)
            alias = Path(raw) / "candidate-alias.rpm"
            alias.symlink_to(package.name)
            with self.assertRaisesRegex(verify_contract.VerificationError, "cannot open"):
                verify_contract.regular_bytes(alias, 1024, "RPM package")
            hardlink = Path(raw) / "candidate-hardlink.rpm"
            os.link(package, hardlink)
            with self.assertRaisesRegex(verify_contract.VerificationError, "singly-linked"):
                verify_contract.regular_bytes(package, 1024, "RPM package")

    def test_verifier_requires_systemd_without_forcing_firewalld(self) -> None:
        with mock.patch.object(
            verify_contract, "rpm_query", return_value="systemd\nnftables\n"
        ):
            verify_contract.validate_dependencies(Path("candidate.rpm"))
        with mock.patch.object(
            verify_contract,
            "rpm_query",
            return_value="systemd\nnftables\nfirewalld\n",
        ):
            with self.assertRaisesRegex(verify_contract.VerificationError, "must not force"):
                verify_contract.validate_dependencies(Path("candidate.rpm"))
        with mock.patch.object(verify_contract, "rpm_query", return_value="nftables\n"):
            with self.assertRaisesRegex(verify_contract.VerificationError, "do not include"):
                verify_contract.validate_dependencies(Path("candidate.rpm"))

    def test_overflow_owner_exception_requires_an_unmapped_user_namespace(self) -> None:
        with mock.patch.object(verify_contract.os, "geteuid", return_value=1000), \
             mock.patch.object(verify_contract.Path, "lstat") as path_lstat, \
             mock.patch.object(verify_contract.Path, "read_text", return_value="0 0 4294967295\n"):
            path_lstat.return_value = mock.Mock(st_uid=65534)
            self.assertFalse(verify_contract.unmapped_overflow_owner_is_expected())

        with mock.patch.object(verify_contract.os, "geteuid", return_value=1000), \
             mock.patch.object(verify_contract.Path, "lstat") as path_lstat, \
             mock.patch.object(verify_contract.Path, "read_text", return_value="1000 0 1\n"):
            path_lstat.return_value = mock.Mock(st_uid=65534)
            self.assertTrue(verify_contract.unmapped_overflow_owner_is_expected())


if __name__ == "__main__":
    unittest.main()
