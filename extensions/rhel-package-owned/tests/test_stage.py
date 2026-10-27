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

    def test_native_install_gate_refuses_every_nonfresh_phase_before_effects(self) -> None:
        guards = []
        for name in ("pre-install.sh", "post-install.sh"):
            source = (EXTENSION_ROOT / "scriptlets" / name).read_text(encoding="utf-8")
            # Execute the actual unconditional entry prefix. The suffix that
            # queries native state or mutates the host is replaced by a sentinel.
            prefix = source[:source.index('fail() {')]
            self.assertIn('if [ "$#" -ne 1 ] || [ "${1:-}" != 1 ]; then', prefix)
            self.assertNotIn("/usr/bin/", prefix)
            guards.append(prefix)
            for arguments in ((), ("",), ("0",), ("01",), ("2",), ("23",),
                              ("recovery",), ("1", "extra"), ("1",), ("999999999999999999999999",)):
                for inherited in ("fresh", "upgrade"):
                    with self.subTest(script=name, arguments=arguments, inherited=inherited):
                        result = subprocess.run(
                            ["/bin/sh", "-c", prefix + "\nprintf 'EFFECT-SENTINEL\\n'\n", "rhel-install-gate", *arguments],
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                 "SYSWARDEN_NATIVE_INSTALL_PHASE": inherited,
                                 "SYSWARDEN_PKG_INSTALL": "1", "SYSWARDEN_OFFLINE_QUALIFICATION": "1"},
                            capture_output=True, text=True, check=False, timeout=5,
                        )
                        if arguments == ("1",):
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stdout, "EFFECT-SENTINEL\n")
                        else:
                            self.assertEqual(result.returncode, 1, result.stderr)
                            self.assertEqual(result.stdout, "")
                            self.assertIn("separately approved coordinated native transaction", result.stderr)
        self.assertEqual(guards[0], guards[1])

    def test_assembly_nonfresh_refusal_requires_exact_reason_and_unchanged_state(self) -> None:
        source = (EXTENSION_ROOT / "tests/test-rpm-assembly.sh").read_text(encoding="utf-8")
        helpers = source[source.index("snapshot_native_refusal_state() {"):
                         source.index("expect_rhel_upgrade_refusal() {")]
        refusal = ("Non-fresh RHEL package-owned installation is refused before scriptlet effects. "
                   "A separately approved coordinated native transaction is required.")
        stub = r'''
set -euo pipefail
TEST_WORKSPACE="$1"
PACKAGE_PATH=fixture.rpm
chroot_admin() { "$@"; }
rpm_at_root() {
    local root="$1"
    shift
    if [ "$1" = --query ]; then
        case "$*" in
            *--dump*) printf '%s\n' '/etc/policy fixture-owned-inventory' ;;
            *) cat "${root}/usr/lib/sysimage/rpm/identity" ;;
        esac
        return
    fi
    case "${TEST_EFFECT}" in
        accepted) return 0 ;;
        wrong-error) printf '%s\n' 'unrelated RPM failure' >&2; return 1 ;;
        bytes) printf '%s\n' changed > "${root}/etc/policy" ;;
        mode) chmod 0660 "${root}/etc/policy" ;;
        symlink) ln -sfn elsewhere "${root}/etc/alias" ;;
        service) printf '%s\n' 'preset syswarden-core.service' >> "${root}/var/lib/systemctl.log" ;;
        identity) printf '%s\n' 'syswarden-unexpected' > "${root}/usr/lib/sysimage/rpm/identity" ;;
        new-file) printf '%s\n' unexpected > "${root}/etc/unexpected" ;;
        removed-file) rm "${root}/etc/policy" ;;
        directory-mode) chmod 0775 "${root}/etc" ;;
        none) ;;
        *) return 2 ;;
    esac
    printf '%s\n' "${TEST_REFUSAL}" >&2
    return 1
}
'''
        for effect in ("none", "accepted", "wrong-error", "bytes", "mode", "symlink",
                       "service", "identity", "new-file", "removed-file", "directory-mode"):
            with self.subTest(effect=effect), tempfile.TemporaryDirectory() as raw:
                workspace = Path(raw)
                root = workspace / "root"
                for path in ("etc", "var/lib", "usr/lib/sysimage/rpm", "proc"):
                    (root / path).mkdir(parents=True, exist_ok=True)
                (root / "etc/policy").write_text("original\n", encoding="utf-8")
                (root / "etc/alias").symlink_to("policy")
                (root / "var/lib/systemctl.log").write_text("", encoding="utf-8")
                (root / "usr/lib/sysimage/rpm/identity").write_text("syswarden-original\n", encoding="utf-8")
                result = subprocess.run(
                    ["bash", "-c", stub + helpers +
                     '\nexpect_native_nonfresh_refusal "$1/root" "fixture scenario" --replacepkgs\n',
                     "rpm-refusal-regression", raw],
                    env={**os.environ, "TEST_EFFECT": effect, "TEST_REFUSAL": refusal},
                    capture_output=True, text=True, check=False, timeout=10,
                )
                if effect == "none":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("Verified non-fresh refusal with unchanged native state", result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    if effect not in {"accepted", "wrong-error"}:
                        self.assertIn("changed native state", result.stderr)

    def test_assembly_keeps_descriptor_for_native_removal_and_separate_legacy_fixture(self) -> None:
        source = (EXTENSION_ROOT / "tests/test-rpm-assembly.sh").read_text(encoding="utf-8")
        profile = source[source.index("for binary in syswarden-cli syswarden-core syswarden-tui;"):
                         source.index('assemble_profile_rpm 4.10.4 "${PACKAGE_PATH}"')]
        self.assertIn("scripts/ci/native_activation_descriptor.py", profile)
        self.assertIn('--root "${PROFILE_STAGE}/payload"', profile)
        erase = source[source.index("prepare_exact_erase_state() {"):
                       source.index("assert_final_absence() {")]
        self.assertIn("! -name activation-contract-v1.json", erase)
        self.assertIn('assert_chroot_path_absent "${root}" /opt/syswarden/activation-contract-v1.json', source)
        self.assertIn('expect_rhel_upgrade_refusal "${LEGACY_CHROOT_ROOT}"', source)
        self.assertIn("migration/rollback/reupgrade cycle remain unqualified", source)
        independent_fresh = source[source.index("# Exercise profile removal independently"):
                                   source.index("# Even exact legacy priority units")]
        self.assertLess(
            independent_fresh.index('chroot_admin install -d -m 0755 -- "${CHROOT_ROOT}/etc/systemd/system"'),
            independent_fresh.index('rpm_at_root "${CHROOT_ROOT}" --install'),
        )
        # Every direct upgrade in the assembly harness must pass through the
        # refusal helper. Successful fresh and native erase paths stay explicit.
        self.assertEqual(source.count('--upgrade --nodeps'), 1)
        self.assertNotRegex(source, r'rpm_at_root[^\n]+--upgrade --(?:replacepkgs|oldpackage)')
        self.assertIn('rpm_at_root "${CHROOT_ROOT}" --install --nodeps', source)
        self.assertIn('rpm_at_root "${CHROOT_ROOT}" --erase syswarden', source)

    def test_inventory_is_exact_ordered_and_digest_bound(self) -> None:
        entries = self.inventory["entries"]
        self.assertEqual(self.inventory["schema_version"], 2)
        self.assertEqual(self.inventory["profile"], "rhel-package-owned-runtime/v2")
        self.assertEqual(len(entries), 20)
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
            self.assertEqual(manifest["managed_entry_count"], 20)
            self.assertEqual(manifest["rpm_payload_entry_count"], 14)
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
        scriptlet_sources = [
            (EXTENSION_ROOT / relative).read_text(encoding="utf-8")
            for relative in self.profile["rpm"]["lifecycle"].values()
        ]
        for scriptlet in scriptlet_sources:
            verify_contract.validate_no_product_binary_execution(scriptlet)
        scriptlets = "\n".join(scriptlet_sources)
        for forbidden in (
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
        self.assertIn(".syswarden-rhelpo-erase-ready-v1", pre_uninstall)
        self.assertIn("/usr/bin/timeout 15 /usr/bin/rpm", pre_uninstall)
        self.assertNotIn("/usr/bin/systemctl disable", pre_uninstall)
        self.assertNotIn("/usr/bin/systemctl stop", pre_uninstall)
        readme = (EXTENSION_ROOT / "README.md").read_text(encoding="utf-8")
        qualification = (EXTENSION_ROOT / "NATIVE_QUALIFICATION_V4.10.0.md").read_text(
            encoding="utf-8"
        )
        recovery_helper = (EXTENSION_ROOT / "scriptlets/postun-recovery.sh").read_bytes()
        recovery_digest = hashlib.sha256(recovery_helper).hexdigest()
        post_uninstall = (EXTENSION_ROOT / "scriptlets/post-uninstall.sh").read_text(
            encoding="utf-8"
        )
        assembly_test = (EXTENSION_ROOT / "tests/test-rpm-assembly.sh").read_text(encoding="utf-8")
        for document in (readme, pre_uninstall, post_uninstall):
            self.assertIn("/var/lib/.syswarden-rhelpo-postun-recovery-v1", document)
            self.assertIn(f"0:0:700:1:{len(recovery_helper)}", document)
            self.assertIn(recovery_digest, document)
        self.assertIn(recovery_digest, assembly_test)
        self.assertIn("v4.10.0", qualification)
        self.assertIn("cf60ef354a217753bd3704e1fb5b182a1694abcc75a631b6d3218320f7b4fa63", qualification)
        preset = (REPOSITORY_ROOT / "src/init/systemd/90-syswarden-rhel-image.preset").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            preset,
            "enable syswarden-firewall.service\nenable syswarden-core.service\n",
        )

    def test_current_rpm_and_erase_record_digests_match_source_version(self) -> None:
        version = verify_contract.PACKAGE_VERSION
        identity = f"syswarden\t0\t{version}\t1.rhelpo\tx86_64\n".encode()
        identity_digest = hashlib.sha256(identity).hexdigest()
        marker = f"SYSWARDEN_RHELPO_ERASE_READY_V1\nnevra=syswarden-{version}-1.rhelpo.x86_64\n".encode()
        marker_digest = hashlib.sha256(marker).hexdigest()
        for name in ("pre-install.sh", "post-install.sh", "pre-uninstall.sh"):
            self.assertIn(identity_digest, (EXTENSION_ROOT / "scriptlets" / name).read_text())
        for name in ("pre-uninstall.sh", "postun-recovery.sh"):
            self.assertIn(marker_digest, (EXTENSION_ROOT / "scriptlets" / name).read_text())
        self.assertIn(marker_digest, (EXTENSION_ROOT / "tests/test-rpm-assembly.sh").read_text())

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
        records: dict[str, tuple[str, str, str, str, str, str]] = {}
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
        for path, (permissions, target) in verify_contract.SHARED_PAYLOAD_RECORDS.items():
            digest = "1" * 64 if permissions.startswith("-") else ""
            records[path] = (permissions, "root", "root", target, digest, "1")
        verify_contract.validate_payload(self.inventory["entries"], records, "8")
        security_lines = []
        for path in records:
            flags = "0"
            if path in {
                "/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt",
                "/usr/share/doc/syswarden/LICENSE.txt",
                "/usr/share/doc/syswarden/rhel-package-owned-profile.json",
            }:
                flags = "2"
            security_lines.append(f"{path}\t(none)\t(none)\t{flags}\n")
        security_metadata = "".join(security_lines)
        verify_contract.validate_file_security_metadata(records, security_metadata)
        for substituted in (
            security_metadata.replace("\t(none)\t", "\tcap_net_admin=ep\t", 1),
            security_metadata.replace("\t(none)\t0\n", "\tsystem_u:object_r:bin_t:s0\t0\n", 1),
            security_metadata.replace("\t0\n", "\t64\n", 1),
        ):
            with self.assertRaisesRegex(
                verify_contract.VerificationError,
                "file security metadata mismatch",
            ):
                verify_contract.validate_file_security_metadata(records, substituted)
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
            verify_contract.VerificationError, "undeclared package-owned path"
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

        del records["/etc/syswarden/config/modules/99-user.toml"]
        records["/etc/cron.d/unreviewed"] = (
            "-rw-r--r--",
            "root",
            "root",
            "",
            "5" * 64,
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

    def test_verifier_package_version_matches_current_source(self) -> None:
        source = (REPOSITORY_ROOT / "src/core/syswarden-cli/pkg/system/upgrade.go").read_text(encoding="utf-8")
        versions = re.findall(r'(?m)^var Version = "v([0-9]+\.[0-9]{2}\.[0-9]+)"$', source)
        self.assertEqual(versions, [verify_contract.PACKAGE_VERSION])

    def test_verifier_pins_exact_rhel_package_owned_nevra(self) -> None:
        exact = ["syswarden", "0", "4.10.4", "1.rhelpo", "x86_64", "8"]
        self.assertEqual(
            verify_contract.validate_package_identity(
                exact, "syswarden-4.10.4-1.rhelpo.x86_64.rpm"
            ),
            "8",
        )
        for metadata, filename in (
            (
                ["syswarden", "0", "4.10.5", "1.rhelpo", "x86_64", "8"],
                "syswarden-4.10.5-1.rhelpo.x86_64.rpm",
            ),
            (
                ["syswarden", "0", "4.10.4", "2.rhelpo", "x86_64", "8"],
                "syswarden-4.10.4-2.rhelpo.x86_64.rpm",
            ),
            (exact, "syswarden-4.10.5-1.rhelpo.x86_64.rpm"),
            (["syswarden", "1", "4.10.4", "1.rhelpo", "x86_64", "8"], "syswarden-4.10.4-1.rhelpo.x86_64.rpm"),
        ):
            with self.subTest(metadata=metadata, filename=filename), self.assertRaisesRegex(
                verify_contract.VerificationError, "identity does not match"
            ):
                verify_contract.validate_package_identity(metadata, filename)

    def test_verifier_allows_passive_product_attestation_but_rejects_execution(self) -> None:
        verify_contract.validate_no_product_binary_execution(
            (EXTENSION_ROOT / "scriptlets/pre-uninstall.sh").read_text(encoding="utf-8")
        )
        passive = """for entry in /opt/syswarden/bin/*; do
case "$entry" in
  /opt/syswarden/bin/syswarden-cli|/opt/syswarden/bin/syswarden-core) stat "$entry" ;;
esac
done
"""
        verify_contract.validate_no_product_binary_execution(passive)
        adversarial = (
            "/opt/syswarden/bin/syswarden-cli install\n",
            "command /opt/syswarden/bin/syswarden-core\n",
            "env MODE=test /opt/syswarden/bin/syswarden-tui\n",
            "tool=/opt/syswarden/bin/syswarden-cli\n\"$tool\" install\n",
            "root=/opt/syswarden/bin\ntool=syswarden-cli\n\"$root/$tool\"\n",
            "eval '/opt/syswarden/bin/syswarden-cli install'\n",
            "source /opt/syswarden/bin/syswarden-cli\n",
            ". /opt/syswarden/bin/syswarden-cli\n",
            "/bin/sh -c '/opt/syswarden/bin/syswarden-cli install'\n",
            "find /tmp -exec /opt/syswarden/bin/syswarden-cli {} \\;\n",
            "printf x | xargs /opt/syswarden/bin/syswarden-cli\n",
        )
        for scriptlet in adversarial:
            with self.subTest(scriptlet=scriptlet), self.assertRaises(
                verify_contract.VerificationError
            ):
                verify_contract.validate_no_product_binary_execution(scriptlet)

    def test_verifier_rejects_every_unreviewed_rpm_script_or_trigger_tag(self) -> None:
        package = Path("candidate.rpm")
        absent = "".join(
            f"{tag}=absent\n" for tag in verify_contract.UNREVIEWED_SCRIPT_TAGS
        )
        with mock.patch.object(verify_contract, "rpm_query", return_value=absent):
            verify_contract.validate_no_unreviewed_script_sections(package)

        for forbidden_tag in verify_contract.UNREVIEWED_SCRIPT_TAGS:
            response = "".join(
                f"{tag}={'present' if tag == forbidden_tag else 'absent'}\n"
                for tag in verify_contract.UNREVIEWED_SCRIPT_TAGS
            )
            with self.subTest(tag=forbidden_tag), mock.patch.object(
                verify_contract, "rpm_query", return_value=response
            ), self.assertRaisesRegex(
                verify_contract.VerificationError,
                f"unreviewed script or trigger tag {forbidden_tag}",
            ):
                verify_contract.validate_no_unreviewed_script_sections(package)

        with mock.patch.object(
            verify_contract, "rpm_query", return_value="PRETRANS=absent\n"
        ), self.assertRaisesRegex(
            verify_contract.VerificationError,
            "inventory is malformed",
        ):
            verify_contract.validate_no_unreviewed_script_sections(package)

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

class RHELActivationDescriptorTests(unittest.TestCase):
    """Optional capability bytes do not widen the historical payload contract."""

    def test_preun_descriptor_query_has_a_kernel_output_bound_and_cleans_failure(self):
        import shlex

        source = (EXTENSION_ROOT / "scriptlets/pre-uninstall.sh").read_text(encoding="utf-8")
        match = re.search(r"^exact_optional_activation_descriptor\(\) \{\n.*?^\}\n", source, re.M | re.S)
        self.assertIsNotNone(match)
        function = match.group(0)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            writer = root / "oversized-query.py"
            writer.write_text(
                "import os\nos.write(1, b'x' * (2 << 20))\nos.write(1, b'\\n')\n",
                encoding="ascii",
            )
            function = function.replace(
                "/usr/bin/timeout 15 /usr/bin/rpm",
                "/usr/bin/timeout 5 " + shlex.quote(sys.executable) + " " + shlex.quote(str(writer)),
                1,
            ).replace(
                "/usr/bin/mktemp /tmp/syswarden-rhelpo-preun-activation.XXXXXXXXXX",
                "/usr/bin/mktemp " + shlex.quote(str(root / "capture.XXXXXXXXXX")),
                1,
            )
            # Only the query writer and ownership callback are fixtures. The
            # production ulimit, subprocess status, parser and cleanup remain.
            script = (
                "set -eu\numask 077\n"
                "fail() { printf '%s\\n' \"$1\" >&2; exit 1; }\n"
                "exact_owned_payload_file() { :; }\n" + function +
                "exact_optional_activation_descriptor /opt/syswarden/activation-contract-v1.json\n"
            )
            result = subprocess.run(
                ["/bin/sh", "-s"], input=script, text=True,
                capture_output=True, check=False, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Cannot query the installed native activation descriptor bindings.", result.stderr)
            self.assertEqual(list(root.glob("capture.*")), [])

    def records(self):
        entries = json.loads(INVENTORY.read_text(encoding="utf-8"))["entries"]
        records = {}
        for entry in entries:
            if entry["rpm_ownership"] == "payload":
                records["/" + entry["destination"].removeprefix("payload/")] = (
                    verify_contract.expected_permissions(entry), "root", "root", "",
                    entry["sha256"] or "", "1",
                )
        for path, (mode, target) in verify_contract.SHARED_PAYLOAD_RECORDS.items():
            records[path] = (mode, "root", "root", target, "1" * 64 if mode[0] == "-" else "", "1")
        records["/opt/syswarden/bin/syswarden-core"] = (
            "-rwxr-x---", "root", "root", "", "2" * 64, "1",
        )
        return entries, records

    def descriptor_record(self, records):
        contract = verify_contract.native_activation_descriptor
        digest = hashlib.sha256(contract.descriptor_for_digests(
            records["/opt/syswarden/bin/syswarden-cli"][4],
            records["/opt/syswarden/bin/syswarden-core"][4],
        )).hexdigest()
        return "/" + contract.DESCRIPTOR_PATH, ("-rw-r--r--", "root", "root", "", digest, "1")

    def test_rpm_accepts_historical_absence_and_exact_optional_descriptor(self):
        entries, records = self.records()
        verify_contract.validate_payload(entries, records, "8")
        path, record = self.descriptor_record(records)
        self.assertNotIn(path, verify_contract.SHARED_PAYLOAD_RECORDS)
        records[path] = record
        verify_contract.validate_payload(entries, records, "8")
        records[path + ".extra"] = record
        with self.assertRaisesRegex(verify_contract.VerificationError, "undeclared package-owned path"):
            verify_contract.validate_payload(entries, records, "8")

    def test_rpm_rejects_descriptor_metadata_and_binary_digest_drift(self):
        entries, original = self.records()
        path, record = self.descriptor_record(original)
        for field, value in (
            (0, "-rw-------"), (0, "lrwxrwxrwx"), (0, "drw-r--r--"),
            (1, "administrator"), (2, "administrator"), (3, "/other"),
            (4, "3" * 64), (4, "A" * 64), (5, "2"),
        ):
            with self.subTest(field=field, value=value):
                records = dict(original)
                altered = list(record)
                altered[field] = value
                records[path] = tuple(altered)
                with self.assertRaisesRegex(verify_contract.VerificationError, "descriptor metadata or digest mismatch"):
                    verify_contract.validate_payload(entries, records, "8")
        for binary in ("cli", "core"):
            with self.subTest(binary=binary):
                records = dict(original)
                records[path] = record
                binary_path = "/opt/syswarden/bin/syswarden-" + binary
                prior = records[binary_path]
                records[binary_path] = (*prior[:4], "4" * 64, prior[5])
                with self.assertRaisesRegex(verify_contract.VerificationError, "descriptor metadata or digest mismatch"):
                    verify_contract.validate_payload(entries, records, "8")

    def test_rpm_descriptor_forbids_security_attributes(self):
        _, original = self.records()
        path, record = self.descriptor_record(original)
        records = {path: record}
        verify_contract.validate_file_security_metadata(records, f"{path}\t(none)\t(none)\t0\n")
        for capabilities, context, flags in (
            ("cap_net_admin=ep", "(none)", "0"),
            ("(none)", "system_u:object_r:bin_t:s0", "0"),
            ("(none)", "(none)", "2"),
            ("(none)", "(none)", "64"),
        ):
            with self.subTest(capabilities=capabilities, context=context, flags=flags):
                with self.assertRaisesRegex(verify_contract.VerificationError, "file security metadata mismatch"):
                    verify_contract.validate_file_security_metadata(
                        records, f"{path}\t{capabilities}\t{context}\t{flags}\n",
                    )

    def shared_base(self, root):
        base = root / "base"
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        for relative in stage_contract.SHARED_PAYLOADS:
            entry = next(entry for entry in inventory["entries"]
                         if entry["destination"] == "payload/" + str(relative))
            shared = base / relative
            shared.parent.mkdir(parents=True, exist_ok=True)
            shared.write_bytes((REPOSITORY_ROOT / entry["source"]).read_bytes())
            shared.chmod(0o644)
        return base

    def test_stager_accepts_absence_and_exact_descriptor_without_republishing_it(self):
        for present in (False, True):
            with self.subTest(present=present), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base = self.shared_base(root)
                if present:
                    self.runtime_descriptor(base)
                output = root / "profile"
                stage_contract.stage(output, base)
                self.assertTrue(output.is_dir())
                self.assertFalse((output / "payload" / stage_contract.native_activation_descriptor.DESCRIPTOR_PATH).exists())

    def runtime_descriptor(self, base):
        binaries = base / "opt/syswarden/bin"
        binaries.mkdir(parents=True)
        for name in ("cli", "core"):
            binary = binaries / ("syswarden-" + name)
            binary.write_bytes(("synthetic " + name + "\n").encode("ascii"))
            binary.chmod(0o750)
        stage_contract.native_activation_descriptor.generate(base)
        return base / stage_contract.native_activation_descriptor.DESCRIPTOR_PATH

    def test_stager_rejects_present_invalid_descriptor_without_publishing(self):
        for mutation in ("bytes", "mode", "symlink", "dangling", "directory", "hardlink", "cli", "core", "parent"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                base = self.shared_base(root)
                descriptor = self.runtime_descriptor(base)
                if mutation == "bytes":
                    descriptor.write_bytes(descriptor.read_bytes() + b" ")
                elif mutation == "mode":
                    descriptor.chmod(0o600)
                elif mutation in ("symlink", "dangling"):
                    saved = root / "saved"
                    descriptor.rename(saved)
                    descriptor.symlink_to(saved if mutation == "symlink" else root / "absent")
                elif mutation == "directory":
                    descriptor.unlink()
                    descriptor.mkdir()
                elif mutation == "hardlink":
                    os.link(descriptor, root / "extra-link")
                elif mutation in ("cli", "core"):
                    (base / "opt/syswarden/bin" / ("syswarden-" + mutation)).write_bytes(b"changed binary\n")
                else:
                    (base / "opt/syswarden").chmod(0o777)
                output = root / "profile"
                with self.assertRaisesRegex(stage_contract.StageError, "invalid optional native activation descriptor"):
                    stage_contract.stage(output, base)
                self.assertFalse(output.exists())
                self.assertTrue(descriptor.exists() or descriptor.is_symlink())
                self.assertEqual(list(root.glob(".syswarden-rhel-profile.*")), [])


if __name__ == "__main__":
    unittest.main()
