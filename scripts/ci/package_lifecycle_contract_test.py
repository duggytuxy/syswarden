#!/usr/bin/env python3
"""Characterize package lifecycle scripts without mutating a host."""

from __future__ import annotations

import io
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

try:
    from scripts.ci import package_lifecycle_lab
except ModuleNotFoundError:  # Direct execution from scripts/ci.
    import package_lifecycle_lab


REPOSITORY = Path(__file__).resolve().parents[2]
PACKAGE_WORKFLOW = REPOSITORY / ".github" / "workflows" / "package.yml"
BUILD_SCRIPT = REPOSITORY / "build.ps1"
LOCAL_BUILD_SCRIPT = REPOSITORY / "build_packages.sh"
WEBTUI_RETIREMENT_HELPER = REPOSITORY / "scripts" / "ci" / "package_webtui_retirement.sh"
DEFERRED_PURGE_POSTINSTALL_HELPER = (
    REPOSITORY / "scripts" / "ci" / "package_deferred_purge_postinstall.sh"
)
REMOVAL_STATE_HELPER = REPOSITORY / "scripts" / "ci" / "package_removal_state.sh"
SERVICE_SOURCE = REPOSITORY / "src" / "core" / "syswarden-cli" / "pkg" / "system" / "service_linux.go"


def workflow_step_script(workflow: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {step_name}")
    step = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
    run_marker = "        run: |\n"
    if step.count(run_marker) != 1:
        raise AssertionError(f"expected one shell body for workflow step {step_name}")
    return textwrap.dedent(step.split(run_marker, 1)[1])


def workflow_run_commands(workflow: str) -> tuple[tuple[str, str], ...]:
    lines = workflow.splitlines()
    commands: list[tuple[str, str]] = []
    step_name = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("      - name: "):
            step_name = line.removeprefix("      - name: ")
        if line.startswith("        run: "):
            value = line.removeprefix("        run: ")
            if value == "|":
                body: list[str] = []
                index += 1
                while index < len(lines):
                    candidate = lines[index]
                    if candidate and len(candidate) - len(candidate.lstrip()) <= 8:
                        index -= 1
                        break
                    body.append(candidate)
                    index += 1
                value = textwrap.dedent("\n".join(body))
            commands.append((step_name, value))
        index += 1
    return tuple(commands)


def stop_test_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    process.wait(timeout=2)


class PackageLifecycleContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._package_install_marker = os.environ.get("SYSWARDEN_PKG_INSTALL")
        os.environ["SYSWARDEN_PKG_INSTALL"] = "1"

    def tearDown(self) -> None:
        if self._package_install_marker is None:
            os.environ.pop("SYSWARDEN_PKG_INSTALL", None)
        else:
            os.environ["SYSWARDEN_PKG_INSTALL"] = self._package_install_marker

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = PACKAGE_WORKFLOW.read_text(encoding="utf-8")

    def script(self, name: str) -> str:
        destination = f"${{PACKAGE_SCRIPTS}}/{name}"
        opener = re.compile(
            rf"^\s*cat\s+<<\s*'(?P<delimiter>[A-Z][A-Z0-9_]*)'\s+>>?\s+"
            rf'"{re.escape(destination)}"\s*$'
        )
        lines = self.workflow.splitlines()
        bodies: list[str] = []
        for index, line in enumerate(lines):
            match = opener.match(line)
            if match is None:
                continue
            delimiter = match.group("delimiter")
            body: list[str] = []
            for candidate in lines[index + 1 :]:
                if candidate.strip() == delimiter:
                    bodies.append(textwrap.dedent("\n".join(body)))
                    break
                body.append(candidate)
            else:
                self.fail(f"package script {name} has no heredoc terminator")
        self.assertEqual(
            len(bodies),
            1,
            f"package script {name} must have exactly one isolated heredoc",
        )
        body = bodies[0]
        if name in {"preinst.sh", "postinst.sh", "prerm.sh", "postrm.sh"}:
            prefix = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8")
            if name in {"preinst.sh", "postinst.sh"}:
                prefix += DEFERRED_PURGE_POSTINSTALL_HELPER.read_text(encoding="utf-8")
            if name == "postrm.sh":
                prefix += REMOVAL_STATE_HELPER.read_text(encoding="utf-8")
            body = prefix + body
        return body

    def test_package_service_cleanup_hashes_match_runtime_service_sources(self) -> None:
        source = SERVICE_SOURCE.read_text(encoding="utf-8")
        helper = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8")
        for constant, path, mode in (
            ("systemdCoreService", "/etc/systemd/system/syswarden-core.service", "600"),
            ("systemdFirewallService", "/etc/systemd/system/syswarden-firewall.service", "600"),
            ("openRCCoreService", "/etc/init.d/syswarden-core", "755"),
            ("openRCFirewallService", "/etc/init.d/syswarden-firewall", "755"),
        ):
            match = re.search(rf"\b{constant}\s*=\s*`(?P<body>.*?)`", source, re.DOTALL)
            self.assertIsNotNone(match, constant)
            digest = hashlib.sha256(match.group("body").encode("utf-8")).hexdigest()
            self.assertRegex(
                helper,
                rf"{re.escape(path)}\s+\\\s+{digest}\s+{mode}\s+\|\| return 1",
                constant,
            )

    def test_every_package_workflow_run_command_fits_github_limit(self) -> None:
        commands = workflow_run_commands(self.workflow)
        self.assertGreater(len(commands), 0)
        for step_name, script in commands:
            with self.subTest(step=step_name):
                encoded_size = len(json.dumps(script, ensure_ascii=False))
                self.assertLessEqual(
                    encoded_size,
                    21_000,
                    f"GitHub rejects {step_name!r} above 21,000 encoded characters",
                )

    def local_build_script(self, name: str) -> str:
        source = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        opener = re.compile(
            rf"^\s*cat\s+<<\s*'(?P<delimiter>[A-Z][A-Z0-9_]*)'\s+>>?\s+"
            rf"{re.escape(name)}\s*$"
        )
        lines = source.splitlines()
        bodies: list[str] = []
        for index, line in enumerate(lines):
            match = opener.match(line)
            if match is None:
                continue
            delimiter = match.group("delimiter")
            body: list[str] = []
            for candidate in lines[index + 1 :]:
                if candidate.strip() == delimiter:
                    bodies.append(textwrap.dedent("\n".join(body)))
                    break
                body.append(candidate)
            else:
                self.fail(f"local package script {name} has no heredoc terminator")
        self.assertEqual(
            len(bodies),
            1,
            f"local package script {name} must have exactly one isolated heredoc",
        )
        body = bodies[0]
        if name in {"preinst.sh", "postinst.sh", "prerm.sh", "postrm.sh"}:
            prefix = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8")
            if name in {"preinst.sh", "postinst.sh"}:
                prefix += DEFERRED_PURGE_POSTINSTALL_HELPER.read_text(encoding="utf-8")
            if name == "postrm.sh":
                prefix += REMOVAL_STATE_HELPER.read_text(encoding="utf-8")
            body = prefix + body
        return body

    def seed_systemd_runtime(self, root: Path) -> None:
        (root / "run/systemd/system").mkdir(parents=True, exist_ok=True)
        comm = root / "proc/1/comm"
        comm.parent.mkdir(parents=True, exist_ok=True)
        comm.write_text("systemd\n", encoding="ascii")
        executable = root / "proc/1/exe"
        if executable.exists() or executable.is_symlink():
            executable.unlink()
        executable.symlink_to("/usr/lib/systemd/systemd")

    def migration_state_machine(self, script_name: str) -> str:
        script = self.script(script_name)
        start = script.index("modular_config_complete() {")
        invocation = "\nmigrate_legacy_configuration\n"
        end = script.index(invocation, start) + len(invocation)
        return script[start:end]

    def secure_directory_function(self, script_name: str) -> str:
        script = self.script(script_name)
        start = script.index("secure_private_directory() {")
        end = script.index("\n}\n", start) + len("\n}\n")
        return script[start:end]

    def test_linux_package_family_and_architecture_matrix(self) -> None:
        required_assets = {
            'syswarden_${VERSION}_amd64.deb',
            "syswarden-${VERSION}-1.x86_64.rpm",
            'syswarden_${VERSION}_x86_64.apk',
        }
        for asset in required_assets:
            with self.subTest(asset=asset):
                self.assertIn(asset, self.workflow)

    def test_packaging_workspace_is_isolated_and_fail_closed(self) -> None:
        self.assertIn(
            'PACKAGE_WORKSPACE="$(mktemp -d '
            '"${RUNNER_TEMP%/}/syswarden-package.XXXXXX")"',
            self.workflow,
        )
        for variable, suffix in (
            ("STAGING_AMD64", "staging-amd64"),
            ("STAGING_APK_AMD64", "staging-apk-amd64"),
            ("PACKAGE_ASSETS", "assets"),
            ("PACKAGE_SCRIPTS", "scripts"),
            ("PACKAGE_RPM_SCRIPTS", "rpm-scripts"),
            ("PACKAGE_CONFIGS", "configs"),
        ):
            with self.subTest(variable=variable):
                self.assertIn(
                    f'{variable}="${{PACKAGE_WORKSPACE}}/{suffix}"',
                    self.workflow,
                )

        self.assertEqual(
            self.workflow.count("scripts/ci/package_stage_gate.py"),
            2,
        )
        for platform, root in (
            ("linux", "STAGING_AMD64"),
            ("linux", "STAGING_APK_AMD64"),
        ):
            with self.subTest(platform=platform, root=root):
                self.assertIn(
                    f'{platform} --root "${{{root}}}"',
                    self.workflow,
                )

        self.assertEqual(
            self.workflow.count("scripts/ci/repository_state.py"),
            2,
        )
        self.assertIn("capture \\\n            --output", self.workflow)
        self.assertIn("verify \\\n            --snapshot", self.workflow)
        capture = self.workflow.index("Capture Candidate Repository State")
        compile_step = self.workflow.index("Compile AMD64 Release Binaries")
        workspace = self.workflow.index("Create Isolated Packaging Workspace")
        first_stage = self.workflow.index("Prepare Staging Environment (AMD64)")
        verify = self.workflow.index("Prove Packaging Did Not Mutate Source")
        upload = self.workflow.index("Upload Package Artifacts")
        self.assertLess(capture, compile_step)
        self.assertLess(compile_step, workspace)
        self.assertLess(workspace, first_stage)
        self.assertLess(first_stage, verify)
        self.assertLess(verify, upload)
        self.assertIn("if: always()", self.workflow[verify:upload])
        self.assertNotIn("package_assets", self.workflow)

    def test_local_builder_is_pinned_readonly_and_source_immutable(self) -> None:
        source = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", source)
        self.assertIn("GOTOOLCHAIN=go1.26.6 GOPROXY=off go env GOROOT", source)
        self.assertIn("go version go1.26.6 linux/amd64", source)
        self.assertIn(
            'SOURCE_TAG="$(PATH="${GO_TOOLCHAIN_ROOT}/bin:${PATH}" \\\n'
            '    "${REPOSITORY_ROOT}/scripts/versioning.sh" inspect '
            '--repo "${REPOSITORY_ROOT}")"',
            source,
        )
        self.assertIn('"$(fpm --version)" = "1.17.0"', source)
        self.assertIn('github.com/goreleaser/nfpm/v2" && $3 == "v2.47.0"', source)
        self.assertNotIn("go mod tidy", source)
        self.assertNotIn("go install", source)
        self.assertNotIn("go1.26.4", source)
        self.assertNotIn("v2.43.0", source)
        self.assertNotIn("sudo ", source)
        self.assertNotIn("https://go.dev/dl/", source)
        self.assertEqual(source.count('"${GO_BIN}" -C'), 3)
        self.assertIn("export GOWORK=off", source)
        self.assertIn("mod download", source)
        self.assertIn("-mod=readonly -buildmode=pie", source)
        self.assertIn("staging/usr/local/bin", source)
        self.assertIn("install -d -m 0755", source)
        self.assertIn(
            "ln -s /opt/syswarden/bin/syswarden-cli "
            "staging/usr/local/bin/syswarden",
            source,
        )
        self.assertIn("scripts/ci/package_stage_gate.py", source)
        self.assertIn(
            'find "${module_cache}" -type d -exec chmod u+w -- {} +',
            source,
        )
        self.assertIn("publish_local_package()", source)
        self.assertIn('temporary="$(mktemp "${LOCAL_PACKAGE_OUTPUT}/', source)
        self.assertIn('sync -f "${LOCAL_PACKAGE_OUTPUT}"', source)
        self.assertIn('! cmp -s -- "${source_path}" "${destination}"', source)
        for variable in ("GOCACHE", "GOTMPDIR", "GOMODCACHE"):
            with self.subTest(variable=variable):
                self.assertIn(f'export {variable}="${{PACKAGE_WORKSPACE}}/', source)
        self.assertIn("/tmp/syswarden-local-package.XXXXXX", source)
        self.assertIn("scripts/ci/repository_state.py", source)
        capture = source.index(" capture \\\n")
        compile_loop = source.index("for module in syswarden-cli")
        verify = source.rindex(" verify \\\n")
        publication = source.index("for artifact in \\\n")
        self.assertLess(capture, compile_loop)
        self.assertLess(publication, verify)
        self.assertIn("trap cleanup_package_workspace EXIT", source)
        self.assertIn("PACKAGE_STATE_VERIFIED=1", source)

    def test_workflow_and_local_packages_have_exact_reproducibility_contract(self) -> None:
        local = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        version_step = workflow_step_script(
            self.workflow, "Validate and Export Version Contract"
        )
        normalization_step = workflow_step_script(
            self.workflow, "Normalize Package Input Timestamps"
        )
        workflow_deb = workflow_step_script(
            self.workflow, "Build Debian Package (.deb)"
        )
        workflow_rpm = workflow_step_script(
            self.workflow, "Build RHEL Family Package (.rpm)"
        )
        workflow_apk = workflow_step_script(
            self.workflow, "Build Alpine Package (.apk)"
        )
        workflow_validation = workflow_step_script(
            self.workflow, "Validate Package Metadata"
        )
        workflow_script_preparation = workflow_step_script(
            self.workflow, "Prepare Linux Maintainer Scripts"
        )
        local_deb = local.split("# Generate DEB", 1)[1].split(
            "# Generate RPM", 1
        )[0]
        local_rpm = local.split("# Generate RPM", 1)[1].split(
            "# Generate Alpine APK", 1
        )[0]
        local_apk = local.split("# Generate Alpine APK", 1)[1]

        self.assertIn(
            'SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"', version_step
        )
        self.assertIn(
            'SOURCE_DATE_EPOCH="$(git -C "${REPOSITORY_ROOT}" log -1 '
            '--format=%ct HEAD)"',
            local,
        )
        self.assertIn(
            'if [[ ! "${SOURCE_DATE_EPOCH}" =~ ^[1-9][0-9]*$ ]]; then',
            version_step,
        )
        self.assertIn('echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"', version_step)
        for assignment in ("LC_ALL=C", "LANG=C", "TZ=UTC"):
            with self.subTest(environment=assignment):
                self.assertIn(f'echo "{assignment}" >> "${{GITHUB_ENV}}"', version_step)
                self.assertIn(f"export {assignment}", local)

        workflow_changelog_start = normalization_step.index(
            "prepare_rpm_changelog() {"
        )
        workflow_changelog_end = normalization_step.index(
            "\n}\n", workflow_changelog_start
        ) + len("\n}\n")
        workflow_changelog = normalization_step[
            workflow_changelog_start:workflow_changelog_end
        ]
        local_changelog_start = local.index("prepare_rpm_changelog() {")
        local_changelog_end = local.index("\n}\n", local_changelog_start) + len(
            "\n}\n"
        )
        local_changelog = local[local_changelog_start:local_changelog_end]
        for changelog in (workflow_changelog, local_changelog):
            self.assertIn('date --utc --date="@${SOURCE_DATE_EPOCH}"', changelog)
            self.assertIn('date --utc --date="${changelog_day} 12:00:00"', changelog)
            self.assertIn("SysWarden Engineering - %s-1", changelog)
            self.assertIn('chmod 0600 "${destination}"', changelog)

        workflow_normalizer_start = normalization_step.index(
            "normalize_package_mtimes() {"
        )
        workflow_normalizer_end = normalization_step.index(
            "\n}\n", workflow_normalizer_start
        ) + len("\n}\n")
        workflow_normalizer = normalization_step[
            workflow_normalizer_start:workflow_normalizer_end
        ]
        local_normalizer_start = local.index("normalize_package_mtimes() {")
        local_normalizer_end = local.index("\n}\n", local_normalizer_start) + len(
            "\n}\n"
        )
        local_normalizer = local[local_normalizer_start:local_normalizer_end]
        for normalizer in (workflow_normalizer, local_normalizer):
            self.assertIn('find "${target}" -depth -exec', normalizer)
            self.assertIn(
                'touch -h --date="@${SOURCE_DATE_EPOCH}" -- {} +', normalizer
            )
            self.assertIn('[ ! -e "${target}" ] && [ ! -L "${target}" ]', normalizer)

        for target in (
            "STAGING_AMD64",
            "STAGING_APK_AMD64",
            "PACKAGE_SCRIPTS",
            "PACKAGE_RPM_SCRIPTS",
        ):
            self.assertEqual(normalization_step.count(f'"${{{target}}}"'), 1, target)
        self.assertIn('prepare_rpm_changelog "${RPM_CHANGELOG}"', normalization_step)
        self.assertIn('"${RPM_CHANGELOG}"\n', normalization_step)
        self.assertIn('echo "RPM_CHANGELOG=${RPM_CHANGELOG}"', normalization_step)
        self.assertIn(
            'echo "RPM_CHANGELOG_EPOCH=${RPM_CHANGELOG_EPOCH}"',
            normalization_step,
        )
        local_targets = (
            "staging",
            "staging-rpm",
            "staging-apk",
            "preinst.sh",
            "postinst.sh",
            "prerm.sh",
            "postrm.sh",
            '"${RPM_SCRIPTS}"',
            '"${RPM_CHANGELOG}"',
        )
        local_normalization_call = local[
            local_normalizer_end : local.index("# 4. Generate Packages")
        ]
        for index, target in enumerate(local_targets):
            suffix = " \\" if index < len(local_targets) - 1 else ""
            self.assertIn(f"    {target}{suffix}\n", local_normalization_call)
        self.assertLess(
            self.workflow.index("Normalize Package Input Timestamps"),
            self.workflow.index("Build Debian Package (.deb)"),
        )
        self.assertLess(local_normalizer_end, local.index("# Generate DEB"))

        for block, count in (
            (workflow_deb, 1),
            (workflow_rpm, 1),
            (local_deb, 1),
            (local_rpm, 1),
        ):
            self.assertEqual(
                block.count('--source-date-epoch-default "${SOURCE_DATE_EPOCH}"'),
                count,
            )
        rpm_defines = (
            "use_source_date_epoch_as_buildtime 1",
            "clamp_mtime_to_source_date_epoch 1",
            "_buildhost syswarden-build.invalid",
        )
        for definition in rpm_defines:
            with self.subTest(rpm_definition=definition):
                flag = f'--rpm-rpmbuild-define "{definition}"'
                self.assertEqual(workflow_rpm.count(flag), 1)
                self.assertEqual(local_rpm.count(flag), 1)
        self.assertEqual(workflow_rpm.count('--rpm-changelog "${RPM_CHANGELOG}"'), 1)
        self.assertEqual(local_rpm.count('--rpm-changelog "${RPM_CHANGELOG}"'), 1)
        self.assertIn("prepare_rpm_scriptlet() {", workflow_script_preparation)
        self.assertIn("prepare_rpm_scriptlet() {", local)
        for source in (workflow_script_preparation, local):
            self.assertIn("sed 's/%/%%/g'", source)
        for script_name in ("preinst.sh", "postinst.sh", "prerm.sh", "postrm.sh"):
            with self.subTest(rpm_scriptlet=script_name):
                self.assertIn(
                    f'"${{PACKAGE_RPM_SCRIPTS}}/{script_name}"', workflow_rpm
                )
                self.assertNotIn(
                    f'"${{PACKAGE_RPM_SCRIPTS}}/{script_name}"', workflow_deb
                )
                self.assertNotIn(
                    f'"${{PACKAGE_RPM_SCRIPTS}}/{script_name}"', workflow_apk
                )
                self.assertIn(
                    f'"${{PACKAGE_SCRIPTS}}/{script_name}"', workflow_deb
                )
                self.assertIn(
                    f'"${{PACKAGE_SCRIPTS}}/{script_name}"', workflow_apk
                )
                self.assertIn(f'"${{RPM_SCRIPTS}}/{script_name}"', local_rpm)
                self.assertNotIn(f'"${{RPM_SCRIPTS}}/{script_name}"', local_deb)
                self.assertNotIn(f'"${{RPM_SCRIPTS}}/{script_name}"', local_apk)
                self.assertIn(
                    f'"${{PACKAGE_SCRIPTS}}/{script_name}"', workflow_validation
                )
                self.assertIn(
                    f"validate_local_rpm_scriptlet \"${{rpm_path}}\" ", local
                )
        for query, expected in (
            ("%{BUILDTIME}", "${SOURCE_DATE_EPOCH}"),
            ("%{BUILDHOST}", "syswarden-build.invalid"),
            ("%{CHANGELOGTIME}", "${RPM_CHANGELOG_EPOCH}"),
        ):
            self.assertIn(query, workflow_validation)
            self.assertIn(expected, workflow_validation)
            self.assertIn(query, local)
            self.assertIn(expected, local)

        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            changelog_epochs: list[int] = []
            for index, (epoch, expected_date) in enumerate(
                (
                    (946684800, "Sat Jan  1 2000"),
                    (946771200, "Sun Jan  2 2000"),
                )
            ):
                destination = root_path / f"rpm-changelog-{index}"
                generated = subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        local_changelog
                        + '\nprepare_rpm_changelog "$1"\n'
                        + 'printf "%s" "${RPM_CHANGELOG_EPOCH}"',
                        "rpm-changelog-cross-day-contract",
                        str(destination),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "LC_ALL": "C",
                        "SOURCE_DATE_EPOCH": str(epoch),
                        "TZ": "UTC",
                        "VERSION": "4.03.2",
                    },
                )
                self.assertEqual(generated.returncode, 0, generated)
                changelog_epochs.append(int(generated.stdout))
                self.assertEqual(
                    destination.read_text(encoding="utf-8"),
                    f"* {expected_date} SysWarden Engineering - 4.03.2-1\n"
                    "- Package created with FPM\n",
                )
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(changelog_epochs[1] - changelog_epochs[0], 86400)

            epoch = 946684800
            root = Path(temporary) / "random workspace\nwith spaces"
            nested = root / "nested"
            nested.mkdir(parents=True)
            payload = nested / "payload\nname"
            payload.write_bytes(b"deterministic")
            dangling = root / "dangling link"
            dangling.symlink_to("missing-target")
            result = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    local_normalizer + '\nnormalize_package_mtimes "$1"',
                    "package-mtime-contract",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch)},
            )
            self.assertEqual(result.returncode, 0, result)
            for path in (root, nested, payload, dangling):
                with self.subTest(normalized_path=path):
                    self.assertEqual(path.lstat().st_mtime_ns, epoch * 1_000_000_000)

            missing = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    local_normalizer + '\nnormalize_package_mtimes "$1"',
                    "package-mtime-missing-contract",
                    str(root / "missing"),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "SOURCE_DATE_EPOCH": str(epoch)},
            )
            self.assertNotEqual(missing.returncode, 0, missing)
            self.assertIn("package timestamp target is missing", missing.stderr)

    def test_local_builder_closes_deb_mode_and_rpm_build_id_parity(self) -> None:
        source = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        deb_block = source.split("# Generate DEB", 1)[1].split(
            "# Generate RPM", 1
        )[0]
        rpm_block = source.split("# Generate RPM", 1)[1].split(
            "# Generate Alpine APK", 1
        )[0]

        self.assertEqual(deb_block.count("umask 022"), 1)
        self.assertIn("(\n", deb_block)
        self.assertIn("\n    umask 022\n", deb_block)
        self.assertIn("\n    fpm -f -s dir -t deb", deb_block)
        self.assertTrue(deb_block.rstrip().endswith(")"))
        self.assertIn("validate_local_deb_changelog()", source)
        self.assertIn(
            '$1 == "-rw-r--r--" && $2 == "0/0"', source
        )
        self.assertIn(
            '$6 == "./usr/share/doc/syswarden/changelog.gz"', source
        )

        self.assertIn("prepare_rpm_build_id_links()", source)
        self.assertIn("LC_ALL=C readelf --notes", source)
        self.assertIn("^[0-9a-f]{40}$", source)
        self.assertIn(
            '"../../../../opt/syswarden/bin/$(basename -- "${rpm_binary}")"',
            source,
        )
        self.assertIn(
            '--rpm-rpmbuild-define "_build_id_links none"', rpm_block
        )
        self.assertEqual(rpm_block.count("umask 022"), 1)
        self.assertIn("\n    fpm -f -s dir -t rpm", rpm_block)
        self.assertTrue(rpm_block.rstrip().endswith(")"))
        self.assertIn("--directories /usr/lib/.build-id", rpm_block)
        self.assertIn("-C staging-rpm .", rpm_block)
        self.assertNotIn("-C staging .", rpm_block)
        self.assertIn("validate_local_rpm_build_ids()", source)
        for target in (
            "../../../../opt/syswarden/bin/syswarden-cli",
            "../../../../opt/syswarden/bin/syswarden-core",
            "../../../../opt/syswarden/bin/syswarden-tui",
        ):
            self.assertEqual(source.count(target), 1, target)

    def test_local_builder_rpm_build_id_preparation_is_exact_and_fail_closed(
        self,
    ) -> None:
        source = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        start = source.index("prepare_rpm_build_id_links() {")
        end = source.index("\ninstall -d -m 0755 staging-rpm", start)
        function = source[start:end]
        build_ids = {
            "syswarden-cli": "11" + "1" * 38,
            "syswarden-core": "22" + "2" * 38,
            "syswarden-tui": "33" + "3" * 38,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            readelf = fake_bin / "readelf"
            readelf.write_text(
                "#!/bin/sh\n"
                "name=${2##*/}\n"
                "if [ \"${COLLIDE:-0}\" = 1 ]; then\n"
                f"  id={'4' * 40}\n"
                "else\n"
                "  case \"${name}\" in\n"
                + "".join(
                    f"    {name}) id={build_id} ;;\n"
                    for name, build_id in build_ids.items()
                )
                + "    *) exit 1 ;;\n"
                "  esac\n"
                "fi\n"
                "printf '  Build ID: %s\\n' \"${id}\"\n",
                encoding="utf-8",
            )
            readelf.chmod(0o700)
            artifacts = []
            for name in build_ids:
                artifact = root / name
                artifact.write_bytes(b"fixture")
                artifacts.append(artifact)
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}:/usr/bin:/bin",
            }

            staging = root / "staging"
            result = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    function
                    + '\nprepare_rpm_build_id_links "$1" "$2" "$3" "$4"',
                    "rpm-build-id-contract",
                    str(staging),
                    *(str(path) for path in artifacts),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result)
            build_id_root = staging / "usr/lib/.build-id"
            self.assertEqual(build_id_root.stat().st_mode & 0o777, 0o755)
            for name, build_id in build_ids.items():
                link = build_id_root / build_id[:2] / build_id[2:]
                self.assertTrue(link.is_symlink(), link)
                self.assertEqual(
                    os.readlink(link),
                    f"../../../../opt/syswarden/bin/{name}",
                )
                self.assertEqual(link.parent.stat().st_mode & 0o777, 0o755)

            collision = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    function
                    + '\nprepare_rpm_build_id_links "$1" "$2" "$3" "$4"',
                    "rpm-build-id-collision",
                    str(root / "collision"),
                    *(str(path) for path in artifacts),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**environment, "COLLIDE": "1"},
            )
            self.assertNotEqual(collision.returncode, 0, collision)
            self.assertIn("share a GNU build-id", collision.stderr)

    def test_local_builder_exit_guard_detects_repository_mutation(self) -> None:
        source = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        marker = "PACKAGE_STATE_CAPTURED=1\n"
        self.assertEqual(source.count(marker), 1)
        prelude = source.split(marker, 1)[0] + marker
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            (repository / "scripts/ci").mkdir(parents=True)
            shutil.copy2(
                REPOSITORY / "scripts/ci/repository_state.py",
                repository / "scripts/ci/repository_state.py",
            )
            probe = repository / "probe-builder.sh"
            probe.write_text(
                prelude
                + 'printf "%s\\n" "mutated" >> "${REPOSITORY_ROOT}/tracked.txt"\n'
                + "exit 0\n",
                encoding="utf-8",
            )
            probe.chmod(0o700)
            (repository / "tracked.txt").write_text("baseline\n", encoding="utf-8")
            git_environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "SysWarden Test",
                "GIT_AUTHOR_EMAIL": "test@syswarden.invalid",
                "GIT_COMMITTER_NAME": "SysWarden Test",
                "GIT_COMMITTER_EMAIL": "test@syswarden.invalid",
            }
            subprocess.run(["git", "init", "-q", str(repository)], check=True, env=git_environment)
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True, env=git_environment)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
                check=True,
                env=git_environment,
            )
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            for name in ("go", "fpm", "nfpm"):
                command = mock_bin / name
                command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                command.chmod(0o700)
            result = subprocess.run(
                [str(probe)],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
                env={**git_environment, "PATH": f"{mock_bin}:{os.environ['PATH']}"},
            )
            self.assertNotEqual(result.returncode, 0, result)
            self.assertIn("repository state changed during validation", result.stderr)
            self.assertEqual(
                (repository / "tracked.txt").read_text(encoding="utf-8"),
                "baseline\nmutated\n",
            )

    def test_all_package_outputs_use_the_isolated_asset_directory(self) -> None:
        assets = (
            'syswarden_${VERSION}_amd64.deb',
            "syswarden-${VERSION}-1.x86_64.rpm",
            'syswarden_${VERSION}_x86_64.apk',
        )
        for asset in assets:
            with self.subTest(asset=asset):
                self.assertIn(f'"${{PACKAGE_ASSETS}}/{asset}"', self.workflow)
        self.assertIn('cd "${PACKAGE_ASSETS}"', self.workflow)
        self.assertIn('--packages "${PACKAGE_ASSETS}"', self.workflow)
        self.assertIn(
            "name: syswarden-packages-${{ env.VERSION }}",
            self.workflow,
        )
        self.assertIn(
            "path: ${{ steps.package_workspace.outputs.assets }}",
            self.workflow,
        )

    def test_linux_install_and_upgrade_preservation_contract(self) -> None:
        preinstall = self.script("preinst.sh")
        postinstall = self.script("postinst.sh")
        self.assertIn(
            "mv /opt/syswarden/syswarden-auto.conf "
            "/opt/syswarden/syswarden-auto.conf.migration_backup",
            preinstall,
        )
        self.assertIn(
            "[ ! -e /opt/syswarden/syswarden-auto.conf.migration_backup ]",
            preinstall,
        )
        self.assertIn("set -e", preinstall)
        self.assertIn('export SYSWARDEN_PKG_INSTALL=1', preinstall)
        self.assertLess(
            preinstall.index('export SYSWARDEN_PKG_INSTALL=1'),
            preinstall.index("syswarden_retire_legacy_webtui / || exit 1"),
        )
        self.assertIn('export SYSWARDEN_PKG_INSTALL=1', postinstall)
        self.assertIn("set -e", postinstall)
        self.assertIn('[ "$1" = "2" ]', postinstall)
        self.assertIn('[ "$1" = "configure" ]', postinstall)
        self.assertIn("syswarden_classify_service_manager", postinstall)
        self.assertNotIn("/opt/syswarden/bin/syswarden-cli reload", postinstall)
        self.assertIn(
            "Service-manager runtime is offline; host configuration is deferred until an explicit online install.",
            postinstall,
        )
        self.assertIn('! modular_config_complete', postinstall)
        self.assertIn('marker=/etc/syswarden/config/.migration-in-progress', postinstall)
        self.assertIn('archive=/opt/syswarden/syswarden-auto.conf.bak', postinstall)
        self.assertIn('[ ! -e "${archive}" ] && [ ! -L "${archive}" ]', postinstall)
        self.assertIn('mv "${source}.migrated" "${archive}"', postinstall)
        self.assertIn("Refusing a symlinked legacy configuration path", preinstall)
        self.assertLess(
            postinstall.index("migrate_legacy_configuration\n"),
            postinstall.index('if [ "$1" = "2" ]'),
        )
        self.assertNotRegex(postinstall, r"migrate-config[^\n]*\|\|\s*true")
        self.assertIn('/opt/syswarden/bin/syswarden-cli install', postinstall)
        self.assertIn('[ -f /etc/alpine-release ]', postinstall)

    def test_package_preinstall_tightens_directories_and_rejects_links(self) -> None:
        for script_name in ("preinst.sh",):
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                private = root / "private"
                private.mkdir(mode=0o755)
                private.chmod(0o755)
                function = self.secure_directory_function(script_name)
                self.assertIn("find", function)
                self.assertIn("-user", function)
                self.assertIn("-group", function)
                self.assertIn("identity changed while securing", function)

                tightened = subprocess.run(
                    ["/bin/sh", "-c", function + '\nsecure_private_directory "$1"', "probe", str(private)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(tightened.returncode, 0, tightened)
                self.assertEqual(private.stat().st_mode & 0o777, 0o750)

                target = root / "target"
                target.mkdir(mode=0o700)
                link = root / "link"
                link.symlink_to(target, target_is_directory=True)
                rejected = subprocess.run(
                    ["/bin/sh", "-c", function + '\nsecure_private_directory "$1"', "probe", str(link)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(rejected.returncode, 0, rejected)
                self.assertIn("Refusing unsafe SysWarden directory", rejected.stderr)
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_install_barrier_preflight_precedes_mutation_and_is_read_only(self) -> None:
        owner = f"{os.getuid()}:{os.getgid()}"
        scripts = {
            "preinst": self.script("preinst.sh"),
            "postinst": self.script("postinst.sh"),
        }
        invocation = "\nsyswarden_preflight_install_barriers\n"
        prefixes: dict[str, str] = {}
        for name, script in scripts.items():
            start = script.index("syswarden_install_path_absent() {")
            end = script.index(invocation, start) + len(invocation)
            prefixes[name] = script[start:end]
        self.assertLess(
            scripts["preinst"].index(invocation),
            scripts["preinst"].index("secure_private_directory() {"),
        )
        self.assertLess(
            scripts["postinst"].index(invocation),
            scripts["postinst"].index(
                "ln -sf /opt/syswarden/bin/syswarden-cli /usr/local/bin/syswarden"
            ),
        )

        with tempfile.TemporaryDirectory(prefix="sw-install-barrier-", dir="/tmp") as temporary:
            root = Path(temporary)
            state_root = root / "var/lib/syswarden"
            state_root.mkdir(parents=True, mode=0o750)
            state_root.chmod(0o750)
            parent = root / "var/lib"
            parent.chmod(0o755)
            active = state_root / "removal-in-progress-v1"
            deferred = state_root / "removed-awaiting-purge-v1"
            finalizing = parent / ".syswarden-removal-finalizing-v1"
            payload = b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"
            operator = state_root / "operator.json"
            operator.write_bytes(b"operator\n")
            operator.chmod(0o600)

            def prepare(script: str) -> str:
                executable = script.replace(
                    "/var/lib/.syswarden-removal-finalizing-v1", str(finalizing)
                ).replace("/var/lib/syswarden", str(state_root))
                executable = executable.replace(
                    "[ ! -L /var/lib ] && [ -d /var/lib ]",
                    f"[ ! -L {parent} ] && [ -d {parent} ]",
                ).replace(
                    '"$(stat -c \'%u:%g:%a\' /var/lib)"',
                    f'"$(stat -c \'%u:%g:%a\' {parent})"',
                )
                return executable.replace(
                    "0:0:700|0:0:710|0:0:711|0:0:750|0:0:751|0:0:755",
                    f"{owner}:700|{owner}:710|{owner}:711|{owner}:750|{owner}:751|{owner}:755",
                ).replace(
                    "0:0:700|0:0:750|0:0:755",
                    f"{owner}:700|{owner}:750|{owner}:755",
                ).replace("'0:0:600:1'", f"'{owner}:600:1'")

            executables = {name: prepare(script) for name, script in prefixes.items()}

            def snapshot() -> tuple[tuple[str, int, bytes | None], ...]:
                observed = []
                for path in sorted(root.rglob("*")):
                    metadata = path.lstat()
                    observed.append(
                        (
                            str(path.relative_to(root)),
                            stat.S_IMODE(metadata.st_mode),
                            path.read_bytes() if path.is_file() else None,
                        )
                    )
                return tuple(observed)

            def run(name: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ("/bin/sh", "-c", executables[name], f"{name}-barrier"),
                    check=False,
                    capture_output=True,
                    text=True,
                )

            active.write_bytes(payload)
            active.chmod(0o600)
            active_snapshot = snapshot()
            for name in executables:
                with self.subTest(script=name, barrier="active"):
                    refused = run(name)
                    self.assertNotEqual(refused.returncode, 0, refused)
                    self.assertIn("active package-removal barrier", refused.stderr)
                    self.assertEqual(snapshot(), active_snapshot)

            active.unlink()
            deferred.write_bytes(payload)
            deferred.chmod(0o600)
            deferred_snapshot = snapshot()
            for name in executables:
                with self.subTest(script=name, barrier="deferred"):
                    accepted = run(name)
                    self.assertEqual(accepted.returncode, 0, accepted)
                    self.assertEqual(snapshot(), deferred_snapshot)

            deferred.unlink()
            finalizing.write_bytes(payload)
            finalizing.chmod(0o600)
            finalizing_snapshot = snapshot()
            for name in executables:
                with self.subTest(script=name, barrier="finalizing"):
                    accepted = run(name)
                    self.assertEqual(accepted.returncode, 0, accepted)
                    self.assertEqual(snapshot(), finalizing_snapshot)

    def test_product_service_enablement_cleanup_accepts_only_exact_release_targets(self) -> None:
        allowed_targets = (
            "../syswarden-core.service",
            "/etc/systemd/system/syswarden-core.service",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, target in enumerate((*allowed_targets, "../operator.service")):
                link = root / f"syswarden-core-{index}.service"
                link.symlink_to(target)
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; shift; syswarden_remove_exact_service_enablement "$@"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(link),
                        *allowed_targets,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if target in allowed_targets:
                    self.assertEqual(result.returncode, 0, result)
                    self.assertFalse(link.exists() or link.is_symlink())
                else:
                    self.assertNotEqual(result.returncode, 0, result)
                    self.assertTrue(link.is_symlink())
                    self.assertEqual(os.readlink(link), target)

    def test_legacy_webtui_package_retirement_is_exact_and_fail_closed(self) -> None:
        helper = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8")
        self.assertNotIn("pkill", helper)
        self.assertNotIn("killall", helper)
        self.assertNotIn("62027", helper)
        self.assertNotIn('${syswarden_retire_process%%:*}', helper)
        self.assertIn('kill -0 "${syswarden_retire_pid}"', helper)
        self.assertIn(
            "LC_ALL=C awk -F ':' 'NR == 1 { print $1; exit }'", helper
        )
        self.assertIn(
            ')" || return 1\n        syswarden_retire_starttime=', helper
        )
        self.assertIn("Description=SYSWARDEN Web-TUI (WebTTY)", helper)
        self.assertIn("ExecStart=/opt/syswarden/bin/syswarden-cli web-tui", helper)
        self.assertIn('command_args="web-tui"', helper)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            unit = root / "etc/systemd/system/syswarden-webtui.service"
            wants = root / "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
            pid = root / "run/syswarden-webtui.pid"
            module = root / "etc/syswarden/config/modules/99-user.toml"
            manager = root / "run/systemd/system"
            for directory in (unit.parent, wants.parent, pid.parent, module.parent, manager):
                directory.mkdir(parents=True, exist_ok=True)
            self.seed_systemd_runtime(root)
            unit.write_text(
                "[Unit]\n"
                "Description=SYSWARDEN Web-TUI (WebTTY)\n"
                "After=network-online.target\n"
                "Wants=network-online.target\n\n"
                "[Service]\n"
                "Type=simple\n"
                "User=root\n"
                "ExecStart=/opt/syswarden/bin/syswarden-cli web-tui\n"
                "Restart=on-failure\n"
                "RestartSec=5s\n\n"
                "# Security Hardening\n"
                "ProtectSystem=full\n"
                "ProtectHome=yes\n"
                "NoNewPrivileges=true\n"
                "PrivateTmp=true\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n",
                encoding="utf-8",
            )
            unit.chmod(0o600)
            wants.symlink_to("../syswarden-webtui.service")
            pid.write_text("4194303\n", encoding="ascii")
            module.write_text(
                "# preserve operator bytes\n[user]\n"
                'webtui_password = "retire-without-reporting"\n'
                'profile_name = "operator"\n',
                encoding="utf-8",
            )
            module.chmod(0o640)
            unrelated = root / "operator-owned-62027"
            unrelated.write_text("preserve-exactly\n", encoding="utf-8")

            commands = Path(temporary) / "commands"
            state = Path(temporary) / "state"
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            state.write_text("active\n", encoding="ascii")
            systemctl = mock_bin / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                'if [ "$1" != show ]; then printf "%s\\n" "$*" >> "$TEST_COMMANDS"; fi\n'
                'case "$1" in\n'
                '  show)\n'
                '    case "$3" in\n'
                '      --property=LoadState) [ -f "$TEST_ROOT/etc/systemd/system/syswarden-webtui.service" ] && printf "loaded\\n" || printf "not-found\\n" ;;\n'
                '      --property=ActiveState) cat "$TEST_STATE" ;;\n'
                '      --property=FragmentPath) printf "%s\\n" "$TEST_ROOT/etc/systemd/system/syswarden-webtui.service" ;;\n'
                '      --property=DropInPaths) printf "\\n" ;;\n'
                '      --property=ExecStart) printf "%s\\n" "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }" ;;\n'
                '      *) exit 9 ;;\n'
                '    esac ;;\n'
                '  is-active) [ "$(cat "$TEST_STATE")" = active ] && exit 0; exit 3 ;;\n'
                '  stop) printf "%s\\n" inactive > "$TEST_STATE" ;;\n'
                '  disable) rm -f "$TEST_ROOT/etc/systemd/system/multi-user.target.wants/syswarden-webtui.service" ;;\n'
                '  daemon-reload) : ;;\n'
                '  *) exit 9 ;;\n'
                "esac\n",
                encoding="utf-8",
            )
            systemctl.chmod(0o700)
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "TEST_COMMANDS": str(commands),
                    "TEST_STATE": str(state),
                    "TEST_ROOT": str(root),
                },
            )
            self.assertEqual(result.returncode, 0, result)
            retry = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "TEST_COMMANDS": str(commands),
                    "TEST_STATE": str(state),
                    "TEST_ROOT": str(root),
                },
            )
            self.assertEqual(retry.returncode, 0, retry)
            for retired in (unit, wants, pid):
                self.assertFalse(retired.exists() or retired.is_symlink(), retired)
            self.assertEqual(
                module.read_text(encoding="utf-8"),
                '# preserve operator bytes\n[user]\nprofile_name = "operator"\n',
            )
            self.assertEqual(module.stat().st_mode & 0o777, 0o640)
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve-exactly\n")
            self.assertEqual(
                commands.read_text(encoding="utf-8").splitlines(),
                [
                    "is-active --quiet syswarden-webtui.service",
                    "stop syswarden-webtui.service",
                    "is-active --quiet syswarden-webtui.service",
                    "disable syswarden-webtui.service",
                    "daemon-reload",
                ],
            )

    def test_service_manager_classifier_requires_package_marker_for_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            (root / "run").mkdir(parents=True)

            def classify(marker: str | None) -> str:
                environment = dict(os.environ)
                if marker is None:
                    environment.pop("SYSWARDEN_PKG_INSTALL", None)
                else:
                    environment["SYSWARDEN_PKG_INSTALL"] = marker
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_classify_service_manager "$2" systemd',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(result.returncode, 0, result)
                return result.stdout.strip()

            self.assertEqual(classify(None), "AMBIGUOUS")
            self.assertEqual(classify("true"), "AMBIGUOUS")
            self.assertEqual(classify("1"), "OFFLINE")
            (root / "run/systemd/system").mkdir(parents=True)
            self.assertEqual(classify("1"), "AMBIGUOUS")
            self.seed_systemd_runtime(root)
            self.assertEqual(classify(None), "ACTIVE")

            shutil.rmtree(root / "run/systemd")
            openrc = root / "run/openrc"
            openrc.mkdir()
            self.assertEqual(classify("1"), "AMBIGUOUS")

            (openrc / "softlevel").write_text("default\n", encoding="ascii")
            comm = root / "proc/1/comm"
            comm.parent.mkdir(parents=True, exist_ok=True)
            comm.write_text("init\n", encoding="ascii")
            openrc_result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_classify_service_manager "$2" openrc',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "SYSWARDEN_PKG_INSTALL": "1"},
            )
            self.assertEqual(openrc_result.returncode, 0, openrc_result)
            self.assertEqual(openrc_result.stdout.strip(), "ACTIVE")

            openrc.chmod(0o775)
            standard_mode_result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_classify_service_manager "$2" openrc',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "SYSWARDEN_PKG_INSTALL": "1"},
            )
            self.assertEqual(standard_mode_result.returncode, 0, standard_mode_result)
            self.assertEqual(standard_mode_result.stdout.strip(), "ACTIVE")

    def test_openrc_softlevel_encoding_and_metadata_are_fail_closed(self) -> None:
        def seed_runtime(root: Path, content: bytes) -> tuple[Path, Path, str]:
            runtime = root / "run/openrc"
            runtime.mkdir(parents=True)
            softlevel = runtime / "softlevel"
            softlevel.write_bytes(content)
            comm = root / "proc/1/comm"
            comm.parent.mkdir(parents=True)
            comm.write_text("openrc-init\n", encoding="ascii")
            owner = f"{root.stat().st_uid}:{root.stat().st_gid}"
            return runtime, softlevel, owner

        def attest(
            root: Path,
            runtime: Path,
            owner: str,
            *,
            environment: dict[str, str] | None = None,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_attest_openrc_runtime "$2" "$3" "$4"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                    str(runtime),
                    owner,
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

        for label, content in (
            ("no-terminal-newline", b"default"),
            ("one-terminal-newline", b"default\n"),
            ("maximum-size-without-newline", b"a" * 64),
            ("maximum-token-with-newline", b"a" * 63 + b"\n"),
        ):
            with self.subTest(accepted=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                runtime, _, owner = seed_runtime(root, content)
                result = attest(root, runtime, owner)
                self.assertEqual(result.returncode, 0, result)

        with self.subTest(
            runtime_mode="openrc-standard-0775"
        ), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            runtime, _, owner = seed_runtime(root, b"default")
            runtime.chmod(0o775)
            result = attest(root, runtime, owner)
            self.assertEqual(result.returncode, 0, result)

        for mode in (0o770, 0o777, 0o1775):
            with self.subTest(
                rejected_runtime_mode=oct(mode)
            ), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                runtime, _, owner = seed_runtime(root, b"default")
                runtime.chmod(mode)
                result = attest(root, runtime, owner)
                self.assertNotEqual(result.returncode, 0, result)

        rejected = (
            ("empty", b""),
            ("newline-only", b"\n"),
            ("carriage-return", b"default\r"),
            ("carriage-return-newline", b"default\r\n"),
            ("embedded-newline", b"de\nfault"),
            ("double-newline", b"default\n\n"),
            ("newline-suffix", b"default\nsuffix"),
            ("nul", b"default\x00"),
            ("nul-only", b"\x00"),
            ("space", b"default "),
            ("oversized", b"a" * 65),
            ("oversized-with-newline", b"a" * 64 + b"\n"),
        )
        for label, content in rejected:
            with self.subTest(rejected=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                runtime, _, owner = seed_runtime(root, content)
                result = attest(root, runtime, owner)
                self.assertNotEqual(result.returncode, 0, result)

        for metadata in ("writable", "symlink", "owner"):
            with self.subTest(metadata=metadata), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                runtime, softlevel, owner = seed_runtime(root, b"default")
                if metadata == "writable":
                    softlevel.chmod(0o666)
                elif metadata == "symlink":
                    target = runtime / "operator-softlevel"
                    target.write_bytes(b"default")
                    softlevel.unlink()
                    softlevel.symlink_to(target)
                else:
                    owner = "4294967294:4294967294"
                result = attest(root, runtime, owner)
                self.assertNotEqual(result.returncode, 0, result)

        with self.subTest(metadata="replacement-race"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            runtime, softlevel, owner = seed_runtime(root, b"default")
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            stat_probe = mock_bin / "stat"
            stat_probe.write_text(
                "#!/bin/sh\n"
                "last=\n"
                "for last do :; done\n"
                "if [ \"${last}\" = \"${TEST_SOFTLEVEL}\" ]; then\n"
                "  count=$(cat \"${TEST_STAT_COUNT}\" 2>/dev/null || printf 0)\n"
                "  count=$((count + 1))\n"
                "  printf '%s\\n' \"${count}\" > \"${TEST_STAT_COUNT}\"\n"
                "  \"${REAL_STAT}\" \"$@\"\n"
                "  status=$?\n"
                "  if [ \"${count}\" -eq 3 ]; then\n"
                "    mv -- \"${TEST_SOFTLEVEL}\" \"${TEST_SOFTLEVEL}.before\" || exit 97\n"
                "    printf '%s' changed > \"${TEST_SOFTLEVEL}\" || exit 97\n"
                "    chmod 0644 \"${TEST_SOFTLEVEL}\" || exit 97\n"
                "  fi\n"
                "  exit \"${status}\"\n"
                "fi\n"
                "exec \"${REAL_STAT}\" \"$@\"\n",
                encoding="ascii",
            )
            stat_probe.chmod(0o700)
            real_stat = shutil.which("stat")
            self.assertIsNotNone(real_stat)
            stat_count = Path(temporary) / "stat-count"
            environment = {
                **os.environ,
                "PATH": f"{mock_bin}:{os.environ['PATH']}",
                "REAL_STAT": str(real_stat),
                "TEST_SOFTLEVEL": str(softlevel),
                "TEST_STAT_COUNT": str(stat_count),
            }
            result = attest(root, runtime, owner, environment=environment)
            self.assertNotEqual(result.returncode, 0, result)
            self.assertTrue(Path(f"{softlevel}.before").is_file())
            self.assertGreaterEqual(
                int(stat_count.read_text(encoding="ascii").strip()), 3
            )

    def test_service_manager_classifier_rejects_dangling_runtime_links(self) -> None:
        for relative in ("run/systemd", "run/systemd/system", "run/openrc"):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                (root / "run").mkdir(parents=True)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(root / "missing", target_is_directory=True)
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_classify_service_manager "$2" systemd',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={**os.environ, "SYSWARDEN_PKG_INSTALL": "1"},
                )
                self.assertEqual(result.returncode, 0, result)
                self.assertEqual(result.stdout.strip(), "AMBIGUOUS")

    def test_legacy_webtui_openrc_offline_retirement_never_calls_manager(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            unit = root / "etc/init.d/syswarden-webtui"
            enablement = root / "etc/runlevels/default/syswarden-webtui"
            pid = root / "run/syswarden-webtui.pid"
            for directory in (unit.parent, enablement.parent, pid.parent):
                directory.mkdir(parents=True, exist_ok=True)
            unit.write_text(
                "#!/sbin/openrc-run\n\n"
                'name="syswarden-webtui"\n'
                'description="SYSWARDEN Web-TUI (WebTTY)"\n'
                'command="/opt/syswarden/bin/syswarden-cli"\n'
                'command_args="web-tui"\n'
                "command_background=true\n"
                'pidfile="/run/syswarden-webtui.pid"\n'
                'retry="TERM/5/KILL/5"\n\n'
                "depend() {\n\tneed net\n}\n",
                encoding="utf-8",
            )
            enablement.symlink_to("/etc/init.d/syswarden-webtui")
            pid.write_text("4194303\n", encoding="ascii")
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            calls = Path(temporary) / "calls"
            for name in ("rc-service", "rc-update"):
                manager = mock_bin / name
                manager.write_text(
                    '#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$TEST_CALLS"\nexit 99\n',
                    encoding="utf-8",
                )
                manager.chmod(0o700)

            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "TEST_CALLS": str(calls),
                },
            )
            self.assertEqual(result.returncode, 0, result)
            self.assertFalse(calls.exists(), "offline retirement invoked an OpenRC manager")
            for retired in (unit, enablement, pid):
                self.assertFalse(retired.exists() or retired.is_symlink(), retired)

    def test_legacy_webtui_active_openrc_runtime_is_stopped_and_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            unit = root / "etc/init.d/syswarden-webtui"
            enablement = root / "etc/runlevels/default/syswarden-webtui"
            runtime = root / "run/openrc"
            pid = root / "run/syswarden-webtui.pid"
            for directory in (unit.parent, enablement.parent, runtime, pid.parent):
                directory.mkdir(parents=True, exist_ok=True)
            (runtime / "softlevel").write_text("default\n", encoding="ascii")
            comm = root / "proc/1/comm"
            comm.parent.mkdir(parents=True)
            comm.write_text("init\n", encoding="ascii")
            unit.write_text(
                "#!/sbin/openrc-run\n\n"
                'name="syswarden-webtui"\n'
                'description="SYSWARDEN Web-TUI (WebTTY)"\n'
                'command="/opt/syswarden/bin/syswarden-cli"\n'
                'command_args="web-tui"\ncommand_background=true\n'
                'pidfile="/run/syswarden-webtui.pid"\n'
                'retry="TERM/5/KILL/5"\n\ndepend() {\n\tneed net\n}\n',
                encoding="utf-8",
            )
            enablement.symlink_to("/etc/init.d/syswarden-webtui")
            pid.write_text("4194303\n", encoding="ascii")
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            calls = Path(temporary) / "calls"
            state = Path(temporary) / "state"
            state.write_text("active\n", encoding="ascii")
            rc_service = mock_bin / "rc-service"
            rc_service.write_text(
                "#!/bin/sh\n"
                'printf "rc-service %s\\n" "$*" >> "$TEST_CALLS"\n'
                'case "$2" in\n'
                '  status) [ "$(cat "$TEST_STATE")" = active ] && exit 0; exit 3 ;;\n'
                '  stop) printf "%s\\n" inactive > "$TEST_STATE" ;;\n'
                "  *) exit 9 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            rc_service.chmod(0o700)
            rc_update = mock_bin / "rc-update"
            rc_update.write_text(
                "#!/bin/sh\n"
                'printf "rc-update %s\\n" "$*" >> "$TEST_CALLS"\n'
                '[ "$*" = "del syswarden-webtui default" ] || exit 9\n'
                'rm -f "$TEST_ROOT/etc/runlevels/default/syswarden-webtui"\n',
                encoding="utf-8",
            )
            rc_update.chmod(0o700)

            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "TEST_CALLS": str(calls),
                    "TEST_ROOT": str(root),
                    "TEST_STATE": str(state),
                },
            )
            self.assertEqual(result.returncode, 0, result)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                [
                    "rc-service syswarden-webtui status",
                    "rc-service syswarden-webtui stop",
                    "rc-service syswarden-webtui status",
                    "rc-update del syswarden-webtui default",
                ],
            )
            for retired in (unit, enablement, pid):
                self.assertFalse(retired.exists() or retired.is_symlink(), retired)

    def test_legacy_webtui_openrc_runtime_path_is_fail_closed(self) -> None:
        for runtime_kind in ("file", "symlink"):
            with self.subTest(runtime=runtime_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                unit = root / "etc/init.d/syswarden-webtui"
                enablement = root / "etc/runlevels/default/syswarden-webtui"
                runtime = root / "run/openrc"
                for directory in (unit.parent, enablement.parent, runtime.parent):
                    directory.mkdir(parents=True, exist_ok=True)
                unit.write_text(
                    "#!/sbin/openrc-run\n\n"
                    'name="syswarden-webtui"\n'
                    'description="SYSWARDEN Web-TUI (WebTTY)"\n'
                    'command="/opt/syswarden/bin/syswarden-cli"\n'
                    'command_args="web-tui"\ncommand_background=true\n'
                    'pidfile="/run/syswarden-webtui.pid"\n'
                    'retry="TERM/5/KILL/5"\n\ndepend() {\n\tneed net\n}\n',
                    encoding="utf-8",
                )
                enablement.symlink_to("/etc/init.d/syswarden-webtui")
                if runtime_kind == "file":
                    runtime.write_text("ambiguous\n", encoding="ascii")
                else:
                    target = runtime.parent / "operator-runtime"
                    target.mkdir()
                    runtime.symlink_to(target, target_is_directory=True)

                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_retire_legacy_webtui "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, result)
                self.assertTrue(unit.exists())
                self.assertTrue(enablement.is_symlink())
                self.assertIn("OpenRC runtime", result.stderr)

    def test_legacy_webtui_package_retirement_rejects_manager_overrides_before_mutation(self) -> None:
        systemd_template = (
            "[Unit]\nDescription=SYSWARDEN Web-TUI (WebTTY)\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=simple\nUser=root\n"
            "ExecStart=/opt/syswarden/bin/syswarden-cli web-tui\n"
            "Restart=on-failure\nRestartSec=5s\n\n# Security Hardening\n"
            "ProtectSystem=full\nProtectHome=yes\nNoNewPrivileges=true\n"
            "PrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n"
        )
        openrc_template = (
            "#!/sbin/openrc-run\n\nname=\"syswarden-webtui\"\n"
            "description=\"SYSWARDEN Web-TUI (WebTTY)\"\n"
            "command=\"/opt/syswarden/bin/syswarden-cli\"\n"
            "command_args=\"web-tui\"\ncommand_background=true\n"
            "pidfile=\"/run/syswarden-webtui.pid\"\n"
            "retry=\"TERM/5/KILL/5\"\n\ndepend() {\n\tneed net\n}\n"
        )
        cases = (
            ("etc/systemd/system/syswarden-webtui.service.d", False, True),
            ("run/systemd/system/syswarden-webtui.service", False, False),
            ("run/systemd/system/syswarden-webtui.service.d", False, True),
            ("etc/conf.d/syswarden-webtui", True, False),
        )
        for relative, alpine, directory in cases:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                if alpine:
                    unit = root / "etc/init.d/syswarden-webtui"
                    enablement = root / "etc/runlevels/default/syswarden-webtui"
                    template = openrc_template
                    target = "/etc/init.d/syswarden-webtui"
                else:
                    unit = root / "etc/systemd/system/syswarden-webtui.service"
                    enablement = root / "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
                    template = systemd_template
                    target = "../syswarden-webtui.service"
                unit.parent.mkdir(parents=True)
                enablement.parent.mkdir(parents=True)
                unit.write_text(template, encoding="utf-8")
                enablement.symlink_to(target)
                override = root / relative
                override.parent.mkdir(parents=True, exist_ok=True)
                if directory:
                    override.mkdir()
                    (override / "operator.conf").write_text(
                        "ExecStart=/srv/operator/listener\n", encoding="utf-8"
                    )
                else:
                    override.write_text("operator-owned override\n", encoding="utf-8")
                mock_bin = Path(temporary) / "bin"
                mock_bin.mkdir()
                calls = Path(temporary) / "calls"
                manager_name = "rc-service" if alpine else "systemctl"
                manager = mock_bin / manager_name
                manager.write_text(
                    '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_CALLS"\n',
                    encoding="utf-8",
                )
                manager.chmod(0o700)

                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_retire_legacy_webtui "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "PATH": f"{mock_bin}:{os.environ['PATH']}",
                        "TEST_CALLS": str(calls),
                    },
                )
                self.assertNotEqual(result.returncode, 0, result)
                self.assertTrue(unit.exists())
                self.assertTrue(enablement.is_symlink())
                self.assertTrue(override.exists() or override.is_symlink())
                self.assertFalse(calls.exists(), "manager was called before override rejection")
                self.assertNotIn("/srv/operator/listener", result.stderr)

    def test_legacy_webtui_package_retirement_attests_loaded_systemd_identity(self) -> None:
        template = (
            "[Unit]\nDescription=SYSWARDEN Web-TUI (WebTTY)\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=simple\nUser=root\n"
            "ExecStart=/opt/syswarden/bin/syswarden-cli web-tui\n"
            "Restart=on-failure\nRestartSec=5s\n\n# Security Hardening\n"
            "ProtectSystem=full\nProtectHome=yes\nNoNewPrivileges=true\n"
            "PrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n"
        )
        exact_exec = (
            "{ path=/opt/syswarden/bin/syswarden-cli ; "
            "argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
            "pid=0 ; code=(null) ; status=0/0 }"
        )
        for bad_property, bad_value in (
            ("FragmentPath", "/run/systemd/system/operator.service"),
            ("DropInPaths", "/etc/systemd/system/operator.conf"),
            ("ExecStart", exact_exec.replace(" web-tui ;", " web-tui --operator ;")),
        ):
            with self.subTest(property=bad_property), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                unit = root / "etc/systemd/system/syswarden-webtui.service"
                wants = root / "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
                manager_root = root / "run/systemd/system"
                for directory in (unit.parent, wants.parent, manager_root):
                    directory.mkdir(parents=True, exist_ok=True)
                self.seed_systemd_runtime(root)
                unit.write_text(template, encoding="utf-8")
                wants.symlink_to("../syswarden-webtui.service")
                mock_bin = Path(temporary) / "bin"
                mock_bin.mkdir()
                calls = Path(temporary) / "calls"
                systemctl = mock_bin / "systemctl"
                systemctl.write_text(
                    "#!/bin/sh\n"
                    'if [ "$1" != show ]; then printf "%s\\n" "$*" >> "$TEST_CALLS"; fi\n'
                    'case "$3" in\n'
                    '  --property=FragmentPath) value="$TEST_ROOT/etc/systemd/system/syswarden-webtui.service" ;;\n'
                    '  --property=DropInPaths) value= ;;\n'
                    '  --property=ExecStart) value="$EXACT_EXEC" ;;\n'
                    '  *) exit 9 ;;\n'
                    'esac\n'
                    '[ "$3" != "--property=$BAD_PROPERTY" ] || value="$BAD_VALUE"\n'
                    'printf "%s\\n" "$value"\n',
                    encoding="utf-8",
                )
                systemctl.chmod(0o700)
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_retire_legacy_webtui "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "PATH": f"{mock_bin}:{os.environ['PATH']}",
                        "TEST_ROOT": str(root),
                        "TEST_CALLS": str(calls),
                        "BAD_PROPERTY": bad_property,
                        "BAD_VALUE": bad_value,
                        "EXACT_EXEC": exact_exec,
                    },
                )
                self.assertNotEqual(result.returncode, 0, result)
                self.assertTrue(unit.exists())
                self.assertTrue(wants.is_symlink())
                self.assertFalse(calls.exists(), "unsafe loaded unit triggered mutation")
                self.assertNotIn("--operator", result.stderr)

    def test_legacy_webtui_accepts_only_exact_vendor_systemd_dropin(self) -> None:
        vendor_content = (
            "# This file is part of the systemd package.\n"
            "# See https://fedoraproject.org/wiki/Changes/Shorter_Shutdown_Timer.\n"
            "#\n"
            "# To facilitate debugging when a service fails to stop cleanly,\n"
            '# TimeoutStopFailureMode=abort is set to "crash" services that fail to stop in\n'
            "# the time allotted. This will cause the service to be terminated with SIGABRT\n"
            "# and a coredump to be generated.\n"
            "#\n"
            "# To undo this configuration change, create a mask file:\n"
            "#   sudo mkdir -p /etc/systemd/system/service.d\n"
            "#   sudo ln -sv /dev/null /etc/systemd/system/service.d/10-timeout-abort.conf\n"
            "\n"
            "[Service]\n"
            "TimeoutStopFailureMode=abort\n"
        )
        expected_digest = (
            "ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37"
        )
        self.assertEqual(
            hashlib.sha256(vendor_content.encode("ascii")).hexdigest(),
            expected_digest,
        )
        exact_exec = (
            "{ path=/opt/syswarden/bin/syswarden-cli ; "
            "argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
            "pid=0 ; code=(null) ; status=0/0 }"
        )
        cases = (
            "exact",
            "merged-usr",
            "operator-path",
            "second-path",
            "content",
            "mode",
            "nlink",
            "parent-mode",
            "parent-symlink",
            "package",
            "owner-fields",
            "owner-lines",
            "digest",
            "drift",
            "late-drift",
            "rpm-path",
            "rpm-outside-alias",
            "rpm-mode",
            "rpm-nlink",
            "rpm-drift",
            "temp-mode",
            "temp-symlink",
            "temp-nlink",
        )
        real_mktemp = shutil.which("mktemp")
        self.assertIsNotNone(real_mktemp)
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir(mode=0o755)
                self.seed_systemd_runtime(root)
                fragment = root / "etc/systemd/system/syswarden-webtui.service"
                fragment.parent.mkdir(parents=True, exist_ok=True)
                fragment.write_text("legacy unit fixture\n", encoding="ascii")
                dropin = (
                    root
                    / "usr/lib/systemd/system/service.d/10-timeout-abort.conf"
                )
                dropin.parent.mkdir(parents=True)
                dropin.write_text(vendor_content, encoding="ascii")
                dropin.chmod(0o644)
                if case == "content":
                    dropin.write_text(
                        vendor_content.replace(
                            "TimeoutStopFailureMode=abort\n",
                            "TimeoutStopFailureMode=terminate\n",
                        ),
                        encoding="ascii",
                    )
                elif case == "mode":
                    dropin.chmod(0o664)
                elif case == "nlink":
                    os.link(dropin, dropin.with_suffix(".operator"))
                elif case == "parent-mode":
                    dropin.parent.chmod(0o775)
                elif case == "parent-symlink":
                    real_parent = dropin.parent.with_name("service.d.real")
                    dropin.parent.rename(real_parent)
                    dropin.parent.symlink_to(real_parent.name, target_is_directory=True)

                rooted_bin = root / "usr/bin"
                rooted_bin.mkdir(parents=True, exist_ok=True)
                rpm = rooted_bin / "rpm"
                rpm.write_text(
                    "#!/bin/sh\n"
                    'printf "%s\\n" "$*" >> "$TEST_RPM_CALLS"\n'
                    'call_count="$(wc -l < "$TEST_RPM_CALLS" | tr -d " ")"\n'
                    'case "$5" in\n'
                    "  '%{NAME}\\t%{EVR}\\t%{ARCH}\\t%{FILEDIGESTALGO}\\n')\n"
                    '    if [ "$TEST_CASE" = package ]; then name=operator-package; else name=systemd; fi\n'
                    '    if [ "$TEST_CASE" = owner-fields ]; then\n'
                    '      printf "%s\\t259.5-1.fc44\\t%s\\n" "$name" "$(uname -m)"\n'
                    '    elif [ "$TEST_CASE" = owner-lines ]; then\n'
                    '      printf "%s\\t259.5-1.fc44\\t%s\\t8\\n" "$name" "$(uname -m)"\n'
                    '      printf "%s\\t259.5-1.fc44\\t%s\\t8\\n" "$name" "$(uname -m)"\n'
                    "    else\n"
                    '      printf "%s\\t259.5-1.fc44\\t%s\\t8\\n" "$name" "$(uname -m)"\n'
                    "    fi\n"
                    "    ;;\n"
                    "  '[%{FILENAMES}\\n]') printf '%s\\n' \"$TEST_DROPIN\" ;;\n"
                    "  '[%{FILEDIGESTS}\\n]')\n"
                    '    if [ "$TEST_CASE" = digest ]; then\n'
                    "      printf '%064d\\n' 0\n"
                    "    else\n"
                    '      printf "%s\\n" "$TEST_DIGEST"\n'
                    "    fi\n"
                    '    if [ "$TEST_CASE" = drift ] && [ ! -e "$TEST_DRIFTED" ]; then\n'
                    '      : > "$TEST_DRIFTED"\n'
                    '      printf x >> "$TEST_DROPIN"\n'
                    "    fi\n"
                    '    if [ "$TEST_CASE" = late-drift ] && [ "$call_count" -eq 6 ]; then\n'
                    '      printf x >> "$TEST_DROPIN"\n'
                    "    fi\n"
                    "    ;;\n"
                    "  *) exit 91 ;;\n"
                    "esac\n"
                    'if [ "$TEST_CASE" = rpm-drift ] && [ "$call_count" -eq 6 ]; then\n'
                    '  chmod 0775 "$0"\n'
                    "fi\n",
                    encoding="ascii",
                )
                rpm.chmod(0o755)
                if case == "rpm-mode":
                    rpm.chmod(0o775)
                elif case == "rpm-nlink":
                    os.link(rpm, rpm.with_suffix(".linked"))
                mock_bin = Path(temporary) / "mock-bin"
                mock_bin.mkdir()
                systemctl = mock_bin / "systemctl"
                systemctl.write_text(
                    "#!/bin/sh\n"
                    'case "$3" in\n'
                    "  --property=LoadState) printf 'loaded\\n' ;;\n"
                    '  --property=FragmentPath) printf "%s\\n" "$TEST_FRAGMENT" ;;\n'
                    '  --property=DropInPaths) printf "%s\\n" "$TEST_DROPINS" ;;\n'
                    '  --property=ExecStart) printf "%s\\n" "$TEST_EXEC" ;;\n'
                    "  *) exit 92 ;;\n"
                    "esac\n",
                    encoding="ascii",
                )
                systemctl.chmod(0o755)
                temporary_link_record = Path(temporary) / "temporary-link-record"
                if case.startswith("temp-"):
                    mock_mktemp = mock_bin / "mktemp"
                    mock_mktemp.write_text(
                        "#!/bin/sh\n"
                        f'result="$("{real_mktemp}" "$@")" || exit 1\n'
                        'case "$result" in\n'
                        '  /tmp/syswarden-webtui-rpm-*)\n'
                        '    case "$TEST_CASE" in\n'
                        '      temp-mode) chmod 0644 "$result" ;;\n'
                        '      temp-symlink) rm -f "$result"; ln -s "$TEST_DROPIN" "$result" ;;\n'
                        '      temp-nlink)\n'
                        '        if [ ! -e "$TEST_TEMP_LINK_RECORD" ]; then\n'
                        '          link="${result}.operator-link"\n'
                        '          ln "$result" "$link" || { rm -f -- "$result"; exit 1; }\n'
                        '          printf "%s\\n" "$link" > "$TEST_TEMP_LINK_RECORD"\n'
                        "        fi\n"
                        "        ;;\n"
                        "    esac\n"
                        "    ;;\n"
                        "esac\n"
                        'printf "%s\\n" "$result"\n',
                        encoding="ascii",
                    )
                    mock_mktemp.chmod(0o755)
                rpm_calls = Path(temporary) / "rpm-calls"
                dropins = str(dropin)
                if case == "operator-path":
                    dropins = str(
                        root
                        / "etc/systemd/system/syswarden-webtui.service.d/operator.conf"
                    )
                elif case == "second-path":
                    dropins += " " + str(root / "etc/systemd/system/operator.conf")
                path_entries = [str(mock_bin), str(rooted_bin), os.environ["PATH"]]
                if case == "merged-usr":
                    merged_bin = root / "bin"
                    merged_bin.symlink_to("usr/bin", target_is_directory=True)
                    path_entries = [
                        str(mock_bin),
                        str(merged_bin),
                        str(rooted_bin),
                        os.environ["PATH"],
                    ]
                elif case == "rpm-path":
                    fake_rpm = mock_bin / "rpm"
                    fake_rpm.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                    fake_rpm.chmod(0o755)
                    path_entries = [str(mock_bin), str(rooted_bin), os.environ["PATH"]]
                elif case == "rpm-outside-alias":
                    foreign_rpm = mock_bin / "rpm-foreign"
                    foreign_rpm.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                    foreign_rpm.chmod(0o755)
                    (mock_bin / "rpm").symlink_to(foreign_rpm)
                    path_entries = [str(mock_bin), str(rooted_bin), os.environ["PATH"]]
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_attest_systemd_webtui_runtime "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "PATH": ":".join(path_entries),
                        "TEST_CASE": case,
                        "TEST_DIGEST": expected_digest,
                        "TEST_DRIFTED": str(Path(temporary) / "drifted"),
                        "TEST_DROPIN": str(dropin),
                        "TEST_DROPINS": dropins,
                        "TEST_EXEC": exact_exec,
                        "TEST_FRAGMENT": str(fragment),
                        "TEST_RPM_CALLS": str(rpm_calls),
                        "TEST_TEMP_LINK_RECORD": str(temporary_link_record),
                    },
                )
                if temporary_link_record.exists():
                    temporary_link = Path(
                        temporary_link_record.read_text(encoding="ascii").strip()
                    )
                    self.assertEqual(temporary_link.parent, Path("/tmp"))
                    self.assertTrue(
                        temporary_link.name.startswith("syswarden-webtui-rpm-")
                    )
                    self.assertTrue(temporary_link.name.endswith(".operator-link"))
                    temporary_link.unlink(missing_ok=False)
                if case in ("exact", "merged-usr"):
                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(
                        len(rpm_calls.read_text(encoding="ascii").splitlines()),
                        6,
                    )
                else:
                    self.assertNotEqual(result.returncode, 0, result)

    def test_legacy_webtui_systemd_root_normalization_is_exact_and_fail_closed(self) -> None:
        exact_exec = (
            "{ path=/opt/syswarden/bin/syswarden-cli ; "
            "argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
            "pid=0 ; code=(null) ; status=0/0 }"
        )
        probe = (
            '. "$1"\n'
            "syswarden_assert_no_webtui_manager_overrides() { return 0; }\n"
            "syswarden_read_systemd_webtui_property() {\n"
            '    printf "%s\\n" "$1" >> "$TEST_CALLS"\n'
            '    if [ "$1" = LoadState ] && [ "${TEST_MUTATE_ROOT:-}" = 1 ] && '
            '[ ! -e "${TEST_ROOT}.before" ]; then\n'
            '        mv -- "$TEST_ROOT" "${TEST_ROOT}.before" || return 1\n'
            '        mkdir -- "$TEST_ROOT" || return 1\n'
            "    fi\n"
            '    case "$1" in\n'
            '        LoadState) printf "%s\\n" loaded ;;\n'
            '        FragmentPath) printf "%s\\n" "$TEST_FRAGMENT" ;;\n'
            '        DropInPaths) printf "\\n" ;;\n'
            '        ExecStart) printf "%s\\n" "$TEST_EXEC" ;;\n'
            "        *) return 1 ;;\n"
            "    esac\n"
            "}\n"
            'syswarden_attest_systemd_webtui_runtime "$2"\n'
        )

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)

            def invoke(
                root_argument: str,
                fragment: str,
                *,
                root_path: Path,
                mutate_root: bool = False,
            ) -> tuple[subprocess.CompletedProcess[str], Path]:
                calls = temporary_root / f"calls-{len(tuple(temporary_root.glob('calls-*')))}"
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        probe,
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        root_argument,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "TEST_CALLS": str(calls),
                        "TEST_EXEC": exact_exec,
                        "TEST_FRAGMENT": fragment,
                        "TEST_MUTATE_ROOT": "1" if mutate_root else "0",
                        "TEST_ROOT": str(root_path),
                    },
                )
                return result, calls

            live_root = temporary_root / "root"
            live_root.mkdir()
            system_fragment = "/etc/systemd/system/syswarden-webtui.service"
            rooted_fragment = str(
                live_root / "etc/systemd/system/syswarden-webtui.service"
            )

            for root_argument, fragment, root_path in (
                ("/", system_fragment, Path("/")),
                (str(live_root), rooted_fragment, live_root),
                (f"{live_root}/", rooted_fragment, live_root),
            ):
                with self.subTest(root=root_argument, outcome="exact"):
                    result, calls = invoke(
                        root_argument,
                        fragment,
                        root_path=root_path,
                    )
                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(
                        calls.read_text(encoding="utf-8").splitlines(),
                        ["LoadState", "FragmentPath", "DropInPaths", "ExecStart"],
                    )

            unexpected, _ = invoke(
                str(live_root),
                "/run/systemd/system/operator.service",
                root_path=live_root,
            )
            self.assertNotEqual(unexpected.returncode, 0, unexpected)
            self.assertIn("unexpected fragment", unexpected.stderr)

            symlink_target = temporary_root / "symlink-target"
            symlink_target.mkdir()
            symlink_root = temporary_root / "symlink-root"
            symlink_root.symlink_to(symlink_target, target_is_directory=True)
            symlink_result, symlink_calls = invoke(
                str(symlink_root),
                str(symlink_root / "etc/systemd/system/syswarden-webtui.service"),
                root_path=symlink_root,
            )
            self.assertNotEqual(symlink_result.returncode, 0, symlink_result)
            self.assertFalse(symlink_calls.exists())

            mutation_root = temporary_root / "mutation-root"
            mutation_root.mkdir()
            mutation_result, _ = invoke(
                str(mutation_root),
                str(mutation_root / "etc/systemd/system/syswarden-webtui.service"),
                root_path=mutation_root,
                mutate_root=True,
            )
            self.assertNotEqual(mutation_result.returncode, 0, mutation_result)
            self.assertIn("root changed", mutation_result.stderr)

            for unsafe_root in (
                "relative/root",
                f"{live_root}/../root",
                f"{live_root}//",
            ):
                with self.subTest(root=unsafe_root, outcome="unsafe"):
                    unsafe, unsafe_calls = invoke(
                        unsafe_root,
                        rooted_fragment,
                        root_path=live_root,
                    )
                    self.assertNotEqual(unsafe.returncode, 0, unsafe)
                    self.assertFalse(unsafe_calls.exists())

    def test_legacy_webtui_package_retirement_stops_cached_unit_before_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            wants = root / "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
            manager_root = root / "run/systemd/system"
            pid = root / "run/syswarden-webtui.pid"
            wants.parent.mkdir(parents=True)
            manager_root.mkdir(parents=True)
            self.seed_systemd_runtime(root)
            wants.symlink_to("../syswarden-webtui.service")
            pid.write_text("4194303\n", encoding="ascii")
            load_state = Path(temporary) / "load-state"
            service_state = Path(temporary) / "service-state"
            load_state.write_text("loaded\n", encoding="ascii")
            service_state.write_text("active\n", encoding="ascii")
            commands = Path(temporary) / "commands"
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            systemctl = mock_bin / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                'if [ "$1" != show ]; then printf "%s\\n" "$*" >> "$TEST_COMMANDS"; fi\n'
                'case "$1" in\n'
                '  show)\n'
                '    case "$3" in\n'
                '      --property=LoadState) cat "$TEST_LOAD_STATE" ;;\n'
                '      --property=ActiveState) cat "$TEST_SERVICE_STATE" ;;\n'
                '      --property=FragmentPath) printf "%s\\n" "$TEST_ROOT/etc/systemd/system/syswarden-webtui.service" ;;\n'
                '      --property=DropInPaths) printf "\\n" ;;\n'
                '      --property=ExecStart) printf "%s\\n" "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=900 ; code=(null) ; status=0/0 }" ;;\n'
                '      *) exit 9 ;;\n'
                '    esac ;;\n'
                '  is-active) [ "$(cat "$TEST_SERVICE_STATE")" = active ] && exit 0; exit 3 ;;\n'
                '  stop) printf "inactive\\n" > "$TEST_SERVICE_STATE" ;;\n'
                '  daemon-reload)\n'
                '    [ "$(cat "$TEST_SERVICE_STATE")" = inactive ] || exit 8\n'
                '    printf "not-found\\n" > "$TEST_LOAD_STATE" ;;\n'
                '  *) exit 9 ;;\n'
                "esac\n",
                encoding="utf-8",
            )
            systemctl.chmod(0o700)
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "TEST_ROOT": str(root),
                    "TEST_COMMANDS": str(commands),
                    "TEST_LOAD_STATE": str(load_state),
                    "TEST_SERVICE_STATE": str(service_state),
                },
            )
            self.assertEqual(result.returncode, 0, result)
            self.assertEqual(load_state.read_text(encoding="ascii"), "not-found\n")
            self.assertEqual(service_state.read_text(encoding="ascii"), "inactive\n")
            self.assertFalse(wants.exists() or wants.is_symlink())
            self.assertFalse(pid.exists())
            self.assertEqual(
                commands.read_text(encoding="utf-8").splitlines(),
                [
                    "stop syswarden-webtui.service",
                    "daemon-reload",
                ],
            )

    def test_legacy_webtui_package_retirement_never_stops_ambiguous_cached_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            wants = root / "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
            (root / "run/systemd/system").mkdir(parents=True)
            self.seed_systemd_runtime(root)
            wants.parent.mkdir(parents=True)
            wants.symlink_to("../syswarden-webtui.service")
            calls = Path(temporary) / "calls"
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            systemctl = mock_bin / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                'if [ "$1" != show ]; then printf "%s\\n" "$*" >> "$TEST_CALLS"; fi\n'
                'case "$3" in\n'
                '  --property=LoadState) printf "loaded\\n" ;;\n'
                '  --property=FragmentPath) printf "%s\\n" "$TEST_ROOT/etc/systemd/system/syswarden-webtui.service" ;;\n'
                '  --property=DropInPaths) printf "\\n" ;;\n'
                '  --property=ExecStart) printf "%s\\n" "{ path=/srv/operator/listener ; argv[]=/srv/operator/listener serve ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=900 ; code=(null) ; status=0/0 }" ;;\n'
                '  *) exit 9 ;;\n'
                'esac\n',
                encoding="utf-8",
            )
            systemctl.chmod(0o700)
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "TEST_ROOT": str(root),
                    "TEST_CALLS": str(calls),
                },
            )
            self.assertNotEqual(result.returncode, 0, result)
            self.assertTrue(wants.is_symlink())
            self.assertFalse(calls.exists(), "ambiguous cached unit was stopped")
            self.assertNotIn("/srv/operator/listener", result.stderr)

    def test_legacy_webtui_manager_errors_fail_closed_and_reload_is_retryable(self) -> None:
        template = (
            "[Unit]\n"
            "Description=SYSWARDEN Web-TUI (WebTTY)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\nType=simple\nUser=root\n"
            "ExecStart=/opt/syswarden/bin/syswarden-cli web-tui\n"
            "Restart=on-failure\nRestartSec=5s\n\n"
            "# Security Hardening\nProtectSystem=full\nProtectHome=yes\n"
            "NoNewPrivileges=true\nPrivateTmp=true\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
        for failure in ("status", "disable", "reload"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                unit = root / "etc/systemd/system/syswarden-webtui.service"
                wants = root / "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
                manager = root / "run/systemd/system"
                for directory in (unit.parent, wants.parent, manager):
                    directory.mkdir(parents=True, exist_ok=True)
                self.seed_systemd_runtime(root)
                unit.write_text(template, encoding="utf-8")
                unit.chmod(0o600)
                wants.symlink_to("../syswarden-webtui.service")
                mock_bin = Path(temporary) / "bin"
                mock_bin.mkdir()
                systemctl = mock_bin / "systemctl"
                systemctl.write_text(
                    "#!/bin/sh\n"
                    'case "$1:$FAIL_STEP" in\n'
                    '  show:*)\n'
                    '    case "$3" in\n'
                    '      --property=LoadState) printf "loaded\\n" ;;\n'
                    '      --property=FragmentPath) printf "%s\\n" "$TEST_ROOT/etc/systemd/system/syswarden-webtui.service" ;;\n'
                    '      --property=DropInPaths) printf "\\n" ;;\n'
                    '      --property=ExecStart) printf "%s\\n" "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }" ;;\n'
                    '      *) exit 9 ;;\n'
                    '    esac ;;\n'
                    '  is-active:status) exit 7 ;;\n'
                    '  is-active:*) exit 3 ;;\n'
                    '  disable:disable) exit 9 ;;\n'
                    '  disable:*) rm -f "$TEST_ROOT/etc/systemd/system/multi-user.target.wants/syswarden-webtui.service" ;;\n'
                    '  daemon-reload:reload) exit 9 ;;\n'
                    '  daemon-reload:*) : ;;\n'
                    '  *) exit 9 ;;\n'
                    "esac\n",
                    encoding="utf-8",
                )
                systemctl.chmod(0o700)

                def invoke(fail_step: str) -> subprocess.CompletedProcess[str]:
                    return subprocess.run(
                        [
                            "/bin/sh",
                            "-c",
                            '. "$1"; syswarden_retire_legacy_webtui "$2"',
                            "probe",
                            str(WEBTUI_RETIREMENT_HELPER),
                            str(root),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        env={
                            **os.environ,
                            "PATH": f"{mock_bin}:{os.environ['PATH']}",
                            "FAIL_STEP": fail_step,
                            "TEST_ROOT": str(root),
                        },
                    )

                failed = invoke(failure)
                self.assertNotEqual(failed.returncode, 0, failed)
                self.assertTrue(unit.exists(), "failed retirement did not restore the exact unit")
                self.assertEqual(unit.read_text(encoding="utf-8"), template)
                if failure == "reload":
                    recovered = invoke("")
                    self.assertEqual(recovered.returncode, 0, recovered)
                    self.assertFalse(unit.exists())
                    self.assertFalse((unit.parent / f"{unit.name}.syswarden-retiring").exists())

    def test_legacy_webtui_package_retirement_rejects_ambiguous_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            unit = root / "etc/systemd/system/syswarden-webtui.service"
            unit.parent.mkdir(parents=True)
            unit.write_text(
                "[Unit]\n"
                "Description=SYSWARDEN Web-TUI (WebTTY)\n"
                "After=network-online.target\n"
                "Wants=network-online.target\n\n"
                "[Service]\n"
                "Type=simple\n"
                "User=root\n"
                "ExecStart=/opt/syswarden/bin/syswarden-cli web-tui\n"
                "ExecStart=/srv/operator/bin/listener\n"
                "Restart=on-failure\n"
                "RestartSec=5s\n\n"
                "# Security Hardening\n"
                "ProtectSystem=full\n"
                "ProtectHome=yes\n"
                "NoNewPrivileges=true\n"
                "PrivateTmp=true\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n",
                encoding="utf-8",
            )
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            calls = Path(temporary) / "calls"
            systemctl = mock_bin / "systemctl"
            systemctl.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_CALLS"\n',
                encoding="utf-8",
            )
            systemctl.chmod(0o700)
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": f"{mock_bin}:{os.environ['PATH']}",
                    "TEST_CALLS": str(calls),
                },
            )
            self.assertNotEqual(result.returncode, 0, result)
            self.assertTrue(unit.exists())
            self.assertFalse(calls.exists())
            self.assertNotIn("/srv/operator/bin/listener", result.stderr)

    def test_legacy_webtui_package_retirement_preserves_reused_live_pid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid = root / "run/syswarden-webtui.pid"
            pid.parent.mkdir()
            pid.write_text(f"{os.getpid()}\n", encoding="ascii")
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result)
            self.assertFalse(pid.exists())
            self.assertIsNone(os.kill(os.getpid(), 0))
            self.assertNotIn(str(os.getpid()), result.stderr)

    def test_legacy_webtui_package_retirement_recovers_exact_dangling_enablement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            systemd = (
                root
                / "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
            )
            openrc = root / "etc/runlevels/default/syswarden-webtui"
            systemd.parent.mkdir(parents=True)
            openrc.parent.mkdir(parents=True)
            (root / "run").mkdir()
            systemd.symlink_to("../syswarden-webtui.service")
            openrc.symlink_to("/etc/init.d/syswarden-webtui")
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result)
            self.assertFalse(systemd.exists() or systemd.is_symlink())
            self.assertFalse(openrc.exists() or openrc.is_symlink())

    def test_legacy_webtui_package_retirement_rejects_modified_dangling_enablement(self) -> None:
        for relative in (
            "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service",
            "etc/runlevels/default/syswarden-webtui",
        ):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                link = root / relative
                link.parent.mkdir(parents=True)
                link.symlink_to("/srv/operator/service")
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_retire_legacy_webtui "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, result)
                self.assertTrue(link.is_symlink())
                self.assertNotIn("/srv/operator/service", result.stderr)

    def test_legacy_webtui_verifier_rejects_enablement_residue_and_unsafe_cli(self) -> None:
        for residue in (
            "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service",
            "etc/runlevels/default/syswarden-webtui",
        ):
            with self.subTest(residue=residue), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tui = root / "opt/syswarden/bin/syswarden-tui"
                link = root / "usr/local/bin/syswarden-tui"
                retired = root / residue
                tui.parent.mkdir(parents=True)
                link.parent.mkdir(parents=True)
                retired.parent.mkdir(parents=True)
                tui.write_bytes(b"")
                tui.chmod(0o750)
                link.symlink_to("/opt/syswarden/bin/syswarden-tui")
                retired.symlink_to("/srv/operator/service")
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_verify_webtui_retirement "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, result)
                self.assertIn("runtime path remains", result.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "opt/syswarden/bin/syswarden-cli"
            executable.parent.mkdir(parents=True)
            executable.symlink_to(Path(os.sys.executable).resolve())
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_verify_no_exact_webtui_process "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result)
            self.assertIn("symlinked SysWarden CLI", result.stderr)

    def test_active_openrc_root_is_canonical_for_preinstall_retirement(self) -> None:
        for name, preinstall in (
            ("workflow", self.script("preinst.sh")),
            ("local", self.local_build_script("preinst.sh")),
        ):
            with self.subTest(script=name):
                self.assertEqual(
                    preinstall.count("syswarden_retire_legacy_webtui / || exit 1"),
                    1,
                )

        helper = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8")
        function_start = helper.index("syswarden_openrc_runtime_available() {")
        function_end = helper.index(
            "\n}\n\nsyswarden_read_exact_webtui_unit()", function_start
        ) + 2
        openrc_function = helper[function_start:function_end]
        absence_guard = (
            'if [ ! -e "${syswarden_retire_runtime}" ] && '
            '[ ! -L "${syswarden_retire_runtime}" ]; then'
        )
        self.assertEqual(openrc_function.count(absence_guard), 1)
        openrc_function = openrc_function.replace(absence_guard, "if false; then")

        probe = subprocess.run(
            [
                "/bin/sh",
                "-c",
                openrc_function
                + "\n"
                "stat() {\n"
                "  case \"$*\" in\n"
                "    '-c %u:%g /') printf '%s\\n' '0:0' ;;\n"
                "    *) return 97 ;;\n"
                "  esac\n"
                "}\n"
                "syswarden_safe_runtime_object() {\n"
                "  printf 'safe:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\"\n"
                "}\n"
                "syswarden_attest_openrc_runtime() {\n"
                "  printf 'attest:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\"\n"
                "}\n"
                'syswarden_openrc_runtime_available ""\n',
                "active-openrc-root-probe",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(probe.returncode, 0, probe)
        self.assertEqual(
            probe.stdout,
            "safe:/run:directory:0:0\nattest::/run/openrc:0:0\n",
        )

    def test_legacy_webtui_runtime_absence_verifier_accepts_removed_native_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            absence = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_verify_legacy_webtui_runtime_absent "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(absence.returncode, 0, absence)

            complete = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_verify_webtui_retirement "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(complete.returncode, 0, complete)
            self.assertIn("Native SysWarden TUI payload is missing", complete.stderr)

            tui = root / "opt/syswarden/bin/syswarden-tui"
            launcher = root / "usr/local/bin/syswarden-tui"
            tui.parent.mkdir(parents=True)
            launcher.parent.mkdir(parents=True)
            tui.write_bytes(b"native-tui\n")
            tui.chmod(0o750)
            launcher.symlink_to("/opt/syswarden/bin/syswarden-tui")
            complete = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_verify_webtui_retirement "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(complete.returncode, 0, complete)

    def test_legacy_webtui_runtime_absence_verifier_rejects_every_residue(self) -> None:
        residues = (
            "etc/systemd/system/syswarden-webtui.service",
            "etc/systemd/system/syswarden-webtui.service.syswarden-retiring",
            "etc/systemd/system/syswarden-webtui.service.d",
            "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service",
            "run/systemd/system/syswarden-webtui.service",
            "run/systemd/system/syswarden-webtui.service.d",
            "etc/init.d/syswarden-webtui",
            "etc/conf.d/syswarden-webtui",
            "etc/runlevels/default/syswarden-webtui",
            "run/syswarden-webtui.pid",
        )
        for residue in residues:
            with self.subTest(residue=residue), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                path = root / residue
                path.parent.mkdir(parents=True)
                path.write_bytes(b"legacy-runtime\n")
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_verify_legacy_webtui_runtime_absent "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0, result)
                self.assertIn("runtime path remains", result.stderr)

    def test_legacy_webtui_runtime_absence_verifier_rejects_deleted_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "opt/syswarden/bin/syswarden-cli"
            executable.parent.mkdir(parents=True)
            shutil.copy2(os.sys.executable, executable)
            (root / "web-tui").write_text(
                "import time\nwhile True: time.sleep(1)\n",
                encoding="utf-8",
            )
            legacy = subprocess.Popen(
                [str(executable), "web-tui"],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.addCleanup(stop_test_process, legacy)
            executable.unlink()
            deleted_link = f"{executable} (deleted)"
            deadline = time.monotonic() + 2
            observed = ""
            while time.monotonic() < deadline:
                try:
                    observed = os.readlink(f"/proc/{legacy.pid}/exe")
                except OSError:
                    observed = ""
                if observed == deleted_link:
                    break
                time.sleep(0.02)
            self.assertEqual(observed, deleted_link)

            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_verify_legacy_webtui_runtime_absent "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result)
            self.assertIsNone(legacy.poll(), "unattested deleted process was killed")
            self.assertIn("cannot be identity-attested", result.stderr)

    def test_legacy_webtui_package_retirement_rejects_inline_toml_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "etc/syswarden/config/modules/99-user.toml"
            module.parent.mkdir(parents=True)
            content = 'user = { profile_name = "operator", webtui_password = "never-report-this" }\n'
            module.write_text(content, encoding="utf-8")
            module.chmod(0o640)
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result)
            self.assertEqual(module.read_text(encoding="utf-8"), content)
            self.assertNotIn("never-report-this", result.stderr)
            self.assertFalse(list(module.parent.glob("*.webtui-retire.*")))

    def test_legacy_webtui_cleanup_preserves_v4028_no_final_newline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "etc/syswarden/config/modules/99-user.toml"
            module.parent.mkdir(parents=True)
            preserved = b'[user]\nprofile_name = "operator"'
            module.write_bytes(preserved + b'\nwebtui_password = "retired-token"')
            module.chmod(0o640)
            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_retire_legacy_webtui "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result)
            self.assertEqual(module.read_bytes(), preserved)
            self.assertEqual(module.stat().st_mode & 0o777, 0o640)

    def test_configuration_parent_sync_failure_is_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            module = root / "etc/syswarden/config/modules/99-user.toml"
            module.parent.mkdir(parents=True)
            module.write_text(
                '[user]\nwebtui_password = "retire"\nprofile_name = "operator"\n',
                encoding="utf-8",
            )
            module.chmod(0o640)
            mock_bin = Path(temporary) / "bin"
            mock_bin.mkdir()
            marker = Path(temporary) / "parent-sync-failed"
            sync = mock_bin / "sync"
            sync.write_text(
                "#!/bin/sh\n"
                'if [ -d "$2" ] && [ ! -f "$SYNC_MARKER" ]; then\n'
                '  : > "$SYNC_MARKER"\n'
                "  exit 9\n"
                "fi\n"
                'exec /usr/bin/sync "$@"\n',
                encoding="utf-8",
            )
            sync.chmod(0o700)

            def invoke() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        '. "$1"; syswarden_retire_legacy_webtui "$2"',
                        "probe",
                        str(WEBTUI_RETIREMENT_HELPER),
                        str(root),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "PATH": f"{mock_bin}:{os.environ['PATH']}",
                        "SYNC_MARKER": str(marker),
                    },
                )

            failed = invoke()
            self.assertNotEqual(failed.returncode, 0, failed)
            self.assertNotIn("webtui_password", module.read_text(encoding="utf-8"))
            recovered = invoke()
            self.assertEqual(recovered.returncode, 0, recovered)
            self.assertEqual(
                module.read_text(encoding="utf-8"),
                '[user]\nprofile_name = "operator"\n',
            )

    def test_process_retirement_matches_executable_and_subcommand_not_port(self) -> None:
        legacy_directory = tempfile.TemporaryDirectory()
        self.addCleanup(legacy_directory.cleanup)
        legacy_script = Path(legacy_directory.name) / "web-tui"
        legacy_script.write_text(
            "import time\nwhile True: time.sleep(1)\n",
            encoding="utf-8",
        )
        listener_code = (
            "import socket\n"
            "s=socket.socket()\n"
            "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "s.bind(('127.0.0.1',62027))\n"
            "s.listen()\n"
            "while True:\n"
            " c,_=s.accept(); c.sendall(b'operator-62027'); c.close()\n"
        )
        try:
            listener = subprocess.Popen(
                [os.sys.executable, "-c", listener_code],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            self.fail(f"start operator listener: {exc}")
        legacy = subprocess.Popen(
            [os.sys.executable, "web-tui", "--bind=0.0.0.0:62027", "--token=legacy"],
            cwd=legacy_directory.name,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(stop_test_process, listener)
        self.addCleanup(stop_test_process, legacy)
        ready = False
        for _ in range(30):
            try:
                with socket.create_connection(("127.0.0.1", 62027), timeout=0.1) as connection:
                    ready = connection.recv(32) == b"operator-62027"
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            listener_error = listener.stderr.read().decode("utf-8", errors="replace") if listener.poll() is not None else ""
            if "PermissionError" in listener_error and "Operation not permitted" in listener_error:
                listener_supported = False
            else:
                self.fail(f"operator listener did not start: {listener_error}")
        else:
            listener_supported = True

        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                '. "$1"; syswarden_retire_exact_webtui_processes "" /proc "$2"',
                "probe",
                str(WEBTUI_RETIREMENT_HELPER),
                str(Path(os.sys.executable).resolve()),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result)
        legacy.wait(timeout=2)
        if listener_supported:
            self.assertIsNone(listener.poll(), "third-party listener was terminated")
            with socket.create_connection(("127.0.0.1", 62027), timeout=1) as connection:
                self.assertEqual(connection.recv(32), b"operator-62027")
        if listener.stderr is not None:
            listener.stderr.close()

    def test_process_match_distinguishes_vanished_from_unreadable_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "syswarden-cli"
            shutil.copy2("/bin/true", executable)
            identity = executable.stat()
            expected_identity = f"{identity.st_dev}:{identity.st_ino}"

            for mode, expected_status in (("vanish", 1), ("unreadable", 2)):
                with self.subTest(mode=mode):
                    process_root = root / f"proc-{mode}" / "4242"
                    process_root.mkdir(parents=True)
                    (process_root / "exe").symlink_to(executable)
                    result = subprocess.run(
                        [
                            "/bin/sh",
                            "-c",
                            '. "$1"; '
                            'syswarden_test_process_root="$3/$4"; '
                            'syswarden_test_mode="$6"; '
                            "syswarden_webtui_process_starttime() { "
                            'if [ "${syswarden_test_mode}" = vanish ]; then '
                            'mv -- "${syswarden_test_process_root}" '
                            '"${syswarden_test_process_root}.gone" || return 2; '
                            "fi; return 1; }; "
                            'syswarden_webtui_process_matches "$4" "$3" "$2" "$5"',
                            "probe",
                            str(WEBTUI_RETIREMENT_HELPER),
                            str(executable),
                            str(process_root.parent),
                            process_root.name,
                            expected_identity,
                            mode,
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, expected_status, result)

    def test_deleted_old_process_with_replaced_binary_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "syswarden-cli"
            shutil.copy2(os.sys.executable, executable)
            (Path(temporary) / "web-tui").write_text(
                "import time\nwhile True: time.sleep(1)\n",
                encoding="utf-8",
            )
            legacy = subprocess.Popen(
                [str(executable), "web-tui", "--bind=0.0.0.0:62027"],
                cwd=temporary,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.addCleanup(stop_test_process, legacy)
            deadline = time.monotonic() + 2
            deleted_link = f"{executable} (deleted)"
            executable.unlink()
            shutil.copy2("/bin/true", executable)
            while time.monotonic() < deadline:
                try:
                    observed = os.readlink(f"/proc/{legacy.pid}/exe")
                except OSError:
                    observed = ""
                if observed == deleted_link:
                    break
                time.sleep(0.02)
            self.assertEqual(observed, deleted_link)

            result = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    '. "$1"; syswarden_verify_no_exact_webtui_process "" /proc "$2"',
                    "probe",
                    str(WEBTUI_RETIREMENT_HELPER),
                    str(executable),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result)
            self.assertIsNone(legacy.poll(), "unattested deleted process was killed")
            self.assertIn("cannot be identity-attested", result.stderr)

    def test_package_hooks_publish_removal_barrier_before_retirement(self) -> None:
        workflow_preinstall = self.script("preinst.sh")
        workflow_preremove = self.script("prerm.sh")
        local_preinstall = self.local_build_script("preinst.sh")
        local_preremove = self.local_build_script("prerm.sh")
        for name, script in (
            ("workflow-preinstall", workflow_preinstall),
            ("workflow-preremove", workflow_preremove),
            ("local-preinstall", local_preinstall),
            ("local-preremove", local_preremove),
        ):
            with self.subTest(script=name):
                self.assertEqual(script.count("syswarden_retire_legacy_webtui / || exit 1"), 1)
                self.assertIn("syswarden_retire_stale_webtui_pid", script)
                if name.endswith("preremove"):
                    self.assertEqual(
                        script.count(
                            "/opt/syswarden/bin/syswarden-cli "
                            "prepare-package-removal || exit 1"
                        ),
                        1,
                    )
                    self.assertNotIn("nft delete table", script)
                    self.assertNotIn("syswarden_cleanup_crontab", script)
                    self.assertNotIn("syswarden_read_crontab", script)
                    self.assertLess(
                        script.index(
                            "/opt/syswarden/bin/syswarden-cli "
                            "prepare-package-removal || exit 1"
                        ),
                        script.index("syswarden_retire_legacy_webtui / || exit 1"),
                    )
        self.assertLess(
            workflow_preinstall.index("syswarden_retire_legacy_webtui / || exit 1"),
            workflow_preinstall.index("mv /opt/syswarden/syswarden-auto.conf"),
        )
        self.assertLess(
            workflow_preremove.index(
                "/opt/syswarden/bin/syswarden-cli prepare-package-removal || exit 1"
            ),
            workflow_preremove.index("syswarden_retire_legacy_webtui / || exit 1"),
        )
        self.assertLess(
            workflow_preremove.index(
                'case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in'
            ),
            workflow_preremove.index("syswarden_retire_legacy_webtui / || exit 1"),
        )
        for source in (self.workflow, LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")):
            self.assertIn("scripts/ci/package_webtui_retirement.sh", source)

    def test_preremove_argument_matrix_runs_barrier_before_retirement(self) -> None:
        scripts = (
            ("workflow", self.script("prerm.sh")),
            ("local", self.local_build_script("prerm.sh")),
        )
        matrix = (
            ("rpm-final-erase", "0", None, None, 0, "barrier\nretired\n"),
            ("rpm-upgrade", "1", None, None, 0, ""),
            ("rpm-downgrade", "1", None, None, 0, ""),
            ("rpm-multiple-installed", "2", None, None, 0, ""),
            ("rpm-malformed-count", "1x", None, None, 1, ""),
            ("rpm-negative-count", "-1", None, None, 1, ""),
            ("rpm-missing-count", "", None, None, 1, ""),
            ("deb-remove", "remove", None, None, 0, "barrier\nretired\n"),
            ("deb-purge", "purge", None, None, 0, "barrier\nretired\n"),
            ("deb-upgrade", "upgrade", None, None, 0, ""),
            ("deb-downgrade", "downgrade", None, None, 0, ""),
            ("deb-failed-upgrade", "failed-upgrade", None, None, 0, ""),
            ("deb-reinstall", "reinstall", None, None, 0, ""),
            ("deb-deconfigure", "deconfigure", None, None, 0, ""),
            ("deb-ambiguous", "ambiguous", None, None, 1, ""),
            ("ambiguous-canonical-version", "4.3.0", None, None, 1, ""),
            (
                "apk-legacy-pre-deinstall-version",
                "4.3.0",
                None,
                None,
                0,
                "barrier\nretired\n",
            ),
            (
                "apk-pre-deinstall-version",
                "4.3.0",
                "syswarden",
                "pre-deinstall",
                0,
                "barrier\nretired\n",
            ),
            (
                "apk-pre-deinstall-later-version",
                "10.0.14",
                "syswarden",
                "pre-deinstall",
                0,
                "barrier\nretired\n",
            ),
            ("apk-missing-version", "", "syswarden", "pre-deinstall", 1, ""),
            (
                "apk-leading-zero-version",
                "4.03.0",
                "syswarden",
                "pre-deinstall",
                1,
                "",
            ),
            (
                "apk-release-suffix",
                "4.3.0-r0",
                "syswarden",
                "pre-deinstall",
                1,
                "",
            ),
            (
                "apk-multiline-version",
                "4.3.0\nambiguous",
                "syswarden",
                "pre-deinstall",
                1,
                "",
            ),
            (
                "apk-wrong-package",
                "4.3.0",
                "not-syswarden",
                "pre-deinstall",
                1,
                "",
            ),
            (
                "apk-pre-upgrade-is-preinstall",
                "4.2.8",
                "syswarden",
                "pre-upgrade",
                1,
                "",
            ),
            (
                "apk-unknown-hook",
                "4.2.8",
                "syswarden",
                "post-upgrade",
                1,
                "",
            ),
        )
        for source_name, script in scripts:
            start = script.index(
                'case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in'
            )
            retirement = "\nsyswarden_retire_legacy_webtui / || exit 1"
            end = script.index(retirement, start) + len(retirement)
            gate = script[start:end].replace(
                "[ -f /etc/alpine-release ]",
                '[ "${SYSWARDEN_TEST_ALPINE:-}" = 1 ]',
            ).replace(
                "/opt/syswarden/bin/syswarden-cli prepare-package-removal",
                "syswarden_prepare_removal_barrier",
            )
            for case_name, action, apk_package, apk_script, returncode, stdout in matrix:
                with self.subTest(source=source_name, case=case_name):
                    environment = {**os.environ}
                    environment.pop("APK_PACKAGE", None)
                    environment.pop("APK_SCRIPT", None)
                    if apk_package is not None:
                        environment["APK_PACKAGE"] = apk_package
                    if apk_script is not None:
                        environment["APK_SCRIPT"] = apk_script
                    if case_name.startswith("apk-legacy-"):
                        environment["SYSWARDEN_TEST_ALPINE"] = "1"
                    else:
                        environment.pop("SYSWARDEN_TEST_ALPINE", None)
                    result = subprocess.run(
                        [
                            "/bin/sh",
                            "-c",
                            "set -u\n"
                            "syswarden_prepare_removal_barrier() { "
                            "printf '%s\\n' barrier; }\n"
                            "syswarden_retire_legacy_webtui() { "
                            "printf '%s\\n' retired; }\n"
                            + gate,
                            "prerm-argument-contract",
                            action,
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, returncode, result)
                    self.assertEqual(result.stdout, stdout, result)

    def test_workflow_and_local_maintainer_hooks_are_byte_and_order_identical(self) -> None:
        local_source = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            self.workflow.count(
                'cat scripts/ci/package_deferred_purge_postinstall.sh >> '
                '"${PACKAGE_SCRIPTS}/postinst.sh"'
            ),
            1,
        )
        self.assertEqual(
            self.workflow.count(
                'cat scripts/ci/package_deferred_purge_postinstall.sh >> '
                '"${PACKAGE_SCRIPTS}/preinst.sh"'
            ),
            1,
        )
        self.assertEqual(
            local_source.count(
                'cat "${REPOSITORY_ROOT}/scripts/ci/'
                'package_deferred_purge_postinstall.sh" >> preinst.sh'
            ),
            1,
        )
        self.assertEqual(
            local_source.count(
                'cat "${REPOSITORY_ROOT}/scripts/ci/'
                'package_deferred_purge_postinstall.sh" >> postinst.sh'
            ),
            1,
        )
        self.assertEqual(
            self.workflow.count(
                'cat scripts/ci/package_removal_state.sh >> '
                '"${PACKAGE_SCRIPTS}/postrm.sh"'
            ),
            1,
        )
        self.assertEqual(
            local_source.count(
                'cat "${REPOSITORY_ROOT}/scripts/ci/'
                'package_removal_state.sh" >> postrm.sh'
            ),
            1,
        )
        for name in ("preinst.sh", "postinst.sh", "prerm.sh", "postrm.sh"):
            with self.subTest(script=name):
                self.assertEqual(
                    self.workflow.count(
                        "cat scripts/ci/package_webtui_retirement.sh > "
                        f'"${{PACKAGE_SCRIPTS}}/{name}"'
                    ),
                    1,
                )
                self.assertEqual(
                    local_source.count(
                        'cat "${REPOSITORY_ROOT}/scripts/ci/'
                        f'package_webtui_retirement.sh" > {name}'
                    ),
                    1,
                )
                workflow = self.script(name).encode("utf-8")
                local = self.local_build_script(name).encode("utf-8")
                self.assertEqual(local, workflow)
                self.assertTrue(workflow.startswith(b"#!/bin/sh\n"))
                if name in {"preinst.sh", "postinst.sh", "prerm.sh"}:
                    self.assertEqual(
                        workflow.count(b"syswarden_retire_legacy_webtui / || exit 1"),
                        1 if name != "postinst.sh" else 0,
                    )

    def test_postremove_uses_runtime_absence_verifier_without_native_payload(self) -> None:
        for name, postremove in (
            ("workflow", self.script("postrm.sh")),
            ("local", self.local_build_script("postrm.sh")),
        ):
            with self.subTest(script=name):
                tail = postremove[postremove.index("syswarden_attest_state_root() {") :]
                self.assertEqual(
                    tail.count(
                        "syswarden_verify_legacy_webtui_runtime_absent / || return 1"
                    ),
                    1,
                )
                self.assertNotIn("syswarden_verify_webtui_retirement /", tail)

        for name, postinstall in (
            ("workflow", self.script("postinst.sh")),
            ("local", self.local_build_script("postinst.sh")),
        ):
            with self.subTest(script=name):
                tail = postinstall[postinstall.rindex("export SYSWARDEN_PKG_INSTALL=1") :]
                self.assertEqual(tail.count("syswarden_verify_webtui_retirement /"), 1)

    def test_postremove_payload_absent_reaches_socket_and_tombstone_matrix(self) -> None:
        matrix = (
            ("deb-remove", "remove", False, True),
            ("rpm-final-erase", "0", False, False),
            ("apk-post-deinstall", "4.3.2", True, False),
        )
        owner = f"{os.getuid()}:{os.getgid()}"
        for source_name, postremove in (
            ("workflow", self.script("postrm.sh")),
            ("local", self.local_build_script("postrm.sh")),
        ):
            for case_name, argument, alpine, preserve_roots in matrix:
                with (
                    self.subTest(source=source_name, case=case_name),
                    tempfile.TemporaryDirectory() as temporary,
                    tempfile.TemporaryDirectory(
                        prefix="sw-postrm-", dir="/tmp"
                    ) as socket_temporary,
                ):
                    root = Path(temporary)
                    opt_root = root / "opt/syswarden"
                    etc_root = root / "etc/syswarden"
                    local_bin = root / "usr/local/bin"
                    runtime_socket = Path(socket_temporary) / "syswarden.sock"
                    self.assertLess(len(os.fsencode(runtime_socket)), 108)
                    state_root = root / "var/lib/syswarden"
                    log_root = root / "var/log/syswarden"
                    tombstone = state_root / "removal-in-progress-v1"
                    deferred = state_root / "removed-awaiting-purge-v1"
                    finalizing = root / "var/lib/.syswarden-removal-finalizing-v1"
                    for path in (
                        opt_root,
                        etc_root,
                        local_bin,
                        runtime_socket.parent,
                        log_root,
                    ):
                        path.mkdir(parents=True, mode=0o755, exist_ok=True)
                    state_root.mkdir(parents=True, mode=0o750)
                    state_root.chmod(0o750)
                    tombstone.write_bytes(
                        b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"
                    )
                    tombstone.chmod(0o600)

                    tail = postremove[
                        postremove.index("syswarden_attest_state_root() {") :
                    ]
                    tail = tail.replace(
                        "[ -f /etc/alpine-release ]",
                        '[ "${SYSWARDEN_TEST_ALPINE:-}" = 1 ]',
                    )
                    tail = tail.replace(
                        "[ ! -L /var/lib ] && [ -d /var/lib ]",
                        f"[ ! -L {root / 'var/lib'} ] && [ -d {root / 'var/lib'} ]",
                    ).replace(
                        '"$(stat -c \'%u:%g:%a\' /var/lib)"',
                        f'"$(stat -c \'%u:%g:%a\' {root / "var/lib"})"',
                    ).replace(
                        "0:0:700|0:0:710|0:0:711|0:0:750|0:0:751|0:0:755",
                        f"{owner}:700|{owner}:710|{owner}:711|{owner}:750|{owner}:751|{owner}:755",
                    )
                    for source, destination in sorted(
                        (
                            (
                                "/var/lib/.syswarden-removal-finalizing-v1",
                                str(finalizing),
                            ),
                            ("/var/lib/syswarden", str(state_root)),
                            ("/var/log/syswarden", str(log_root)),
                            ("/usr/local/bin", str(local_bin)),
                            ("/opt/syswarden", str(opt_root)),
                            ("/etc/syswarden", str(etc_root)),
                            ("/run/syswarden.sock", str(runtime_socket)),
                        ),
                        key=lambda item: len(item[0]),
                        reverse=True,
                    ):
                        tail = tail.replace(source, destination)
                    tail = tail.replace(
                        "0:0:700|0:0:750|0:0:755",
                        f"{owner}:700|{owner}:750|{owner}:755",
                    )
                    tail = tail.replace("'0:0:600:1'", f"'{owner}:600:1'")
                    tail = tail.replace("'0:0:1'", f"'{owner}:1'")

                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        listener.bind(str(runtime_socket))
                        environment = {**os.environ}
                        environment.pop("APK_PACKAGE", None)
                        environment.pop("APK_SCRIPT", None)
                        environment.pop("SYSWARDEN_TEST_ALPINE", None)
                        if alpine:
                            environment.update(
                                {
                                    "APK_PACKAGE": "syswarden",
                                    "APK_SCRIPT": "post-deinstall",
                                    "SYSWARDEN_TEST_ALPINE": "1",
                                }
                            )
                        result = subprocess.run(
                            [
                                "/bin/sh",
                                "-c",
                                "syswarden_verify_legacy_webtui_runtime_absent() { "
                                "printf 'verified:%s\\n' \"$1\"; }\n"
                                + tail,
                                "postremove-payload-absent",
                                argument,
                            ],
                            check=False,
                            capture_output=True,
                            text=True,
                            env=environment,
                        )
                    except PermissionError as exc:
                        self.skipTest(
                            f"UNIX socket binding is unavailable in this sandbox: {exc}"
                        )
                    finally:
                        listener.close()

                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(result.stdout, "verified:/\n", result)
                    self.assertIn("Preserving root crontab", result.stderr)
                    self.assertFalse(runtime_socket.exists())
                    self.assertFalse(runtime_socket.is_symlink())
                    self.assertFalse(tombstone.exists())
                    self.assertFalse(tombstone.is_symlink())
                    self.assertFalse(finalizing.exists())
                    self.assertEqual(deferred.exists(), preserve_roots)
                    if preserve_roots:
                        self.assertEqual(
                            deferred.read_bytes(),
                            b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
                        )
                        self.assertEqual(deferred.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(opt_root.exists(), preserve_roots)
                    self.assertEqual(etc_root.exists(), preserve_roots)
                    self.assertEqual(log_root.exists(), preserve_roots)
                    self.assertEqual(state_root.exists(), preserve_roots)

    def test_linux_remove_and_purge_contract(self) -> None:
        preremove = self.script("prerm.sh")
        for forbidden in (
            "syswarden_cleanup_crontab",
            "syswarden_filter_crontab",
            "syswarden_read_crontab",
            "crontab -l",
            "crontab -r",
            "crontab - <",
        ):
            self.assertNotIn(forbidden, preremove)
        self.assertIn(
            "/opt/syswarden/bin/syswarden-cli prepare-package-removal || exit 1",
            preremove,
        )
        self.assertIn("Root crontab bytes", preremove)
        postremove = self.script("postrm.sh")
        self.assertIn("syswarden_remove_dedicated_root /opt/syswarden", postremove)
        self.assertIn("syswarden_remove_dedicated_root /etc/syswarden", postremove)
        self.assertIn("syswarden_remove_exact_product_link", postremove)
        self.assertIn("syswarden_remove_exact_runtime_socket", postremove)
        self.assertIn("syswarden_remove_exact_runtime_socket /run/syswarden.sock", postremove)
        self.assertIn("/var/lib/syswarden/removal-in-progress-v1", postremove)
        self.assertIn("/var/lib/syswarden/removed-awaiting-purge-v1", postremove)
        self.assertIn("SYSWARDEN_REMOVAL_V1\\nstate=in-progress\\n", postremove)
        self.assertIn("syswarden_transition_to_deferred_purge", postremove)
        self.assertIn("syswarden_finalize_removal_state_root", postremove)
        self.assertIn('cmp - "${syswarden_marker_path}"', postremove)
        self.assertNotIn('$(cat "${syswarden_tombstone}")', postremove)
        self.assertIn("0:0:600:1", postremove)
        removal_tail = postremove[postremove.rindex("export SYSWARDEN_PKG_INSTALL=1") :]
        for forbidden in (
            "crontab -l",
            "crontab -r",
            "crontab - <",
            "systemctl ",
            "rc-service ",
            "try-restart rsyslog",
            "/etc/rsyslog.d/99-syswarden",
        ):
            self.assertNotIn(forbidden, removal_tail)

    def test_package_removal_never_reads_filters_or_writes_root_crontab(self) -> None:
        scripts = (
            ("workflow-prerm", self.script("prerm.sh")),
            ("workflow-postrm", self.script("postrm.sh")),
            ("local-prerm", self.local_build_script("prerm.sh")),
            ("local-postrm", self.local_build_script("postrm.sh")),
        )
        for name, script in scripts:
            with self.subTest(script=name):
                for forbidden in (
                    "syswarden_managed_cron_line",
                    "syswarden_filter_crontab",
                    "syswarden_read_crontab",
                    "syswarden_cleanup_crontab",
                    "crontab -l",
                    "crontab -r",
                    "crontab - <",
                ):
                    self.assertNotIn(forbidden, script)
                self.assertIn("root crontab", script.lower())

    def test_removal_tombstone_contract_is_identical_in_package_generators(self) -> None:
        workflow = self.script("postrm.sh")
        local = self.local_build_script("postrm.sh")
        self.assertEqual(workflow, local)
        for required in (
            "/var/lib/syswarden/removal-in-progress-v1",
            "/var/lib/syswarden/removed-awaiting-purge-v1",
            "SYSWARDEN_REMOVAL_V1\\nstate=in-progress\\n",
            'cmp - "${syswarden_marker_path}"',
            "syswarden_refuse_mounted_path_tree",
            "syswarden_empty_removal_state || exit 1",
            "syswarden_finalize_removal_state_root || exit 1",
            "syswarden_transition_to_deferred_purge || exit 1",
            "syswarden_resume_unmarked_terminal_state || exit 1",
            "0:0:600:1",
            "= '39'",
        ):
            self.assertIn(required, workflow)
        main = workflow[
            workflow.rindex(
                'if [ -f /etc/alpine-release ] || [ "$1" = "0" ] || '
                '[ "$1" = "remove" ] || [ "$1" = "purge" ]; then'
            ) :
        ]
        self.assertLess(
            main.index("for syswarden_purge_root in"),
            main.index("syswarden_remove_dedicated_root /opt/syswarden"),
        )
        self.assertLess(
            main.index("syswarden_remove_dedicated_root /var/log/syswarden"),
            main.index("syswarden_empty_removal_state || exit 1"),
        )
        self.assertLess(
            main.index("syswarden_empty_removal_state || exit 1"),
            main.index("syswarden_finalize_removal_state_root || exit 1"),
        )
        finalizer_start = workflow.index("syswarden_finalize_removal_state_root() {")
        finalizer_end = workflow.index(
            "\nsyswarden_resume_unmarked_terminal_state() {", finalizer_start
        )
        finalizer = workflow[finalizer_start:finalizer_end]
        rename = finalizer.index(
            'mv -- "${syswarden_active_barrier}" "${syswarden_finalizing_barrier}"'
        )
        rmdir = finalizer.index("rmdir -- /var/lib/syswarden")
        unlink = finalizer.index('rm -f -- "${syswarden_finalizing_barrier}"')
        self.assertLess(
            rename,
            rmdir,
        )
        self.assertLess(rmdir, unlink)
        self.assertGreaterEqual(finalizer.count("sync || return 1"), 3)

    def test_postremove_barrier_is_crash_retryable_and_precedes_deletion(self) -> None:
        owner = f"{os.getuid()}:{os.getgid()}"
        postremove = self.script("postrm.sh")
        tail = postremove[postremove.index("syswarden_attest_state_root() {") :]

        with tempfile.TemporaryDirectory(prefix="sw-postrm-order-", dir="/tmp") as temporary:
            root = Path(temporary)
            opt_root = root / "opt/syswarden"
            etc_root = root / "etc/syswarden"
            log_root = root / "var/log/syswarden"
            state_root = root / "var/lib/syswarden"
            local_bin = root / "usr/local/bin"
            completion = root / "usr/share/bash-completion/completions/syswarden"
            runtime_socket = root / "run/syswarden.sock"
            mountinfo = root / "mountinfo"
            tombstone = state_root / "removal-in-progress-v1"
            finalizing = root / "var/lib/.syswarden-removal-finalizing-v1"

            def populate() -> None:
                for path in (
                    opt_root,
                    etc_root,
                    log_root,
                    state_root,
                    local_bin,
                    runtime_socket.parent,
                ):
                    path.mkdir(parents=True, mode=0o750, exist_ok=True)
                    path.chmod(0o750)
                (opt_root / "operator.bin").write_bytes(b"opt\n")
                (etc_root / "operator.conf").write_bytes(b"etc\n")
                (log_root / "security.log").write_bytes(b"log\n")
                (state_root / "operator.json").write_bytes(b"state\n")
                tombstone.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n")
                tombstone.chmod(0o600)

            replacements = sorted(
                (
                    ("/var/lib/.syswarden-removal-finalizing-v1", str(finalizing)),
                    ("/usr/share/bash-completion/completions/syswarden", str(completion)),
                    ("/proc/self/mountinfo", str(mountinfo)),
                    ("/var/lib/syswarden", str(state_root)),
                    ("/var/log/syswarden", str(log_root)),
                    ("/usr/local/bin", str(local_bin)),
                    ("/opt/syswarden", str(opt_root)),
                    ("/etc/syswarden", str(etc_root)),
                    ("/run/syswarden.sock", str(runtime_socket)),
                ),
                key=lambda item: len(item[0]),
                reverse=True,
            )
            executable = tail.replace(
                "[ -f /etc/alpine-release ]",
                '[ "${SYSWARDEN_TEST_ALPINE:-}" = 1 ]',
            )
            executable = executable.replace(
                "[ ! -L /var/lib ] && [ -d /var/lib ]",
                f"[ ! -L {root / 'var/lib'} ] && [ -d {root / 'var/lib'} ]",
            ).replace(
                '"$(stat -c \'%u:%g:%a\' /var/lib)"',
                f'"$(stat -c \'%u:%g:%a\' {root / "var/lib"})"',
            ).replace(
                "0:0:700|0:0:710|0:0:711|0:0:750|0:0:751|0:0:755",
                f"{owner}:700|{owner}:710|{owner}:711|{owner}:750|{owner}:751|{owner}:755",
            )
            for source, destination in replacements:
                executable = executable.replace(source, destination)
            executable = executable.replace(
                "0:0:700|0:0:750|0:0:755",
                f"{owner}:700|{owner}:750|{owner}:755",
            )
            executable = executable.replace("'0:0:600:1'", f"'{owner}:600:1'")
            executable = executable.replace("'0:0:1'", f"'{owner}:1'")
            executable = executable.replace(
                "        syswarden_finalize_removal_state_root || exit 1\n",
                "        if [ \"${SYSWARDEN_TEST_FAIL_FINALIZE:-0}\" = 1 ]; then exit 97; fi\n"
                "        syswarden_finalize_removal_state_root || exit 1\n",
            )
            executable = executable.replace(
                "    syswarden_attest_finalizing_marker || return 1\n"
                "    syswarden_state_root_is_empty || return 1\n",
                "    syswarden_attest_finalizing_marker || return 1\n"
                '    if [ "${SYSWARDEN_TEST_CRASH_AFTER_UNLINK:-0}" = 1 ]; then exit 98; fi\n'
                "    syswarden_state_root_is_empty || return 1\n",
            )
            executable = (
                "syswarden_verify_legacy_webtui_runtime_absent() { :; }\n" + executable
            )

            def run(
                argument: str,
                *,
                alpine: bool = False,
                fail_finalize: bool = False,
                crash_after_unlink: bool = False,
            ) -> subprocess.CompletedProcess[str]:
                environment = {
                    **os.environ,
                    "SYSWARDEN_TEST_ALPINE": "1" if alpine else "0",
                    "SYSWARDEN_TEST_FAIL_FINALIZE": "1" if fail_finalize else "0",
                    "SYSWARDEN_TEST_CRASH_AFTER_UNLINK": (
                        "1" if crash_after_unlink else "0"
                    ),
                }
                return subprocess.run(
                    ("/bin/sh", "-c", executable, "postrm-order", argument),
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )

            mountinfo.write_text(
                "36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n",
                encoding="ascii",
            )
            populate()
            interrupted = run("purge", fail_finalize=True)
            self.assertEqual(interrupted.returncode, 97, interrupted)
            self.assertFalse(opt_root.exists())
            self.assertFalse(etc_root.exists())
            self.assertFalse(log_root.exists())
            self.assertTrue(tombstone.is_file())
            self.assertEqual(tuple(path.name for path in state_root.iterdir()), (tombstone.name,))
            retried = run("purge")
            self.assertEqual(retried.returncode, 0, retried)
            self.assertFalse(state_root.exists())

            for case_name, argument, alpine in (
                ("deb", "purge", False),
                ("rpm", "0", False),
                ("apk", "4.03.3", True),
            ):
                with self.subTest(crash_retry=case_name):
                    populate()
                    crashed = run(
                        argument,
                        alpine=alpine,
                        crash_after_unlink=True,
                    )
                    self.assertEqual(crashed.returncode, 98, crashed)
                    self.assertTrue(state_root.is_dir())
                    self.assertEqual(tuple(state_root.iterdir()), ())
                    self.assertEqual(
                        finalizing.read_bytes(),
                        b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
                    )
                    retried = run(argument, alpine=alpine)
                    self.assertEqual(retried.returncode, 0, retried)
                    self.assertFalse(state_root.exists())
                    self.assertFalse(finalizing.exists())

            populate()
            mounted_child = state_root / "operator-volume"
            mounted_child.mkdir(mode=0o750)
            mountinfo.write_text(
                f"37 36 0:33 / {mounted_child} rw,relatime - ext4 /dev/loop0 rw\n",
                encoding="ascii",
            )
            refused = run("purge")
            self.assertNotEqual(refused.returncode, 0, refused)
            self.assertIn("Refusing removal across a mounted product path", refused.stderr)
            self.assertEqual((opt_root / "operator.bin").read_bytes(), b"opt\n")
            self.assertEqual((etc_root / "operator.conf").read_bytes(), b"etc\n")
            self.assertEqual((log_root / "security.log").read_bytes(), b"log\n")
            self.assertEqual((state_root / "operator.json").read_bytes(), b"state\n")
            self.assertTrue(tombstone.is_file())

    def test_deb_remove_then_later_purge_or_reinstall_is_retry_safe(self) -> None:
        owner = f"{os.getuid()}:{os.getgid()}"
        postremove = self.script("postrm.sh")
        tail = postremove[postremove.index("syswarden_attest_state_root() {") :]
        postinstall = self.script("postinst.sh")
        consumer_start = postinstall.index("syswarden_install_path_absent() {")
        consumer_end = postinstall.index("\nmodular_config_complete() {", consumer_start)
        consumer = postinstall[consumer_start:consumer_end]

        with tempfile.TemporaryDirectory(prefix="sw-deb-deferred-", dir="/tmp") as temporary:
            root = Path(temporary)
            opt_root = root / "opt/syswarden"
            etc_root = root / "etc/syswarden"
            log_root = root / "var/log/syswarden"
            state_root = root / "var/lib/syswarden"
            local_bin = root / "usr/local/bin"
            completion = root / "usr/share/bash-completion/completions/syswarden"
            runtime_socket = root / "run/syswarden.sock"
            mountinfo = root / "mountinfo"
            active = state_root / "removal-in-progress-v1"
            deferred = state_root / "removed-awaiting-purge-v1"
            finalizing = root / "var/lib/.syswarden-removal-finalizing-v1"

            def populate() -> None:
                for path in (opt_root, etc_root, log_root, state_root, local_bin):
                    path.mkdir(parents=True, mode=0o750, exist_ok=True)
                    path.chmod(0o750)
                (opt_root / "operator.bin").write_bytes(b"opt\n")
                (etc_root / "operator.conf").write_bytes(b"etc\n")
                (log_root / "security.log").write_bytes(b"log\n")
                (state_root / "operator.json").write_bytes(b"state\n")
                active.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n")
                active.chmod(0o600)

            replacements = sorted(
                (
                    ("/var/lib/.syswarden-removal-finalizing-v1", str(finalizing)),
                    ("/usr/share/bash-completion/completions/syswarden", str(completion)),
                    ("/proc/self/mountinfo", str(mountinfo)),
                    ("/var/lib/syswarden", str(state_root)),
                    ("/var/log/syswarden", str(log_root)),
                    ("/usr/local/bin", str(local_bin)),
                    ("/opt/syswarden", str(opt_root)),
                    ("/etc/syswarden", str(etc_root)),
                    ("/run/syswarden.sock", str(runtime_socket)),
                ),
                key=lambda item: len(item[0]),
                reverse=True,
            )
            executable = tail.replace(
                "[ -f /etc/alpine-release ]",
                '[ "${SYSWARDEN_TEST_ALPINE:-0}" = 1 ]',
            )
            executable = executable.replace(
                "[ ! -L /var/lib ] && [ -d /var/lib ]",
                f"[ ! -L {root / 'var/lib'} ] && [ -d {root / 'var/lib'} ]",
            ).replace(
                '"$(stat -c \'%u:%g:%a\' /var/lib)"',
                f'"$(stat -c \'%u:%g:%a\' {root / "var/lib"})"',
            ).replace(
                "0:0:700|0:0:710|0:0:711|0:0:750|0:0:751|0:0:755",
                f"{owner}:700|{owner}:710|{owner}:711|{owner}:750|{owner}:751|{owner}:755",
            )
            install_consumer = consumer
            for source, destination in replacements:
                executable = executable.replace(source, destination)
                install_consumer = install_consumer.replace(source, destination)
            install_consumer = install_consumer.replace(
                "[ ! -L /var/lib ] && [ -d /var/lib ]",
                f"[ ! -L {root / 'var/lib'} ] && [ -d {root / 'var/lib'} ]",
            ).replace(
                '"$(stat -c \'%u:%g:%a\' /var/lib)"',
                f'"$(stat -c \'%u:%g:%a\' {root / "var/lib"})"',
            ).replace(
                "0:0:700|0:0:710|0:0:711|0:0:750|0:0:751|0:0:755",
                f"{owner}:700|{owner}:710|{owner}:711|{owner}:750|{owner}:751|{owner}:755",
            )
            for metadata in ("0:0:700|0:0:750|0:0:755",):
                executable = executable.replace(
                    metadata,
                    f"{owner}:700|{owner}:750|{owner}:755",
                )
                install_consumer = install_consumer.replace(
                    metadata,
                    f"{owner}:700|{owner}:750|{owner}:755",
                )
            executable = executable.replace("'0:0:600:1'", f"'{owner}:600:1'")
            executable = executable.replace("'0:0:1'", f"'{owner}:1'")
            install_consumer = install_consumer.replace(
                "'0:0:600:1'", f"'{owner}:600:1'"
            )
            executable = executable.replace(
                "    syswarden_attest_finalizing_marker || return 1\n"
                "    syswarden_state_root_is_empty || return 1\n",
                "    syswarden_attest_finalizing_marker || return 1\n"
                '    if [ "${SYSWARDEN_TEST_CRASH_AFTER_FINALIZING_MOVE:-0}" = 1 ]; then exit 98; fi\n'
                "    syswarden_state_root_is_empty || return 1\n",
            )
            executable = (
                "syswarden_verify_legacy_webtui_runtime_absent() { :; }\n" + executable
            )

            def run_postremove(
                argument: str, *, crash_after_finalizing_move: bool = False
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ("/bin/sh", "-c", executable, "deb-deferred", argument),
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "SYSWARDEN_TEST_ALPINE": "0",
                        "SYSWARDEN_TEST_CRASH_AFTER_FINALIZING_MOVE": (
                            "1" if crash_after_finalizing_move else "0"
                        ),
                    },
                )

            mountinfo.write_text(
                "36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n",
                encoding="ascii",
            )
            populate()
            removed = run_postremove("remove")
            self.assertEqual(removed.returncode, 0, removed)
            self.assertFalse(active.exists())
            self.assertEqual(
                deferred.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            self.assertEqual((etc_root / "operator.conf").read_bytes(), b"etc\n")
            self.assertEqual((state_root / "operator.json").read_bytes(), b"state\n")
            self.assertEqual((log_root / "security.log").read_bytes(), b"log\n")
            removed_retry = run_postremove("remove")
            self.assertEqual(removed_retry.returncode, 0, removed_retry)
            purged = run_postremove("purge")
            self.assertEqual(purged.returncode, 0, purged)
            for product_root in (opt_root, etc_root, log_root, state_root):
                self.assertFalse(product_root.exists(), product_root)

            populate()
            removed = run_postremove("remove")
            self.assertEqual(removed.returncode, 0, removed)
            consumed = subprocess.run(
                (
                    "/bin/sh",
                    "-c",
                    install_consumer + "\nsyswarden_consume_deferred_purge_marker\n",
                    "deb-reinstall-consumer",
                ),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(consumed.returncode, 0, consumed)
            self.assertFalse(deferred.exists())
            self.assertEqual((state_root / "operator.json").read_bytes(), b"state\n")
            self.assertEqual((etc_root / "operator.conf").read_bytes(), b"etc\n")

            active.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n")
            active.chmod(0o600)
            refused_active = subprocess.run(
                (
                    "/bin/sh",
                    "-c",
                    install_consumer + "\nsyswarden_consume_deferred_purge_marker\n",
                    "deb-reinstall-active-consumer",
                ),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused_active.returncode, 0, refused_active)
            self.assertIn("active package-removal barrier", refused_active.stderr)
            self.assertEqual(
                active.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            active.unlink()

            deferred.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n")
            deferred.chmod(0o600)
            active.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n")
            active.chmod(0o600)
            mounted_reconciliation_child = state_root / "operator-volume"
            mounted_reconciliation_child.mkdir(mode=0o750)
            (mounted_reconciliation_child / "operator.bin").write_bytes(b"mounted\n")
            mountinfo.write_text(
                f"37 36 0:33 / {mounted_reconciliation_child} rw,relatime - ext4 /dev/loop0 rw\n",
                encoding="ascii",
            )
            refused_mounted_reconciliation = run_postremove("remove")
            self.assertNotEqual(
                refused_mounted_reconciliation.returncode,
                0,
                refused_mounted_reconciliation,
            )
            self.assertEqual(
                active.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            self.assertEqual(
                deferred.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            self.assertEqual(
                (mounted_reconciliation_child / "operator.bin").read_bytes(),
                b"mounted\n",
            )
            mountinfo.write_text(
                "36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n",
                encoding="ascii",
            )
            (mounted_reconciliation_child / "operator.bin").unlink()
            mounted_reconciliation_child.rmdir()
            removed_after_stale_reappearance = run_postremove("remove")
            self.assertEqual(
                removed_after_stale_reappearance.returncode,
                0,
                removed_after_stale_reappearance,
            )
            self.assertFalse(active.exists())
            self.assertEqual(
                deferred.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            final_purge = run_postremove("purge")
            self.assertEqual(final_purge.returncode, 0, final_purge)

            populate()
            crashed_purge = run_postremove(
                "purge", crash_after_finalizing_move=True
            )
            self.assertEqual(crashed_purge.returncode, 98, crashed_purge)
            self.assertTrue(state_root.is_dir())
            self.assertEqual(tuple(state_root.iterdir()), ())
            self.assertEqual(
                finalizing.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            reinstalled = subprocess.run(
                (
                    "/bin/sh",
                    "-c",
                    install_consumer + "\nsyswarden_consume_deferred_purge_marker\n",
                    "deb-reinstall-finalizing-consumer",
                ),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(reinstalled.returncode, 0, reinstalled)
            self.assertFalse(finalizing.exists())
            populate()
            removed_after_reinstall = run_postremove("remove")
            self.assertEqual(
                removed_after_reinstall.returncode, 0, removed_after_reinstall
            )
            purged_after_reinstall = run_postremove("purge")
            self.assertEqual(
                purged_after_reinstall.returncode, 0, purged_after_reinstall
            )

            populate()
            crashed_before_failed_reinstall = run_postremove(
                "purge", crash_after_finalizing_move=True
            )
            self.assertEqual(
                crashed_before_failed_reinstall.returncode,
                98,
                crashed_before_failed_reinstall,
            )
            self.assertTrue(finalizing.is_file())
            populate()
            partial_reinstall_mount = state_root / "partial-reinstall-volume"
            partial_reinstall_mount.mkdir(mode=0o750)
            (partial_reinstall_mount / "operator.bin").write_bytes(b"mounted\n")
            mountinfo.write_text(
                f"37 36 0:33 / {partial_reinstall_mount} rw,relatime - ext4 /dev/loop0 rw\n",
                encoding="ascii",
            )
            refused_partial_reinstall_purge = run_postremove("purge")
            self.assertNotEqual(
                refused_partial_reinstall_purge.returncode,
                0,
                refused_partial_reinstall_purge,
            )
            self.assertEqual(
                active.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            self.assertEqual(
                finalizing.read_bytes(),
                b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n",
            )
            self.assertEqual(
                (partial_reinstall_mount / "operator.bin").read_bytes(),
                b"mounted\n",
            )
            mountinfo.write_text(
                "36 25 0:32 / / rw,relatime - ext4 /dev/root rw\n",
                encoding="ascii",
            )
            (partial_reinstall_mount / "operator.bin").unlink()
            partial_reinstall_mount.rmdir()
            resumed_partial_reinstall_purge = run_postremove("purge")
            self.assertEqual(
                resumed_partial_reinstall_purge.returncode,
                0,
                resumed_partial_reinstall_purge,
            )
            self.assertFalse(finalizing.exists())
            for product_root in (opt_root, etc_root, log_root, state_root):
                self.assertFalse(product_root.exists(), product_root)

    def test_removal_marker_rejects_same_size_nul_substitution(self) -> None:
        owner = f"{os.getuid()}:{os.getgid()}"
        postremove = self.script("postrm.sh")
        tail = postremove[postremove.index("syswarden_attest_state_root() {") :]
        start = tail.index("syswarden_attest_state_root() {")
        end = tail.index("\nsyswarden_assert_product_binaries_absent() {", start)
        attestation = tail[start:end]
        with tempfile.TemporaryDirectory(prefix="sw-marker-nul-", dir="/tmp") as temporary:
            state_root = Path(temporary) / "var/lib/syswarden"
            state_root.mkdir(parents=True, mode=0o750)
            state_root.chmod(0o750)
            marker = state_root / "removal-in-progress-v1"
            attestation = attestation.replace("/var/lib/syswarden", str(state_root))
            attestation = attestation.replace(
                "0:0:700|0:0:750|0:0:755",
                f"{owner}:700|{owner}:750|{owner}:755",
            ).replace("'0:0:600:1'", f"'{owner}:600:1'")

            marker.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\x00")
            self.assertEqual(marker.stat().st_size, 39)
            marker.chmod(0o600)
            refused = subprocess.run(
                ("/bin/sh", "-c", attestation + "\nsyswarden_attest_removal_tombstone\n"),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0, refused)

            marker.write_bytes(b"SYSWARDEN_REMOVAL_V1\nstate=in-progress\n")
            marker.chmod(0o600)
            accepted = subprocess.run(
                ("/bin/sh", "-c", attestation + "\nsyswarden_attest_removal_tombstone\n"),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted)

    def test_rpm_artifact_gate_requires_exact_scriptlet_bodies(self) -> None:
        validation_step = workflow_step_script(
            self.workflow, "Validate Package Metadata"
        )
        function_start = validation_step.index("validate_rpm_scriptlet() {")
        function_end = validation_step.index("\nvalidate_apk() {", function_start)
        validate_rpm = validation_step[function_start:function_end]
        for required in (
            'actual="$(rpm --query --package --queryformat "%{${tag}}"',
            'expected="$(cat "${expected_path}")"',
            '"%{${tag}PROG}"',
            '== "/bin/sh"',
            'validate_rpm_scriptlet "${path}" PREIN "${PACKAGE_SCRIPTS}/preinst.sh"',
            'validate_rpm_scriptlet "${path}" POSTIN "${PACKAGE_SCRIPTS}/postinst.sh"',
            'validate_rpm_scriptlet "${path}" PREUN "${PACKAGE_SCRIPTS}/prerm.sh"',
            'validate_rpm_scriptlet "${path}" POSTUN "${PACKAGE_SCRIPTS}/postrm.sh"',
        ):
            self.assertIn(required, validate_rpm)
        forbidden_tokens = (
            "syswarden_cron_candidate",
            "syswarden_cron_minute",
            "syswarden_managed_cron_line",
            "syswarden_filter_crontab",
            "syswarden_read_crontab",
            "syswarden_cleanup_crontab",
            "crontab -l",
            "crontab -r",
            "crontab - <",
        )
        for forbidden in forbidden_tokens:
            self.assertIn(forbidden, validate_rpm)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            package_scripts = root / "package-scripts"
            package_scripts.mkdir()
            artifact_scripts = root / "artifact-scripts"
            artifact_scripts.mkdir()
            scriptlets = root / "scriptlets"
            fake_rpm = fake_bin / "rpm"
            fake_rpm.write_text(
                "#!/bin/sh\n"
                "if [ \"$3\" = --scripts ]; then\n"
                "  cat \"${RPM_SCRIPTLETS_FILE}\"\n"
                "  exit 0\n"
                "fi\n"
                "[ \"$3\" = --queryformat ] || exit 90\n"
                "case \"$4\" in\n"
                "  '%{VERSION}') printf 4.02.14; exit \"${RPM_VERSION_EXIT}\" ;;\n"
                "  '%{ARCH}') printf x86_64; exit \"${RPM_ARCH_EXIT}\" ;;\n"
                "  '%{BUILDTIME}') printf '%s' \"${SOURCE_DATE_EPOCH}\"; exit \"${RPM_BUILDTIME_EXIT}\" ;;\n"
                "  '%{BUILDHOST}') printf syswarden-build.invalid; exit \"${RPM_BUILDHOST_EXIT}\" ;;\n"
                "  '%{CHANGELOGTIME}') printf '%s' \"${RPM_CHANGELOG_EPOCH}\"; exit \"${RPM_CHANGELOGTIME_EXIT}\" ;;\n"
                "  '%{PREIN}') cat \"${RPM_PREIN_FILE}\" ;;\n"
                "  '%{POSTIN}') cat \"${RPM_POSTIN_FILE}\" ;;\n"
                "  '%{PREUN}') cat \"${RPM_PREUN_FILE}\" ;;\n"
                "  '%{POSTUN}') cat \"${RPM_POSTUN_FILE}\" ;;\n"
                "  '%{PREINPROG}') printf '%s' \"${RPM_PREIN_PROG}\"; exit \"${RPM_PREIN_PROG_EXIT}\" ;;\n"
                "  '%{POSTINPROG}') printf '%s' \"${RPM_POSTIN_PROG}\"; exit \"${RPM_POSTIN_PROG_EXIT}\" ;;\n"
                "  '%{PREUNPROG}') printf '%s' \"${RPM_PREUN_PROG}\"; exit \"${RPM_PREUN_PROG_EXIT}\" ;;\n"
                "  '%{POSTUNPROG}') printf '%s' \"${RPM_POSTUN_PROG}\"; exit \"${RPM_POSTUN_PROG_EXIT}\" ;;\n"
                "  *) exit 91 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_rpm.chmod(0o700)
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "RPM_SCRIPTLETS_FILE": str(scriptlets),
                "SOURCE_DATE_EPOCH": "946684800",
                "RPM_CHANGELOG_EPOCH": "946728000",
                "RPM_VERSION_EXIT": "0",
                "RPM_ARCH_EXIT": "0",
                "RPM_BUILDTIME_EXIT": "0",
                "RPM_BUILDHOST_EXIT": "0",
                "RPM_CHANGELOGTIME_EXIT": "0",
            }
            tag_to_name = {
                "PREIN": "preinst.sh",
                "POSTIN": "postinst.sh",
                "PREUN": "prerm.sh",
                "POSTUN": "postrm.sh",
            }
            canonical_bodies = {
                "PREIN": (
                    "#!/bin/sh\n"
                    "set -eu\n"
                    'record="123:456"\n'
                    'pid="${record%%:*}"\n'
                    "printf '%s\\n' \"${pid}\""
                ),
                "POSTIN": "#!/bin/sh\nset -eu\nprintf '%s\\n' postinst",
                "PREUN": "#!/bin/sh\nset -eu\nprintf '%s\\n' prerm",
                "POSTUN": "#!/bin/sh\nset -eu\nprintf '%s\\n' postrm",
            }

            def validate(
                artifact_bodies: dict[str, str],
                *,
                source_bodies: dict[str, str] | None = None,
                programs: dict[str, str] | None = None,
                program_statuses: dict[str, str] | None = None,
                metadata_statuses: dict[str, str] | None = None,
                scriptlet_payload: str | None = None,
            ) -> subprocess.CompletedProcess[bytes]:
                sources = source_bodies or canonical_bodies
                interpreters = programs or {tag: "/bin/sh" for tag in tag_to_name}
                interpreter_statuses = program_statuses or {
                    tag: "0" for tag in tag_to_name
                }
                case_environment = dict(environment)
                for field, status in (metadata_statuses or {}).items():
                    case_environment[f"RPM_{field}_EXIT"] = status
                for tag, name in tag_to_name.items():
                    (package_scripts / name).write_text(sources[tag], encoding="utf-8")
                    artifact_path = artifact_scripts / name
                    if tag in artifact_bodies:
                        artifact_path.write_text(artifact_bodies[tag], encoding="utf-8")
                    else:
                        artifact_path.unlink(missing_ok=True)
                    case_environment[f"RPM_{tag}_FILE"] = str(artifact_path)
                    case_environment[f"RPM_{tag}_PROG"] = interpreters[tag]
                    case_environment[f"RPM_{tag}_PROG_EXIT"] = interpreter_statuses[
                        tag
                    ]
                if scriptlet_payload is None:
                    scriptlet_payload = "\n".join(artifact_bodies.values())
                scriptlets.write_text(scriptlet_payload, encoding="utf-8")
                return subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        "set -euo pipefail\nVERSION=4.02.14\nPACKAGE_SCRIPTS=\"$2\"\n"
                        + validate_rpm
                        + '\nvalidate_rpm "$1" x86_64',
                        "rpm-artifact-contract",
                        str(root / "candidate.rpm"),
                        str(package_scripts),
                    ],
                    check=False,
                    capture_output=True,
                    env=case_environment,
                )

            accepted = validate(dict(canonical_bodies))
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            trailing_newlines = {
                tag: f"{body}\n\n" for tag, body in canonical_bodies.items()
            }
            accepted = validate(
                trailing_newlines,
                source_bodies=trailing_newlines,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            for tag in tag_to_name:
                with self.subTest(mutation="one-byte-drift", tag=tag):
                    mutated = dict(canonical_bodies)
                    mutated[tag] += "x"
                    rejected = validate(mutated)
                    self.assertNotEqual(rejected.returncode, 0, rejected)
                with self.subTest(mutation="missing-body", tag=tag):
                    missing = dict(canonical_bodies)
                    del missing[tag]
                    rejected = validate(missing)
                    self.assertNotEqual(rejected.returncode, 0, rejected)
                with self.subTest(mutation="empty-body", tag=tag):
                    empty = dict(canonical_bodies)
                    empty[tag] = ""
                    rejected = validate(empty)
                    self.assertNotEqual(rejected.returncode, 0, rejected)

            transformed = dict(canonical_bodies)
            transformed["PREIN"] = transformed["PREIN"].replace("%%:*", "%:*")
            rejected = validate(transformed)
            self.assertNotEqual(rejected.returncode, 0, rejected)

            for tag in tag_to_name:
                with self.subTest(mutation="wrong-interpreter", tag=tag):
                    wrong_programs = {name: "/bin/sh" for name in tag_to_name}
                    wrong_programs[tag] = "/bin/bash"
                    rejected = validate(
                        dict(canonical_bodies), programs=wrong_programs
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected)
                with self.subTest(mutation="interpreter-query-failure", tag=tag):
                    failing_statuses = {name: "0" for name in tag_to_name}
                    failing_statuses[tag] = "92"
                    rejected = validate(
                        dict(canonical_bodies),
                        program_statuses=failing_statuses,
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected)

            for field in (
                "VERSION",
                "ARCH",
                "BUILDTIME",
                "BUILDHOST",
                "CHANGELOGTIME",
            ):
                with self.subTest(mutation="metadata-query-failure", field=field):
                    rejected = validate(
                        dict(canonical_bodies),
                        metadata_statuses={field: "92"},
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected)

            for forbidden in forbidden_tokens:
                with self.subTest(forbidden=forbidden):
                    bodies = dict(canonical_bodies)
                    bodies["POSTIN"] += f"\n{forbidden}"
                    rejected = validate(
                        bodies,
                        source_bodies=bodies,
                        scriptlet_payload="\n".join(bodies.values()),
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected)

    def test_package_removal_executes_barrier_without_touching_operator_cron(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            calls = root / "cli-calls"
            fake_cli = fake_bin / "syswarden-cli"
            fake_cli.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSWARDEN_TEST_CLI_CALLS\"\n",
                encoding="ascii",
            )
            fake_cli.chmod(0o700)
            cron_called = root / "crontab-called"
            fake_crontab = fake_bin / "crontab"
            fake_crontab.write_text(
                "#!/bin/sh\n: > \"$SYSWARDEN_TEST_CRONTAB_CALLED\"\nexit 99\n",
                encoding="ascii",
            )
            fake_crontab.chmod(0o700)
            operator_cron = root / "operator-cron"
            operator_bytes = b"19 4 * * * /usr/local/bin/operator --exact  value\n"
            operator_cron.write_bytes(operator_bytes)
            for name, source in (
                ("workflow", self.script("prerm.sh")),
                ("local", self.local_build_script("prerm.sh")),
            ):
                with self.subTest(script=name):
                    calls.unlink(missing_ok=True)
                    cron_called.unlink(missing_ok=True)
                    tail = source[source.rindex("export SYSWARDEN_PKG_INSTALL=1") :]
                    tail = tail.replace(
                        "/opt/syswarden/bin/syswarden-cli",
                        str(fake_cli),
                    )
                    environment = {
                        **os.environ,
                        "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                        "SYSWARDEN_TEST_CLI_CALLS": str(calls),
                        "SYSWARDEN_TEST_CRONTAB_CALLED": str(cron_called),
                    }
                    result = subprocess.run(
                        [
                            "/bin/sh",
                            "-c",
                            "syswarden_retire_legacy_webtui() { :; }\n" + tail,
                            "package-removal-cron-preservation",
                            "remove",
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(calls.read_text(encoding="ascii"), "prepare-package-removal\n")
                    self.assertFalse(cron_called.exists())
                    self.assertEqual(operator_cron.read_bytes(), operator_bytes)

    def test_active_package_builders_use_the_hidden_removal_barrier(self) -> None:
        for name, preremove in (
            ("workflow", self.script("prerm.sh")),
            ("local", self.local_build_script("prerm.sh")),
        ):
            with self.subTest(script=name):
                self.assertIn(
                    "/opt/syswarden/bin/syswarden-cli prepare-package-removal || exit 1",
                    preremove,
                )
                self.assertNotIn("syswarden_cleanup_crontab", preremove)
                self.assertNotIn("syswarden_read_crontab", preremove)
                self.assertNotIn("LC_ALL=C crontab", preremove)
                self.assertNotIn("grep -v 'syswarden-cli'", preremove)
                self.assertNotIn(
                    "grep -F -v '/opt/syswarden/bin/syswarden-cli'",
                    preremove,
                )

    def test_package_postremove_finalizes_the_exact_tombstone_last(self) -> None:
        for name, postremove in (
            ("workflow", self.script("postrm.sh")),
            ("local", self.local_build_script("postrm.sh")),
        ):
            with self.subTest(script=name):
                tail = postremove[postremove.index("syswarden_attest_state_root() {") :]
                self.assertIn(
                    "syswarden_finalize_removal_state_root || exit 1",
                    tail,
                )
                self.assertIn(
                    "SYSWARDEN_REMOVAL_V1\\nstate=in-progress\\n",
                    tail,
                )
                self.assertIn(
                    "Preserving root crontab and every modified or ambiguous legacy host artifact for manual recovery.",
                    tail,
                )
                self.assertNotIn("Removal completed", tail)
                self.assertNotIn("SUCCESS", tail)
                self.assertNotIn("syswarden_cleanup_crontab", tail)
                self.assertNotIn("syswarden_read_crontab", tail)
                self.assertNotIn("LC_ALL=C crontab", tail)
                executable_check = tail.index(
                    "for syswarden_binary in \\\n        /opt/syswarden/bin/syswarden-cli"
                )
                finalization_function = tail.index(
                    "syswarden_finalize_removal_state_root() {"
                )
                finalization_call = tail.index(
                    "syswarden_finalize_removal_state_root || exit 1"
                )
                self.assertLess(executable_check, finalization_function)
                self.assertLess(finalization_function, finalization_call)
                self.assertEqual(
                    tail.count(
                        "syswarden_finalize_removal_state_root || exit 1"
                    ),
                    1,
                )
                rename = tail.index(
                    'mv -- "${syswarden_active_barrier}" '
                    '"${syswarden_finalizing_barrier}"',
                    finalization_function,
                )
                rmdir = tail.index("rmdir -- /var/lib/syswarden", rename)
                unlink = tail.index(
                    'rm -f -- "${syswarden_finalizing_barrier}"', rmdir
                )
                recovery = tail.index("syswarden_resume_unmarked_terminal_state", rmdir)
                self.assertLess(rename, rmdir)
                self.assertLess(rmdir, unlink)
                self.assertLess(unlink, recovery)

    def test_linux_postinstall_does_not_treat_systemctl_presence_as_active_systemd(self) -> None:
        postinstall = self.script("postinst.sh")
        self.assertNotIn("systemd_running()", postinstall)
        self.assertIn("syswarden_classify_service_manager", postinstall)
        self.assertIn("AMBIGUOUS", postinstall)
        self.assertIn("OFFLINE", postinstall)
        self.assertNotIn("/opt/syswarden/bin/syswarden-cli reload", postinstall)
        active_branch = postinstall.index("ACTIVE)")
        offline_branch = postinstall.index("OFFLINE)", active_branch)
        install = postinstall.index("/opt/syswarden/bin/syswarden-cli install", active_branch)
        revalidate = postinstall.index(
            '[ "$(syswarden_classify_service_manager / "${manager}")" = ACTIVE ]',
            install,
        )
        self.assertLess(active_branch, install)
        self.assertLess(install, revalidate)
        self.assertLess(revalidate, offline_branch)

    def test_linux_packages_declare_every_runtime_dependency(self) -> None:
        for dependency in (
            "wireguard-tools",
            "qrencode",
            "jq",
        ):
            self.assertGreaterEqual(
                self.workflow.count(f'-d "{dependency}"'),
                2,
                dependency,
            )
        for dependency in ("checkpolicy", "policycoreutils-python-utils"):
            self.assertEqual(self.workflow.count(f'-d "{dependency}"'), 1)
        for dependency in (
            "wireguard-tools",
            "libqrencode-tools",
            "jq",
            "openrc",
            "cronie",
            "cronie-openrc",
        ):
            self.assertGreaterEqual(
                self.workflow.count(f"            - {dependency}\n"),
                1,
                dependency,
            )

        local = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        for dependency in ("unattended-upgrades", "apt-listchanges", "procps"):
            self.assertEqual(self.workflow.count(f'-d "{dependency}"'), 1, dependency)
            self.assertEqual(local.count(f'-d "{dependency}"'), 1, dependency)
        for dependency in ("dnf-automatic", "procps-ng"):
            self.assertEqual(self.workflow.count(f'-d "{dependency}"'), 1, dependency)
            self.assertEqual(local.count(f'-d "{dependency}"'), 1, dependency)
        self.assertEqual(self.workflow.count("            - procps-ng\n"), 1)
        self.assertEqual(local.count("  - procps-ng\n"), 1)
        self.assertEqual(self.workflow.count("            - shadow\n"), 1)
        self.assertEqual(local.count("  - shadow\n"), 1)

    def test_runtime_dependency_sets_match_all_package_generators_and_lab(self) -> None:
        local = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")

        def fpm_dependencies(source: str) -> set[str]:
            return set(re.findall(r'-d "([A-Za-z0-9+_.-]+)"', source))

        def yaml_dependencies(source: str) -> set[str]:
            block = source.split("depends:\n", 1)[1].split("\ncontents:\n", 1)[0]
            return set(re.findall(r"^\s+- ([A-Za-z0-9+_.-]+)$", block, re.MULTILINE))

        workflow_sets = {
            "deb": fpm_dependencies(workflow_step_script(self.workflow, "Build Debian Package (.deb)")),
            "rpm": fpm_dependencies(workflow_step_script(self.workflow, "Build RHEL Family Package (.rpm)")),
            "apk": yaml_dependencies(workflow_step_script(self.workflow, "Build Alpine Package (.apk)")),
        }
        local_sets = {
            "deb": fpm_dependencies(local.split("# Generate DEB", 1)[1].split("# Generate RPM", 1)[0]),
            "rpm": fpm_dependencies(local.split("# Generate RPM", 1)[1].split("# Generate Alpine APK", 1)[0]),
            "apk": yaml_dependencies(local.split("cat << EOF > nfpm_alpine_amd64.yaml", 1)[1]),
        }
        dependency_contract = package_lifecycle_lab.LIFECYCLE_SCRIPT.split(
            "expected_runtime_dependencies() {", 1
        )[1].split("\n}\n\npackage_runtime_dependencies() {", 1)[0]
        lab_sets: dict[str, set[str]] = {}
        for family in ("deb", "rpm", "apk"):
            case = dependency_contract.split(f"        {family})", 1)[1].split("            ;;", 1)[0]
            values = re.search(r"printf '%s\\n' ([^\n]+)", case)
            self.assertIsNotNone(values, family)
            lab_sets[family] = set(values.group(1).split())

        self.assertEqual(local_sets, workflow_sets)
        self.assertEqual(lab_sets, workflow_sets)

    def test_apk_fresh_and_upgrade_hooks_share_exact_pre_and_post_contracts(self) -> None:
        workflow_preinstall = 'preinstall: "${PACKAGE_SCRIPTS}/preinst.sh"'
        workflow_preupgrade = 'preupgrade: "${PACKAGE_SCRIPTS}/preinst.sh"'
        workflow_postinstall = 'postinstall: "${PACKAGE_SCRIPTS}/postinst.sh"'
        workflow_postupgrade = 'postupgrade: "${PACKAGE_SCRIPTS}/postinst.sh"'
        workflow_apk_hook = (
            "          apk:\n"
            "            scripts:\n"
            '              preupgrade: "${PACKAGE_SCRIPTS}/preinst.sh"\n'
            '              postupgrade: "${PACKAGE_SCRIPTS}/postinst.sh"\n'
        )
        self.assertEqual(self.workflow.count(workflow_preinstall), 1)
        self.assertEqual(self.workflow.count(workflow_preupgrade), 1)
        self.assertEqual(self.workflow.count(workflow_postinstall), 1)
        self.assertEqual(self.workflow.count(workflow_postupgrade), 1)
        self.assertEqual(self.workflow.count(workflow_apk_hook), 1)
        self.assertEqual(self.workflow.count("            - openrc\n"), 1)
        self.assertEqual(self.workflow.count("            - cronie\n"), 1)
        self.assertEqual(self.workflow.count("            - cronie-openrc\n"), 1)
        self.assertIn(".pre-install$/", self.workflow)
        self.assertIn(".pre-upgrade$/", self.workflow)
        self.assertIn(".post-install$/", self.workflow)
        self.assertIn(".post-upgrade$/", self.workflow)
        self.assertIn("^depend = openrc$", self.workflow)
        self.assertIn("^depend = cronie$", self.workflow)
        self.assertIn("^depend = cronie-openrc$", self.workflow)
        self.assertIn('"${preinstall_members[0]}"', self.workflow)
        self.assertIn('"${preupgrade_members[0]}"', self.workflow)
        self.assertIn('"${postinstall_members[0]}"', self.workflow)
        self.assertIn('"${postupgrade_members[0]}"', self.workflow)

        local = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(local.count('preinstall: "./preinst.sh"'), 1)
        self.assertEqual(local.count('preupgrade: "./preinst.sh"'), 1)
        self.assertEqual(local.count('postinstall: "./postinst.sh"'), 1)
        self.assertEqual(local.count('postupgrade: "./postinst.sh"'), 1)
        self.assertEqual(
            local.count(
                'apk:\n  scripts:\n    preupgrade: "./preinst.sh"\n'
                '    postupgrade: "./postinst.sh"\n'
            ),
            1,
        )
        self.assertEqual(local.count("  - openrc\n"), 1)
        self.assertEqual(local.count("  - cronie\n"), 1)
        self.assertEqual(local.count("  - cronie-openrc\n"), 1)

    def test_apk_archive_hook_validation_rejects_missing_drift_and_arch_mismatch(
        self,
    ) -> None:
        validation_step = workflow_step_script(
            self.workflow, "Validate Package Metadata"
        )
        validate_start = validation_step.index("validate_apk() {")
        invocation_start = validation_step.index("\nvalidate_deb ", validate_start)
        validate_function = validation_step[validate_start:invocation_start]

        hooks = {
            ".pre-install": b"#!/bin/sh\nprintf pre\n",
            ".pre-upgrade": b"#!/bin/sh\nprintf pre\n",
            ".post-install": b"#!/bin/sh\nprintf post\n",
            ".post-upgrade": b"#!/bin/sh\nprintf post\n",
        }

        def write_apk(
            path: Path,
            architecture: str,
            archive_hooks: dict[str, bytes],
        ) -> None:
            members = {
                ".PKGINFO": (
                    "pkgname = syswarden\n"
                    "pkgver = 4.02.14\n"
                    f"arch = {architecture}\n"
                    "depend = openrc\n"
                    "depend = cronie\n"
                    "depend = cronie-openrc\n"
                ).encode("utf-8"),
                **archive_hooks,
            }
            with tarfile.open(path, "w:gz") as archive:
                for name, content in members.items():
                    metadata = tarfile.TarInfo(name)
                    metadata.mode = 0o755 if name != ".PKGINFO" else 0o600
                    metadata.size = len(content)
                    archive.addfile(metadata, io.BytesIO(content))

        def validate(path: Path, architecture: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\nVERSION=4.02.14\n"
                    + validate_function
                    + '\nvalidate_apk "$1" "$2"',
                    "apk-archive-contract",
                    str(path),
                    architecture,
                ],
                check=False,
                capture_output=True,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            x86 = root / "syswarden_4.02.14_x86_64.apk"
            write_apk(x86, "x86_64", hooks)
            accepted = validate(x86, "x86_64")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            mutations = {
                "missing-preupgrade": {
                    name: content
                    for name, content in hooks.items()
                    if name != ".pre-upgrade"
                },
                "drifted-preupgrade": {
                    **hooks,
                    ".pre-upgrade": b"#!/bin/sh\nprintf drift\n",
                },
                "missing-postupgrade": {
                    name: content
                    for name, content in hooks.items()
                    if name != ".post-upgrade"
                },
            }
            for name, mutated_hooks in mutations.items():
                with self.subTest(mutation=name):
                    mutated = root / f"{name}.apk"
                    write_apk(mutated, "x86_64", mutated_hooks)
                    rejected = validate(mutated, "x86_64")
                    self.assertNotEqual(rejected.returncode, 0, rejected)

            wrong_arch = validate(x86, "unsupported")
            self.assertNotEqual(wrong_arch.returncode, 0, wrong_arch)

    def test_package_migration_state_machine_is_retry_safe_and_preserves_modular_bytes(self) -> None:
        platforms = (
            (
                "postinst.sh",
                "/opt/syswarden/bin/syswarden-cli",
                "/opt/syswarden/syswarden-auto.conf.migration_backup",
                "/opt/syswarden/syswarden-auto.conf.bak",
            ),
        )
        for script_name, cli_path, source_path, backup_path in platforms:
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cli = root / "syswarden-cli"
                calls = root / "calls"
                cli.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s\\n' \"$*\" >> {calls}\n"
                    "source_path=\noutput_path=\n"
                    "while [ \"$#\" -gt 0 ]; do\n"
                    "  case \"$1\" in\n"
                    "    --source) source_path=$2; shift 2 ;;\n"
                    "    --output) output_path=$2; shift 2 ;;\n"
                    "    *) shift ;;\n"
                    "  esac\n"
                    "done\n"
                    "mkdir -p \"${output_path}/modules\"\n"
                    "printf 'migrated\\n' > \"${output_path}/modules/40-integrations.toml\"\n"
                    "rm -f \"${output_path}/.migration-in-progress\"\n"
                    "if [ -f \"${source_path}\" ]; then mv \"${source_path}\" \"${source_path}.migrated\"; fi\n",
                    encoding="utf-8",
                )
                cli.chmod(0o700)
                config_root = root / "config"
                source = root / "legacy.migration_backup"
                backup = root / "legacy.bak"
                state_machine = self.migration_state_machine(script_name)
                state_machine = state_machine.replace(cli_path, str(cli))
                state_machine = state_machine.replace(source_path, str(source))
                state_machine = state_machine.replace(backup_path, str(backup))
                state_machine = state_machine.replace("/etc/syswarden/config", str(config_root))

                def run_state_machine() -> subprocess.CompletedProcess[str]:
                    return subprocess.run(
                        ["/bin/sh", "-c", "set -e\n" + state_machine],
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                source.write_text("legacy-fresh\n", encoding="utf-8")
                fresh = run_state_machine()
                self.assertEqual(fresh.returncode, 0, fresh)
                self.assertEqual(backup.read_text(encoding="utf-8"), "legacy-fresh\n")
                self.assertTrue(calls.exists())

                calls.unlink()
                backup.unlink()
                source.write_text("legacy-existing\n", encoding="utf-8")
                modules = config_root / "modules"
                modules.mkdir(parents=True, exist_ok=True)
                complete_modular_files = {
                    config_root / "config.toml": "master-byte-exact\n",
                    modules / "00-core.toml": "core-byte-exact\n",
                    modules / "10-network.toml": "network-byte-exact\n",
                    modules / "20-security.toml": "security-byte-exact\n",
                    modules / "30-waap.toml": "waap-byte-exact\n",
                    modules / "40-integrations.toml": "integrations-byte-exact\n",
                    modules / "99-user.toml": "user-byte-exact\n",
                }
                for path, content in complete_modular_files.items():
                    path.write_text(content, encoding="utf-8")
                preserved = run_state_machine()
                self.assertEqual(preserved.returncode, 0, preserved)
                self.assertFalse(calls.exists(), "existing modular config unexpectedly reran migration")
                for path, content in complete_modular_files.items():
                    self.assertEqual(path.read_text(encoding="utf-8"), content)
                self.assertEqual(backup.read_text(encoding="utf-8"), "legacy-existing\n")

                backup.unlink()
                source.write_text("legacy-retry\n", encoding="utf-8")
                (config_root / ".migration-in-progress").write_text("publishing\n", encoding="utf-8")
                retried = run_state_machine()
                self.assertEqual(retried.returncode, 0, retried)
                self.assertTrue(calls.exists(), "transaction marker did not force migration retry")
                self.assertFalse((config_root / ".migration-in-progress").exists())
                self.assertEqual(backup.read_text(encoding="utf-8"), "legacy-retry\n")

                calls.unlink()
                source.write_text("legacy-new\n", encoding="utf-8")
                backup.write_text("legacy-authoritative\n", encoding="utf-8")
                collision = run_state_machine()
                self.assertNotEqual(collision.returncode, 0, collision)
                self.assertEqual(source.read_text(encoding="utf-8"), "legacy-new\n")
                self.assertEqual(
                    backup.read_text(encoding="utf-8"), "legacy-authoritative\n"
                )
                self.assertFalse(calls.exists(), "archive collision unexpectedly ran migration")
                self.assertNotIn("legacy-new", collision.stderr)
                self.assertNotIn("legacy-authoritative", collision.stderr)

    def test_linux_state_machine_precedes_every_package_family_branch(self) -> None:
        postinstall = self.script("postinst.sh")
        invocation = postinstall.index("migrate_legacy_configuration\n")
        branch = 'if [ "$1" = "2" ] || [ "$1" = "1" ] || [ "$1" = "configure" ] || [ -f /etc/alpine-release ]; then'
        self.assertLess(invocation, postinstall.index(branch))

    def test_postinstall_propagates_install_failure_without_completion(self) -> None:
        for script_name, install_command in (
            ("postinst.sh", "/opt/syswarden/bin/syswarden-cli install"),
        ):
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as temporary:
                postinstall = self.script(script_name)
                self.assertLess(postinstall.index("set -e"), postinstall.index(install_command))
                self.assertNotIn(f"{install_command} || true", postinstall)

                fake_cli = Path(temporary) / "syswarden-cli"
                fake_cli.write_text(
                    "#!/bin/sh\nprintf '[ERROR] configuration preflight failed\\n' >&2\nexit 23\n",
                    encoding="utf-8",
                )
                fake_cli.chmod(0o700)
                probe = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        'set -e\n"$1" install\nprintf "Installation Complete\\n"',
                        "postinstall-probe",
                        str(fake_cli),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(probe.returncode, 23, probe)
                self.assertIn("[ERROR] configuration preflight failed", probe.stderr)
                self.assertNotIn("Installation Complete", probe.stdout)

    def test_completion_is_package_owned_and_postinstall_never_mutates_shell_startup(self) -> None:
        completion = "/usr/share/bash-completion/completions/syswarden"
        postinstall = self.script("postinst.sh")
        for forbidden in (
            "/etc/bash_completion.d/syswarden",
            "/root/.bashrc",
            "SysWarden Auto-Completion Hook",
            "completion bash > /etc",
        ):
            self.assertNotIn(forbidden, postinstall)

        workflow_stage = workflow_step_script(
            self.workflow, "Prepare Staging Environment (AMD64)"
        ) + workflow_step_script(self.workflow, "Build and Stage Static Alpine Binaries")
        self.assertEqual(workflow_stage.count("completion bash >"), 2)
        self.assertGreaterEqual(workflow_stage.count(completion), 2)
        local = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(local.count("completion bash >"), 2)
        self.assertGreaterEqual(local.count(completion), 2)
        self.assertIn(
            '"usr/share/bash-completion/completions/syswarden": ExpectedEntry(',
            (REPOSITORY / "scripts/ci/package_stage_gate.py").read_text(
                encoding="utf-8"
            ),
        )
        self.assertEqual(
            self.workflow.count(
                "--completion-contract scripts/ci/package_completion_contract.json"
            ),
            2,
        )
        self.assertEqual(
            local.count(
                '--completion-contract "${REPOSITORY_ROOT}/scripts/ci/'
                'package_completion_contract.json"'
            ),
            2,
        )
        stage_gate = (REPOSITORY / "scripts/ci/package_stage_gate.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("validate_exact_content", stage_gate)
        self.assertIn("contracted content SHA-256 mismatch", stage_gate)
        lifecycle_lab = (
            REPOSITORY / "scripts/ci/package_lifecycle_lab.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            "/opt/syswarden/bin/syswarden-cli completion bash > \\\n"
            "        /etc/bash_completion.d/syswarden",
            lifecycle_lab,
        )
        self.assertIn(
            "legacy_bash_completion_is_exact() {",
            lifecycle_lab,
        )
        self.assertIn(
            "package_owned_bash_completion_is_exact() {",
            lifecycle_lab,
        )
        for versioned_legacy_condition in (
            '[ "${EXPECTED_PREVIOUS_VERSION}" = 4.03.2 ]',
            '[ "${FORWARD_ONLY_APK_TRANSITION}" = 1 ]',
            '[ "${EXPECTED_PREVIOUS_VERSION}" = 4.02.8 ]',
            '[ "${EXPECTED_CANDIDATE_VERSION}" = 4.03.2 ]',
        ):
            self.assertIn(versioned_legacy_condition, lifecycle_lab)
        self.assertIn("completion-legacy-residual", lifecycle_lab)
        self.assertIn(
            "operator-owned ambiguous SysWarden completion",
            lifecycle_lab,
        )

    def test_final_removal_deletes_dedicated_state_only_for_purge_equivalents(self) -> None:
        postremove = self.script("postrm.sh")
        main = postremove[
            postremove.rindex(
                'if [ -f /etc/alpine-release ] || [ "$1" = "0" ] || '
                '[ "$1" = "remove" ] || [ "$1" = "purge" ]; then'
            ) :
        ].replace(
            "[ -f /etc/alpine-release ]",
            '[ "${SYSWARDEN_TEST_ALPINE:-0}" = 1 ]',
        )
        harness = (
            "cleanup_generated_runtime_artifacts() { printf 'cleanup\\n'; }\n"
            "syswarden_remove_exact_product_link() { printf 'link:%s\\n' \"$1\"; }\n"
            "syswarden_remove_exact_runtime_socket() { printf 'socket:%s\\n' \"$1\"; }\n"
            "syswarden_attest_dedicated_root() { :; }\n"
            "syswarden_refuse_mounted_path_tree() { :; }\n"
            "syswarden_select_removal_barrier() { "
            "syswarden_active_barrier=barrier; printf 'barrier\\n'; }\n"
            "syswarden_attest_removal_marker() { :; }\n"
            "syswarden_remove_dedicated_root() { printf 'root:%s\\n' \"$1\"; }\n"
            "syswarden_empty_removal_state() { printf 'state-empty\\n'; }\n"
            "syswarden_finalize_removal_state_root() { printf 'tombstone-root\\n'; }\n"
            "syswarden_resume_unmarked_terminal_state() { printf 'terminal-retry\\n'; }\n"
            "syswarden_transition_to_deferred_purge() { printf 'deferred\\n'; }\n"
            + main
        )
        matrix = (
            ("deb-remove", "remove", False, False),
            ("deb-purge", "purge", False, True),
            ("rpm-final-erase", "0", False, True),
            ("rpm-upgrade", "1", False, None),
            ("apk-post-deinstall", "4.03.3", True, True),
        )
        for name, argument, alpine, destructive in matrix:
            with self.subTest(case=name):
                environment = {**os.environ, "SYSWARDEN_TEST_ALPINE": "1" if alpine else "0"}
                result = subprocess.run(
                    ("/bin/sh", "-c", harness, name, argument),
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(result.returncode, 0, result)
                calls = result.stdout.splitlines()
                if destructive is None:
                    self.assertEqual(calls, [])
                    continue
                log_call = "root:/var/log/syswarden"
                if destructive:
                    self.assertIn("barrier", calls)
                    self.assertIn("root:/opt/syswarden", calls)
                    self.assertIn("root:/etc/syswarden", calls)
                    self.assertIn(log_call, calls)
                    self.assertIn("state-empty", calls)
                    self.assertIn("tombstone-root", calls)
                    self.assertLess(calls.index(log_call), calls.index("state-empty"))
                    self.assertLess(calls.index("state-empty"), calls.index("tombstone-root"))
                else:
                    self.assertIn("deferred", calls)
                    self.assertNotIn("barrier", calls)
                    self.assertNotIn("root:/opt/syswarden", calls)
                    self.assertNotIn("root:/etc/syswarden", calls)
                    self.assertNotIn(log_call, calls)
                    self.assertNotIn("state-empty", calls)
                    self.assertNotIn("tombstone-root", calls)

    def test_no_package_rollback_implementation_is_claimed(self) -> None:
        scripts = "\n".join(
            self.script(name)
            for name in (
                "preinst.sh",
                "postinst.sh",
                "prerm.sh",
                "postrm.sh",
            )
        )
        self.assertNotRegex(scripts.lower(), r"\brollback\b")

    def test_package_artifact_upload_is_github_strict_and_act_compatible(self) -> None:
        github_sha = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        act_sha = "ea165f8d65b6e75b540449e92b4886f43607fa02"
        self.assertEqual(self.workflow.count(f"actions/upload-artifact@{github_sha}"), 1)
        self.assertEqual(self.workflow.count(f"actions/upload-artifact@{act_sha}"), 1)
        self.assertIn("if: ${{ !github.event.act }}", self.workflow)
        self.assertIn("if: ${{ github.event.act }}", self.workflow)
        self.assertIn("ACTIONS_ARTIFACT_UPLOAD_CONCURRENCY: '1'", self.workflow)
        self.assertEqual(self.workflow.count("name: syswarden-packages-${{ env.VERSION }}"), 2)

    def test_apk_metadata_accepts_only_equivalent_numeric_version_components(self) -> None:
        self.assertIn('package_version="$(sed -n \'s/^pkgver = //p\'', self.workflow)
        self.assertIn('pattern = re.compile(r"^[0-9]+(?:\\.[0-9]+){2}$")', self.workflow)
        self.assertIn(
            'normalize = lambda value: tuple(int(part) for part in value.split("."))',
            self.workflow,
        )
        self.assertIn('[[ "${package_architecture}" == "${architecture}" ]]', self.workflow)

    def test_package_formats_use_their_exact_linux_binary_variants(self) -> None:
        build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
        local_builder = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("BuildMode = 'pie'", build_script)
        self.assertNotIn("-ldflags=-s -w -d", build_script)
        self.assertIn("validate_linux_pie", self.workflow)
        self.assertIn("validate_static_apk_binary", self.workflow)
        self.assertIn("STAGING_APK_AMD64", self.workflow)
        self.assertIn('elf_type}" == "EXEC"', self.workflow)
        self.assertIn("CGO_ENABLED=0", self.workflow)
        self.assertIn(
            '"${STAGING_APK_AMD64}/opt/syswarden/bin/syswarden-cli" --help',
            self.workflow,
        )
        self.assertIn(
            "docker.io/library/alpine:3.22@sha256:"
            "7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6",
            self.workflow,
        )
        self.assertIn("/usr/local/bin/syswarden --help", self.workflow)
        self.assertEqual(self.workflow.count('-C "${STAGING_AMD64}" .'), 2)
        self.assertIn('- src: "${STAGING_APK_AMD64}/opt"', self.workflow)

        static_build = local_builder[
            local_builder.index('echo " -> Compiling static Alpine ${module}..."') :
            local_builder.index("\ndone\n", local_builder.index('echo " -> Compiling static Alpine ${module}..."'))
        ]
        self.assertIn('dist/bin-apk/${module}', static_build)
        self.assertIn("-mod=readonly -ldflags", static_build)
        self.assertNotIn("-buildmode=pie", static_build)
        self.assertIn("validate_static_apk_binary()", local_builder)
        self.assertIn('[ "${elf_type}" = "EXEC" ]', local_builder)
        self.assertIn("CGO_ENABLED=0", local_builder)
        self.assertIn("staging-apk/opt/syswarden/bin/syswarden-cli --help", local_builder)
        self.assertEqual(local_builder.count("package_stage_gate.py"), 2)
        self.assertIn("linux --root staging-apk", local_builder)
        self.assertIn('- src: "./staging-apk/opt"', local_builder)
        self.assertIn('- src: "./staging-apk/usr"', local_builder)
        self.assertNotIn('- src: "./staging/opt"\n    dst: "/opt"', local_builder)

    def test_universal_build_inventory_matches_linux_only_matrix(self) -> None:
        build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
        inventory = build_script.split(
            "function Assert-ExactDistInventory {", 1
        )[1].split("\n}\n\nWrite-Host", 1)[0]
        for variable in (
            "ExpectedFiles",
            "ExpectedDirectories",
            "ActualFiles",
            "ActualDirectories",
        ):
            self.assertIn(f"${variable} = @(\n        @(", inventory)
        self.assertEqual(inventory.count(") | Sort-Object\n    )"), 4)
        self.assertEqual(build_script.count("Name = 'Linux "), 1)
        self.assertEqual(build_script.count("Name = 'syswarden-"), 3)
        self.assertIn("if ($VerifiedArtifactCount -ne 3)", build_script)
        self.assertIn(
            'throw "Build verification expected 3 binaries but verified '
            '$VerifiedArtifactCount."',
            build_script,
        )
        self.assertIn("the exact 4-file AMD64 distribution inventory", build_script)
        self.assertNotIn("expected 9 binaries", build_script)
        self.assertNotIn("exact 11-file distribution inventory", build_script)


if __name__ == "__main__":
    unittest.main()
