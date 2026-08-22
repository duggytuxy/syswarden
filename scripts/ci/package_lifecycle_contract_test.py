#!/usr/bin/env python3
"""Characterize package lifecycle scripts without mutating a host."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import signal
import socket
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
            body = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8") + "\n" + body
        return body

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
            body = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8") + "\n" + body
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

    def cron_functions(self, script: str) -> str:
        start = script.index("syswarden_managed_cron_line() {")
        cleanup = script.index("syswarden_cleanup_crontab() {", start)
        end = script.index("\n}\n", cleanup) + len("\n}\n")
        return script[start:end]

    def cron_script_matrix(self) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
        linux_paths = ("/opt/syswarden/bin/syswarden-cli",)
        return (
            ("workflow-prerm", self.script("prerm.sh"), linux_paths),
            ("workflow-postrm", self.script("postrm.sh"), linux_paths),
            ("local-build-prerm", self.local_build_script("prerm.sh"), linux_paths),
        )

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
            'syswarden_${VERSION}_arm64.deb',
            "syswarden-${VERSION}-1.x86_64.rpm",
            "syswarden-${VERSION}-1.aarch64.rpm",
            'syswarden_${VERSION}_x86_64.apk',
            'syswarden_${VERSION}_aarch64.apk',
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
            ("STAGING_ARM64", "staging-arm64"),
            ("STAGING_APK_AMD64", "staging-apk-amd64"),
            ("STAGING_APK_ARM64", "staging-apk-arm64"),
            ("PACKAGE_ASSETS", "assets"),
            ("PACKAGE_SCRIPTS", "scripts"),
            ("PACKAGE_CONFIGS", "configs"),
        ):
            with self.subTest(variable=variable):
                self.assertIn(
                    f'{variable}="${{PACKAGE_WORKSPACE}}/{suffix}"',
                    self.workflow,
                )

        self.assertEqual(
            self.workflow.count("scripts/ci/package_stage_gate.py"),
            4,
        )
        for platform, root in (
            ("linux", "STAGING_AMD64"),
            ("linux", "STAGING_ARM64"),
            ("linux", "STAGING_APK_AMD64"),
            ("linux", "STAGING_APK_ARM64"),
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
        compile_step = self.workflow.index("Compile Universal Script")
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
        self.assertNotIn("staging_arm64", self.workflow)

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
        workflow_validation = workflow_step_script(
            self.workflow, "Validate Package Metadata"
        )
        local_deb = local.split("# Generate DEB", 1)[1].split(
            "# Generate RPM", 1
        )[0]
        local_rpm = local.split("# Generate RPM", 1)[1].split(
            "# Generate Alpine APK", 1
        )[0]

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
            "STAGING_ARM64",
            "STAGING_APK_AMD64",
            "STAGING_APK_ARM64",
            "PACKAGE_SCRIPTS",
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
            (workflow_deb, 2),
            (workflow_rpm, 2),
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
                self.assertEqual(workflow_rpm.count(flag), 2)
                self.assertEqual(local_rpm.count(flag), 1)
        self.assertEqual(workflow_rpm.count('--rpm-changelog "${RPM_CHANGELOG}"'), 2)
        self.assertEqual(local_rpm.count('--rpm-changelog "${RPM_CHANGELOG}"'), 1)
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
                        "VERSION": "4.03.1",
                    },
                )
                self.assertEqual(generated.returncode, 0, generated)
                changelog_epochs.append(int(generated.stdout))
                self.assertEqual(
                    destination.read_text(encoding="utf-8"),
                    f"* {expected_date} SysWarden Engineering - 4.03.1-1\n"
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
            'syswarden_${VERSION}_arm64.deb',
            "syswarden-${VERSION}-1.x86_64.rpm",
            "syswarden-${VERSION}-1.aarch64.rpm",
            'syswarden_${VERSION}_x86_64.apk',
            'syswarden_${VERSION}_aarch64.apk',
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
        self.assertIn("reload --no-restart", postinstall)
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
        self.assertIn('kill -0 "${syswarden_retire_pid}"', helper)
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

    def test_package_hooks_inject_retirement_before_replacement_or_removal(self) -> None:
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
        self.assertLess(
            workflow_preinstall.index("syswarden_retire_legacy_webtui / || exit 1"),
            workflow_preinstall.index("mv /opt/syswarden/syswarden-auto.conf"),
        )
        self.assertLess(
            workflow_preremove.index("syswarden_retire_legacy_webtui / || exit 1"),
            workflow_preremove.index(
                "if [ -f /etc/alpine-release ]; then manager=openrc"
            ),
        )
        self.assertLess(
            workflow_preremove.index(
                'case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in'
            ),
            workflow_preremove.index("syswarden_retire_legacy_webtui / || exit 1"),
        )
        for source in (self.workflow, LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")):
            self.assertIn("scripts/ci/package_webtui_retirement.sh", source)

    def test_preremove_argument_matrix_retires_only_true_deletion(self) -> None:
        scripts = (
            ("workflow", self.script("prerm.sh")),
            ("local", self.local_build_script("prerm.sh")),
        )
        matrix = (
            ("rpm-final-erase", "0", None, None, 0, "retired\n"),
            ("rpm-upgrade", "1", None, None, 0, ""),
            ("rpm-downgrade", "1", None, None, 0, ""),
            ("rpm-multiple-installed", "2", None, None, 0, ""),
            ("rpm-malformed-count", "1x", None, None, 1, ""),
            ("rpm-negative-count", "-1", None, None, 1, ""),
            ("rpm-missing-count", "", None, None, 1, ""),
            ("deb-remove", "remove", None, None, 0, "retired\n"),
            ("deb-purge", "purge", None, None, 0, "retired\n"),
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
                "retired\n",
            ),
            (
                "apk-pre-deinstall-version",
                "4.3.0",
                "syswarden",
                "pre-deinstall",
                0,
                "retired\n",
            ),
            (
                "apk-pre-deinstall-later-version",
                "10.0.14",
                "syswarden",
                "pre-deinstall",
                0,
                "retired\n",
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
                "apk-transition-hook",
                "4.3.0",
                "syswarden",
                "pre-upgrade",
                1,
                "",
            ),
        )
        for source_name, script in scripts:
            start = script.index(
                'case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in'
            )
            end = script.index("\nsyswarden_managed_cron_line() {", start)
            gate = script[start:end].replace(
                "[ -f /etc/alpine-release ]",
                '[ "${SYSWARDEN_TEST_ALPINE:-}" = 1 ]',
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
        for name in ("preinst.sh", "postinst.sh", "prerm.sh", "postrm.sh"):
            with self.subTest(script=name):
                workflow = self.script(name).encode("utf-8")
                local = self.local_build_script(name).encode("utf-8")
                self.assertEqual(local, workflow)
                self.assertTrue(workflow.startswith(b"#!/bin/sh\n"))
                if name in {"preinst.sh", "postinst.sh", "prerm.sh"}:
                    self.assertEqual(
                        workflow.count(b"syswarden_retire_legacy_webtui / || exit 1"),
                        1 if name != "postinst.sh" else 0,
                    )

    def test_linux_remove_and_purge_contract(self) -> None:
        preremove = self.script("prerm.sh")
        self.assertNotIn("/tmp/sw_cron.bak", preremove)
        self.assertIn("mktemp -d /var/tmp/syswarden-cron.XXXXXX", preremove)
        self.assertIn("umask 077", preremove)
        self.assertIn(
            'cron_backup="${cron_work}/backup"',
            preremove,
        )
        self.assertIn('cron_error="${cron_work}/error"', preremove)
        self.assertIn('cron_filtered="${cron_work}/filtered"', preremove)
        self.assertIn('chmod 0700 "${cron_work}"', preremove)
        self.assertNotIn('${cron_backup}.error', preremove)
        self.assertNotIn('${cron_backup}.filtered', preremove)
        self.assertIn("syswarden_cleanup_crontab", preremove)
        self.assertIn(
            '"*/30 * * * * ${syswarden_cron_cli} ha-sync >/dev/null 2>&1"',
            preremove,
        )
        self.assertIn(
            '"${syswarden_cron_minute} * * * * ${syswarden_cron_cli} update-feeds >/dev/null 2>&1"',
            preremove,
        )
        self.assertIn("/opt/syswarden/bin/syswarden-cli || exit 1", preremove)
        self.assertNotIn(
            "grep -F -v '/opt/syswarden/bin/syswarden-cli'", preremove
        )
        self.assertNotIn("grep -v 'syswarden-cli'", preremove)
        postremove = self.script("postrm.sh")
        gate = preremove[
            preremove.index(
                'case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in'
            ) : preremove.index("\nsyswarden_managed_cron_line() {")
        ]
        self.assertIn("::0|::remove|::purge)", gate)
        self.assertIn("::*grade|::reinstall|::deconfigure) exit;;", gate)
        self.assertIn("syswarden:pre-deinstall:*|::*.*.*)", gate)
        self.assertIn("^[1-9][0-9]*", gate)
        self.assertIn("*) exit 1;;", gate)
        self.assertIn("[ -f /etc/alpine-release ]", gate)
        for service in (
            "syswarden-core.service",
            "syswarden-firewall.service",
        ):
            self.assertIn(service, preremove)
        for broad_retired_manager_action in (
            "systemctl stop syswarden-webtui.service",
            "systemctl disable syswarden-webtui.service",
            "rc-service syswarden-webtui stop",
            "rc-update del syswarden-webtui default",
        ):
            native_removal = preremove[
                preremove.index(
                    "if [ -f /etc/alpine-release ]; then manager=openrc"
                ) :
            ]
            self.assertNotIn(broad_retired_manager_action, native_removal)
        for table in (
            "netdev syswarden_hw_drop",
            "arp syswarden_arp",
            "inet syswarden",
        ):
            self.assertIn(f"nft delete table {table}", preremove)
        self.assertIn('[ "$1" = "0" ]', postremove)
        self.assertIn('[ "$1" = "purge" ]', postremove)
        self.assertIn('[ "$1" = "remove" ]', postremove)
        self.assertIn("[ -f /etc/alpine-release ]", postremove)
        self.assertIn("rm -rf /opt/syswarden", postremove)
        self.assertIn("rm -rf /etc/syswarden", postremove)
        self.assertIn("cleanup_generated_runtime_artifacts", postremove)
        helper = WEBTUI_RETIREMENT_HELPER.read_text(encoding="utf-8")
        self.assertIn('syswarden_remove_exact_product_services "${manager}"', postremove)
        for generated in (
            "/etc/systemd/system/syswarden-core.service",
            "/etc/systemd/system/syswarden-firewall.service",
            "/etc/init.d/syswarden-core",
            "/etc/init.d/syswarden-firewall",
        ):
            self.assertIn(generated, helper)
        for generated in (
            "/etc/bash_completion.d/syswarden",
            "/etc/rsyslog.d/99-syswarden-siem.conf",
            "/etc/rsyslog.d/99-syswarden-waf-bridge.conf",
        ):
            self.assertIn(generated, postremove)
        self.assertIn("syswarden_verify_webtui_retirement", postremove)
        self.assertIn("syswarden_cleanup_crontab", postremove)
        self.assertIn("cleanup_generated_runtime_artifacts || exit 1", postremove)
        self.assertNotIn("grep -F -v '/opt/syswarden/bin/syswarden-cli'", postremove)
        self.assertIn("syswarden_classify_service_manager", postremove)
        self.assertIn("OFFLINE) : ;;", postremove)

    def test_package_cron_filters_are_exact_and_preserve_operator_bytes(self) -> None:
        for name, script, managed_paths in self.cron_script_matrix():
            functions = self.cron_functions(script)
            self.assertNotIn("syswarden_cron_candidate%", functions)
            self.assertIn(
                'printf \'%s\\n\' "${syswarden_cron_candidate}" | '
                "awk 'NR == 1 { print $1; exit }'",
                functions,
            )
            managed_lines = [
                line
                for path in managed_paths
                for line in (
                    f"*/30 * * * * {path} ha-sync >/dev/null 2>&1",
                    f"17 * * * * {path} update-feeds >/dev/null 2>&1",
                )
            ]
            primary = managed_paths[0]
            survivors = [
                "# operator note mentioning syswarden-cli",
                f"19 4 * * * {primary} update-feeds --operator-option",
                " " + managed_lines[0],
                managed_lines[1] + " ",
                managed_lines[1].replace("17 *", "17  *", 1),
                managed_lines[0].replace("*/30 *", "*/30\t*", 1),
                " \t ",
            ]
            alternate = (
                "23 * * * * /srv/operator/bin/syswarden-cli "
                "update-feeds >/dev/null 2>&1"
            )
            if "/srv/operator/bin/syswarden-cli" not in managed_paths:
                survivors.append(alternate)
            input_lines = [survivors[0], *managed_lines, *survivors[1:]]
            if alternate not in input_lines:
                input_lines.append(alternate)
            variants = (
                ("source", functions),
                ("rpm-scriptlet", functions.replace("%%", "%")),
            )
            for variant, executable_functions in variants:
                for final_lf in (False, True):
                    with self.subTest(
                        script=name,
                        variant=variant,
                        final_lf=final_lf,
                    ), tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        source = root / "input"
                        destination = root / "output"
                        source_bytes = "\n".join(input_lines).encode("utf-8")
                        if final_lf:
                            source_bytes += b"\n"
                        managed_candidates = set(managed_lines)
                        if "/srv/operator/bin/syswarden-cli" in managed_paths:
                            managed_candidates.add(alternate)
                        expected = b""
                        for index, line in enumerate(input_lines):
                            if line in managed_candidates:
                                continue
                            expected += line.encode("utf-8")
                            if index < len(input_lines) - 1 or final_lf:
                                expected += b"\n"
                        source.write_bytes(source_bytes)
                        result = subprocess.run(
                            [
                                "/bin/sh",
                                "-c",
                                executable_functions
                                + '\nsyswarden_cron_source="$1"\n'
                                + 'syswarden_cron_destination="$2"\n'
                                + "shift 2\n"
                                + 'syswarden_filter_crontab "${syswarden_cron_source}" '
                                + '"${syswarden_cron_destination}" "$@"',
                                "cron-filter-contract",
                                str(source),
                                str(destination),
                                *managed_paths,
                            ],
                            check=False,
                            capture_output=True,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(destination.read_bytes(), expected)

    def test_rpm_scriptlet_transform_rejects_percent_and_awk_mutations(self) -> None:
        functions = self.cron_functions(self.script("prerm.sh"))
        extraction = (
            'syswarden_cron_minute="$(printf \'%s\\n\' '
            '"${syswarden_cron_candidate}" | '
            "awk 'NR == 1 { print $1; exit }')\""
        )
        self.assertEqual(functions.count(extraction), 1)

        managed = (
            "17 * * * * /opt/syswarden/bin/syswarden-cli "
            "update-feeds >/dev/null 2>&1\n"
        )

        def filtered_bytes(candidate_functions: str) -> bytes:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "input"
                destination = root / "output"
                source.write_bytes(managed.encode("utf-8"))
                result = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        candidate_functions.replace("%%", "%")
                        + '\nsyswarden_cron_source="$1"\n'
                        + 'syswarden_cron_destination="$2"\n'
                        + 'syswarden_filter_crontab "${syswarden_cron_source}" '
                        + '"${syswarden_cron_destination}" '
                        + '"/opt/syswarden/bin/syswarden-cli"',
                        "rpm-scriptlet-contract",
                        str(source),
                        str(destination),
                    ],
                    check=False,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return destination.read_bytes()

        self.assertEqual(filtered_bytes(functions), b"")
        legacy_percent = functions.replace(
            extraction,
            'syswarden_cron_minute="${syswarden_cron_candidate%% *}"',
        )
        wrong_awk_field = functions.replace("print $1; exit", "print $2; exit")
        self.assertEqual(filtered_bytes(legacy_percent), managed.encode("utf-8"))
        self.assertEqual(filtered_bytes(wrong_awk_field), managed.encode("utf-8"))

    def test_rpm_artifact_gate_rejects_transformed_scriptlet_mutations(self) -> None:
        validation_step = workflow_step_script(
            self.workflow, "Validate Package Metadata"
        )
        function_start = validation_step.index("validate_rpm() {")
        function_end = validation_step.index("\nvalidate_apk() {", function_start)
        validate_rpm = validation_step[function_start:function_end]
        self.assertIn("rpm --query --package --scripts", validate_rpm)
        self.assertIn("grep --fixed-strings --count", validate_rpm)
        self.assertIn("'${syswarden_cron_candidate%'", validate_rpm)

        expected = (
            'syswarden_cron_minute="$(printf \'%s\\n\' '
            '"${syswarden_cron_candidate}" | '
            "awk 'NR == 1 { print $1; exit }')\""
        )
        legacy = 'syswarden_cron_minute="${syswarden_cron_candidate% *}"'
        wrong_awk = expected.replace("print $1; exit", "print $2; exit")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
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
                "  '%{VERSION}') printf 4.02.14 ;;\n"
                "  '%{ARCH}') printf x86_64 ;;\n"
                "  '%{BUILDTIME}') printf '%s' \"${SOURCE_DATE_EPOCH}\" ;;\n"
                "  '%{BUILDHOST}') printf syswarden-build.invalid ;;\n"
                "  '%{CHANGELOGTIME}') printf '%s' \"${RPM_CHANGELOG_EPOCH}\" ;;\n"
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
            }

            def validate(payload: str) -> subprocess.CompletedProcess[bytes]:
                scriptlets.write_text(payload, encoding="utf-8")
                return subprocess.run(
                    [
                        "/bin/bash",
                        "-c",
                        "set -euo pipefail\nVERSION=4.02.14\n"
                        + validate_rpm
                        + '\nvalidate_rpm "$1" x86_64',
                        "rpm-artifact-contract",
                        str(root / "candidate.rpm"),
                    ],
                    check=False,
                    capture_output=True,
                    env=environment,
                )

            accepted = validate(f"{expected}\n{expected}\n")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            for name, payload in (
                ("single-helper", f"{expected}\n"),
                ("legacy-percent", f"{legacy}\n{legacy}\n"),
                ("wrong-awk-field", f"{wrong_awk}\n{wrong_awk}\n"),
            ):
                with self.subTest(mutation=name):
                    rejected = validate(payload)
                    self.assertNotEqual(rejected.returncode, 0, rejected)

    def test_package_cron_cleanup_distinguishes_absence_and_errors(self) -> None:
        matrix = self.cron_script_matrix()
        reference = self.cron_functions(matrix[0][1])
        for name, script, _paths in matrix[1:]:
            with self.subTest(shared_helper=name):
                self.assertEqual(self.cron_functions(script), reference)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_crontab = fake_bin / "crontab"
            fake_crontab.write_text(
                "#!/bin/sh\n"
                "record_cronie_backup() {\n"
                "  [ \"${CRONTAB_CREATE_BACKUP:-0}\" -eq 1 ] || return 0\n"
                "  [ -n \"${XDG_CACHE_HOME:-}\" ] || return 96\n"
                "  mkdir -p \"${XDG_CACHE_HOME}/crontab\" || return 1\n"
                "  printf 'previous cron\\n' > \"${XDG_CACHE_HOME}/crontab/crontab.bak\" || return 1\n"
                "  printf '%s' \"${XDG_CACHE_HOME}\" > \"${CRONTAB_CACHE_PATH_OUTPUT}\" || return 1\n"
                "}\n"
                "case \"${1:-}\" in\n"
                "  -l)\n"
                "    if [ -e \"${CRONTAB_REMOVED_MARKER}\" ]; then\n"
                "      printf '%s' \"${CRONTAB_VERIFY_STDOUT:-}\"\n"
                "      printf '%s' \"${CRONTAB_VERIFY_STDERR:-}\" >&2\n"
                "      exit \"${CRONTAB_VERIFY_RC:-1}\"\n"
                "    fi\n"
                "    printf '%s' \"${CRONTAB_STDOUT:-}\"\n"
                "    printf '%s' \"${CRONTAB_STDERR:-}\" >&2\n"
                "    exit \"${CRONTAB_READ_RC:-0}\"\n"
                "    ;;\n"
                "  -r)\n"
                "    record_cronie_backup || exit $?\n"
                "    crontab_remove_rc=${CRONTAB_REMOVE_RC:-0}\n"
                "    if [ \"${crontab_remove_rc}\" -eq 0 ]; then\n"
                "      : > \"${CRONTAB_REMOVED_MARKER}\"\n"
                "      if [ \"${CRONTAB_REMOVE_SPOOL:-0}\" -eq 1 ] && "
                "[ -n \"${SYSWARDEN_CRON_ABSENCE_SPOOL:-}\" ]; then\n"
                "        rm -f -- \"${SYSWARDEN_CRON_ABSENCE_SPOOL}\"\n"
                "      fi\n"
                "    fi\n"
                "    exit \"${crontab_remove_rc}\"\n"
                "    ;;\n"
                "  -)\n"
                "    record_cronie_backup || exit $?\n"
                "    cat > \"${CRONTAB_WRITE_OUTPUT}\"\n"
                "    exit \"${CRONTAB_WRITE_RC:-0}\"\n"
                "    ;;\n"
                "  *) exit 97 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_crontab.chmod(0o700)
            fake_cmp = fake_bin / "cmp"
            real_cmp = shutil.which("cmp")
            self.assertIsNotNone(real_cmp)
            fake_cmp.write_text(
                "#!/bin/sh\n"
                "if [ -n \"${CMP_FORCE_RC:-}\" ]; then\n"
                "  exit \"${CMP_FORCE_RC}\"\n"
                "fi\n"
                f'exec "{real_cmp}" "$@"\n',
                encoding="utf-8",
            )
            fake_cmp.chmod(0o700)
            fake_mktemp = fake_bin / "mktemp"
            real_mktemp = shutil.which("mktemp")
            self.assertIsNotNone(real_mktemp)
            fake_mktemp.write_text(
                "#!/bin/sh\n"
                "[ \"$#\" -eq 2 ] || exit 95\n"
                "[ \"$1\" = -d ] || exit 95\n"
                "[ \"$2\" = /var/tmp/syswarden-cron.XXXXXX ] || exit 95\n"
                "[ -n \"${SYSWARDEN_TEST_MKTEMP_ROOT:-}\" ] || exit 94\n"
                f'exec "{real_mktemp}" -d '
                '"${SYSWARDEN_TEST_MKTEMP_ROOT}/syswarden-cron.XXXXXX"\n',
                encoding="utf-8",
            )
            fake_mktemp.chmod(0o700)
            backup = root / "backup"
            error = root / "error"
            filtered = root / "filtered"
            written = root / "written"
            removed = root / "removed"
            command = [
                "/bin/sh",
                "-c",
                reference
                + '\nsyswarden_cleanup_crontab "$1" "$2" "$3" "$4"',
                "cron-cleanup-contract",
                str(backup),
                str(error),
                str(filtered),
                "/opt/syswarden/bin/syswarden-cli",
            ]

            def run_cleanup(**updates: str) -> subprocess.CompletedProcess[bytes]:
                written.unlink(missing_ok=True)
                removed.unlink(missing_ok=True)
                environment = os.environ.copy()
                environment.update(
                    {
                        "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
                        "CRONTAB_WRITE_OUTPUT": str(written),
                        "CRONTAB_CACHE_PATH_OUTPUT": str(root / "cache-path"),
                        "CRONTAB_CREATE_BACKUP": "0",
                        "CRONTAB_REMOVED_MARKER": str(removed),
                        "CRONTAB_READ_RC": "0",
                        "CRONTAB_WRITE_RC": "0",
                        "CRONTAB_REMOVE_RC": "0",
                        "CRONTAB_REMOVE_SPOOL": "0",
                        "CRONTAB_STDOUT": "",
                        "CRONTAB_STDERR": "",
                        "CRONTAB_VERIFY_RC": "1",
                        "CRONTAB_VERIFY_STDOUT": "",
                        "CRONTAB_VERIFY_STDERR": "no crontab for root\n",
                        "CMP_FORCE_RC": "",
                        "SYSWARDEN_CRON_ABSENCE_SPOOL": "",
                        "SYSWARDEN_TEST_MKTEMP_ROOT": str(root),
                        **updates,
                    }
                )
                return subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    env=environment,
                )

            for message in (
                "no crontab for root",
                "crontab: no crontab for root",
                "crontab: can't open 'root': No such file or directory",
            ):
                for terminator in ("", "\n"):
                    with self.subTest(absence=message, terminator=repr(terminator)):
                        result = run_cleanup(
                            CRONTAB_READ_RC="1",
                            CRONTAB_STDERR=message + terminator,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertFalse(written.exists())
                        self.assertFalse(removed.exists())

            spool = root / "root-spool"
            spool.write_text("operator cron\n", encoding="utf-8")
            result = run_cleanup(
                CRONTAB_READ_RC="1",
                CRONTAB_STDERR="crontab: no crontab for root\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(written.exists())
            spool.unlink()
            spool.symlink_to(root / "missing-spool-target")
            result = run_cleanup(
                CRONTAB_READ_RC="1",
                CRONTAB_STDERR="crontab: no crontab for root\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(written.exists())
            spool.unlink()

            for read_rc, stdout, message in (
                ("1", "", "permission denied\n"),
                ("1", "", "no crontab for root\nextra diagnostic\n"),
                ("1", "", " no crontab for root\n"),
                ("1", "", "no crontab for root \n"),
                ("2", "", "no crontab for root\n"),
                ("1", "partial stdout", "no crontab for root\n"),
            ):
                with self.subTest(read_rc=read_rc, stdout=stdout, read_error=message):
                    result = run_cleanup(
                        CRONTAB_READ_RC=read_rc,
                        CRONTAB_STDOUT=stdout,
                        CRONTAB_STDERR=message,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(written.exists())
                    self.assertFalse(removed.exists())

            managed = (
                "17 * * * * /opt/syswarden/bin/syswarden-cli "
                "update-feeds >/dev/null 2>&1"
            )
            operator = (
                "19 4 * * * /opt/syswarden/bin/syswarden-cli "
                "update-feeds --operator-option"
            )
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n" + operator,
                CRONTAB_STDERR="provider warning must not become cron input\n",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(written.read_bytes(), operator.encode("utf-8"))

            result = run_cleanup(CRONTAB_STDOUT=operator)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(written.exists(), "unchanged operator crontab was rewritten")
            self.assertFalse(removed.exists(), "operator crontab was removed")

            result = run_cleanup(CRONTAB_STDOUT="")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(written.exists(), "explicit empty crontab was rewritten")
            self.assertFalse(removed.exists(), "explicit empty crontab was removed")

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CMP_FORCE_RC="2"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(written.exists(), "cmp error reached crontab write")

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CRONTAB_WRITE_RC="23"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(removed.exists(), "managed-only crontab was not removed")
            self.assertFalse(written.exists(), "managed-only crontab was rewritten empty")

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CRONTAB_REMOVE_RC="23"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(removed.exists())
            self.assertFalse(written.exists())

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n", CRONTAB_VERIFY_RC="0"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(removed.exists())
            self.assertFalse(written.exists())

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                CRONTAB_VERIFY_RC="2",
                CRONTAB_VERIFY_STDERR="permission denied\n",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(removed.exists())
            self.assertFalse(written.exists())

            spool.write_text(managed + "\n", encoding="utf-8")
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(spool.exists())
            spool.unlink()

            spool.symlink_to(root / "missing-spool-target")
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(spool.is_symlink())
            spool.unlink()

            spool.write_text(managed + "\n", encoding="utf-8")
            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n",
                SYSWARDEN_CRON_ABSENCE_SPOOL=str(spool),
                CRONTAB_REMOVE_SPOOL="1",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(spool.exists())

            result = run_cleanup(
                CRONTAB_STDOUT=managed + "\n" + operator,
                CRONTAB_WRITE_RC="23",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(removed.exists())

            cache_path_output = root / "cache-path"
            prepared_command = [
                "/bin/sh",
                "-c",
                reference
                + "\numask 077\n"
                + "SYSWARDEN_CRON_ABSENCE_SPOOL=\n"
                + "cron_work=\n"
                + "trap 'syswarden_cleanup_cron_work' 0\n"
                + "trap 'syswarden_cleanup_cron_work; exit 129' 1\n"
                + "trap 'syswarden_cleanup_cron_work; exit 130' 2\n"
                + "trap 'syswarden_cleanup_cron_work; exit 143' 15\n"
                + "syswarden_prepare_cron_work || exit 1\n"
                + 'syswarden_cleanup_crontab "${cron_backup}" '
                + '"${cron_error}" "${cron_filtered}" "$1" || exit 1\n'
                + "syswarden_cleanup_cron_work || exit 1\n"
                + "trap - 0 1 2 15\n",
                "cronie-private-cache-contract",
                "/opt/syswarden/bin/syswarden-cli",
            ]
            for write_rc in ("0", "23"):
                with self.subTest(cronie_write_rc=write_rc):
                    written.unlink(missing_ok=True)
                    cache_path_output.unlink(missing_ok=True)
                    environment = os.environ.copy()
                    environment.update(
                        {
                            "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
                            "CRONTAB_WRITE_OUTPUT": str(written),
                            "CRONTAB_CACHE_PATH_OUTPUT": str(cache_path_output),
                            "CRONTAB_CREATE_BACKUP": "1",
                            "CRONTAB_READ_RC": "0",
                            "CRONTAB_STDOUT": managed + "\n" + operator,
                            "CRONTAB_STDERR": "",
                            "CRONTAB_WRITE_RC": write_rc,
                            "SYSWARDEN_TEST_MKTEMP_ROOT": str(root),
                        }
                    )
                    result = subprocess.run(
                        prepared_command,
                        check=False,
                        capture_output=True,
                        env=environment,
                    )
                    if write_rc == "0":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(written.read_bytes(), operator.encode("utf-8"))
                    else:
                        self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(
                        cache_path_output.exists(),
                        "private Cronie cache setup did not reach crontab: "
                        + result.stderr.decode("utf-8", errors="replace"),
                    )
                    cache_path = Path(
                        cache_path_output.read_text(encoding="utf-8")
                    )
                    self.assertEqual(cache_path.name, "cache")
                    self.assertTrue(cache_path.parent.name.startswith("syswarden-cron."))
                    self.assertFalse(
                        cache_path.parent.exists(),
                        "private Cronie cache work directory remains",
                    )
                    self.assertFalse(
                        (cache_path / "crontab" / "crontab.bak").exists(),
                        "Cronie backup remains outside cleanup",
                    )

    def test_active_local_package_builder_uses_exact_fail_closed_cron_cleanup(self) -> None:
        preremove = self.local_build_script("prerm.sh")
        self.assertIn("syswarden_cleanup_crontab", preremove)
        self.assertIn("/opt/syswarden/bin/syswarden-cli || exit 1", preremove)
        self.assertIn("mktemp -d /var/tmp/syswarden-cron.XXXXXX", preremove)
        self.assertIn("LC_ALL=C crontab -r", preremove)
        self.assertIn(
            'syswarden_read_crontab "${syswarden_cron_backup}" '
            '"${syswarden_cron_error}"',
            preremove,
        )
        self.assertIn('chmod 0700 "${cron_work}"', preremove)
        self.assertNotIn('${cron_backup}.error', preremove)
        self.assertNotIn('${cron_backup}.filtered', preremove)
        self.assertNotIn("grep -v 'syswarden-cli'", preremove)
        self.assertNotIn("grep -F -v '/opt/syswarden/bin/syswarden-cli'", preremove)

    def test_package_cron_signal_handlers_cleanup_and_never_succeed(self) -> None:
        handlers = (
            "trap 'syswarden_cleanup_cron_work' 0",
            "trap 'syswarden_cleanup_cron_work; exit 129' 1",
            "trap 'syswarden_cleanup_cron_work; exit 130' 2",
            "trap 'syswarden_cleanup_cron_work; exit 143' 15",
        )
        matrix = self.cron_script_matrix()
        for name, script, _paths in matrix:
            with self.subTest(handler_contract=name):
                for handler in handlers:
                    self.assertIn(handler, script)
                self.assertIn("mktemp -d", script)
                self.assertIn("syswarden_prepare_cron_work", script)
                self.assertIn('chmod 0700 "${cron_work}"', script)
                self.assertIn('cron_cache="${cron_work}/cache"', script)
                self.assertIn('chmod 0700 "${cron_cache}"', script)
                self.assertIn('XDG_CACHE_HOME="${cron_cache}"', script)
                self.assertIn("export XDG_CACHE_HOME", script)
                self.assertIn("unset XDG_CACHE_HOME", script)
                self.assertIn(
                    "private cron work directory remains after cleanup",
                    script,
                )
                self.assertIn('cron_backup="${cron_work}/backup"', script)
                self.assertIn('cron_error="${cron_work}/error"', script)
                self.assertIn('cron_filtered="${cron_work}/filtered"', script)
                self.assertIn("LC_ALL=C crontab -r", script)
                self.assertIn(
                    "crontab -r returned success but the root crontab is still present",
                    script,
                )
                self.assertNotIn('${cron_backup}.error', script)
                self.assertNotIn('${cron_backup}.filtered', script)
                self.assertIn("SYSWARDEN_CRON_ABSENCE_SPOOL=\n", script)

        functions = self.cron_functions(matrix[0][1])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "private-cron-work"
            work.mkdir(mode=0o700)
            (work / "backup").write_text("operator cron\n", encoding="utf-8")
            ready = root / "ready"
            code = (
                functions
                + '\ncron_work="$1"\n'
                + "\n".join(handlers)
                + '\nprintf ready > "$2"\n'
                + "while :; do sleep 1; done\n"
            )
            process = subprocess.Popen(
                [
                    "/bin/sh",
                    "-c",
                    code,
                    "cron-signal-contract",
                    str(work),
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "signal probe did not become ready")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0, (stdout, stderr))
            self.assertFalse(work.exists(), "signal handler left private cron work")

    def test_linux_postinstall_does_not_treat_systemctl_presence_as_active_systemd(self) -> None:
        postinstall = self.script("postinst.sh")
        self.assertNotIn("systemd_running()", postinstall)
        self.assertIn("syswarden_classify_service_manager", postinstall)
        self.assertIn("AMBIGUOUS", postinstall)
        self.assertIn("OFFLINE", postinstall)
        self.assertIn("/opt/syswarden/bin/syswarden-cli reload\n", postinstall)
        self.assertIn("/opt/syswarden/bin/syswarden-cli reload --no-restart", postinstall)

    def test_linux_packages_declare_every_runtime_dependency(self) -> None:
        for dependency in (
            "wireguard-tools",
            "qrencode",
            "jq",
        ):
            self.assertGreaterEqual(
                self.workflow.count(f'-d "{dependency}"'),
                4,
                dependency,
            )
        for dependency in ("checkpolicy", "policycoreutils-python-utils"):
            self.assertEqual(self.workflow.count(f'-d "{dependency}"'), 2)
        for dependency in ("wireguard-tools", "libqrencode-tools", "jq", "openrc"):
            self.assertGreaterEqual(
                self.workflow.count(f"            - {dependency}\n"),
                2,
                dependency,
            )

        local = LOCAL_BUILD_SCRIPT.read_text(encoding="utf-8")
        for dependency in ("unattended-upgrades", "apt-listchanges", "procps"):
            self.assertEqual(self.workflow.count(f'-d "{dependency}"'), 2, dependency)
            self.assertEqual(local.count(f'-d "{dependency}"'), 1, dependency)
        for dependency in ("dnf-automatic", "procps-ng"):
            self.assertEqual(self.workflow.count(f'-d "{dependency}"'), 2, dependency)
            self.assertEqual(local.count(f'-d "{dependency}"'), 1, dependency)
        self.assertEqual(self.workflow.count("            - procps-ng\n"), 2)
        self.assertEqual(local.count("  - procps-ng\n"), 1)
        self.assertEqual(self.workflow.count("            - shadow\n"), 2)
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
        self.assertEqual(self.workflow.count(workflow_preinstall), 2)
        self.assertEqual(self.workflow.count(workflow_preupgrade), 2)
        self.assertEqual(self.workflow.count(workflow_postinstall), 2)
        self.assertEqual(self.workflow.count(workflow_postupgrade), 2)
        self.assertEqual(self.workflow.count(workflow_apk_hook), 2)
        self.assertEqual(self.workflow.count("            - openrc\n"), 2)
        self.assertIn(".pre-install$/", self.workflow)
        self.assertIn(".pre-upgrade$/", self.workflow)
        self.assertIn(".post-install$/", self.workflow)
        self.assertIn(".post-upgrade$/", self.workflow)
        self.assertIn("^depend = openrc$", self.workflow)
        self.assertIn('"${preinstall_members[0]}"', self.workflow)
        self.assertIn('"${preupgrade_members[0]}"', self.workflow)
        self.assertIn('"${postinstall_members[0]}"', self.workflow)
        self.assertIn('"${postupgrade_members[0]}"', self.workflow)
        self.assertIn("compare_apk_hook_parity", self.workflow)
        self.assertIn(
            "for hook in .pre-install .pre-upgrade .post-install .post-upgrade; do",
            self.workflow,
        )

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

    def test_apk_archive_hook_validation_rejects_missing_drift_and_arch_mismatch(
        self,
    ) -> None:
        validation_step = workflow_step_script(
            self.workflow, "Validate Package Metadata"
        )
        validate_start = validation_step.index("validate_apk() {")
        parity_start = validation_step.index("\ncompare_apk_hook_parity() {")
        invocation_start = validation_step.index("\nvalidate_deb ", parity_start)
        validate_function = validation_step[validate_start:parity_start]
        parity_function = validation_step[parity_start + 1 : invocation_start]

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
            arm = root / "syswarden_4.02.14_aarch64.apk"
            write_apk(x86, "x86_64", hooks)
            write_apk(arm, "aarch64", hooks)
            accepted = validate(x86, "x86_64")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            parity = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    + parity_function
                    + '\ncompare_apk_hook_parity "$1" "$2" .pre-upgrade',
                    "apk-parity-contract",
                    str(x86),
                    str(arm),
                ],
                check=False,
                capture_output=True,
            )
            self.assertEqual(parity.returncode, 0, parity.stderr)

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

            wrong_arch = validate(x86, "aarch64")
            self.assertNotEqual(wrong_arch.returncode, 0, wrong_arch)

            drifted_arm = root / "drifted-arm.apk"
            write_apk(
                drifted_arm,
                "aarch64",
                {**hooks, ".pre-upgrade": b"#!/bin/sh\nprintf drift\n"},
            )
            rejected_parity = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    "set -euo pipefail\n"
                    + parity_function
                    + '\ncompare_apk_hook_parity "$1" "$2" .pre-upgrade',
                    "apk-parity-contract",
                    str(x86),
                    str(drifted_arm),
                ],
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(rejected_parity.returncode, 0, rejected_parity)

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
        self.assertIn("STAGING_APK_ARM64", self.workflow)
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
        for generic_root in ("STAGING_AMD64", "STAGING_ARM64"):
            with self.subTest(generic_root=generic_root):
                self.assertEqual(
                    self.workflow.count(f'-C "${{{generic_root}}}" .'),
                    2,
                )
        for apk_root in ("STAGING_APK_AMD64", "STAGING_APK_ARM64"):
            with self.subTest(apk_root=apk_root):
                self.assertIn(f'- src: "${{{apk_root}}}/opt"', self.workflow)

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
        self.assertEqual(build_script.count("Name = 'Linux "), 2)
        self.assertEqual(build_script.count("Name = 'syswarden-"), 3)
        self.assertIn("if ($VerifiedArtifactCount -ne 6)", build_script)
        self.assertIn(
            'throw "Build verification expected 6 binaries but verified '
            '$VerifiedArtifactCount."',
            build_script,
        )
        self.assertIn("the exact 8-file distribution inventory", build_script)
        self.assertNotIn("expected 9 binaries", build_script)
        self.assertNotIn("exact 11-file distribution inventory", build_script)


if __name__ == "__main__":
    unittest.main()
