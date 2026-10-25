#!/usr/bin/env python3
"""Exercise local package generation without compiling or installing packages."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "build_packages.sh"
METADATA = ROOT / "scripts/ci/package_variant_metadata.sh"
BASE_DEPENDENCIES = {
    "deb": {"bash-completion", "cron", "curl", "jq", "nftables", "procps", "wget"},
    "rpm": {"bash-completion", "cronie", "curl", "jq", "nftables", "procps-ng", "wget"},
    "apk": {
        "bash-completion", "cronie", "cronie-openrc", "curl", "jq", "nftables",
        "openrc", "procps-ng", "shadow", "wget",
    },
}


def bash(script: str, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": os.environ["PATH"], "LC_ALL": "C"}
    return subprocess.run(
        ["/bin/bash", "-eu", "-c", script, "package-variant-test", *arguments],
        cwd=cwd, env=environment, capture_output=True, check=False, timeout=5,
    )


def selection() -> str:
    return 'source "$1"\nsyswarden_select_local_package_variant "$2"\n'


def metadata(variant: str) -> dict[str, list[str]]:
    result = bash(
        selection()
        + 'printf "name=%s\\nconflict=%s\\n" "$PACKAGE_NAME" "$PACKAGE_CONFLICT"\n'
        + 'printf "deb=%s\\n" "${DEB_PACKAGE_DEPENDENCIES[@]}"\n'
        + 'printf "rpm=%s\\n" "${RPM_PACKAGE_DEPENDENCIES[@]}"\n'
        + 'printf "apk=%s\\n" "${APK_PACKAGE_DEPENDENCIES[@]}"\n',
        str(METADATA), variant,
    )
    if result.returncode:
        raise AssertionError(result.stderr.decode())
    values: dict[str, list[str]] = {}
    for line in result.stdout.decode().splitlines():
        key, value = line.split("=", 1)
        values.setdefault(key, []).append(value)
    return values


class PackageVariantMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = BUILDER.read_text(encoding="utf-8")

    def test_options_select_one_variant_before_any_build_action(self) -> None:
        options = self.source.split('echo "[*] Initializing', 1)[0]
        for arguments, expected in (
            ((), b"compatibility:0\n"),
            (("--minimal-package",), b"minimal:0\n"),
            (("--rhel-package-owned-profile",), b"compatibility:1\n"),
        ):
            with self.subTest(arguments=arguments):
                result = bash(options + '\nprintf "%s:%s\\n" "$LOCAL_PACKAGE_VARIANT" "$RHEL_PACKAGE_OWNED_PROFILE"', *arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
        for arguments in (
            ("--unknown",), ("--minimal-package", "--minimal-package"),
            ("--minimal-package", "--rhel-package-owned-profile"),
            ("--rhel-package-owned-profile", "--minimal-package"),
        ):
            with self.subTest(arguments=arguments):
                result = bash(options, *arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"Usage:", result.stderr)

    def test_identity_dependencies_and_mutual_conflicts_are_exact(self) -> None:
        compatibility = metadata("compatibility")
        minimal = metadata("minimal")
        self.assertEqual(compatibility["name"], ["syswarden"])
        self.assertEqual(compatibility["conflict"], ["syswarden-base"])
        self.assertEqual(minimal["name"], ["syswarden-base"])
        self.assertEqual(minimal["conflict"], ["syswarden"])
        for family in BASE_DEPENDENCIES:
            self.assertEqual(set(minimal[family]), BASE_DEPENDENCIES[family])
            self.assertEqual(len(minimal[family]), len(BASE_DEPENDENCIES[family]))
            for values in (compatibility[family], minimal[family]):
                self.assertNotIn("syswarden", values)
                self.assertNotIn("syswarden-base", values)
        for variant in ("", "base", "minimal compatibility"):
            self.assertEqual(bash(selection(), str(METADATA), variant).returncode, 2)

    def test_minimal_dependencies_match_manual_base_contract(self) -> None:
        source = (ROOT / "src/core/syswarden-cli/pkg/system/dependencies.go").read_text()
        function = source.split("func baseDependencyArguments(", 1)[1].split("\nfunc ", 1)[0]
        for family, marker in (("deb", 'case "/usr/bin/apt-get":'), ("rpm", 'case "/usr/bin/dnf", "/usr/bin/yum":'), ("apk", 'case "/sbin/apk", "/usr/sbin/apk":')):
            block = function.split(marker, 1)[1].split("\n\tcase ", 1)[0]
            arrays = re.findall(r'return \[\]string\{([^}]+)\}', block)
            dependencies = [value for value in re.findall(r'"([^"\n]+)"', arrays[-1]) if value not in {"install", "add"} and not value.startswith("-")]
            self.assertEqual(set(dependencies), set(metadata("minimal")[family]))

    def generated_fpm(self, variant: str, family: str) -> list[str]:
        start, end = {"deb": ("# Generate DEB", "# Generate RPM"), "rpm": ("# Generate RPM", "# Generate Alpine APK")}[family]
        block = self.source.split(start, 1)[1].split(end, 1)[0]
        names = self.source.split("# Read metadata from the same committed source snapshot as the payload.", 1)[1].split('echo "[+] Detected', 1)[0]
        result = bash(
            'SOURCE_ROOT="$3"\nVERSION=5.00.0\nLOCAL_PACKAGE_VARIANT="$2"\nRHEL_PACKAGE_OWNED_PROFILE=0\n'
            + names
            + 'PACKAGE_WORKSPACE=/private/packages\nSOURCE_DATE_EPOCH=1\nRPM_CHANGELOG=/private/changelog\nRPM_SCRIPTS=/private/scripts\n'
            + 'RPM_PROFILE_DEPENDENCIES=()\nRPM_PROFILE_FPM_OPTIONS=()\nRPM_BUILD_ID_DEFINE_OPTIONS=()\nRPM_BUILD_ID_FPM_OPTIONS=()\nRPM_SOCKET_FPM_OPTIONS=()\n'
            + "fpm() { printf '%s\\0' \"$@\"; }\n" + block,
            str(METADATA), variant, str(ROOT),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().rstrip("\0").split("\0")

    def test_real_fpm_blocks_select_metadata_without_changing_payload_or_hooks(self) -> None:
        for family in ("deb", "rpm"):
            normalized = []
            for variant in ("compatibility", "minimal"):
                with self.subTest(family=family, variant=variant):
                    expected = metadata(variant)
                    arguments = self.generated_fpm(variant, family)
                    self.assertEqual(arguments[arguments.index("-n") + 1], expected["name"][0])
                    self.assertEqual(arguments[arguments.index("--conflicts") + 1], expected["conflict"][0])
                    self.assertEqual([arguments[index + 1] for index, value in enumerate(arguments) if value == "-d"], expected[family])
                    self.assertEqual(arguments[arguments.index("-p") + 1], f'/private/packages/{expected["name"][0]}' + ("_5.00.0_amd64.deb" if family == "deb" else "-5.00.0-1.x86_64.rpm"))
                    for forbidden in ("--provides", "--replaces", "--obsoletes"):
                        self.assertNotIn(forbidden, arguments)
                    remaining = []
                    index = 0
                    while index < len(arguments):
                        if arguments[index] in ("-n", "-d", "--conflicts", "-p"):
                            index += 2
                        else:
                            remaining.append(arguments[index])
                            index += 1
                    normalized.append(remaining)
            self.assertEqual(normalized[0], normalized[1])

    def test_real_nfpm_configuration_preserves_full_payload_and_hooks(self) -> None:
        block = 'cat << EOF > nfpm_alpine_amd64.yaml' + self.source.split('cat << EOF > nfpm_alpine_amd64.yaml', 1)[1].split('\nEOF\n', 1)[0] + '\nEOF\n'
        payloads = []
        with tempfile.TemporaryDirectory() as directory:
            for variant in ("compatibility", "minimal"):
                result = bash(selection() + "VERSION=5.00.0\n" + block, str(METADATA), variant, cwd=Path(directory))
                self.assertEqual(result.returncode, 0, result.stderr)
                generated = (Path(directory) / "nfpm_alpine_amd64.yaml").read_text()
                expected = metadata(variant)
                self.assertIn(f'name: "{expected["name"][0]}"\n', generated)
                self.assert_exact_nfpm_version(generated, "5.00.0")
                dependencies = generated.split("depends:\n", 1)[1].split("conflicts:\n", 1)[0]
                self.assertEqual(dependencies.splitlines(), [f"  - {value}" for value in expected["apk"]] + [f'  - "!{expected["conflict"][0]}"'])
                self.assertEqual(generated.split("conflicts:\n", 1)[1].split("contents:\n", 1)[0], f'  - "{expected["conflict"][0]}"\n')
                self.assertIn('arch: "amd64"\n', generated)
                for forbidden in ("provides:", "replaces:", "obsoletes:"):
                    self.assertNotIn(forbidden, generated)
                payloads.append(generated.split("contents:\n", 1)[1])
        self.assertEqual(payloads[0], payloads[1])

    def assert_exact_nfpm_version(self, generated: str, version: str, revision: bool = True) -> None:
        self.assertEqual(re.findall(r"^version:.*$", generated, re.MULTILINE), [f'version: "{version}"'])
        # nfpm's default semver schema would strip the release's zero padding.
        self.assertEqual(re.findall(r"^version_schema:.*$", generated, re.MULTILINE), ["version_schema: none"])
        self.assertEqual(re.findall(r"^release:.*$", generated, re.MULTILINE), ['release: "0"'] if revision else [])

    def render_hook(self, source: str, variant: str) -> str:
        with tempfile.TemporaryDirectory() as directory:
            hook = Path(directory) / "hook.sh"
            hook.write_text(source)
            result = bash(selection() + 'syswarden_render_local_package_hook "$3"', str(METADATA), variant, str(hook))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode()

    def test_apk_phase_selectors_are_bound_to_the_built_identity(self) -> None:
        source = (ROOT / "scripts/ci/package_alpine_cronie_preflight.sh").read_text()
        phase = "syswarden_alpine_apk_phase() {" + source.split("syswarden_alpine_apk_phase() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        self.assertEqual(self.render_hook(source, "compatibility"), source)
        for variant, name in (("compatibility", "syswarden"), ("minimal", "syswarden-base")):
            rendered = self.render_hook(phase, variant)
            for script, expected in (("pre-install", b"fresh\n"), ("post-install", b"fresh\n"), ("pre-upgrade", b"upgrade\n"), ("post-upgrade", b"upgrade\n")):
                result = bash(rendered + 'APK_PACKAGE="$1" APK_SCRIPT="$2" syswarden_alpine_apk_phase', name, script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
            other = "syswarden" if name == "syswarden-base" else "syswarden-base"
            self.assertNotEqual(bash(rendered + 'APK_PACKAGE="$1" APK_SCRIPT=pre-upgrade syswarden_alpine_apk_phase', other).returncode, 0)

    def test_apk_removal_selector_never_accepts_upgrade_or_other_identity(self) -> None:
        guard = 'case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in' + self.source.split('case "${APK_PACKAGE:-}:${APK_SCRIPT:-}:${1:-}" in', 1)[1].split("\nesac\n", 1)[0] + '\nesac\nprintf "removal-selected\\n"\n'
        for variant, name in (("compatibility", "syswarden"), ("minimal", "syswarden-base")):
            rendered = self.render_hook(guard, variant)
            def run(package: str, phase: str) -> subprocess.CompletedProcess[bytes]:
                return bash('APK_PACKAGE="$2"\nAPK_SCRIPT="$3"\n' + rendered, "5.0.0", package, phase)
            result = run(name, "pre-deinstall")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"removal-selected\n")
            for package, phase in ((name, "pre-upgrade"), (name, "post-upgrade"), ("unrelated", "pre-deinstall"), ("syswarden" if name == "syswarden-base" else "syswarden-base", "pre-deinstall")):
                result = run(package, phase)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_local_hook_binding_precedes_packaging(self) -> None:
        self.assertLess(self.source.index('syswarden_render_local_package_hook "${package_hook}"'), self.source.index("# Generate DEB"))
        self.assertIn('LOCAL_PACKAGE_OUTPUT="${LOCAL_PACKAGE_OUTPUT}/minimal"', self.source)
        self.assertIn('secure_builder_directory "${REPOSITORY_ROOT}/dist/packages"', self.source)

    def test_minimal_publication_uses_only_selected_filenames(self) -> None:
        names = self.source.split("# Read metadata from the same committed source snapshot as the payload.", 1)[1].split('echo "[+] Detected', 1)[0]
        publication = "publish_local_package() {" + self.source.split("publish_local_package() {", 1)[1].split('\ncd "${REPOSITORY_ROOT}"\n', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            output = Path(directory) / "output"
            workspace.mkdir()
            output.mkdir()
            filenames = ("syswarden-base_5.00.0_amd64.deb", "syswarden-base-5.00.0-1.x86_64.rpm", "syswarden-base_5.00.0_x86_64.apk")
            for filename in filenames:
                (workspace / filename).write_bytes(b"inert metadata test payload\n")
            result = bash(
                'SOURCE_ROOT="$1"\nVERSION=5.00.0\nLOCAL_PACKAGE_VARIANT=minimal\nRHEL_PACKAGE_OWNED_PROFILE=0\n'
                + names + '\nPACKAGE_WORKSPACE="$2"\nLOCAL_PACKAGE_OUTPUT="$3"\n'
                + publication + "\npublish_local_artifacts\n",
                str(ROOT), str(workspace), str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({item.name for item in output.iterdir()}, {*filenames, "SHA256SUMS.txt"})
            manifest = (output / "SHA256SUMS.txt").read_text()
            self.assertEqual([line.split("  ")[1] for line in manifest.splitlines()], list(filenames))


def workflow_step(name: str) -> str:
    source = (ROOT / ".github/workflows/package.yml").read_text(encoding="utf-8")
    step = source.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]
    script = textwrap.dedent(step.split("        run: |\n", 1)[1])
    return script.replace("${{ github.repository }}", "public-test/syswarden")


def workflow_fixture(directory: Path, version: str) -> dict[str, str]:
    environment = {
        "VERSION": version,
        "RELEASE_TAG": f"v{version}",
        "EXACT_SOURCE_ROOT": str(ROOT),
        "PACKAGE_WORKSPACE": str(directory),
        "SOURCE_DATE_EPOCH": "1700000000",
        "SOURCE_COMMIT_SHA": "a" * 40,
        "SOURCE_VCS_TIME": "2023-11-14T22:13:20Z",
        "RPM_CHANGELOG_EPOCH": "1699963200",
        "VALIDATED_AMD64_DIGEST_CONTRACT": "v1;synthetic-pie-digests",
        "VALIDATED_APK_AMD64_DIGEST_CONTRACT": "v1;synthetic-static-digests",
    }
    for key, leaf in (
        ("PACKAGE_ASSETS", "assets"), ("PACKAGE_SCRIPTS", "scripts"),
        ("PACKAGE_RPM_SCRIPTS", "rpm-scripts"), ("PACKAGE_CONFIGS", "configs"),
        ("STAGING_AMD64", "stage"), ("STAGING_APK_AMD64", "apk-stage"),
        ("RHEL_PROFILE_STAGING", "rhel-stage"), ("RHEL_PROFILE_SOURCE", "rhel-source"),
        ("RHEL_PROFILE_ASSETS", "rhel-assets"), ("RHEL_PROFILE_RPM_SCRIPTS", "rhel-scripts"),
    ):
        path = directory / leaf
        path.mkdir()
        environment[key] = str(path)
    environment["RPM_CHANGELOG"] = str(directory / "configs/rpm-changelog")
    environment["GITHUB_ENV"] = str(directory / "github-environment")
    return environment


def fixture_shell(environment: dict[str, str]) -> str:
    return "".join(f"{key}={shlex.quote(value)}\n" for key, value in environment.items())


def workflow_assets(version: str) -> list[str]:
    names = ["syswarden"] if version.startswith("4.") else ["syswarden", "syswarden-base"]
    return [filename for name in names for filename in (
        f"{name}_{version}_amd64.deb", f"{name}-{version}-1.x86_64.rpm", f"{name}_{version}_x86_64.apk",
    )]


def nul_calls(output: bytes) -> list[list[str]]:
    return [call.decode().split("\0") for call in output.rstrip(b"\0").split(b"\0\0")]


class UnsignedWorkflowVariantTests(unittest.TestCase):
    def test_source_versions_select_a_closed_unsigned_inventory(self) -> None:
        for version, expected in (("4.10.4", b"compatibility\n"), ("5.00.0", b"compatibility\nminimal\n"), ("5.01.1", b"compatibility\nminimal\n")):
            result = bash('source "$1"\nsyswarden_select_workflow_package_variants "$2"\nprintf "%s\\n" "${WORKFLOW_PACKAGE_VARIANTS[@]}"', str(METADATA), version)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
        for version in ("", "v5.00.0", "05.00.0", "5.0.0", "5.00.00", "5.00.2147483648", "5.00.1\n", "3.99.1", "6.00.0", "9.99.9"):
            with self.subTest(version=version):
                self.assertNotEqual(bash('source "$1"\nsyswarden_select_workflow_package_variants "$2"', str(METADATA), version).returncode, 0)
        self.assertNotEqual(bash('source "$1"\nsyswarden_select_workflow_package_variant 4.10.4 minimal', str(METADATA)).returncode, 0)
        self.assertNotEqual(bash('source "$1"\nsyswarden_select_workflow_package_variant 5.00.0 foreign', str(METADATA)).returncode, 0)

    def test_workflow_fpm_steps_generate_each_selected_identity(self) -> None:
        for version in ("4.10.4", "5.00.0"):
            for family, step in (("deb", "Build Debian Package (.deb)"), ("rpm", "Build RHEL Family Package (.rpm)")):
                with self.subTest(version=version, family=family), tempfile.TemporaryDirectory() as directory:
                    environment = workflow_fixture(Path(directory), version)
                    result = bash(fixture_shell(environment) + "fpm() { printf '%s\\0' \"$@\"; printf '\\0'; }\n" + workflow_step(step))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = nul_calls(result.stdout)
                    variants = ("compatibility",) if version.startswith("4.") else ("compatibility", "minimal")
                    self.assertEqual(len(calls), len(variants))
                    for arguments, variant in zip(calls, variants, strict=True):
                        expected = metadata(variant)
                        name = expected["name"][0]
                        value = lambda key: arguments[arguments.index(key) + 1]
                        self.assertEqual(value("-n"), name)
                        self.assertEqual(value("-v"), version)
                        self.assertEqual(value("--architecture"), "amd64" if family == "deb" else "x86_64")
                        suffix = f"{name}_{version}_amd64.deb" if family == "deb" else f"{name}-{version}-1.x86_64.rpm"
                        self.assertEqual(value("-p"), str(Path(environment["PACKAGE_ASSETS"]) / suffix))
                        self.assertEqual([arguments[i + 1] for i, item in enumerate(arguments) if item == "-d"], expected[family])
                        script_root = environment["PACKAGE_SCRIPTS" if family == "deb" else "PACKAGE_RPM_SCRIPTS"]
                        if version.startswith("5."):
                            self.assertEqual(value("--conflicts"), expected["conflict"][0])
                            script_root += "/" + name
                        else:
                            self.assertNotIn("--conflicts", arguments)
                        for flag, hook in (("--before-install", "preinst"), ("--after-install", "postinst"), ("--before-remove", "prerm"), ("--after-remove", "postrm")):
                            self.assertEqual(value(flag), f"{script_root}/{hook}.sh")
                        self.assertEqual(arguments[-3:], ["-C", environment["STAGING_AMD64"], "."])
                        for forbidden in ("--provides", "--replaces", "--obsoletes"):
                            self.assertNotIn(forbidden, arguments)

    def test_workflow_nfpm_step_preserves_exact_versions_and_effective_conflicts(self) -> None:
        for version in ("4.10.4", "5.00.0", "5.01.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                environment = workflow_fixture(Path(directory), version)
                tools = Path(directory) / "tools"
                tools.mkdir()
                nfpm = tools / "nfpm"
                nfpm.write_text("#!/bin/bash\nprintf '%s\\0' \"$@\"\nprintf '\\0'\n")
                nfpm.chmod(0o755)
                result = bash(fixture_shell(environment) + 'go() { [[ "$*" == "install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0" ]]; }\n' + workflow_step("Build Alpine Package (.apk)"))
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = nul_calls(result.stdout)
                variants = ("compatibility",) if version.startswith("4.") else ("compatibility", "minimal")
                self.assertEqual(len(calls), len(variants))
                for arguments, variant in zip(calls, variants, strict=True):
                    expected = metadata(variant)
                    name = expected["name"][0]
                    config = Path(arguments[arguments.index("--config") + 1])
                    generated = config.read_text()
                    self.assertEqual(arguments[-2:], ["--target", str(Path(environment["PACKAGE_ASSETS"]) / f"{name}_{version}_x86_64.apk")])
                    self.assertIn(f'name: "{name}"\n', generated)
                    self.assertIn('arch: "amd64"\n', generated)
                    PackageVariantMetadataTests.assert_exact_nfpm_version(self, generated, version, revision=version.startswith("5."))
                    dependencies = generated.split("depends:\n", 1)[1].split("contents:\n", 1)[0]
                    script_root = environment["PACKAGE_SCRIPTS"]
                    if version.startswith("5."):
                        self.assertEqual(dependencies.split("conflicts:\n", 1)[0].splitlines(), [f"  - {value}" for value in expected["apk"]] + [f'  - "!{expected["conflict"][0]}"'])
                        self.assertEqual(dependencies.split("conflicts:\n", 1)[1], f'  - "{expected["conflict"][0]}"\n')
                        script_root += "/" + name
                    else:
                        self.assertEqual(dependencies.splitlines(), [f"  - {value}" for value in expected["apk"]])
                        self.assertEqual(config.name, "nfpm_alpine_x86_64.yaml")
                    for selector, hook in (("preinstall", "preinst"), ("postinstall", "postinst"), ("preremove", "prerm"), ("postremove", "postrm"), ("preupgrade", "preinst"), ("postupgrade", "postupgrade")):
                        self.assertIn(f'{selector}: "{script_root}/{hook}.sh"\n', generated)
                    for forbidden in ("provides:", "replaces:", "obsoletes:"):
                        self.assertNotIn(forbidden, generated)

    def test_workflow_binds_hooks_before_rpm_escaping_and_normalizes_every_identity(self) -> None:
        for version in ("4.10.4", "5.00.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                environment = workflow_fixture(Path(directory), version)
                result = bash(fixture_shell(environment) + workflow_step("Prepare Linux Maintainer Scripts") + workflow_step("Normalize Package Input Timestamps"))
                self.assertEqual(result.returncode, 0, result.stderr)
                names = ("",) if version.startswith("4.") else ("syswarden", "syswarden-base")
                for name in names:
                    for hook in ("preinst.sh", "postinst.sh", "postupgrade.sh", "prerm.sh", "postrm.sh"):
                        template = (Path(environment["PACKAGE_SCRIPTS"]) / hook).read_bytes()
                        expected = template
                        if name == "syswarden-base":
                            for selector in ("pre-install", "post-install", "pre-upgrade", "post-upgrade", "pre-deinstall"):
                                expected = expected.replace(f"syswarden:{selector}".encode(), f"syswarden-base:{selector}".encode())
                        selected = Path(environment["PACKAGE_SCRIPTS"]) / name / hook
                        self.assertEqual(selected.read_bytes(), expected)
                        self.assertEqual(int(selected.stat().st_mtime), int(environment["SOURCE_DATE_EPOCH"]))
                        if hook != "postupgrade.sh":
                            rpm = Path(environment["PACKAGE_RPM_SCRIPTS"]) / name / hook
                            self.assertEqual(rpm.read_bytes(), expected.replace(b"%", b"%%"))
                            self.assertEqual(int(rpm.stat().st_mtime), int(environment["SOURCE_DATE_EPOCH"]))
                if version.startswith("4."):
                    self.assertFalse((Path(environment["PACKAGE_SCRIPTS"]) / "syswarden").exists())
                    self.assertFalse((Path(environment["PACKAGE_SCRIPTS"]) / "syswarden-base").exists())

    def test_workflow_checksums_cover_exact_ordered_unsigned_artifacts(self) -> None:
        for version in ("4.10.4", "5.00.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                environment = workflow_fixture(Path(directory), version)
                assets = Path(environment["PACKAGE_ASSETS"])
                expected = []
                for filename in workflow_assets(version):
                    data = f"synthetic unsigned artifact {filename}\n".encode()
                    (assets / filename).write_bytes(data)
                    expected.append(f"{hashlib.sha256(data).hexdigest()}  {filename}\n")
                result = bash(fixture_shell(environment) + workflow_step("Generate Checksums"))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((assets / "SHA256SUMS.txt").read_text(), "".join(expected))
                (assets / workflow_assets(version)[-1]).unlink()
                result = bash(fixture_shell(environment) + workflow_step("Generate Checksums"))
                self.assertNotEqual(result.returncode, 0)


    def test_workflow_native_metadata_checks_refuse_identity_and_policy_drift(self) -> None:
        functions = workflow_step("Validate Package Metadata").rsplit('for variant in "${WORKFLOW_PACKAGE_VARIANTS[@]}"; do', 1)[0]
        native_stub = r"""import json
from pathlib import Path
import sys

fixture, family, *args = sys.argv[1:]
state = json.loads(Path(fixture).read_text())
if family == "deb":
    if args[0] == "--ctrl-tarfile":
        sys.stdout.buffer.write(Path(state["control_tar"]).read_bytes())
        raise SystemExit(0)
    if args[0] != "--field":
        raise SystemExit("unexpected DEB query")
    key = args[-1]
else:
    if args[:2] != ["--query", "--package"]:
        raise SystemExit("unexpected RPM query")
    key = args[3] if args[2] == "--queryformat" else args[2]
if state.get("query_error") == key:
    raise SystemExit(42)
if key not in state[family]:
    raise SystemExit("undeclared native fixture query: " + key)
sys.stdout.write(state[family][key])
"""
        for variant in ("compatibility", "minimal"):
            expected = metadata(variant)
            name, conflict = expected["name"][0], expected["conflict"][0]
            for family in ("deb", "rpm", "apk"):
                with self.subTest(variant=variant, family=family), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    environment = workflow_fixture(root, "5.00.0")
                    scripts = Path(environment["PACKAGE_SCRIPTS"]) / name
                    scripts.mkdir()
                    hooks = {hook: f"#!/bin/sh\n# Synthetic {name} {hook}\nexit 0\n".encode() for hook in ("preinst.sh", "postinst.sh", "postupgrade.sh", "prerm.sh", "postrm.sh")}
                    for hook, data in hooks.items():
                        (scripts / hook).write_bytes(data)
                    stub, fixture, archive = root / "native-stub.py", root / "native.json", root / "package.tar.gz"
                    stub.write_text(native_stub)
                    deb = {
                        "Package": name, "Version": "5.00.0", "Architecture": "amd64",
                        "License": "GPL-3.0-or-later", "Homepage": "https://github.com/public-test/syswarden",
                        "Depends": ", ".join(expected["deb"]), "Conflicts": conflict,
                        **{field: "" for field in ("Pre-Depends", "Recommends", "Suggests", "Enhances", "Breaks", "Provides", "Replaces")},
                    }
                    rpm = {
                        "%{NAME}": name, "%{VERSION}": "5.00.0", "%{ARCH}": "x86_64",
                        "%{RELEASE}": "1", "%{EPOCHNUM}": "0",
                        "%{BUILDTIME}": environment["SOURCE_DATE_EPOCH"],
                        "%{BUILDHOST}": "syswarden-build.invalid",
                        "%{CHANGELOGTIME}": environment["RPM_CHANGELOG_EPOCH"],
                        "%{LICENSE}": "GPL-3.0-or-later", "%{URL}": "https://github.com/public-test/syswarden",
                        "--conflicts": conflict, "--obsoletes": "",
                        "--requires": "\n".join([*expected["rpm"], "/bin/sh", "rpmlib(FileDigests) <= 4.6.0-1"]),
                        "--provides": f"{name} = 5.00.0-1\n{name}(x86-64) = 5.00.0-1",
                        "--scripts": "synthetic public scriptlets",
                        **{f"--{relation}": "" for relation in ("recommends", "suggests", "supplements", "enhances")},
                        **{f"%{{{tag}}}": "(none)" for tag in ("PRETRANS", "POSTTRANS", "VERIFYSCRIPT")},
                        **{f"[%{{{tag}}}]": "" for tag in ("TRIGGERSCRIPTS", "FILETRIGGERSCRIPTS", "TRANSFILETRIGGERSCRIPTS")},
                    }
                    for tag, hook in (("PREIN", "preinst.sh"), ("POSTIN", "postinst.sh"), ("PREUN", "prerm.sh"), ("POSTUN", "postrm.sh")):
                        rpm[f"%{{{tag}}}"] = hooks[hook].decode()
                        rpm[f"%{{{tag}PROG}}"] = "/bin/sh"
                    apk_info = "\n".join([
                        f"pkgname = {name}", "pkgver = 5.00.0-r0", "arch = x86_64",
                        "license = GPL-3.0-or-later", "url = https://github.com/public-test/syswarden",
                        *[f"depend = {dependency}" for dependency in expected["apk"]],
                        f"depend = !{conflict}", "",
                    ]).encode()
                    apk_hooks = {".pre-install": "preinst.sh", ".pre-upgrade": "preinst.sh", ".post-install": "postinst.sh", ".post-upgrade": "postupgrade.sh", ".pre-deinstall": "prerm.sh", ".post-deinstall": "postrm.sh"}
                    cases = {
                        "deb": ("valid", "name", "version", "architecture", "extra dependency", "duplicate dependency", "conflict", "replacement", "hook", "extra hook", "query error"),
                        "rpm": ("valid", "name", "epoch", "extra dependency", "duplicate dependency", "conflict", "replacement", "provides", "hook", "extra hook", "weak dependency", "requires error", "provides error"),
                        "apk": ("valid", "name", "version", "missing revision", "wrong revision", "architecture", "extra dependency", "duplicate dependency", "conflict", "replacement", "hook", "extra hook", "duplicate hook"),
                    }[family]
                    for case in cases:
                        with self.subTest(case=case):
                            state = {"deb": dict(deb), "rpm": dict(rpm), "control_tar": str(archive)}
                            entries = [(hook.removesuffix(".sh"), data) for hook, data in hooks.items() if hook != "postupgrade.sh"]
                            if family == "deb":
                                changes = {"name": ("Package", conflict), "version": ("Version", "5.0.0"), "architecture": ("Architecture", "all"), "extra dependency": ("Depends", deb["Depends"] + ", unexpected"), "duplicate dependency": ("Depends", deb["Depends"] + ", nftables"), "conflict": ("Conflicts", ""), "replacement": ("Replaces", conflict)}
                                if case in changes:
                                    key, value = changes[case]
                                    state["deb"][key] = value
                                if case == "query error":
                                    state["query_error"] = "Replaces"
                                if case == "hook":
                                    entries[-1] = (entries[-1][0], b"different hook\n")
                                if case == "extra hook":
                                    entries.append(("config", b"unexpected hook\n"))
                            elif family == "rpm":
                                changes = {"name": ("%{NAME}", conflict), "epoch": ("%{EPOCHNUM}", "1"), "extra dependency": ("--requires", rpm["--requires"] + "\nunexpected"), "duplicate dependency": ("--requires", rpm["--requires"] + "\nnftables"), "conflict": ("--conflicts", ""), "replacement": ("--obsoletes", conflict), "provides": ("--provides", rpm["--provides"] + f"\n{conflict} = 5.00.0-1"), "hook": ("%{POSTUN}", "different hook")}
                                if case in changes:
                                    key, value = changes[case]
                                    state["rpm"][key] = value
                                if case == "extra hook":
                                    state["rpm"]["%{POSTTRANS}"] = "unexpected hook"
                                if case == "weak dependency":
                                    state["rpm"]["--recommends"] = "unexpected"
                                if case.endswith(" error"):
                                    state["query_error"] = "--" + case.split()[0]
                            else:
                                info = apk_info
                                changes = {"name": (f"pkgname = {name}", f"pkgname = {conflict}"), "version": ("pkgver = 5.00.0-r0", "pkgver = 5.0.0-r0"), "missing revision": ("pkgver = 5.00.0-r0", "pkgver = 5.00.0"), "wrong revision": ("pkgver = 5.00.0-r0", "pkgver = 5.00.0-r1"), "architecture": ("arch = x86_64", "arch = noarch"), "conflict": (f"depend = !{conflict}\n", "")}
                                if case in changes:
                                    old, new = changes[case]
                                    info = info.replace(old.encode(), new.encode())
                                if case == "extra dependency":
                                    info += b"depend = unexpected\n"
                                if case == "duplicate dependency":
                                    info += f"depend = !{conflict}\n".encode()
                                if case == "replacement":
                                    info += f"replaces = {conflict}\n".encode()
                                entries = [(".PKGINFO", info), *[(member, hooks[hook]) for member, hook in apk_hooks.items()]]
                                if case == "hook":
                                    entries[-1] = (entries[-1][0], b"different hook\n")
                                if case == "extra hook":
                                    entries.append((".trigger", b"unexpected hook\n"))
                                if case == "duplicate hook":
                                    entries.append(entries[-1])
                            fixture.write_text(json.dumps(state))
                            with tarfile.open(archive, "w:gz" if family == "apk" else "w", format=tarfile.USTAR_FORMAT) as writer:
                                for member, data in entries:
                                    header = tarfile.TarInfo(member)
                                    header.size, header.mode = len(data), 0o755
                                    writer.addfile(header, io.BytesIO(data))
                            command = (
                                fixture_shell(environment)
                                + f"NATIVE_STUB={shlex.quote(str(stub))}\nNATIVE_FIXTURE={shlex.quote(str(fixture))}\n"
                                + 'dpkg-deb() { python3 "$NATIVE_STUB" "$NATIVE_FIXTURE" deb "$@"; }\n'
                                + 'rpm() { python3 "$NATIVE_STUB" "$NATIVE_FIXTURE" rpm "$@"; }\n'
                                + functions
                                + f"syswarden_select_workflow_package_variant 5.00.0 {variant}\n"
                                + 'SELECTED_PACKAGE_SCRIPTS="${PACKAGE_SCRIPTS}${PACKAGE_SCRIPT_SUBDIRECTORY}"\n'
                                + f"validate_{family} {shlex.quote(str(archive))} {'amd64' if family == 'deb' else 'x86_64'}\n"
                            )
                            result = bash(command)
                            if case == "valid":
                                self.assertEqual(result.returncode, 0, result.stderr)
                            else:
                                self.assertNotEqual(result.returncode, 0, result.stdout)


    def test_workflow_artifact_and_provenance_gates_cover_each_identity(self) -> None:
        archive_stub = r"""from pathlib import Path
import sys

kind, *args = sys.argv[1:]
if kind == "cpio" or "--file=-" in args:
    package = sys.stdin.read().strip()
else:
    package = args[args.index("--file") + 1]
relative = ["opt/syswarden/bin/syswarden-cli", "opt/syswarden/bin/syswarden-core", "opt/syswarden/bin/syswarden-tui", "opt/syswarden/signatures.json"]
prefix = "" if package.endswith(".apk") else "./"
if "--list" in args:
    print("\n".join(prefix + item for item in relative))
else:
    print(Path(package).name + "|" + args[-1].removeprefix("./"))
"""
        gate_stub = r"""import json
from pathlib import Path
import sys

log, *args = sys.argv[1:]
root = Path(args[args.index("--root") + 1])
contents = {str(path.relative_to(root)): path.read_text() for path in root.rglob("*") if path.is_file()}
with Path(log).open("a") as output:
    output.write(json.dumps({"args": args, "contents": contents}) + "\n")
"""
        for version in ("4.10.4", "5.00.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                environment = workflow_fixture(root, version)
                for name in workflow_assets(version):
                    (Path(environment["PACKAGE_ASSETS"]) / name).write_text(f"synthetic {name}\n")
                profile_name = f"syswarden-{version}-1.rhelpo.x86_64.rpm"
                (Path(environment["RHEL_PROFILE_ASSETS"]) / profile_name).write_text("synthetic RHEL opt-in fixture\n")
                result = bash(fixture_shell(environment) + workflow_step("Generate Checksums") + workflow_step("Generate Opt-in RHEL Package-owned Checksums"))
                self.assertEqual(result.returncode, 0, result.stderr)
                result = bash(fixture_shell(environment) + "python3() { printf '%s\\0' \"$@\"; printf '\\0'; }\n" + workflow_step("Validate Exact Package Artifact"))
                self.assertEqual(result.returncode, 0, result.stderr)
                artifact_calls = nul_calls(result.stdout)
                native_artifacts = [name for name in workflow_assets(version) if not name.endswith(".apk")]
                self.assertEqual(len(artifact_calls), 1 + 2 * len(native_artifacts))
                for name in native_artifacts:
                    self.assertEqual(sum(str(Path(environment["PACKAGE_ASSETS"]) / name) in args for args in artifact_calls), 2)
                archive_script, gate_script, log = root / "archive-stub.py", root / "gate-stub.py", root / "gates.jsonl"
                archive_script.write_text(archive_stub)
                gate_script.write_text(gate_stub)
                stubs = (
                    f"ARCHIVE_STUB={shlex.quote(str(archive_script))}\nGATE_STUB={shlex.quote(str(gate_script))}\nGATE_LOG={shlex.quote(str(log))}\n"
                    + 'dpkg-deb() { [[ "$1" == --fsys-tarfile ]]; printf "%s\\n" "$2"; }\n'
                    + 'rpm2cpio() { printf "%s\\n" "$1"; }\n'
                    + 'tar() { command python3 "$ARCHIVE_STUB" tar "$@"; }\n'
                    + 'cpio() { command python3 "$ARCHIVE_STUB" cpio "$@"; }\n'
                    + 'python3() { command python3 "$GATE_STUB" "$GATE_LOG" "$@"; }\n'
                )
                result = bash(fixture_shell(environment) + stubs + workflow_step("Validate Packaged Binary Provenance"))
                self.assertEqual(result.returncode, 0, result.stderr)
                records = [json.loads(line) for line in log.read_text().splitlines()]
                names = ("syswarden",) if version.startswith("4.") else ("syswarden", "syswarden-base")
                self.assertEqual(len(records), 3 * len(names) + 1)
                expected_roots = {}
                for name in names:
                    namespace = root / "payload-attestation"
                    if version.startswith("5."):
                        namespace /= name
                    for family, filename in zip(("deb", "rpm", "apk"), (f"{name}_{version}_amd64.deb", f"{name}-{version}-1.x86_64.rpm", f"{name}_{version}_x86_64.apk"), strict=True):
                        expected_roots[str(namespace / family)] = filename
                expected_roots[str(root / "payload-attestation/rpm-rhel-package-owned")] = profile_name
                actual_roots = [record["args"][record["args"].index("--root") + 1] for record in records]
                self.assertEqual(sorted(actual_roots), sorted(expected_roots))
                for record in records:
                    args = record["args"]
                    destination = args[args.index("--root") + 1]
                    self.assertEqual(len(record["contents"]), 4)
                    for relative, content in record["contents"].items():
                        self.assertEqual(content, f"{expected_roots[destination]}|{relative}\n")
                    apk = destination.endswith("/apk")
                    self.assertEqual(args[args.index("--mode") + 1], "static" if apk else "pie")
                    self.assertEqual(args[args.index("--expected-digest-contract") + 1], environment["VALIDATED_APK_AMD64_DIGEST_CONTRACT" if apk else "VALIDATED_AMD64_DIGEST_CONTRACT"])


if __name__ == "__main__":
    unittest.main()
