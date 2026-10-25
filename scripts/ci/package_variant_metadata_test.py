#!/usr/bin/env python3
"""Exercise local package generation without compiling or installing packages."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
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
                dependencies = generated.split("depends:\n", 1)[1].split("conflicts:\n", 1)[0]
                self.assertEqual(dependencies.splitlines(), [f"  - {value}" for value in expected["apk"]])
                self.assertEqual(generated.split("conflicts:\n", 1)[1].split("contents:\n", 1)[0], f'  - "{expected["conflict"][0]}"\n')
                self.assertIn('arch: "amd64"\n', generated)
                for forbidden in ("provides:", "replaces:", "obsoletes:"):
                    self.assertNotIn(forbidden, generated)
                payloads.append(generated.split("contents:\n", 1)[1])
        self.assertEqual(payloads[0], payloads[1])

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

    def test_local_hook_binding_precedes_packaging_and_public_inventory_is_unchanged(self) -> None:
        self.assertLess(self.source.index('syswarden_render_local_package_hook "${package_hook}"'), self.source.index("# Generate DEB"))
        self.assertIn('LOCAL_PACKAGE_OUTPUT="${LOCAL_PACKAGE_OUTPUT}/minimal"', self.source)
        self.assertIn('secure_builder_directory "${REPOSITORY_ROOT}/dist/packages"', self.source)
        workflow = (ROOT / ".github/workflows/package.yml").read_text()
        self.assertNotIn("syswarden-base", workflow)
        self.assertNotIn("package_variant_metadata.sh", workflow)

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


if __name__ == "__main__":
    unittest.main()
