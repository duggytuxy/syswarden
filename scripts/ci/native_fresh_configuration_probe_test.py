#!/usr/bin/env python3
"""Regression tests for inert native fresh-hook dispatch and cleanup accounting."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

try:
    from scripts.ci import native_fresh_configuration_probe as probe
    from scripts.ci import package_variant_metadata_test as variants
except ModuleNotFoundError:
    import native_fresh_configuration_probe as probe
    import package_variant_metadata_test as variants


def successful_output(source="local", name="syswarden", format_name="deb"):
    arguments = {"deb": (("install", "", "5.00.0"), ("configure", "")),
                 "rpm": (("1",), ("1",)), "apk": (("5.00.0-r0",), ("5.00.0-r0",))}[format_name]
    lines = ["SysWarden fresh installation: pre-install host mutation deferred.", "HOOK_EVENTS_BEGIN"]
    for hook, args in zip(("preinst.sh", "postinst.sh"), arguments):
        lines += ["HOOK=" + hook, "ARGC=" + str(len(args)), *("ARG=" + argument for argument in args)]
    lines += ["CLI_PHASE=fresh", "CLI_ARGC=1", "CLI_ARG=install", "HOOK_EVENTS_END",
              f"FRESH_HOOK_DISPATCH_PASS={format_name}:{name}:{source}"]
    return ("\n".join(lines) + "\n").encode()


def container_inspection(identity, arguments):
    return {"Id": "d" * 64, "Name": identity.name, "Image": "a" * 64, "Path": "/bin/sh",
            "Args": arguments[arguments.index("a" * 64) + 1:], "Mounts": [],
            "Config": {"Labels": {probe.isolation_helpers().OWNER_LABEL: identity.token}, "User": "0:0", "OpenStdin": True},
            "State": {"Status": "created", "Running": False},
            "EffectiveCaps": ["CAP_SYS_CHROOT"], "BoundingCaps": ["CAP_SYS_CHROOT"],
            "HostConfig": {"Binds": [], "Tmpfs": {}, "VolumesFrom": [], "NetworkMode": "none", "Privileged": False,
                           "PidMode": "private", "IpcMode": "private", "UTSMode": "private", "CgroupMode": "private",
                           "Devices": [], "PortBindings": {}, "PublishAllPorts": False, "AutoRemove": False,
                           "PidsLimit": 64, "Memory": 256 * 1024**2, "NanoCpus": 2 * 10**9,
                           "CapAdd": ["CAP_SYS_CHROOT"], "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"]}}


class FreshHookDispatchTests(unittest.TestCase):
    def identity(self, root=Path("/tmp")):
        helpers = probe.isolation_helpers()
        return helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + "b" * 32, "c" * 32, root / "container.cid")

    def test_extracted_hooks_equal_real_local_and_workflow_generation_without_uid_rewrite(self):
        source = (probe.ROOT / "build_packages.sh").read_text()
        local = source.split("# Pre-Install / Pre-Upgrade script\n", 1)[1].split("\nRPM_SCRIPTS=", 1)[0]
        for name in probe.NAMES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                result = variants.bash('source "$1"\nSOURCE_ROOT="$2"\nPACKAGE_NAME="$3"\n' + local,
                                       str(probe.ROOT / "scripts/ci/package_variant_metadata.sh"), str(probe.ROOT), name, cwd=directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                local_hooks = {hook: (directory / hook).read_bytes() for hook in ("preinst.sh", "postinst.sh")}
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                environment = variants.workflow_fixture(directory, probe.VERSION)
                result = variants.bash(variants.fixture_shell(environment) + variants.workflow_step("Prepare Linux Maintainer Scripts"))
                self.assertEqual(result.returncode, 0, result.stderr)
                for hook in local_hooks:
                    raw = probe.emitted_hook("local", hook)
                    self.assertEqual(raw, probe.emitted_hook("workflow", hook))
                    raw_path = directory / ("raw-" + hook)
                    raw_path.write_bytes(raw)
                    selected = probe.render_variant(raw_path, name)
                    self.assertEqual(selected, local_hooks[hook])
                    self.assertEqual(selected, (Path(environment["PACKAGE_SCRIPTS"]) / name / hook).read_bytes())
                    if hook == "preinst.sh":
                        self.assertIn(b'!= 0:0', selected)
                        self.assertIn(b'syswarden_set_native_install_phase preinstall "$@"', selected)

    def test_missing_duplicated_or_reset_hook_source_refuses(self):
        source = probe.SOURCE_FILES["local"].read_text()
        opening = 'cat << \'EOF\' >> preinst.sh'
        for mutation in (source.replace(opening, "# omitted"), source + "\n" + opening + "\ntrue\nEOF\n",
                         source + '\ncat "${SOURCE_ROOT}/scripts/ci/package_install_phase.sh" > preinst.sh\n'):
            with tempfile.TemporaryDirectory() as temporary:
                candidate = Path(temporary) / "builder"
                candidate.write_text(mutation)
                with mock.patch.dict(probe.SOURCE_FILES, {"local": candidate}), self.assertRaises(ValueError):
                    probe.emitted_hook("local", "preinst.sh")

    def test_sandbox_is_local_offline_owned_and_bounded(self):
        identity = self.identity()
        arguments = probe.sandbox_command("/usr/bin/podman", "a" * 64, identity, "local", "syswarden-base", "apk")
        self.assertEqual(arguments[:3], ["/usr/bin/podman", "--remote=false", "create"])
        for flag in ("--network=none", "--pull=never", "--image-volume=ignore", "--cap-drop=all", "--cap-add=SYS_CHROOT",
                     "--security-opt=no-new-privileges", "--cpus=2", "--memory=256m", "--pids-limit=64", "--timeout=60"):
            self.assertIn(flag, arguments)
        self.assertEqual(arguments[arguments.index("--cidfile") + 1], str(identity.cidfile))
        self.assertEqual(arguments[arguments.index("--label") + 1], probe.isolation_helpers().OWNER_LABEL + "=" + identity.token)
        for forbidden in ("--rm", "--privileged", "--volume", "--mount", "-v", "--pid=host", "--userns=host"):
            self.assertNotIn(forbidden, arguments)
        for image in ("alpine:3.24", "a" * 63, "A" * 64, "--privileged"):
            with self.assertRaises(ValueError):
                probe.sandbox_command("/usr/bin/podman", image, identity, "local", "syswarden", "apk")
        for selected in (("foreign", "syswarden", "deb"), ("local", "--root=/", "deb"), ("local", "syswarden", "arm64")):
            with self.assertRaises(ValueError):
                probe.sandbox_command("/usr/bin/podman", "a" * 64, identity, *selected)

    def test_all_shell_inputs_parse_without_execution(self):
        scripts = [probe.CLI, probe.SCRIPT.encode(), probe.delegate("preinst.sh"), probe.delegate("postinst.sh")]
        scripts += [probe.emitted_hook(source, hook) for source in probe.SOURCES for hook in ("preinst.sh", "postinst.sh")]
        for script in scripts:
            result = subprocess.run(["/bin/sh", "-n"], input=script, capture_output=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_delegate_preserves_empty_native_arguments_and_does_not_set_phase(self):
        for hook, arguments in (("preinst.sh", ("install", "", "5.00.0")), ("postinst.sh", ("configure", ""))):
            with self.subTest(hook=hook), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / hook).write_text('#!/bin/sh\nprintf "%s\\0" "$@" > "$RESULT"\nprintf "%s" "$SYSWARDEN_NATIVE_INSTALL_PHASE" > "$PHASE"\n')
                wrapper = probe.delegate(hook).replace(probe.FIXTURE.encode(), str(root).encode())
                result = subprocess.run(["/bin/sh", "-c", wrapper.decode(), "native-delegate", *arguments],
                                        env={"PATH": os.environ["PATH"], "SYSWARDEN_NATIVE_INSTALL_PHASE": "upgrade",
                                             "RESULT": str(root / "arguments"), "PHASE": str(root / "phase")},
                                        capture_output=True, check=False, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / "arguments").read_bytes(), b"\0".join(item.encode() for item in arguments) + b"\0")
                self.assertEqual((root / "phase").read_bytes(), b"upgrade")

    def test_complete_administrator_metadata_digest_detects_any_file_change(self):
        comparison = 'test "$(sha256sum < administrator.metadata)" = "$(sha256sum < administrator.after)"'
        self.assertIn(comparison, probe.SCRIPT)
        self.assertNotIn("cmp administrator.metadata", probe.SCRIPT)
        original = b"/etc/synthetic-one:1:2:8180:0:0:1:20:100:100\n/etc/synthetic-two:1:3:a1ff:0:0:1:18:100:100\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "administrator.metadata").write_bytes(original)
            for data in (original, original[:-1], original.replace(b"8180", b"81a4"),
                         original.replace(b"1:3:a1ff", b"1:4:a1ff"), original + b"extra\n"):
                (root / "administrator.after").write_bytes(data)
                result = subprocess.run(["/bin/sh", "-eu", "-c", comparison], cwd=root,
                                        capture_output=True, check=False, timeout=5)
                self.assertEqual(result.returncode == 0, data == original)

    def test_fixture_seals_exact_regular_hook_bytes_and_has_only_inert_payload(self):
        actual_run = probe.subprocess.run
        for source in probe.SOURCES:
            for name in probe.NAMES:
                for format_name in probe.FORMATS:
                    with self.subTest(source=source, name=name, format=format_name), tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        def build(arguments, **kwargs):
                            if arguments[0] != "/fixture/nfpm":
                                return actual_run(arguments, **kwargs)
                            config = json.loads(Path(arguments[arguments.index("--config") + 1]).read_text())
                            self.assertEqual(config["name"], name)
                            self.assertEqual(config["version_schema"], "none")
                            self.assertEqual(set(config["scripts"]), {"preinstall", "postinstall"})
                            self.assertEqual([entry["dst"] for entry in config["contents"]], ["/opt/syswarden/bin/syswarden-cli"])
                            for forbidden in ("depends", "recommends", "suggests", "provides", "replaces"):
                                self.assertNotIn(forbidden, config)
                            for hook in ("preinst.sh", "postinst.sh"):
                                self.assertEqual((root / ("delegate-" + hook)).read_bytes(), probe.delegate(hook))
                            Path(arguments[arguments.index("--target") + 1]).write_bytes(b"inert-package")
                            return subprocess.CompletedProcess(arguments, 0, b"built\n")
                        with mock.patch.object(probe.subprocess, "run", side_effect=build):
                            payload, bindings = probe.payload(root, Path("/fixture/nfpm"), source, name, format_name)
                        self.assertEqual(bindings["payload_sha256"], hashlib.sha256(payload).hexdigest())
                        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                            for member in archive.getmembers():
                                self.assertTrue(member.isfile())
                                self.assertEqual(member.mode, 0o600)
                                self.assertEqual((member.uid, member.gid), (0, 0))
                            for hook in ("preinst.sh", "postinst.sh"):
                                data = archive.extractfile(hook).read()
                                self.assertEqual(bindings["emitted_hook_sha256"][hook], hashlib.sha256(data).hexdigest())
                                self.assertNotIn(b"HOOK=", data)
                                self.assertEqual(data, probe.render_variant(root / ("raw-" + hook), name))

    def test_result_requires_one_exact_native_sequence_and_staging_call(self):
        for source in probe.SOURCES:
            for name in probe.NAMES:
                for format_name in probe.FORMATS:
                    result = probe.parse_result(successful_output(source, name, format_name), source, name, format_name)
                    self.assertTrue(result["fresh_cli_staging_call"])
                    self.assertEqual(set(result["native_arguments"]), {"preinst.sh", "postinst.sh"})
        good = successful_output()
        mutations = (b"", good.replace(b"CLI_PHASE=fresh", b"CLI_PHASE=upgrade"), good.replace(b"CLI_ARG=install", b"CLI_ARG=reload"),
                     good.replace(b"CLI_ARGC=1", b"CLI_ARGC=2"), good.replace(b"HOOK=preinst.sh", b"HOOK=postinst.sh"),
                     good.replace(b"ARGC=3", b"ARGC=4"), good.replace(b"HOOK_EVENTS_END", b"CLI_PHASE=fresh\nHOOK_EVENTS_END"),
                     good + b"FRESH_HOOK_DISPATCH_PASS=apk:syswarden-base:workflow\n", b"FORBIDDEN=systemctl\n" + good,
                     good.replace(b"SysWarden fresh installation: pre-install host mutation deferred.\n", b""),
                     good + b"trailing\n", b"x" * ((1 << 20) + 1))
        for data in mutations:
            with self.subTest(data=data[:80]), self.assertRaises(ValueError):
                probe.parse_result(data, "local", "syswarden", "deb")

    def test_only_exact_apk_hook_output_wrapper_is_accepted_once(self):
        disposition = b"SysWarden fresh installation: pre-install host mutation deferred."
        for format_name in probe.FORMATS:
            good = successful_output(format_name=format_name)
            wrapped = good.replace(disposition, b"  * " + disposition)
            if format_name == "apk":
                self.assertTrue(probe.parse_result(wrapped, "local", "syswarden", format_name)["fresh_cli_staging_call"])
            else:
                with self.assertRaises(ValueError):
                    probe.parse_result(wrapped, "local", "syswarden", format_name)
            for replacement in (disposition + b"\n" + disposition, disposition + b"\n  * " + disposition,
                                b"  * " + disposition + b"\n  * " + disposition, b" * " + disposition,
                                b"   * " + disposition, b"\t* " + disposition, b"  *  " + disposition,
                                b"  * " + disposition + b" ", b"prefix " + disposition):
                with self.subTest(format=format_name, replacement=replacement), self.assertRaises(ValueError):
                    probe.parse_result(good.replace(disposition, replacement), "local", "syswarden", format_name)

    def test_isolation_refuses_every_ownership_mount_namespace_or_resource_drift(self):
        identity = self.identity()
        arguments = probe.sandbox_command("/usr/bin/podman", "a" * 64, identity, "local", "syswarden", "deb")
        good = container_inspection(identity, arguments)
        probe.validate_isolation(good, "a" * 64, identity, "d" * 64, arguments)
        mutations = [("Id", "e" * 64), ("Name", "foreign"), ("Image", "e" * 64), ("Path", "/bin/foreign"),
                     ("Args", []), ("Mounts", [{"Type": "bind", "Source": "/", "Destination": "/host"}]),
                     ("EffectiveCaps", ["CAP_SYS_ADMIN"]), ("BoundingCaps", ["CAP_SYS_ADMIN"])]
        nested = {"Config": {"Labels": {}, "User": "1000:1000", "OpenStdin": False},
                  "State": {"Status": "running", "Running": True},
                  "HostConfig": {"Binds": ["/:/host"], "Tmpfs": {"/tmp": "rw"}, "VolumesFrom": ["foreign"],
                                 "NetworkMode": "host", "Privileged": True, "PidMode": "host", "IpcMode": "host",
                                 "UTSMode": "host", "CgroupMode": "host", "Devices": ["/dev/sda"],
                                 "PortBindings": {"22/tcp": []}, "PublishAllPorts": True, "AutoRemove": True,
                                 "PidsLimit": -1, "Memory": 0, "NanoCpus": 0, "CapAdd": ["CAP_SYS_ADMIN"],
                                 "CapDrop": [], "SecurityOpt": []}}
        for key, value in mutations:
            candidate = copy.deepcopy(good)
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.validate_isolation(candidate, "a" * 64, identity, "d" * 64, arguments)
        for group, values in nested.items():
            for key, value in values.items():
                candidate = copy.deepcopy(good)
                candidate[group][key] = value
                with self.subTest(group=group, key=key), self.assertRaises(ValueError):
                    probe.validate_isolation(candidate, "a" * 64, identity, "d" * 64, arguments)
        for key in ("Config", "HostConfig", "State", "Mounts", "EffectiveCaps", "BoundingCaps"):
            candidate = copy.deepcopy(good)
            del candidate[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                probe.validate_isolation(candidate, "a" * 64, identity, "d" * 64, arguments)

    def test_expanded_capability_metadata_requires_exact_effective_and_bounding_sets(self):
        identity = self.identity()
        arguments = probe.sandbox_command("/usr/bin/podman", "a" * 64, identity, "local", "syswarden", "deb")
        item = container_inspection(identity, arguments)
        item["HostConfig"]["CapAdd"] = []
        item["HostConfig"]["CapDrop"] = ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
                                        "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID"]
        probe.validate_isolation(item, "a" * 64, identity, "d" * 64, arguments)
        for key in ("EffectiveCaps", "BoundingCaps"):
            for capabilities in ([], ["CAP_SYS_ADMIN"], ["CAP_SYS_CHROOT", "CAP_SYS_ADMIN"],
                                 ["CAP_SYS_CHROOT", "CAP_SYS_CHROOT"], "CAP_SYS_CHROOT"):
                candidate = copy.deepcopy(item)
                candidate[key] = capabilities
                with self.subTest(key=key, capabilities=capabilities), self.assertRaises(ValueError):
                    probe.validate_isolation(candidate, "a" * 64, identity, "d" * 64, arguments)
        for key, value in (("CapAdd", ["CAP_SYS_ADMIN"]), ("CapAdd", ["CAP_SYS_CHROOT"]),
                           ("CapDrop", item["HostConfig"]["CapDrop"][:-1]),
                           ("CapDrop", item["HostConfig"]["CapDrop"] + ["CAP_SYS_ADMIN"]),
                           ("CapDrop", item["HostConfig"]["CapDrop"] + ["CAP_CHOWN"]), ("CapDrop", ["ALL"])):
            candidate = copy.deepcopy(item)
            candidate["HostConfig"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                probe.validate_isolation(candidate, "a" * 64, identity, "d" * 64, arguments)

    def run_mock(self, root, *, cleanup=True, timeout=False, native_status=0, image_arch="amd64",
                 missing_cid=False, changed_cid=False, unsafe_mount=False, create_failure=False):
        nfpm = root / "nfpm"
        nfpm.write_bytes(b"caller-trusted-tool")
        nfpm.chmod(0o700)
        output = root / "output"
        helpers = probe.isolation_helpers()
        calls = []
        created = None
        def command(arguments, **kwargs):
            nonlocal created
            calls.append(arguments)
            self.assertEqual(arguments[1], "--remote=false")
            if arguments[2] == "info":
                return subprocess.CompletedProcess(arguments, 0, b"true\n")
            if arguments[2:4] == ["image", "inspect"]:
                return subprocess.CompletedProcess(arguments, 0, json.dumps([{"Id": "a" * 64, "Os": "linux", "Architecture": image_arch}]).encode())
            if arguments[2] == "create":
                created = arguments
                self.assertNotIn("input", kwargs)
                if not missing_cid:
                    (output / "container.cid").write_text("d" * 64 + "\n")
                return subprocess.CompletedProcess(arguments, 1 if create_failure else 0, b"" if create_failure else b"d" * 64 + b"\n")
            if arguments[2:4] == ["container", "inspect"]:
                self.assertEqual(arguments[-1], "d" * 64)
                identity = helpers.ContainerIdentity(created[created.index("--name") + 1],
                             created[created.index("--label") + 1].split("=", 1)[1], output / "container.cid")
                item = container_inspection(identity, created)
                if unsafe_mount:
                    item["Mounts"] = [{"Type": "bind", "Source": "/", "Destination": "/host"}]
                return subprocess.CompletedProcess(arguments, 0, json.dumps([item]).encode())
            self.assertEqual(arguments[2:], ["start", "--attach", "--interactive", "d" * 64])
            self.assertEqual(kwargs["input"], b"sealed-tar")
            self.assertTrue(any(call[2:4] == ["container", "inspect"] for call in calls))
            if timeout:
                raise subprocess.TimeoutExpired(arguments, 75, output=b"timeout retained\n")
            if changed_cid:
                (output / "container.cid").unlink()
            return subprocess.CompletedProcess(arguments, native_status, successful_output())
        passed = cleanup and not any((timeout, native_status, missing_cid, changed_cid, unsafe_mount, create_failure)) and image_arch == "amd64"
        with mock.patch.object(probe.os, "geteuid", return_value=1000), mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                mock.patch.object(helpers, "execute_local", side_effect=command), mock.patch.object(helpers, "container_exists", return_value=False), \
                mock.patch.object(helpers, "cleanup_container", return_value={"verified": cleanup}) as cleaned, \
                mock.patch.object(probe, "payload", return_value=(b"sealed-tar", {})):
            if passed:
                probe.run(nfpm, "a" * 64, output, "local", "syswarden", "deb")
            else:
                with self.assertRaises((RuntimeError, ValueError)):
                    probe.run(nfpm, "a" * 64, output, "local", "syswarden", "deb")
            if image_arch == "amd64":
                summary = json.loads((output / "results.json").read_text())
                self.assertEqual(summary["passed"], passed)
                self.assertFalse(summary["real_toml_staging_verified"])
                if missing_cid or changed_cid:
                    cleaned.assert_not_called()
                    self.assertFalse(summary["cleanup"]["verified"])
                else:
                    cleaned.assert_called_once()
                if missing_cid or unsafe_mount or create_failure:
                    self.assertFalse(any(call[2] == "start" for call in calls))
                if timeout:
                    self.assertEqual((output / "native.log").read_bytes(), b"timeout retained\n")
            else:
                cleaned.assert_not_called()
                self.assertFalse(output.exists())
        return calls

    def test_cleanup_timeout_native_failure_and_wrong_architecture_refuse(self):
        for options in ({}, {"cleanup": False}, {"timeout": True}, {"native_status": 1}, {"image_arch": "arm64"},
                        {"missing_cid": True}, {"changed_cid": True}, {"unsafe_mount": True}, {"create_failure": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                self.run_mock(Path(temporary), **options)

    def test_cleanup_never_adopts_another_id_after_original_creation_evidence(self):
        helpers = probe.isolation_helpers()
        for recorded in (None, "e" * 64):
            with self.subTest(recorded=recorded), tempfile.TemporaryDirectory() as temporary:
                identity = self.identity(Path(temporary))
                if recorded:
                    identity.cidfile.write_text(recorded + "\n")
                with mock.patch.object(helpers, "cleanup_container") as cleanup:
                    result = probe.cleanup_owned_container("/usr/bin/podman", identity, "d" * 64)
                self.assertFalse(result["verified"])
                cleanup.assert_not_called()
        with mock.patch.object(helpers, "cleanup_container", return_value={"verified": True}) as cleanup:
            self.assertTrue(probe.cleanup_owned_container("/usr/bin/podman", self.identity(), None)["verified"])
            cleanup.assert_called_once_with("/usr/bin/podman", self.identity(), require_cid=False)

    def test_host_root_refuses_before_any_native_call(self):
        with mock.patch.object(probe.os, "geteuid", return_value=0), mock.patch.object(probe, "isolation_helpers") as helpers:
            with self.assertRaisesRegex(ValueError, "unprivileged"):
                probe.run(Path("/not-used"), "a" * 64, Path("/not-created"), "local", "syswarden", "deb")
            helpers.assert_not_called()


if __name__ == "__main__":
    unittest.main()
