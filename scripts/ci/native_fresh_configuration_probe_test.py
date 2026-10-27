#!/usr/bin/env python3
"""Regression tests for inert native fresh-hook dispatch and cleanup accounting."""
import copy
import hashlib
import io
import json
import os
import re
from pathlib import Path
import struct
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
    if format_name == "apk":
        lines += ["CLI_LAUNCHERS=stage-fresh"]
    lines += ["CLI_PHASE=fresh", "CLI_ARGC=1", "CLI_ARG=install"]
    if format_name == "apk":
        lines += ["CLI_LAUNCHERS=complete-fresh"]
    lines += ["HOOK_EVENTS_END", f"FRESH_HOOK_DISPATCH_PASS={format_name}:{name}:{source}"]
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


def static_cli_bytes():
    data = bytearray(160)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, len(data), len(data), 4096)
    return bytes(data)


def configuration_export(mutate=None):
    contents = {name: b"# synthetic inactive configuration\n" for name in probe.CONFIG_FILES}
    contents["config.toml"] += b'schema_version=1\n[core]\ninstall_profile="unconfigured-v1"\nconfig_dir="/etc/syswarden/config/modules"\n'
    contents["modules/00-core.toml"] += b'core.install_profile="unconfigured-v1"\ncore.firewall_backend="keep"\n'
    contents["modules/10-network.toml"] += b'network.policy_mode="lists"\nnetwork.blocklists.list_choice="4"\n'
    contents["modules/99-user.toml"] += "".join(key + "=false\n" for key in probe.INACTIVE_KEYS).encode()
    contents["modules/99-user.toml"] += "".join(key + '=""\n' for key in probe.EMPTY_CONFIG_KEYS).encode()
    contents["modules/99-user.toml"] += b"security.honeyports=[]\n"
    members = []
    for name in ("config", "config/modules", *("config/" + name for name in probe.CONFIG_FILES)):
        entry = tarfile.TarInfo(name)
        if name in ("config", "config/modules"):
            entry.type, entry.mode = tarfile.DIRTYPE, 0o700
            data = b""
        else:
            entry.mode = 0o600
            data = contents[name[7:]]
            entry.size = len(data)
        members.append([entry, data])
    if mutate:
        mutate(members)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for entry, data in members:
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def real_output(format_name="deb"):
    output = successful_output(format_name=format_name).replace(b"CLI_PHASE=fresh\nCLI_ARGC=1\nCLI_ARG=install\n", b"")
    output = output.replace(b"CLI_LAUNCHERS=stage-fresh\n", b"").replace(b"CLI_LAUNCHERS=complete-fresh\n", b"")
    if format_name == "apk":
        identity_lines = "".join(f"APK_LAUNCHER_ID={index}:1:{index + 10}:a1ff:0:0:1:{len(target)}\n" for index, target in enumerate(probe.APK_ALIAS_TARGETS)).encode()
        output = output.replace(b"HOOK_EVENTS_BEGIN", b"APK_LAUNCHERS_PENDING_PASS\n" + identity_lines + b"APK_LAUNCHERS_COMMITTED_PASS\nHOOK_EVENTS_BEGIN")
    return output.replace(b"HOOK_EVENTS_BEGIN", probe.REAL_STAGING_DISPOSITION.encode() + b"\nREAL_CONFIGURATION_PREVIEW_PASS\nREAL_CONFIGURATION_EDIT_INSPECTION_PASS\nREAL_CONFIGURATION_PASS\nHOOK_EVENTS_BEGIN")


def launcher_export(mutate=None):
    canonical = lambda value: (json.dumps(value, separators=(",", ":")) + "\n").encode()
    digest = lambda raw: hashlib.sha256(raw).hexdigest()
    schema = "syswarden-apk-fresh-launchers/v1"
    evidence = {"absent": True, "identity": {}}
    parents = [{"path": path, "absent": False, "identity": {"inode": index + 1}} for index, path in enumerate((".", "usr", "usr/local", "usr/local/bin"))]
    originals = [{"path": path, "disposition": "absent", "original": evidence, "committed": evidence, "product_dependency": False} for path in probe.APK_ALIAS_PATHS]
    before = b"P:synthetic-unrelated\nV:1\n\n"
    payload_hashes = {"opt/syswarden/bin/syswarden-cli": "a" * 64}
    intent = {"schema": schema, "purpose": "fresh-intent-no-alias-mutation", "database_sha256": digest(before),
              "payload": [{"path": path, "sha256": sha} for path, sha in payload_hashes.items()], "parents": parents, "aliases": originals}
    intent_raw = canonical(intent)
    plan = digest(intent_raw)
    journal = "fresh-" + plan + "/"
    files = {journal + "intent.json": intent_raw, journal + "before-installed": before}
    aliases = []
    for index, (path, target) in enumerate(zip(probe.APK_ALIAS_PATHS, probe.APK_ALIAS_TARGETS)):
        committed = {"absent": False, "identity": {"device": 1, "inode": index + 10, "mode": 0o120777, "uid": 0, "gid": 0, "links": 1, "size": len(target)}, "link_target": target}
        creation = {"schema": schema, "purpose": "exclusive-launcher-created", "prepared_sha256": plan, "path": path, "evidence": committed}
        name = "launcher-created-" + ("cli" if index == 0 else "tui") + ".json"
        files[journal + name] = canonical(creation)
        creation["purpose"], creation["evidence"] = "exclusive-launcher-create-intent", evidence
        files[journal + "intent-" + name] = canonical(creation)
        aliases.append({"path": path, "disposition": "product-created", "original": evidence, "committed": committed, "creation_sha256": digest(files[journal + name]), "product_dependency": False})
    receipt = {"schema": schema, "purpose": "exclusive-fresh-launcher-ownership", "intent_sha256": plan,
               "native": {"name": "syswarden", "version": "v" + probe.VERSION}, "parents": parents, "aliases": aliases}
    files[journal + "receipt.json"] = canonical(receipt)
    files["current.json"] = canonical({"schema": schema, "kind": "fresh", "plan_sha256": plan, "receipt_sha256": digest(files[journal + "receipt.json"])})
    if mutate:
        mutate(files, journal)
    output = io.BytesIO()
    base = probe.APK_LAUNCHER_ROOT.rsplit("/", 1)[1]
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in (base, base + "/" + journal.rstrip("/")):
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode = tarfile.DIRTYPE, 0o700
            archive.addfile(entry)
        for name, raw in files.items():
            entry = tarfile.TarInfo(base + "/" + name)
            entry.mode, entry.size = 0o600, len(raw)
            archive.addfile(entry, io.BytesIO(raw))
    return output.getvalue(), payload_hashes


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

    def test_static_cli_requires_exact_amd64_executable_without_interpreter_or_dynamic_segments(self):
        data = static_cli_bytes()
        probe.validate_static_amd64_elf(data)
        mutations = [b"not-elf", data[:63]]
        for offset, format_name, value in ((4, "B", 1), (5, "B", 2), (7, "B", 9), (16, "H", 3),
                (18, "H", 183), (20, "I", 2), (32, "Q", 1000), (52, "H", 0), (54, "H", 0),
                (56, "H", 0), (56, "H", 129), (64, "I", 2), (64, "I", 3), (68, "I", 4),
                (72, "Q", 1000), (96, "Q", 1000), (104, "Q", 1)):
            changed = bytearray(data)
            struct.pack_into("<" + format_name, changed, offset, value)
            mutations.append(bytes(changed))
        for data in mutations:
            with self.subTest(data=data[:24]), self.assertRaises(ValueError):
                probe.validate_static_amd64_elf(data)

    def test_real_cli_snapshot_refuses_symlink_multilink_and_identity_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "cli"
            binary.write_bytes(static_cli_bytes())
            binary.chmod(0o700)
            link = root / "link"
            link.symlink_to(binary)
            with self.assertRaises(ValueError):
                probe.native.snapshot_retention_binary(link)
            link.unlink()
            os.link(binary, link)
            with self.assertRaises(ValueError):
                probe.native.snapshot_retention_binary(binary)
            link.unlink()
            snapshot = probe.native.snapshot_retention_binary(binary)
            binary.write_bytes(static_cli_bytes() + b"changed")
            with self.assertRaises(ValueError):
                snapshot.recheck()

    def test_independent_toml_export_refuses_inventory_links_permissions_and_active_policy(self):
        result = probe.parse_configuration_export(configuration_export())
        self.assertEqual(set(result["configuration_sha256"]), set(probe.CONFIG_FILES))
        self.assertTrue(result["independent_toml_validation"])
        mutations = [lambda members: members.pop(), lambda members: members.append(copy.deepcopy(members[-1])),
                     lambda members: setattr(members[-1][0], "name", "config/../outside"),
                     lambda members: setattr(members[-1][0], "name", "config/extra.toml"),
                     lambda members: setattr(members[-1][0], "type", tarfile.SYMTYPE),
                     lambda members: setattr(members[-1][0], "type", tarfile.LNKTYPE),
                     lambda members: setattr(members[-1][0], "type", tarfile.GNUTYPE_SPARSE),
                     lambda members: setattr(members[0][0], "name", "/"),
                     lambda members: setattr(members[-1][0], "name", "config//modules/99-user.toml"),
                     lambda members: setattr(members[-1][0], "name", "./config/modules/99-user.toml"),
                     lambda members: setattr(members[-1][0], "uid", 1000),
                     lambda members: setattr(members[-1][0], "mode", 0o644),
                     lambda members: setattr(members[0][0], "mode", 0o777),
                     lambda members: members[-1].__setitem__(1, b"invalid TOML = ["),
                     lambda members: members[-1].__setitem__(1, members[-1][1].replace(b"=false", b"=true", 1)),
                     lambda members: members[-1].__setitem__(1, members[-1][1].replace(b"=false", b'="false"', 1)),
                     lambda members: members[-1].__setitem__(1, b"# missing switches\n"),
                     lambda members: members[4].__setitem__(1, members[4][1].replace(b'choice="4"', b'choice="1"')),
                     lambda members: members[2].__setitem__(1, members[2][1].replace(b'unconfigured-v1', b'standard-v1')),
                     lambda members: members[2].__setitem__(1, members[2][1].replace(b'schema_version=1', b'schema_version=true'))]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                probe.parse_configuration_export(configuration_export(mutation))
        def over_aggregate(members):
            for entry in members[2:]:
                entry[1] = b"#" + b"x" * ((128 << 10) - 2) + b"\n"
        with self.assertRaisesRegex(ValueError, "aggregate"):
            probe.parse_configuration_export(configuration_export(over_aggregate))
        for bad in (b"", b"not-tar", b"x" * ((2 << 20) + 1), configuration_export() + b"trailing",
                    configuration_export() + configuration_export()):
            with self.assertRaises(ValueError):
                probe.parse_configuration_export(bad)

    def test_raw_tar_framing_rejects_hidden_pax_gnu_and_nonfile_headers(self):
        good = configuration_export()
        probe.validate_configuration_tar_framing(good)
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
                     tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.GNUTYPE_SPARSE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            entry = tarfile.TarInfo("override")
            entry.type = kind
            content = b"config/modules/99-user.toml\0"
            entry.size = len(content)
            header = entry.tobuf(format=tarfile.USTAR_FORMAT)
            prefixed = header + content + b"\0" * ((-len(content)) % 512) + good
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "unsupported raw tar header"):
                probe.parse_configuration_export(prefixed)
        # A valid PAX record can cause tarfile to expose an allowed name even
        # when the underlying raw regular header contains a foreign name.
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            entry = tarfile.TarInfo("foreign")
            entry.pax_headers = {"path": "config/config.toml"}
            archive.addfile(entry, io.BytesIO(b""))
        with self.assertRaisesRegex(ValueError, "unsupported raw tar header"):
            probe.parse_configuration_export(stream.getvalue())
        for data in (good[:-1], good + b"x" * 512, b"\0" * 512, good[:512],
                     good[:124] + b"9" * 12 + good[136:],
                     good[:345] + b"prefix" + good[351:]):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                probe.validate_configuration_tar_framing(data)

    def test_real_cli_output_requires_actual_staging_and_validation_without_stub_events(self):
        for format_name in probe.FORMATS:
            good = real_output(format_name)
            self.assertTrue(probe.parse_result(good, "local", "syswarden", format_name, True)["fresh_cli_staging_call"])
            for invalid in (successful_output(format_name=format_name), good.replace(b"REAL_CONFIGURATION_PASS\n", b""),
                            good.replace(probe.REAL_STAGING_DISPOSITION.encode(), b"wrong disposition"),
                            good.replace(b"REAL_CONFIGURATION_PASS", b"REAL_CONFIGURATION_PASS\nREAL_CONFIGURATION_PASS"),
                            good.replace(b"REAL_CONFIGURATION_PREVIEW_PASS\n", b""),
                            good.replace(b"REAL_CONFIGURATION_EDIT_INSPECTION_PASS\n", b""),
                            good.replace(b"REAL_CONFIGURATION_PREVIEW_PASS", b"REAL_CONFIGURATION_PREVIEW_PASS\nREAL_CONFIGURATION_PREVIEW_PASS"),
                            good.replace(b"REAL_CONFIGURATION_EDIT_INSPECTION_PASS", b"REAL_CONFIGURATION_EDIT_INSPECTION_PASS\nREAL_CONFIGURATION_EDIT_INSPECTION_PASS"),
                            good.replace(b"HOOK_EVENTS_END", b"CLI_PHASE=fresh\nHOOK_EVENTS_END")):
                with self.assertRaises(ValueError):
                    probe.parse_result(invalid, "local", "syswarden", format_name, True)
            with self.assertRaises(ValueError):
                probe.parse_result(good, "local", "syswarden", format_name)

    def test_independent_apk_receipt_export_requires_complete_bound_lineage(self):
        raw, payload = launcher_export()
        identities = probe.parse_result(real_output("apk"), "local", "syswarden", "apk", True)["apk_launcher_identities"]
        self.assertTrue(probe.parse_launcher_export(raw, "syswarden", payload, identities)["fresh_apk_launcher_receipt_verified"])
        changes = (
            lambda files, journal: files.__setitem__("pending.json", b"{}\n"),
            lambda files, journal: files.__setitem__(journal + "unknown.json", b"{}\n"),
            lambda files, journal: files.pop(journal + "launcher-created-tui.json"),
            lambda files, journal: files.__setitem__(journal + "before-installed", b"changed\n"),
            lambda files, journal: files.__setitem__(journal + "receipt.json", files[journal + "receipt.json"].replace(b'product-created', b'retained-administrator')),
            lambda files, journal: files.__setitem__("current.json", files["current.json"].replace(b'"fresh"', b'"execution"')),
            lambda files, journal: files.__setitem__(journal + "intent-launcher-created-cli.json", b"{}\n"),
        )
        for change in changes:
            raw, payload = launcher_export(change)
            with self.assertRaises((ValueError, KeyError)):
                probe.parse_launcher_export(raw, "syswarden", payload, identities)
        raw, payload = launcher_export()
        with self.assertRaises(ValueError):
            probe.parse_launcher_export(raw, "syswarden-base", payload, identities)
        with self.assertRaises(ValueError):
            probe.parse_launcher_export(raw, "syswarden", {"foreign": "a" * 64}, identities)
        with self.assertRaises(ValueError):
            probe.parse_launcher_export(raw + raw, "syswarden", payload, identities)
        changed = copy.deepcopy(identities)
        changed[0]["inode"] += 1
        with self.assertRaises(ValueError):
            probe.parse_launcher_export(raw, "syswarden", payload, changed)

    def test_apk_requires_exact_stage_commit_sequence_and_no_false_ownership_in_stub_mode(self):
        stub = successful_output(format_name="apk")
        for marker in (b"CLI_LAUNCHERS=stage-fresh\n", b"CLI_LAUNCHERS=complete-fresh\n"):
            for changed in (stub.replace(marker, b""), stub.replace(marker, marker + marker)):
                with self.assertRaises(ValueError):
                    probe.parse_result(changed, "local", "syswarden", "apk")
        real = real_output("apk")
        for marker in (b"APK_LAUNCHERS_PENDING_PASS\n", b"APK_LAUNCHERS_COMMITTED_PASS\n"):
            for changed in (real.replace(marker, b""), real.replace(marker, marker + marker)):
                with self.assertRaises(ValueError):
                    probe.parse_result(changed, "local", "syswarden", "apk", True)
        with self.assertRaises(ValueError):
            probe.parse_result(stub.replace(b"HOOK_EVENTS_BEGIN", b"APK_LAUNCHERS_COMMITTED_PASS\nHOOK_EVENTS_BEGIN"), "local", "syswarden", "apk")

    def test_final_admin_and_forbidden_checks_follow_readonly_validation(self):
        validation = probe.SCRIPT.index("/bin/sh validate-real.sh")
        self.assertGreater(probe.SCRIPT.index("test ! -s forbidden"), validation)
        self.assertGreater(probe.SCRIPT.index("sha256sum -c administrator.sha256"), validation)
        self.assertIn("/etc/cron.d/syswarden /etc/cron.d/.syswarden*", probe.REAL_VALIDATION)
        for operation in ('"$cli" config preview', '"$cli" config recover-edit'):
            self.assertLess(probe.REAL_VALIDATION.index(operation), probe.REAL_VALIDATION.index("sha256sum -c real-config.sha256"))
            self.assertLess(probe.REAL_VALIDATION.index(operation), probe.REAL_VALIDATION.index("real-config.after"))

    def test_shell_permission_check_cannot_overwrite_real_cli_dispatch(self):
        # Execute the actual selection, permission and branch fragments using
        # only private fixture files and a shell function for container stat.
        # Reusing the selection variable for permissions makes this test fail.
        lines = probe.SCRIPT.splitlines()
        selection = next(line for line in lines if "=$(cat cli-mode)" in line)
        selection_case = next(line for line in lines if "in stub|real)" in line)
        permission = next(line for line in lines if "=$(stat -c '%a' /run/.containerenv)" in line)
        permission_check = next(line for line in lines if "& 0022))" in line)
        branches = re.findall(r'if \[ "\$[a-z_]+" = real \]; then\n.*?\nfi', probe.SCRIPT, flags=re.DOTALL)
        self.assertEqual(len(branches), 2)
        for selected in ("stub", "real"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "cli-mode").write_text(selected + "\n")
                (root / "validate-real.sh").write_text("printf 'real-validation-called\\n'\n")
                program = "\n".join(("set -eu", "format=deb", "stat() { printf '644\\n'; }", selection, selection_case,
                                      permission, permission_check, *branches,
                                      "printf 'list=%s wg=%s\\n' \"${SYSWARDEN_LIST_CHOICE:-unset}\" \"${SYSWARDEN_ENABLE_WG:-unset}\""))
                program = program.replace("/etc/syswarden", str(root / "absent"))
                result = subprocess.run(["/bin/sh", "-eu", "-c", program], cwd=root, env={"PATH": os.environ["PATH"]},
                                        capture_output=True, check=False, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = b"real-validation-called\nlist=1 wg=y\n" if selected == "real" else b"list=unset wg=unset\n"
                self.assertEqual(result.stdout, expected)

    def test_real_mode_inherits_only_known_legacy_selection_challenges(self):
        parser = (probe.ROOT / "src/core/syswarden-cli/config/parser.go").read_text()
        for name in ("SYSWARDEN_LIST_CHOICE", "SYSWARDEN_ENABLE_WG"):
            self.assertIn('case "' + name + '":', parser)
        self.assertIn('if [ "$cli_mode" = real ]; then\n    # Legacy flat-file selection names', probe.SCRIPT)
        self.assertIn('export SYSWARDEN_LIST_CHOICE=1 SYSWARDEN_ENABLE_WG=y', probe.SCRIPT)
        self.assertNotIn('export SYSWARDEN_NETWORK_BLOCKLISTS_LIST_CHOICE', probe.SCRIPT)

    def test_real_payload_uses_exact_sealed_binary_without_host_execution(self):
        actual_run = probe.subprocess.run
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source-cli"
            source.write_bytes(static_cli_bytes())
            source.chmod(0o700)
            snapshot = probe.native.snapshot_retention_binary(source)
            for format_name in probe.FORMATS:
                with self.subTest(format=format_name):
                    work = root / format_name
                    work.mkdir()
                    def build(arguments, **kwargs):
                        if arguments[0] != "/fixture/nfpm":
                            self.assertEqual(arguments[0], "/bin/bash")
                            return actual_run(arguments, **kwargs)
                        spec = json.loads((work / "fixture.json").read_text())
                        self.assertEqual(spec["license"], "GPL-3.0-or-later")
                        self.assertEqual((work / "cli").read_bytes(), snapshot.data)
                        by_path = {entry["dst"][1:]: entry for entry in spec["contents"]}
                        if format_name == "apk":
                            self.assertEqual(set(by_path), set(probe.APK_PAYLOAD_MODES))
                            self.assertFalse(any(path == "usr/local" or path.startswith("usr/local/") for path in by_path))
                        else:
                            self.assertEqual(set(by_path), {"opt/syswarden/bin/syswarden-cli",
                                                           "usr/local/bin/syswarden", "usr/local/bin/syswarden-tui"})
                            for name, target in (("syswarden", "syswarden-cli"), ("syswarden-tui", "syswarden-tui")):
                                self.assertEqual(by_path["usr/local/bin/" + name], {
                                    "src": "/opt/syswarden/bin/" + target, "dst": "/usr/local/bin/" + name, "type": "symlink",
                                    "file_info": {"mode": 0o777, "owner": "root", "group": "root"}})
                        actual_cli = by_path["opt/syswarden/bin/syswarden-cli"]
                        self.assertEqual(Path(actual_cli["src"]).read_bytes(), snapshot.data)
                        self.assertEqual(actual_cli["file_info"]["mode"], 0o750 if format_name == "apk" else 0o755)
                        Path(arguments[arguments.index("--target") + 1]).write_bytes(b"inert-package-with-real-cli")
                        return subprocess.CompletedProcess(arguments, 0, b"built\n")
                    with mock.patch.object(probe.subprocess, "run", side_effect=build):
                        data, binding = probe.payload(work, Path("/fixture/nfpm"), "local", "syswarden-base", format_name, snapshot)
                    self.assertEqual(binding["cli_mode"], "real")
                    self.assertEqual(binding["cli_sha256"], hashlib.sha256(snapshot.data).hexdigest())
                    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                        self.assertEqual(archive.extractfile("cli-mode").read(), b"real\n")
                        self.assertEqual(archive.extractfile("validate-real.sh").read(), probe.REAL_VALIDATION.encode())
                        self.assertEqual(archive.extractfile("real-cli.sha256").read(),
                                         (binding["cli_sha256"] + "  /opt/syswarden/bin/syswarden-cli\n").encode())
            source.write_bytes(snapshot.data + b"drift")
            with self.assertRaises(ValueError):
                probe.payload(root / "not-created", Path("/fixture/nfpm"), "local", "syswarden", "deb", snapshot)
            self.assertFalse((root / "not-created").exists())

    def test_real_validation_script_refuses_cli_failure_or_configuration_mutation(self):
        # Run only a synthetic shell responder and temporary paths on the host.
        for behavior in ("read-only", "mutate", "fail", "empty-query-fail", "menu-fail", "preview-fail", "preview-mutate", "preview-missing-text", "recovery-fail", "recovery-mutate", "recovery-missing-text"):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config = root / "config"
                (config / "modules").mkdir(parents=True)
                for name in probe.CONFIG_FILES:
                    (config / name).write_bytes(b"synthetic private policy\n")
                    (config / name).chmod(0o600)
                cli = root / "responder"
                preview_reply = "Validated configuration preview (7 TOML inputs).\nNo managed threat list is selected.\nNo host change was applied. This preview grants no activation approval and does not prove runtime state or access.\n"
                recovery_reply = "No pending TOML file publication requires recovery.\n"
                inspection = ""
                for command, prefix, reply in (("preview", "preview", preview_reply), ("recover-edit", "recovery", recovery_reply)):
                    inspection += 'if [ "$1" = config ] && [ "${2:-}" = "' + command + '" ]; then\n'
                    if behavior == prefix + "-fail":
                        inspection += "exit 1\n"
                    elif behavior == prefix + "-mutate":
                        inspection += 'printf changed >> "' + str(config / "config.toml") + '"\n'
                    if behavior != prefix + "-missing-text":
                        inspection += "printf '%s' '" + reply + "'\n"
                    inspection += "exit 0\nfi\n"
                cli.write_text('#!/bin/sh\nset -eu\n' + inspection + 'if [ "$1" = config ] && [ "$#" = 1 ]; then\n'
                    + ('exit 1\n' if behavior == "menu-fail" else 'IFS= read -r choice; test "$choice" = 0; exit 0\n')
                    + 'fi\nif [ "$1:$2" = "config:validate" ]; then\n'
                    + ('exit 1\n' if behavior == "fail" else
                       'printf changed >> "' + str(config / "config.toml") + '"\n' if behavior == "mutate" else 'true\n')
                    + 'exit 0\nfi\ntest "$1" = config-get\ncase "$2" in\n'
                    + 'core.install_profile) echo unconfigured-v1 ;;\ncore.firewall_backend) echo keep ;;\n'
                    + 'network.policy_mode) echo lists ;;\nnetwork.blocklists.list_choice) echo 4 ;;\n'
                    + 'core.ssh_port|waap.bruteforce_logs|waap.modsec_logs) ' + ('exit 1' if behavior == "empty-query-fail" else 'echo') + ' ;;\n'
                    + "security.honeyports) echo '[]' ;;\n*) echo false ;;\nesac\n")
                cli.chmod(0o700)
                (root / "real-cli.sha256").write_text(hashlib.sha256(cli.read_bytes()).hexdigest() + "  " + str(cli) + "\n")
                script = probe.REAL_VALIDATION.replace("/etc/syswarden/config", str(config))
                script = script.replace("/opt/syswarden/bin/syswarden-cli", str(cli))
                script = script.replace("0:0:600:1", f"{os.geteuid()}:{os.getegid()}:600:1")
                # The product absence checks are container-only. Point their
                # fixed parent directories at empty private fixture paths.
                for directory in ("/etc/syswarden", "/etc/cron.d", "/etc/runlevels/default", "/usr/lib/systemd/system", "/lib/systemd/system"):
                    script = script.replace(directory, str(root / "absent"))
                # The first replacement already moved the configuration root;
                # its parent inventory should observe that exact private root.
                script = script.replace(str(root / "absent") + "/config", str(config))
                result = subprocess.run(["/bin/sh", "-eu", "-c", script], cwd=root, capture_output=True, check=False, timeout=10)
                self.assertEqual(result.returncode == 0, behavior == "read-only", result.stderr)
                self.assertEqual(b"REAL_CONFIGURATION_PASS\n" in result.stdout, behavior == "read-only")

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
        scripts = [probe.CLI, probe.SCRIPT.encode(), probe.REAL_VALIDATION.encode(), probe.delegate("preinst.sh"), probe.delegate("postinst.sh")]
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
                            expected_paths = set(probe.APK_PAYLOAD_MODES) if format_name == "apk" else {
                                "opt/syswarden/bin/syswarden-cli", "usr/local/bin/syswarden", "usr/local/bin/syswarden-tui"}
                            self.assertEqual({entry["dst"][1:] for entry in config["contents"]}, expected_paths)
                            if format_name != "apk":
                                aliases = [entry for entry in config["contents"] if entry.get("type") == "symlink"]
                                self.assertEqual(aliases, [
                                    {"src": "/opt/syswarden/bin/syswarden-cli", "dst": "/usr/local/bin/syswarden", "type": "symlink",
                                     "file_info": {"mode": 0o777, "owner": "root", "group": "root"}},
                                    {"src": "/opt/syswarden/bin/syswarden-tui", "dst": "/usr/local/bin/syswarden-tui", "type": "symlink",
                                     "file_info": {"mode": 0o777, "owner": "root", "group": "root"}},
                                ])
                            if format_name == "apk":
                                by_path = {entry["dst"][1:]: entry for entry in config["contents"]}
                                for path, mode in probe.APK_PAYLOAD_MODES.items():
                                    self.assertEqual(by_path[path]["file_info"]["mode"], mode)
                                    self.assertFalse(path == "usr/local" or path.startswith("usr/local/"))
                                core = Path(by_path["opt/syswarden/bin/syswarden-core"]["src"]).read_bytes()
                                capability = Path(by_path[probe.descriptor.DESCRIPTOR_PATH]["src"]).read_bytes()
                                self.assertEqual(capability, probe.descriptor.descriptor_for_digests(hashlib.sha256(probe.CLI).hexdigest(), hashlib.sha256(core).hexdigest()))
                                recovery = Path(by_path["etc/apk/commit_hooks.d/syswarden-recovery"]["src"]).read_bytes()
                                self.assertEqual(recovery, (probe.ROOT / "scripts/ci/package_apk_recovery_hook.sh").read_bytes())
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
                 missing_cid=False, changed_cid=False, unsafe_mount=False, create_failure=False,
                 real_cli=False, export_failure=False, export_invalid=False, export_cid_drift=False):
        nfpm = root / "nfpm"
        nfpm.write_bytes(b"caller-trusted-tool")
        nfpm.chmod(0o700)
        output = root / "output"
        binary = None
        if real_cli:
            binary = root / "real-cli"
            binary.write_bytes(static_cli_bytes())
            binary.chmod(0o700)
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
            if arguments[2] == "cp":
                self.assertTrue(real_cli)
                self.assertEqual(arguments[3:], ["d" * 64 + ":/etc/syswarden/config", "-"])
                self.assertTrue(any(call[2] == "start" for call in calls))
                if export_cid_drift:
                    (output / "container.cid").write_text("e" * 64 + "\n")
                return subprocess.CompletedProcess(arguments, 1 if export_failure else 0,
                                                    b"invalid" if export_invalid else configuration_export())
            self.assertEqual(arguments[2:], ["start", "--attach", "--interactive", "d" * 64])
            self.assertEqual(kwargs["input"], b"sealed-tar")
            self.assertTrue(any(call[2:4] == ["container", "inspect"] for call in calls))
            if timeout:
                raise subprocess.TimeoutExpired(arguments, 75, output=b"timeout retained\n")
            if changed_cid:
                (output / "container.cid").unlink()
            return subprocess.CompletedProcess(arguments, native_status, real_output() if real_cli else successful_output())
        passed = cleanup and not any((timeout, native_status, missing_cid, changed_cid, unsafe_mount, create_failure,
                                                export_failure, export_invalid, export_cid_drift)) and image_arch == "amd64"
        with mock.patch.object(probe.os, "geteuid", return_value=1000), mock.patch.object(probe.shutil, "which", return_value="/usr/bin/podman"), \
                mock.patch.object(helpers, "execute_local", side_effect=command), mock.patch.object(helpers, "container_exists", return_value=False), \
                mock.patch.object(helpers, "cleanup_container", return_value={"verified": cleanup}) as cleaned, \
                mock.patch.object(probe, "payload", return_value=(b"sealed-tar", {})):
            if passed:
                probe.run(nfpm, "a" * 64, output, "local", "syswarden", "deb", binary)
            else:
                with self.assertRaises((RuntimeError, ValueError)):
                    probe.run(nfpm, "a" * 64, output, "local", "syswarden", "deb", binary)
            if image_arch == "amd64":
                summary = json.loads((output / "results.json").read_text())
                self.assertEqual(summary["passed"], passed)
                self.assertEqual(summary["real_toml_staging_verified"], passed and real_cli)
                if missing_cid or changed_cid or export_cid_drift:
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
                        {"missing_cid": True}, {"changed_cid": True}, {"unsafe_mount": True}, {"create_failure": True},
                        {"real_cli": True}, {"real_cli": True, "export_failure": True}, {"real_cli": True, "export_invalid": True},
                        {"real_cli": True, "export_cid_drift": True}, {"real_cli": True, "cleanup": False},
                        {"real_cli": True, "native_status": 1}):
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
