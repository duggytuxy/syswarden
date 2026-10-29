#!/usr/bin/env python3
"""Opt-in fresh-hook fixture with an inert or explicitly supplied static CLI.

The default stub qualifies hook dispatch. Real CLI mode additionally verifies
inactive TOML staging, read-only effect preview and pending-edit inspection. Neither mode accepts production
package assembly, prerequisites, runtime activation or migration. Only disposable
offline rootless Linux AMD64 containers execute the fixture or supplied binary.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import textwrap
import tomllib
import uuid

try:
    from scripts.ci import native_dependency_transition_probe as native
    from scripts.ci import native_activation_descriptor as descriptor
except ModuleNotFoundError:
    import native_dependency_transition_probe as native
    import native_activation_descriptor as descriptor

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("syswarden", "syswarden-base")
SOURCES = ("local", "workflow")
FORMATS = ("deb", "rpm", "apk")
FIXTURE = "/tmp/sw-fresh-lab"
VERSION = "5.00.0"
CONFIG_FILES = ("config.toml", "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml",
                "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml")
INACTIVE_KEYS = (
    "core.hardening_enabled", "core.cis_l2_hardening", "network.geo.enabled", "network.asn.enabled",
    "network.wireguard.enabled", "network.blocklists.use_spamhaus", "network.blocklists.osint_enabled",
    "network.saas.allow_monitors", "security.l2.enable_l2", "security.l2.arp_protect", "security.l2.lan_mode",
    "security.compliance.enable_watchdog", "security.detection_enabled", "waap.enabled", "waap.log_bridge_enabled",
    "integrations.ha.enabled", "integrations.ha.v2_enabled", "integrations.siem.enabled", "integrations.abuseipdb.enabled",
    "integrations.webhooks.enabled", "integrations.bunkerweb.enabled", "integrations.wazuh.enabled",
)
EMPTY_CONFIG_KEYS = ("core.ssh_port", "waap.bruteforce_logs", "waap.modsec_logs")
REAL_STAGING_DISPOSITION = ("[INFO] Package installed without activating lists, modules, hardening, services or firewall rules. "
    "Configure TOML with 'syswarden config', run 'syswarden config validate', then explicitly run 'syswarden install' when ready.")
# Podman can report the difference from its default capabilities instead of the
# literal drop-all/add-SYS_CHROOT request. Both effective sets remain mandatory.
PODMAN_EXPANDED_CAP_DROP = frozenset({
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
    "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID",
})
SOURCE_FILES = {"local": ROOT / "build_packages.sh", "workflow": ROOT / ".github/workflows/package.yml"}

APK_LAUNCHER_ROOT = "/var/backups/syswarden-apk-launchers-v1"
APK_ALIAS_PATHS = ("usr/local/bin/syswarden", "usr/local/bin/syswarden-tui")
APK_ALIAS_TARGETS = ("/opt/syswarden/bin/syswarden-cli", "/opt/syswarden/bin/syswarden-tui")
APK_PAYLOAD_MODES = {
    "opt": 0o755, "opt/syswarden": 0o755, "opt/syswarden/bin": 0o755,
    "usr": 0o755, "usr/share": 0o755, "usr/share/bash-completion": 0o755,
    "usr/share/bash-completion/completions": 0o755, "usr/share/doc": 0o755,
    "usr/share/doc/syswarden": 0o755, "etc": 0o755, "etc/apk": 0o755,
    "etc/apk/commit_hooks.d": 0o755,
    "opt/syswarden/bin/syswarden-cli": 0o750, "opt/syswarden/bin/syswarden-core": 0o750,
    "opt/syswarden/bin/syswarden-tui": 0o750, "opt/syswarden/signatures.json": 0o640,
    "opt/syswarden/activation-contract-v1.json": 0o644,
    "usr/share/bash-completion/completions/syswarden": 0o644,
    "usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt": 0o644,
    "usr/share/doc/syswarden/LICENSE.txt": 0o644,
    "etc/apk/commit_hooks.d/syswarden-recovery": 0o755,
}


def apk_fixture_contents(root: Path, cli: bytes) -> tuple[list[dict], dict[str, str]]:
    """Provide exact native membership, with inert companions never executed."""
    inert = b"#!/bin/sh\nprintf 'FORBIDDEN=synthetic-runtime\n' >> /tmp/sw-fresh-lab/forbidden\nexit 97\n"
    content = {
        "opt/syswarden/bin/syswarden-cli": cli,
        "opt/syswarden/bin/syswarden-core": inert,
        "opt/syswarden/bin/syswarden-tui": inert,
        "opt/syswarden/signatures.json": b'{"synthetic_fixture":true}\n',
        "usr/share/bash-completion/completions/syswarden": b"# Inert fixture completion.\n",
        "usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt": b"Synthetic fixture, no GeoIP database.\n",
        "usr/share/doc/syswarden/LICENSE.txt": b"Synthetic fixture companion bytes.\n",
        "etc/apk/commit_hooks.d/syswarden-recovery": (ROOT / "scripts/ci/package_apk_recovery_hook.sh").read_bytes(),
    }
    content[descriptor.DESCRIPTOR_PATH] = descriptor.descriptor_for_digests(
        hashlib.sha256(cli).hexdigest(), hashlib.sha256(inert).hexdigest())
    entries = []
    for index, (path, mode) in enumerate(APK_PAYLOAD_MODES.items()):
        entry = {"dst": "/" + path, "file_info": {"mode": mode, "owner": "root", "group": "root"}}
        if path in content:
            source = root / ("apk-payload-" + str(index))
            write_private(source, content[path])
            entry["src"] = str(source)
        else:
            entry["type"] = "dir"
        entries.append(entry)
    return entries, {path: hashlib.sha256(data).hexdigest() for path, data in content.items()}


def isolation_helpers():
    # Older shared laboratories use sibling imports. Keep namespace and direct
    # entry points usable without requiring an ambient PYTHONPATH adjustment.
    previous = sys.path[:]
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        return native.isolation_helpers()
    finally:
        sys.path[:] = previous


def validate_selection(source: str, package_name: str, format_name: str) -> None:
    if source not in SOURCES or package_name not in NAMES or format_name not in FORMATS:
        raise ValueError("closed hook source, product identity and native format required")


def emitted_hook(source: str, hook: str) -> bytes:
    """Read actual cat inputs without the unit fixture's deliberate UID rewrite."""
    if source not in SOURCES or hook not in ("preinst.sh", "postinst.sh"):
        raise ValueError("unsupported emitted hook")
    source_name = "SOURCE_ROOT" if source == "local" else "EXACT_SOURCE_ROOT"
    destination = re.escape(hook if source == "local" else '${PACKAGE_SCRIPTS}/' + hook)
    helper = re.compile(r'^\s*cat "\$\{' + source_name + r'\}/(?P<path>scripts/ci/[a-z0-9_]+\.sh)" (?P<op>>>?) "?' + destination + r'"?\s*$')
    heredoc = re.compile(r"^\s*cat << '(?P<end>[A-Z][A-Z0-9_]*)' >> \"?" + destination + r'"?\s*$')
    lines = SOURCE_FILES[source].read_text().splitlines()
    parts: list[bytes] = []
    starts = bodies = 0
    for index, line in enumerate(lines):
        matched = helper.fullmatch(line)
        if matched:
            if matched["op"] == ">":
                starts += 1
                if parts:
                    raise ValueError("hook source reset after publication")
            parts.append((ROOT / matched["path"]).read_bytes())
        matched = heredoc.fullmatch(line)
        if matched:
            bodies += 1
            body: list[str] = []
            for following in lines[index + 1:]:
                if following.strip() == matched["end"]:
                    break
                body.append(following)
            else:
                raise ValueError("unterminated emitted hook")
            parts.append((textwrap.dedent("\n".join(body)) + "\n").encode())
    if starts != 1 or bodies != 1 or not parts or sum(map(len, parts)) > 1 << 20:
        raise ValueError("ambiguous emitted hook inventory")
    result = b"".join(parts)
    if not result.startswith(b"#!/bin/sh\n") or b"syswarden_set_native_install_phase " not in result:
        raise ValueError("emitted hook lacks its interpreter or phase boundary")
    return result


def validate_static_amd64_elf(data: bytes) -> None:
    """Bound the sealed CLI's executable format without executing it on the host."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01" or data[7] not in (0, 3):
        raise ValueError("real CLI requires a static Linux AMD64 ELF64 image")
    fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    kind, machine, version, _, offset, _, flags, header_size, entry_size, count, _, _, _ = fields
    if (kind != 2 or machine != 62 or version != 1 or flags != 0 or header_size != 64
            or entry_size != 56 or not 1 <= count <= 128 or offset < 64 or offset + entry_size * count > len(data)):
        raise ValueError("real CLI has an unsupported static ELF header")
    executable = False
    for index in range(count):
        segment, permissions, position, _, _, file_size, memory_size, _ = struct.unpack_from("<IIQQQQQQ", data, offset + index * 56)
        if segment in (2, 3):
            raise ValueError("real CLI must have no dynamic segment or interpreter")
        if position > len(data) or file_size > len(data) - position or memory_size < file_size:
            raise ValueError("real CLI ELF segment exceeds its sealed input")
        executable = executable or segment == 1 and bool(permissions & 1) and file_size > 0
    if not executable:
        raise ValueError("real CLI lacks an executable load segment")


def validate_configuration_tar_framing(data: bytes, maximum_archive: int = 2 << 20, maximum_member: int = 128 << 10) -> None:
    """Reject hidden name/size overrides before tarfile interprets any header."""
    if not data or len(data) > maximum_archive or len(data) % 512:
        raise ValueError("configuration export has invalid bounded tar framing")
    offset = 0
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if not any(header):
            if len(data) - offset < 1024 or any(data[offset:]):
                raise ValueError("configuration export has invalid terminal tar blocks")
            return
        # Fixed short names require no PAX, GNU long-name/link or sparse records.
        # A nonempty ustar prefix would also alter the raw short path.
        if header[156:157] not in (b"0", b"\0", b"5") or any(header[345:500]):
            raise ValueError("configuration export contains an unsupported raw tar header")
        size_field = header[124:136].strip(b"\0 ")
        if not size_field or any(character not in b"01234567" for character in size_field):
            raise ValueError("configuration export has an unsupported raw tar size")
        size = int(size_field, 8)
        if size > maximum_member or header[156:157] == b"5" and size != 0:
            raise ValueError("configuration export raw tar member exceeds its bound")
        following = offset + 512 + ((size + 511) // 512) * 512
        if following > len(data):
            raise ValueError("configuration export raw tar member is truncated")
        offset = following
    raise ValueError("configuration export lacks complete terminal tar blocks")


def parse_configuration_export(data: bytes) -> dict:
    """Independently inspect a bounded tar and TOML without extracting paths."""
    validate_configuration_tar_framing(data)
    contents, hashes, seen = {}, {}, set()
    total_size = 0
    allowed_names = {"config": "", "config/": "", "config/modules": "modules", "config/modules/": "modules"}
    allowed_names.update({"config/" + name: name for name in CONFIG_FILES})
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                if len(seen) >= 10:
                    raise ValueError("unexpected configuration export inventory")
                if member.name not in allowed_names:
                    raise ValueError("unexpected configuration export path")
                name = allowed_names[member.name]
                if name in seen:
                    raise ValueError("duplicated configuration export path")
                seen.add(name)
                if member.uid != 0 or member.gid != 0 or member.mode & 0o7027:
                    raise ValueError("configuration export ownership or permissions differ")
                if name in ("", "modules"):
                    if not member.isdir() or member.mode not in (0o700, 0o750):
                        raise ValueError("configuration export directory is not a protected directory")
                    continue
                if (member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.sparse is not None
                        or member.mode != 0o600 or not 0 < member.size <= 128 << 10):
                    raise ValueError("configuration export must contain bounded private regular files")
                total_size += member.size
                if total_size > 512 << 10:
                    raise ValueError("configuration export aggregate content exceeds its bound")
                content = archive.extractfile(member).read(member.size + 1)
                if len(content) != member.size:
                    raise ValueError("configuration export file is truncated")
                contents[name] = content
                hashes[name] = hashlib.sha256(content).hexdigest()
            trailing = data[archive.offset:]
            if len(trailing) < 1024 or any(trailing):
                raise ValueError("configuration export has missing terminators or trailing members")
    except tarfile.TarError as error:
        raise ValueError("invalid configuration export") from error
    if set(contents) != set(CONFIG_FILES):
        raise ValueError("configuration export lacks the exact seven-file inventory")
    # Bound and inspect the entire membership before asking the TOML parser to
    # decode any file. Never normalize or extract archive-controlled paths.
    try:
        documents = {name: tomllib.loads(content.decode("utf-8")) for name, content in contents.items()}
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("invalid configuration TOML export") from error
    def lookup(document, key):
        value = document
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                raise ValueError("configuration export lacks explicit selection " + key)
            value = value[part]
        return value
    if type(documents["config.toml"].get("schema_version")) is not int or documents["config.toml"]["schema_version"] != 1:
        raise ValueError("configuration export has an unsupported schema")
    for name in ("config.toml", "modules/00-core.toml"):
        if lookup(documents[name], "core.install_profile") != "unconfigured-v1":
            raise ValueError("configuration export lacks both unconfigured markers")
    # Inspect every explicit selector, including earlier modules. A later false
    # override cannot hide an unexpectedly active generated default.
    selections = {}
    def flatten(prefix, value):
        if isinstance(value, dict):
            for key, child in value.items():
                flatten(prefix + "." + key if prefix else key, child)
        else:
            if prefix in INACTIVE_KEYS and value is not False:
                raise ValueError("configuration export activates " + prefix)
            selections[prefix] = value
    for name in CONFIG_FILES:
        flatten("", documents[name])
    expected = {"core.install_profile": "unconfigured-v1", "core.firewall_backend": "keep",
                "core.config_dir": "/etc/syswarden/config/modules",
                "network.policy_mode": "lists", "network.blocklists.list_choice": "4"}
    for key, value in expected.items():
        if selections.get(key) != value:
            raise ValueError("configuration export has an unexpected inactive selection " + key)
    for key in EMPTY_CONFIG_KEYS:
        if key not in selections or selections[key] != "":
            raise ValueError("configuration export selects host access or log discovery " + key)
    if selections.get("security.honeyports") != []:
        raise ValueError("configuration export selects honeyports")
    for key in INACTIVE_KEYS:
        if key not in selections or selections[key] is not False:
            raise ValueError("configuration export lacks an explicit disabled module " + key)
    return {"configuration_sha256": hashes, "configuration_archive_sha256": hashlib.sha256(data).hexdigest(),
            "independent_toml_validation": True}


def parse_launcher_export(data: bytes, package_name: str, payload_hashes: dict[str, str], identities: list[dict]) -> dict:
    """Check native-created fixture receipts without extracting or granting authority."""
    # Long private journal names may use USTAR prefixes or PAX path records.
    # Never extract them: bound the whole uncompressed archive, then admit only
    # the final closed receipt inventory and reject aliases/duplicates below.
    if not data or len(data) > 20 << 20 or len(data) % 512:
        raise ValueError("invalid bounded launcher export framing")
    files, directories = {}, set()
    base = APK_LAUNCHER_ROOT.rsplit("/", 1)[1]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for count, member in enumerate(archive):
            if count >= 32 or member.uid != 0 or member.gid != 0 or member.sparse is not None:
                raise ValueError("invalid bounded launcher export inventory")
            name = member.name.rstrip("/") if member.isdir() else member.name
            if name == base:
                relative = ""
            elif name.startswith(base + "/"):
                relative = name[len(base) + 1:]
            else:
                raise ValueError("foreign launcher export path")
            if any(part in ("", ".", "..") for part in relative.split("/")) and relative:
                raise ValueError("noncanonical launcher export path")
            if relative in files or relative in directories:
                raise ValueError("duplicate launcher export path")
            if member.isdir() and member.mode == 0o700:
                directories.add(relative)
            elif member.isfile() and member.mode == 0o600 and 0 < member.size <= 16 << 20:
                files[relative] = archive.extractfile(member).read(member.size + 1)
                if len(files[relative]) != member.size:
                    raise ValueError("truncated launcher export")
            else:
                raise ValueError("unsafe launcher export type or permissions")
        if len(data) - archive.offset < 1024 or any(data[archive.offset:]):
            raise ValueError("launcher export has trailing or missing terminal blocks")
    def record(name):
        raw = files.get(name)
        if raw is None or len(raw) > 512 << 10:
            raise ValueError("missing or oversized launcher record")
        value = json.loads(raw)
        if (json.dumps(value, separators=(",", ":")) + "\n").encode() != raw:
            raise ValueError("noncanonical launcher record")
        return value
    schema = "syswarden-apk-fresh-launchers/v1"
    current = record("current.json")
    if set(current) != {"schema", "kind", "plan_sha256", "receipt_sha256"} or current["schema"] != schema or current["kind"] != "fresh":
        raise ValueError("wrong current launcher lineage")
    if any(re.fullmatch(r"[a-f0-9]{64}", current[name]) is None for name in ("plan_sha256", "receipt_sha256")):
        raise ValueError("invalid launcher lineage digest")
    journal = "fresh-" + current["plan_sha256"] + "/"
    intent, receipt = record(journal + "intent.json"), record(journal + "receipt.json")
    if (hashlib.sha256(files[journal + "intent.json"]).hexdigest() != current["plan_sha256"]
            or hashlib.sha256(files[journal + "receipt.json"]).hexdigest() != current["receipt_sha256"]
            or intent.get("schema") != schema or intent.get("purpose") != "fresh-intent-no-alias-mutation"
            or intent.get("previous_sha256") or receipt.get("schema") != schema
            or receipt.get("purpose") != "exclusive-fresh-launcher-ownership"
            or receipt.get("intent_sha256") != current["plan_sha256"]):
        raise ValueError("launcher intent and receipt binding differs")
    if hashlib.sha256(files.get(journal + "before-installed", b"")).hexdigest() != intent.get("database_sha256"):
        raise ValueError("launcher native absence evidence differs")
    native_record = receipt.get("native", {})
    if native_record.get("name") != package_name or native_record.get("version") != "v" + VERSION:
        raise ValueError("launcher receipt belongs to another native package")
    payload = intent.get("payload", [])
    if len(payload) != len(payload_hashes) or {item["path"]: item["sha256"] for item in payload} != payload_hashes:
        raise ValueError("launcher intent does not bind the exact fixture payload")
    allowed = {"current.json", journal + "intent.json", journal + "receipt.json", journal + "before-installed"}
    originals, committed = intent.get("aliases", []), receipt.get("aliases", [])
    if len(originals) != 2 or len(committed) != 2 or len(identities) != 2:
        raise ValueError("launcher receipt lacks both aliases")
    for index, (path, target) in enumerate(zip(APK_ALIAS_PATHS, APK_ALIAS_TARGETS)):
        before, after = originals[index], committed[index]
        if (before.get("path") != path or before.get("disposition") != "absent" or before.get("original", {}).get("absent") is not True
                or after.get("path") != path or after.get("disposition") != "product-created" or after.get("original") != before["original"]
                or after.get("product_dependency") is not False or after.get("committed", {}).get("absent") is not False
                or after["committed"].get("link_target") != target):
            raise ValueError("launcher ownership adopted an inherited alias")
        identity = after["committed"].get("identity", {})
        if any(identity.get(key) != value for key, value in identities[index].items()):
            raise ValueError("launcher receipt identity differs from the installed link")
        name = "launcher-created-" + ("cli" if index == 0 else "tui") + ".json"
        creation, proposed = record(journal + name), record(journal + "intent-" + name)
        if (hashlib.sha256(files[journal + name]).hexdigest() != after.get("creation_sha256")
                or creation != {"schema": schema, "purpose": "exclusive-launcher-created", "prepared_sha256": current["plan_sha256"], "path": path, "evidence": after["committed"]}
                or proposed != {"schema": schema, "purpose": "exclusive-launcher-create-intent", "prepared_sha256": current["plan_sha256"], "path": path, "evidence": before["original"]}):
            raise ValueError("launcher exclusive creation evidence differs")
        allowed.update((journal + name, journal + "intent-" + name))
    parents = receipt.get("parents", [])
    if [item.get("path") for item in parents] != [".", "usr", "usr/local", "usr/local/bin"] or len(intent.get("parents", [])) != 4:
        raise ValueError("launcher parent inventory differs")
    for index, parent in enumerate(parents):
        if intent["parents"][index].get("absent"):
            name = "parent-" + str(index) + ".json"
            proposed, created = record(journal + "intent-" + name), record(journal + "created-" + name)
            if (index < 2 or proposed != intent["parents"][index]
                    or hashlib.sha256(files[journal + "created-" + name]).hexdigest() != parent.get("creation_sha256")
                    or created != {key: value for key, value in parent.items() if key != "creation_sha256"}):
                raise ValueError("launcher parent creation evidence differs")
            allowed.update((journal + "intent-" + name, journal + "created-" + name))
        elif parent.get("creation_sha256"):
            raise ValueError("launcher receipt adopted an inherited parent")
    if set(files) != allowed or directories != {"", journal.rstrip("/")}:
        raise ValueError("launcher export has pending, unknown or missing evidence")
    return {"fresh_apk_launcher_receipt_verified": True, "launcher_receipt_sha256": current["receipt_sha256"],
            "launcher_export_sha256": hashlib.sha256(data).hexdigest()}


def write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def render_variant(path: Path, package_name: str) -> bytes:
    if package_name not in NAMES:
        raise ValueError("closed product identity required")
    result = subprocess.run(
        ["/bin/bash", "-eu", "-c", 'source "$1"; PACKAGE_NAME="$2"; syswarden_render_local_package_hook "$3"',
         "fixture-render", str(ROOT / "scripts/ci/package_variant_metadata.sh"), package_name, str(path)],
        env={"PATH": os.environ["PATH"], "LC_ALL": "C"}, capture_output=True, timeout=5, check=False)
    if result.returncode:
        raise ValueError("production package variant renderer refused: " + result.stderr.decode(errors="replace"))
    return result.stdout


def delegate(hook: str) -> bytes:
    if hook not in ("preinst.sh", "postinst.sh"):
        raise ValueError("closed native delegate required")
    after = ""
    if hook == "postinst.sh":
        after = f'''if [ -f /etc/alpine-release ] && [ "$(cat {FIXTURE}/cli-mode)" = real ]; then
    pending={APK_LAUNCHER_ROOT}/pending.json
    test -f "$pending" && test ! -L "$pending"
    test "$(stat -c '%u:%g:%a:%h' "$pending")" = 0:0:600:1
    test ! -e {APK_LAUNCHER_ROOT}/current.json && test ! -L {APK_LAUNCHER_ROOT}/current.json
    for path in /usr/local/bin/syswarden /usr/local/bin/syswarden-tui; do
        test ! -e "$path" && test ! -L "$path"
    done
    printf 'APK_LAUNCHERS_PENDING_PASS\n'
fi
'''
    return ("#!/bin/sh\nset -eu\numask 077\n"
            f"printf 'HOOK={hook}\\nARGC=%s\\n' \"$#\" >> {FIXTURE}/events\n"
            f"for argument do printf 'ARG=%s\\n' \"$argument\" >> {FIXTURE}/events; done\n"
            f"PATH={FIXTURE}/traps:/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n"
            f'/bin/sh {FIXTURE}/{hook} "$@"\n' + after).encode()


CLI = b'''#!/bin/sh
set -eu
case "$*" in
    install)
        test "${SYSWARDEN_PKG_INSTALL:-}" = 1
        test "${SYSWARDEN_NATIVE_INSTALL_PHASE:-}" = fresh
        test "$#" = 1
        printf 'CLI_PHASE=fresh\nCLI_ARGC=1\nCLI_ARG=install\n' >> /tmp/sw-fresh-lab/events
        ;;
    'internal-apk-launchers --stage-fresh')
        test "$#" = 2 && test "${SYSWARDEN_NATIVE_INSTALL_PHASE:-}" = fresh
        printf 'CLI_LAUNCHERS=stage-fresh\n' >> /tmp/sw-fresh-lab/events
        ;;
    'internal-apk-launchers --complete-fresh')
        test "$#" = 2 && test -z "${SYSWARDEN_NATIVE_INSTALL_PHASE:-}"
        printf 'CLI_LAUNCHERS=complete-fresh\n' >> /tmp/sw-fresh-lab/events
        ;;
    *) exit 97 ;;
esac
'''


REAL_VALIDATION = r'''#!/bin/sh
set -eu
root=/etc/syswarden/config
cli=/opt/syswarden/bin/syswarden-cli
test -d "$root" && test ! -L "$root"
test -d "$root/modules" && test ! -L "$root/modules"
sha256sum -c real-cli.sha256
set -- "$root/config.toml" "$root/modules/00-core.toml" "$root/modules/10-network.toml" "$root/modules/20-security.toml" "$root/modules/30-waap.toml" "$root/modules/40-integrations.toml" "$root/modules/99-user.toml"
for path do
    test -f "$path" && test ! -L "$path"
    test "$(stat -c '%u:%g:%a:%h' "$path")" = 0:0:600:1
done
sha256sum "$@" > real-config.sha256
stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "$root" "$root/modules" "$@" > real-config.metadata
PATH=/tmp/sw-fresh-lab/traps:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset SYSWARDEN_PKG_INSTALL SYSWARDEN_NATIVE_INSTALL_PHASE SYSWARDEN_OFFLINE_QUALIFICATION
"$cli" config validate --path "$root"
"$cli" config preview > real-preview.log
grep -Fx 'Validated configuration preview (7 TOML inputs).' real-preview.log
grep -F 'No managed threat list is selected.' real-preview.log
grep -Fx 'No host change was applied. This preview grants no activation approval and does not prove runtime state or access.' real-preview.log
printf 'REAL_CONFIGURATION_PREVIEW_PASS\n'
"$cli" config recover-edit > real-edit-inspection.log
grep -Fx 'No pending TOML file publication requires recovery.' real-edit-inspection.log
printf 'REAL_CONFIGURATION_EDIT_INSPECTION_PASS\n'
# Enter and leave the real menu without selecting an editor or activation.
printf '0\n' | "$cli" config
require_value() {
    actual=$("$cli" config-get "$1")
    test "$actual" = "$2"
}
require_value core.install_profile unconfigured-v1
require_value core.firewall_backend keep
require_value network.policy_mode lists
require_value network.blocklists.list_choice 4
for key in @INACTIVE_KEYS@; do
    require_value "$key" false
done
for key in @EMPTY_CONFIG_KEYS@; do
    require_value "$key" ""
done
require_value security.honeyports '[]'
sha256sum -c real-config.sha256
stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "$root" "$root/modules" "$@" > real-config.after
test "$(sha256sum < real-config.metadata)" = "$(sha256sum < real-config.after)"
# Fresh staging may create only the configuration subtree under this root.
for path in /etc/syswarden/* /etc/syswarden/.[!.]* /etc/syswarden/..?*; do
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then continue; fi
    test "$path" = /etc/syswarden/config
done
for path in /etc/cron.d/syswarden /etc/cron.d/.syswarden* /etc/runlevels/default/syswarden* /usr/lib/systemd/system/syswarden* /lib/systemd/system/syswarden*; do
    test ! -e "$path" && test ! -L "$path"
done
printf 'REAL_CONFIGURATION_PASS\n'
'''.replace("@INACTIVE_KEYS@", " ".join(INACTIVE_KEYS)).replace("@EMPTY_CONFIG_KEYS@", " ".join(EMPTY_CONFIG_KEYS))

SCRIPT = r'''#!/bin/sh
set -eu
umask 077
cd /tmp/sw-fresh-lab
format=$1
package=$2
source=$3
cli_mode=$(cat cli-mode)
case "$cli_mode" in stub|real) ;; *) exit 64 ;; esac
case "$format:$package:$source" in
    deb:syswarden:local|deb:syswarden:workflow|deb:syswarden-base:local|deb:syswarden-base:workflow|rpm:syswarden:local|rpm:syswarden:workflow|rpm:syswarden-base:local|rpm:syswarden-base:workflow|apk:syswarden:local|apk:syswarden:workflow|apk:syswarden-base:local|apk:syswarden-base:workflow) ;;
    *) exit 64 ;;
esac
test "$(uname -m)" = x86_64
test "$(id -u):$(id -g)" = 0:0
for mapping in /proc/self/uid_map /proc/self/gid_map; do
    awk 'NR==1 { if (NF!=3 || $1!=0 || $2<=0 || $3<=0) exit 1; found=1 }
         { if (NF!=3 || $1==$2 || $2==0 || $3<=0) exit 1 }
         END { if (!found) exit 1 }' "$mapping"
done
test -f /run/.containerenv && test ! -L /run/.containerenv
test "$(stat -c '%u:%g:%h' /run/.containerenv)" = 0:0:1
test "$(stat -c '%s' /run/.containerenv)" -le 65536
containerenv_mode=$(stat -c '%a' /run/.containerenv)
test "$((0$containerenv_mode & 0022))" -eq 0
test "$(stat -c '%u:%g:%a:%h' .fixture-marker)" = 0:0:600:1
test "$(cat .fixture-marker)" = SYSWARDEN-FRESH-HOOK-DISPATCH-V1
sha256sum -c inputs.sha256
test ! -e /opt/syswarden && test ! -L /opt/syswarden
test ! -e /etc/syswarden && test ! -L /etc/syswarden
case "$format" in
    deb) for name in syswarden syswarden-base; do if dpkg-query -W "$name" >/dev/null 2>&1; then exit 1; fi; done ;;
    rpm) for name in syswarden syswarden-base; do if rpm -q "$name" >/dev/null 2>&1; then exit 1; fi; done ;;
    apk)
        for name in syswarden syswarden-base; do if apk info --quiet -e "$name"; then exit 1; fi; done
        for path in /usr/local/bin/syswarden /usr/local/bin/syswarden-tui /var/backups/syswarden-apk-launchers-v1; do
            test ! -e "$path" && test ! -L "$path"
        done
        ;;
esac
# Only disposable fixture setup may create these inert administrator sentinels.
mkdir -p /etc/ssh/sshd_config.d /etc/cron.d /etc/systemd/system /etc/init.d /etc/runlevels/default
if [ "$format" != apk ]; then mkdir -p /usr/lib/systemd/system; fi
for path in /etc/sw-fresh-admin.conf /etc/ssh/sshd_config.d/sw-fresh-admin.conf /etc/cron.d/sw-fresh-admin /etc/systemd/system/sw-fresh-admin.service /etc/init.d/sw-fresh-admin; do
    test ! -e "$path" && test ! -L "$path"
    printf 'synthetic administrator sentinel\n' > "$path"
    chmod 0600 "$path"
done
ln -s /etc/init.d/sw-fresh-admin /etc/runlevels/default/sw-fresh-admin
sha256sum /etc/sw-fresh-admin.conf /etc/ssh/sshd_config.d/sw-fresh-admin.conf /etc/cron.d/sw-fresh-admin /etc/systemd/system/sw-fresh-admin.service /etc/init.d/sw-fresh-admin > administrator.sha256
stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' /etc/sw-fresh-admin.conf /etc/ssh/sshd_config.d/sw-fresh-admin.conf /etc/cron.d/sw-fresh-admin /etc/systemd/system/sw-fresh-admin.service /etc/init.d/sw-fresh-admin /etc/runlevels/default/sw-fresh-admin > administrator.metadata
mkdir traps
cat > traps/refuse <<'TRAP'
#!/bin/sh
printf 'FORBIDDEN=%s\n' "$0" >> /tmp/sw-fresh-lab/forbidden
exit 97
TRAP
chmod 0700 traps/refuse
for name in systemctl systemd-run service rc-service rc-update crontab cron crond cronie nft iptables ip6tables ipset ip curl wget sysctl semodule semanage restorecon setsebool pkill killall mkdir chmod ln mv rm rmdir touch; do
    ln -s refuse "traps/$name"
done
: > events
: > forbidden
# A spoofed inherited phase must not turn fresh hooks into an upgrade path.
export SYSWARDEN_NATIVE_INSTALL_PHASE=upgrade SYSWARDEN_PKG_INSTALL=spoofed SYSWARDEN_OFFLINE_QUALIFICATION=
if [ "$cli_mode" = real ]; then
    # Legacy flat-file selection names are inert inherited input on this new,
    # empty fixture. They must not select a list or VPN during fresh staging.
    export SYSWARDEN_LIST_CHOICE=1 SYSWARDEN_ENABLE_WG=y
fi
case "$format" in
    deb) dpkg --install package.deb; dpkg-query -W -f='${Status}\n' "$package" | grep -Fx 'install ok installed' ;;
    rpm) rpm --install package.rpm; rpm -q "$package" ;;
    apk) apk --no-network --no-cache --repositories-file /dev/null --allow-untrusted add ./package.apk; apk info --quiet -e "$package" ;;
esac
if [ "$cli_mode" = real ]; then
    /bin/sh validate-real.sh
    if [ "$format" = apk ]; then
        launcher_root=/var/backups/syswarden-apk-launchers-v1
        test ! -e "$launcher_root/pending.json" && test ! -L "$launcher_root/pending.json"
        test -f "$launcher_root/current.json" && test ! -L "$launcher_root/current.json"
        test "$(stat -c '%u:%g:%a:%h' "$launcher_root/current.json")" = 0:0:600:1
        alias_index=0
        for role in syswarden syswarden-tui; do
            path=/usr/local/bin/$role
            target=/opt/syswarden/bin/$role
            if [ "$role" = syswarden ]; then target=/opt/syswarden/bin/syswarden-cli; fi
            test -L "$path" && test "$(readlink "$path")" = "$target"
            test "$(stat -c '%u:%g:%a:%h' "$path")" = 0:0:777:1
            printf 'APK_LAUNCHER_ID=%s:%s\n' "$alias_index" "$(stat -c '%d:%i:%f:%u:%g:%h:%s' "$path")"
            alias_index=$((alias_index + 1))
        done
        printf 'APK_LAUNCHERS_COMMITTED_PASS\n'
    fi
else
    test ! -e /etc/syswarden && test ! -L /etc/syswarden
fi
test ! -s forbidden
sha256sum -c administrator.sha256
stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' /etc/sw-fresh-admin.conf /etc/ssh/sshd_config.d/sw-fresh-admin.conf /etc/cron.d/sw-fresh-admin /etc/systemd/system/sw-fresh-admin.service /etc/init.d/sw-fresh-admin /etc/runlevels/default/sw-fresh-admin > administrator.after
test "$(sha256sum < administrator.metadata)" = "$(sha256sum < administrator.after)"
test "$(readlink /etc/runlevels/default/sw-fresh-admin)" = /etc/init.d/sw-fresh-admin
for path in /var/lib/syswarden /var/log/syswarden /etc/systemd/system/syswarden-core.service /etc/systemd/system/syswarden-firewall.service /etc/init.d/syswarden-core /etc/init.d/syswarden-firewall; do
    test ! -e "$path" && test ! -L "$path"
done
sha256sum -c inputs.sha256
printf 'HOOK_EVENTS_BEGIN\n'
cat events
printf 'HOOK_EVENTS_END\n'
printf 'FRESH_HOOK_DISPATCH_PASS=%s:%s:%s\n' "$format" "$package" "$source"
'''


def payload(root: Path, nfpm: Path, source: str, package_name: str, format_name: str, cli_snapshot=None) -> tuple[bytes, dict]:
    validate_selection(source, package_name, format_name)
    files: dict[str, bytes] = {"cases.sh": SCRIPT.encode(), ".fixture-marker": b"SYSWARDEN-FRESH-HOOK-DISPATCH-V1\n",
                              "cli-mode": b"real\n" if cli_snapshot is not None else b"stub\n"}
    cli_bytes = CLI
    if cli_snapshot is not None:
        if type(cli_snapshot) is not native.RetentionBinarySnapshot:
            raise ValueError("real CLI requires an exact bounded source snapshot")
        cli_snapshot.recheck()
        validate_static_amd64_elf(cli_snapshot.data)
        cli_bytes = cli_snapshot.data
        files["validate-real.sh"] = REAL_VALIDATION.encode()
        files["real-cli.sha256"] = (hashlib.sha256(cli_bytes).hexdigest() + "  /opt/syswarden/bin/syswarden-cli\n").encode()
    hashes = {}
    for hook in ("preinst.sh", "postinst.sh"):
        raw = emitted_hook(source, hook)
        other = emitted_hook("workflow" if source == "local" else "local", hook)
        if raw != other:
            raise ValueError("local and workflow hook bodies differ")
        original = root / ("raw-" + hook)
        write_private(original, raw)
        files[hook] = render_variant(original, package_name)
        hashes[hook] = hashlib.sha256(files[hook]).hexdigest()
        write_private(root / ("delegate-" + hook), delegate(hook), 0o700)
    write_private(root / "cli", cli_bytes, 0o700)
    spec = {"name": package_name, "arch": "amd64", "platform": "linux", "version": VERSION,
            "version_schema": "none", "maintainer": "SysWarden synthetic laboratory",
            "license": "GPL-3.0-or-later" if cli_snapshot is not None else "MIT",
            "description": "Fresh hook fixture, not a production package",
            "contents": [{"src": str(root / "cli"), "dst": "/opt/syswarden/bin/syswarden-cli",
                          "file_info": {"mode": 0o755}}],
            "scripts": {"preinstall": str(root / "delegate-preinst.sh"), "postinstall": str(root / "delegate-postinst.sh")}}
    payload_hashes = {}
    if format_name == "apk":
        spec["contents"], payload_hashes = apk_fixture_contents(root, cli_bytes)
    else:
        # DEB/RPM own these aliases in their payload. Only APK delegates their
        # exclusive creation to its committed fresh-launcher lifecycle.
        spec["contents"].extend({"src": target, "dst": "/" + path, "type": "symlink",
                                 "file_info": {"mode": 0o777, "owner": "root", "group": "root"}}
                                for path, target in zip(APK_ALIAS_PATHS, APK_ALIAS_TARGETS))
    if format_name in ("rpm", "apk"):
        spec["release"] = "0" if format_name == "apk" else "1"
    config = root / "fixture.json"
    write_private(config, (json.dumps(spec, indent=2) + "\n").encode())
    package = root / ("package." + format_name)
    built = subprocess.run([str(nfpm), "pkg", "--config", str(config), "--packager", format_name, "--target", str(package)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, check=False)
    write_private(root / "fixture-build.log", built.stdout)
    if built.returncode:
        raise ValueError("inert native fixture builder failed")
    package_bytes = package.read_bytes()
    if not package_bytes or len(package_bytes) > (64 if cli_snapshot is not None else 8) << 20:
        raise ValueError("inert package exceeds its byte bound")
    files[package.name] = package_bytes
    files["inputs.sha256"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items()).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o600
            archive.addfile(entry, io.BytesIO(data))
    if cli_snapshot is not None:
        cli_snapshot.recheck()
    return stream.getvalue(), {"cli_mode": "real" if cli_snapshot is not None else "stub",
                              "cli_sha256": hashlib.sha256(cli_bytes).hexdigest(), "cli_size": len(cli_bytes),
                              "cli_binding": "caller-built-source-observation-not-release-authority" if cli_snapshot is not None else "synthetic-stub",
                              "legacy_environment_challenge": {"SYSWARDEN_LIST_CHOICE": "1", "SYSWARDEN_ENABLE_WG": "y"} if cli_snapshot is not None else {},
                              "apk_payload_sha256": payload_hashes,
                              "emitted_hook_sha256": hashes, "package_sha256": hashlib.sha256(package_bytes).hexdigest(),
                              "payload_sha256": hashlib.sha256(stream.getvalue()).hexdigest()}


def sandbox_command(podman: str, image: str, identity, source: str, package_name: str, format_name: str) -> list[str]:
    validate_selection(source, package_name, format_name)
    if re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("exact cached image identity required")
    helpers = isolation_helpers()
    helpers.validate_container(identity)
    return helpers.podman_command(podman, "create", "--name", identity.name, "--label", helpers.OWNER_LABEL + "=" + identity.token,
        "--cidfile", str(identity.cidfile), "--image-volume=ignore", "--pull=never", "--network=none",
        "--pid=private", "--ipc=private", "--uts=private", "--cgroupns=private", "--user=0:0",
        "--cap-drop=all", "--cap-add=SYS_CHROOT", "--security-opt=no-new-privileges", "--cpus=2",
        "--memory=256m", "--pids-limit=64", "--timeout=60", "--entrypoint=/bin/sh", "-i", image, "-c",
        'umask 077; mkdir /tmp/sw-fresh-lab && cd /tmp/sw-fresh-lab && tar --no-same-owner -xf - && /bin/sh cases.sh "$1" "$2" "$3"',
        "probe", format_name, package_name, source)


def validate_isolation(item: dict, image: str, identity, cid: str, arguments: list[str]) -> None:
    """Refuse unexpected actual isolation before any fixture process starts."""
    helpers = isolation_helpers()
    try:
        host, config, state = item["HostConfig"], item["Config"], item["State"]
        expected_args = arguments[arguments.index(image) + 1:]
        if (item["Id"] != cid or item["Name"] not in (identity.name, "/" + identity.name)
                or config["Labels"].get(helpers.OWNER_LABEL) != identity.token
                or item["Image"].removeprefix("sha256:") != image
                or item["Path"] != "/bin/sh" or item["Args"] != expected_args
                or config["User"] != "0:0" or config["OpenStdin"] is not True
                or state["Status"] != "created" or state["Running"] is not False
                or item["Mounts"] != [] or host["Binds"] or host["Tmpfs"] or host["VolumesFrom"]
                or host["NetworkMode"] != "none" or host["Privileged"] is not False
                or any(host[key] != "private" for key in ("PidMode", "CgroupMode", "IpcMode", "UTSMode"))
                or host["Devices"] or host["PortBindings"] or host["PublishAllPorts"] is not False
                or host["AutoRemove"] is not False or host["PidsLimit"] != 64
                or host["Memory"] != 256 * 1024**2 or host["NanoCpus"] != 2 * 10**9
                or set(host["SecurityOpt"]) != {"no-new-privileges"}):
            raise ValueError("unexpected created container isolation")
        if item["EffectiveCaps"] != ["CAP_SYS_CHROOT"] or item["BoundingCaps"] != ["CAP_SYS_CHROOT"]:
            raise ValueError("unexpected created container capabilities")
        added, dropped = host["CapAdd"], host["CapDrop"]
        literal = added == ["CAP_SYS_CHROOT"] and dropped in (["ALL"], ["CAP_ALL"])
        expanded = (added == [] and isinstance(dropped, list)
                    and len(dropped) == len(PODMAN_EXPANDED_CAP_DROP)
                    and set(dropped) == PODMAN_EXPANDED_CAP_DROP)
        if not (literal or expanded):
            raise ValueError("unrecognized created container capability representation")
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("incomplete created container isolation evidence") from error


def cleanup_owned_container(podman: str, identity, original_cid: str | None) -> dict:
    helpers = isolation_helpers()
    if original_cid is not None:
        try:
            if helpers.read_container_id(identity.cidfile) != original_cid:
                raise ValueError("original container ID record absent or changed; preserve container")
        except (OSError, ValueError) as error:
            return {"verified": False, "removal_attempted": False, "error": str(error)}
    # Exact name and token recovery is allowed only for an uncertain creation.
    # It cannot establish a successful native result without original CID proof.
    return helpers.cleanup_container(podman, identity, require_cid=original_cid is not None)


def parse_result(output: bytes, source: str, package_name: str, format_name: str, real_cli: bool = False) -> dict:
    validate_selection(source, package_name, format_name)
    if len(output) > 1 << 20:
        raise ValueError("native dispatch output exceeds its evidence bound")
    lines = output.decode("utf-8", errors="strict").splitlines()
    expected = f"FRESH_HOOK_DISPATCH_PASS={format_name}:{package_name}:{source}"
    if [line for line in lines if line.startswith("FRESH_HOOK_DISPATCH_PASS=")] != [expected] or not lines or lines[-1] != expected:
        raise ValueError("missing or ambiguous native dispatch outcome")
    if lines.count("HOOK_EVENTS_BEGIN") != 1 or lines.count("HOOK_EVENTS_END") != 1 or any("FORBIDDEN=" in line for line in lines):
        raise ValueError("ambiguous hook events or forbidden operation")
    disposition = "SysWarden fresh installation: pre-install host mutation deferred."
    apk_disposition = "  * " + disposition
    observed_dispositions = [line for line in lines if line in (disposition, apk_disposition)]
    if (len(observed_dispositions) != 1
            or observed_dispositions[0] == apk_disposition and format_name != "apk"):
        raise ValueError("original preinstall did not record its exact fresh disposition")
    start, end = lines.index("HOOK_EVENTS_BEGIN"), lines.index("HOOK_EVENTS_END")
    events = lines[start + 1:end]
    observed = {}
    for hook in ("preinst.sh", "postinst.sh"):
        if len(events) < 2 or events[0] != "HOOK=" + hook or re.fullmatch(r"ARGC=[0-3]", events[1]) is None:
            raise ValueError("missing or reordered native hook")
        count = int(events[1].split("=", 1)[1])
        args = events[2:2 + count]
        if len(args) != count or any(not item.startswith("ARG=") for item in args):
            raise ValueError("malformed native hook arguments")
        observed[hook] = [item[4:] for item in args]
        events = events[2 + count:]
    expected_events = [] if real_cli else ["CLI_PHASE=fresh", "CLI_ARGC=1", "CLI_ARG=install"]
    if not real_cli and format_name == "apk":
        expected_events = ["CLI_LAUNCHERS=stage-fresh", *expected_events, "CLI_LAUNCHERS=complete-fresh"]
    if events != expected_events:
        raise ValueError("fresh staging call absent, repeated or not exact")
    real_dispositions = [line for line in lines if line in (REAL_STAGING_DISPOSITION, "  * " + REAL_STAGING_DISPOSITION)]
    if real_cli:
        if (len(real_dispositions) != 1 or real_dispositions[0].startswith("  * ") and format_name != "apk"
                or lines.count("REAL_CONFIGURATION_PASS") != 1
                or lines.count("REAL_CONFIGURATION_PREVIEW_PASS") != 1
                or lines.count("REAL_CONFIGURATION_EDIT_INSPECTION_PASS") != 1):
            raise ValueError("real fresh configuration staging or validation is not exact")
    elif real_dispositions or any(line.startswith("REAL_CONFIGURATION_") for line in lines):
        raise ValueError("real configuration evidence is unexpected in stub mode")
    launcher_markers = [line for line in lines if line.startswith("APK_LAUNCHERS_") or line.startswith("  * APK_LAUNCHERS_")]
    if real_cli and format_name == "apk":
        if launcher_markers not in (["APK_LAUNCHERS_PENDING_PASS", "APK_LAUNCHERS_COMMITTED_PASS"],
                                    ["  * APK_LAUNCHERS_PENDING_PASS", "APK_LAUNCHERS_COMMITTED_PASS"]):
            raise ValueError("fresh APK pending and committed launcher sequence is incomplete")
    elif launcher_markers:
        raise ValueError("launcher ownership evidence is unexpected in this fixture mode")
    identities = []
    identity_lines = [line for line in lines if line.startswith("APK_LAUNCHER_ID=")]
    if real_cli and format_name == "apk":
        for index, line in enumerate(identity_lines):
            matched = re.fullmatch(r"APK_LAUNCHER_ID=([01]):([0-9]+):([1-9][0-9]*):a1ff:0:0:1:([1-9][0-9]*)", line)
            if matched is None or int(matched[1]) != index or index > 1 or int(matched[4]) != len(APK_ALIAS_TARGETS[index]):
                raise ValueError("installed APK launcher identity is malformed or reordered")
            identities.append({"device": int(matched[2]), "inode": int(matched[3]), "mode": 0o120777,
                               "uid": 0, "gid": 0, "links": 1, "size": int(matched[4])})
        if len(identities) != 2:
            raise ValueError("installed APK launcher identities are incomplete")
    elif identity_lines:
        raise ValueError("launcher identities are unexpected in this fixture mode")
    return {"apk_launcher_identities": identities, "native_arguments": observed, "fresh_cli_staging_call": True, "administrator_sentinels_preserved": True,
            "configuration_readonly_observed": real_cli, "configured_effect_preview_observed": real_cli,
            "pending_edit_inspection_observed": real_cli}


def run(nfpm: Path, image: str, output: Path, source: str, package_name: str, format_name: str, cli_binary: Path | None = None) -> None:
    validate_selection(source, package_name, format_name)
    if os.geteuid() == 0 or re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("unprivileged host and exact cached image required")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("existing caller-trusted nfpm executable required")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("new absolute private output directory required")
    cli_snapshot = native.snapshot_retention_binary(cli_binary) if cli_binary is not None else None
    if cli_snapshot is not None:
        validate_static_amd64_elf(cli_snapshot.data)
    helpers = isolation_helpers()
    podman = shutil.which("podman")
    if podman is None:
        raise ValueError("local rootless Podman required")
    rootless = helpers.execute_local(helpers.podman_command(podman, "info", "--format", "{{.Host.Security.Rootless}}"))
    if rootless.returncode or rootless.stdout.strip() != b"true":
        raise ValueError("independent rootless engine evidence required")
    inspection = helpers.execute_local(helpers.podman_command(podman, "image", "inspect", image))
    if inspection.returncode or len(inspection.stdout) > 1 << 20:
        raise ValueError("cached image inspection failed")
    images = json.loads(inspection.stdout)
    if len(images) != 1 or images[0].get("Id", "").removeprefix("sha256:") != image or images[0].get("Os") != "linux" or images[0].get("Architecture") != "amd64":
        raise ValueError("exact cached Linux AMD64 image required")
    output.mkdir(mode=0o700)
    write_private(output / "image.json", inspection.stdout)
    content, binding = payload(output, nfpm, source, package_name, format_name, cli_snapshot)
    identity = helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + uuid.uuid4().hex, uuid.uuid4().hex, output / "container.cid")
    arguments = sandbox_command(podman, image, identity, source, package_name, format_name)
    result = subprocess.CompletedProcess(arguments, 125, b"")
    attempted = False
    cleanup = {"verified": False}
    original_cid = None
    original_cid_verified = isolation_verified = False
    failure = None
    exported_configuration = {}
    exported_launchers = {}
    try:
        if identity.cidfile.exists() or identity.cidfile.is_symlink() or helpers.container_exists(podman, identity.name):
            raise ValueError("disposable identity collision")
        if cli_snapshot is not None:
            cli_snapshot.recheck()
        attempted = True
        created = helpers.execute_local(arguments, timeout=20)
        write_private(output / "create.log", created.stdout)
        if re.fullmatch(rb"[0-9a-f]{64}\n?", created.stdout) is not None:
            original_cid = created.stdout.decode("ascii").rstrip("\n")
        if created.returncode or original_cid is None:
            raise ValueError("create did not return an exact original container ID")
        if helpers.read_container_id(identity.cidfile) != original_cid:
            raise ValueError("create result and original container ID file differ")
        original_cid_verified = True
        inspected = helpers.execute_local(helpers.podman_command(podman, "container", "inspect", original_cid))
        write_private(output / "created-container.json", inspected.stdout)
        if inspected.returncode or len(inspected.stdout) > 1 << 20:
            raise ValueError("created container inspection failed")
        entries = json.loads(inspected.stdout)
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
            raise ValueError("created container inspection is ambiguous")
        validate_isolation(entries[0], image, identity, original_cid, arguments)
        isolation_verified = True
        if helpers.read_container_id(identity.cidfile) != original_cid:
            raise ValueError("original container ID changed before start")
        result = helpers.execute_local(helpers.podman_command(podman, "start", "--attach", "--interactive", original_cid),
                                       timeout=75, input=content)
        if helpers.read_container_id(identity.cidfile) != original_cid:
            raise ValueError("original container ID changed during native execution")
        if result.returncode == 0 and cli_snapshot is not None:
            exported = helpers.execute_local(helpers.podman_command(podman, "cp", original_cid + ":/etc/syswarden/config", "-"), timeout=15)
            write_private(output / "configuration.tar", exported.stdout)
            if exported.returncode:
                raise ValueError("real configuration export failed")
            exported_configuration = parse_configuration_export(exported.stdout)
            if format_name == "apk":
                launchers = helpers.execute_local(helpers.podman_command(podman, "cp", original_cid + ":" + APK_LAUNCHER_ROOT, "-"), timeout=15)
                write_private(output / "launchers.tar", launchers.stdout)
                if launchers.returncode:
                    raise ValueError("real launcher receipt export failed")
                observed = parse_result(result.stdout, source, package_name, format_name, True)
                exported_launchers = parse_launcher_export(launchers.stdout, package_name, binding["apk_payload_sha256"], observed["apk_launcher_identities"])
            if helpers.read_container_id(identity.cidfile) != original_cid:
                raise ValueError("original container ID changed during configuration export")
            cli_snapshot.recheck()
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess(arguments, 124, error.stdout or b"")
        failure = "native fixture operation timed out"
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        failure = str(error)
    finally:
        if attempted:
            cleanup = cleanup_owned_container(podman, identity, original_cid)
        write_private(output / "container.json", (json.dumps({"name": identity.name, "owner_label": helpers.OWNER_LABEL,
                      "owner_token": identity.token, "original_container_id": original_cid,
                      "original_cid_verified": original_cid_verified, "isolation_verified_before_start": isolation_verified,
                      "cleanup": cleanup}, indent=2) + "\n").encode())
    write_private(output / "native.log", result.stdout)
    summary = {"image": image, "source": source, "package_name": package_name, "format": format_name, **binding, **exported_configuration,
               "exit_status": result.returncode, "cleanup": cleanup, "synthetic_only": True,
               "real_toml_staging_verified": False, "production_package_acceptance": False,
               "engine_default_mounts_attested": isolation_verified,
               "original_cid_verified": original_cid_verified, "subprocess_output_byte_cap": None,
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(),
               "nfpm_binding": "caller-trusted-tool-observation-not-execution-attestation", "passed": False}
    try:
        summary.update(exported_launchers)
        summary.update(parse_result(result.stdout, source, package_name, format_name, cli_snapshot is not None))
        summary["passed"] = (result.returncode == 0 and cleanup["verified"] and original_cid_verified
                             and isolation_verified and failure is None
                             and (cli_snapshot is None or bool(exported_configuration))
                             and (cli_snapshot is None or format_name != "apk" or bool(exported_launchers)))
        summary["real_toml_staging_verified"] = summary["passed"] and cli_snapshot is not None
    except (ValueError, UnicodeError) as error:
        summary["error"] = str(error)
    if failure is not None:
        summary["error"] = failure
    write_private(output / "results.json", (json.dumps(summary, indent=2) + "\n").encode())
    if not summary["passed"]:
        raise RuntimeError("native fresh hook dispatch failed; inspect retained results")
    print(f"PASS fresh-hook-dispatch {format_name} {package_name} {source}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--nfpm", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cli-binary", type=Path, help="optional caller-built static Linux AMD64 CLI; never executed on the host")
    parser.add_argument("--source", choices=SOURCES, required=True)
    parser.add_argument("--package-name", choices=NAMES, required=True)
    parser.add_argument("--format", choices=FORMATS, required=True)
    options = parser.parse_args()
    run(options.nfpm, options.image, options.output, options.source, options.package_name, options.format, options.cli_binary)
