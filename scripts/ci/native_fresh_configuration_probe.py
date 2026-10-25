#!/usr/bin/env python3
"""Opt-in native fresh-hook dispatch laboratory with an inert CLI payload.

This qualifies native arguments reaching exact emitted hook bodies, not production
package assembly, real TOML writes, prerequisites, runtime or migration acceptance.
Only disposable offline rootless Linux AMD64 containers execute the fixture.
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
import subprocess
import sys
import tarfile
import textwrap
import uuid

try:
    from scripts.ci import native_dependency_transition_probe as native
except ModuleNotFoundError:
    import native_dependency_transition_probe as native

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("syswarden", "syswarden-base")
SOURCES = ("local", "workflow")
FORMATS = ("deb", "rpm", "apk")
FIXTURE = "/tmp/sw-fresh-lab"
VERSION = "5.00.0"
# Podman can report the difference from its default capabilities instead of the
# literal drop-all/add-SYS_CHROOT request. Both effective sets remain mandatory.
PODMAN_EXPANDED_CAP_DROP = frozenset({
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
    "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID",
})
SOURCE_FILES = {"local": ROOT / "build_packages.sh", "workflow": ROOT / ".github/workflows/package.yml"}


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
    return ("#!/bin/sh\nset -eu\numask 077\n"
            f"printf 'HOOK={hook}\\nARGC=%s\\n' \"$#\" >> {FIXTURE}/events\n"
            f"for argument do printf 'ARG=%s\\n' \"$argument\" >> {FIXTURE}/events; done\n"
            f"PATH={FIXTURE}/traps:/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n"
            f'exec /bin/sh {FIXTURE}/{hook} "$@"\n').encode()


CLI = b'''#!/bin/sh
set -eu
test "${SYSWARDEN_PKG_INSTALL:-}" = 1
test "${SYSWARDEN_NATIVE_INSTALL_PHASE:-}" = fresh
test "$#" = 1 && test "$1" = install
printf 'CLI_PHASE=fresh\nCLI_ARGC=1\nCLI_ARG=install\n' >> /tmp/sw-fresh-lab/events
'''

SCRIPT = r'''#!/bin/sh
set -eu
umask 077
cd /tmp/sw-fresh-lab
format=$1
package=$2
source=$3
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
mode=$(stat -c '%a' /run/.containerenv)
test "$((0$mode & 0022))" -eq 0
test "$(stat -c '%u:%g:%a:%h' .fixture-marker)" = 0:0:600:1
test "$(cat .fixture-marker)" = SYSWARDEN-FRESH-HOOK-DISPATCH-V1
sha256sum -c inputs.sha256
test ! -e /opt/syswarden && test ! -L /opt/syswarden
test ! -e /etc/syswarden && test ! -L /etc/syswarden
case "$format" in
    deb) for name in syswarden syswarden-base; do if dpkg-query -W "$name" >/dev/null 2>&1; then exit 1; fi; done ;;
    rpm) for name in syswarden syswarden-base; do if rpm -q "$name" >/dev/null 2>&1; then exit 1; fi; done ;;
    apk) for name in syswarden syswarden-base; do if apk info --quiet -e "$name"; then exit 1; fi; done ;;
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
case "$format" in
    deb) dpkg --install package.deb; dpkg-query -W -f='${Status}\n' "$package" | grep -Fx 'install ok installed' ;;
    rpm) rpm --install package.rpm; rpm -q "$package" ;;
    apk) apk --no-network --no-cache --repositories-file /dev/null --allow-untrusted add ./package.apk; apk info --quiet -e "$package" ;;
esac
test ! -s forbidden
sha256sum -c administrator.sha256
stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' /etc/sw-fresh-admin.conf /etc/ssh/sshd_config.d/sw-fresh-admin.conf /etc/cron.d/sw-fresh-admin /etc/systemd/system/sw-fresh-admin.service /etc/init.d/sw-fresh-admin /etc/runlevels/default/sw-fresh-admin > administrator.after
test "$(sha256sum < administrator.metadata)" = "$(sha256sum < administrator.after)"
test "$(readlink /etc/runlevels/default/sw-fresh-admin)" = /etc/init.d/sw-fresh-admin
test ! -e /etc/syswarden && test ! -L /etc/syswarden
for path in /var/lib/syswarden /var/log/syswarden /etc/systemd/system/syswarden-core.service /etc/systemd/system/syswarden-firewall.service /etc/init.d/syswarden-core /etc/init.d/syswarden-firewall; do
    test ! -e "$path" && test ! -L "$path"
done
sha256sum -c inputs.sha256
printf 'HOOK_EVENTS_BEGIN\n'
cat events
printf 'HOOK_EVENTS_END\n'
printf 'FRESH_HOOK_DISPATCH_PASS=%s:%s:%s\n' "$format" "$package" "$source"
'''


def payload(root: Path, nfpm: Path, source: str, package_name: str, format_name: str) -> tuple[bytes, dict]:
    validate_selection(source, package_name, format_name)
    files: dict[str, bytes] = {"cases.sh": SCRIPT.encode(), ".fixture-marker": b"SYSWARDEN-FRESH-HOOK-DISPATCH-V1\n"}
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
    write_private(root / "cli", CLI, 0o700)
    spec = {"name": package_name, "arch": "amd64", "platform": "linux", "version": VERSION,
            "version_schema": "none", "maintainer": "SysWarden synthetic laboratory", "license": "MIT",
            "description": "Inert fresh hook dispatch fixture, not a production package",
            "contents": [{"src": str(root / "cli"), "dst": "/opt/syswarden/bin/syswarden-cli",
                          "file_info": {"mode": 0o755}}],
            "scripts": {"preinstall": str(root / "delegate-preinst.sh"), "postinstall": str(root / "delegate-postinst.sh")}}
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
    if not package_bytes or len(package_bytes) > 8 << 20:
        raise ValueError("inert package exceeds its byte bound")
    files[package.name] = package_bytes
    files["inputs.sha256"] = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items()).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o600
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue(), {"emitted_hook_sha256": hashes, "package_sha256": hashlib.sha256(package_bytes).hexdigest(),
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


def parse_result(output: bytes, source: str, package_name: str, format_name: str) -> dict:
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
    if events != ["CLI_PHASE=fresh", "CLI_ARGC=1", "CLI_ARG=install"]:
        raise ValueError("fresh staging call absent, repeated or not exact")
    return {"native_arguments": observed, "fresh_cli_staging_call": True, "administrator_sentinels_preserved": True}


def run(nfpm: Path, image: str, output: Path, source: str, package_name: str, format_name: str) -> None:
    validate_selection(source, package_name, format_name)
    if os.geteuid() == 0 or re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("unprivileged host and exact cached image required")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("existing caller-trusted nfpm executable required")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("new absolute private output directory required")
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
    content, binding = payload(output, nfpm, source, package_name, format_name)
    identity = helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + uuid.uuid4().hex, uuid.uuid4().hex, output / "container.cid")
    arguments = sandbox_command(podman, image, identity, source, package_name, format_name)
    result = subprocess.CompletedProcess(arguments, 125, b"")
    attempted = False
    cleanup = {"verified": False}
    original_cid = None
    original_cid_verified = isolation_verified = False
    failure = None
    try:
        if identity.cidfile.exists() or identity.cidfile.is_symlink() or helpers.container_exists(podman, identity.name):
            raise ValueError("disposable identity collision")
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
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess(arguments, 124, error.stdout or b"")
        failure = "native fixture operation timed out"
    except (OSError, ValueError) as error:
        failure = str(error)
    finally:
        if attempted:
            cleanup = cleanup_owned_container(podman, identity, original_cid)
        write_private(output / "container.json", (json.dumps({"name": identity.name, "owner_label": helpers.OWNER_LABEL,
                      "owner_token": identity.token, "original_container_id": original_cid,
                      "original_cid_verified": original_cid_verified, "isolation_verified_before_start": isolation_verified,
                      "cleanup": cleanup}, indent=2) + "\n").encode())
    write_private(output / "native.log", result.stdout)
    summary = {"image": image, "source": source, "package_name": package_name, "format": format_name, **binding,
               "exit_status": result.returncode, "cleanup": cleanup, "synthetic_only": True,
               "real_toml_staging_verified": False, "production_package_acceptance": False,
               "engine_default_mounts_attested": isolation_verified,
               "original_cid_verified": original_cid_verified, "subprocess_output_byte_cap": None,
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(),
               "nfpm_binding": "caller-trusted-tool-observation-not-execution-attestation", "passed": False}
    try:
        summary.update(parse_result(result.stdout, source, package_name, format_name))
        summary["passed"] = (result.returncode == 0 and cleanup["verified"] and original_cid_verified
                             and isolation_verified and failure is None)
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
    parser.add_argument("--source", choices=SOURCES, required=True)
    parser.add_argument("--package-name", choices=NAMES, required=True)
    parser.add_argument("--format", choices=FORMATS, required=True)
    options = parser.parse_args()
    run(options.nfpm, options.image, options.output, options.source, options.package_name, options.format)
