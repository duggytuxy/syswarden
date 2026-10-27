#!/usr/bin/env python3
"""Characterize a prepared APK launcher transition using inert AMD64 fixtures.

This laboratory does not enable a product migration or qualify direct APK calls.
Only its offline disposable fixtures accept unsigned packages. The rules, native
ownership and independent remove/purge outcomes are observed separately.
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
import tarfile
import uuid

import native_fresh_configuration_probe as isolation

PACKAGE_NAMES = ("syswarden", "syswarden-base")
CASES = ("fresh-directory", "same-directory", "omit-directory", "same-exact",
         "omit-exact", "incoming-rule", "preupgrade-rule",
         "omit-metadata-link-directory", "omit-metadata-regular-directory",
         "omit-overlay", "omit-metadata-regular-overlay", "omit-metadata-link-overlay")
REMOVALS = ("remove", "purge")
ALIASES = ("syswarden", "syswarden-tui")
PARENTS = ("/usr", "/usr/local", "/usr/local/bin")
PASS_MARKER = "APK_PROTECTED_PATH_CHARACTERIZATION_PASS"

OWNERSHIP_SCRIPT = r'''
launcher_ownership() {
    launcher_path=$1
    expected_package=$2
    if apk info --who-owns "$launcher_path" > owner 2>/dev/null; then
        case "$(cat owner)" in
            "$launcher_path is owned by $expected_package") printf 'owned\n' ;;
            "$launcher_path symlink target is owned by $expected_package")
                test -L "$launcher_path" || return 83
                test "$(readlink "$launcher_path")" = /opt/sw-apk-protection/vendor || return 83
                printf 'target-owned\n'
                ;;
            *) return 83 ;;
        esac
    else
        query_status=$?
        test "$query_status" -eq 1 || return 83
        printf 'unowned\n'
    fi
}
'''

SCRIPT = r'''#!/bin/sh
set -eu
cd /tmp/sw-fresh-lab
test "$(apk --print-arch)" = x86_64
apk --version
apk_cmd() { apk --no-network --repositories-file /dev/null --allow-untrusted "$@"; }
''' + OWNERSHIP_SCRIPT + r'''
for package in syswarden syswarden-base; do
    if apk info -e "$package" >/dev/null 2>&1; then exit 80; else test "$?" -eq 1; fi
done
for path in /usr/local/bin/syswarden /usr/local/bin/syswarden-tui /opt/sw-apk-protection /etc/apk/protected_paths.d/sw-lab.list; do
    test ! -e "$path" && test ! -L "$path"
done
mkdir -p /usr/local/bin /opt/sw-apk-protection /etc/apk/protected_paths.d
printf '#!/bin/sh\nprintf "admin-regular\\n"\n' > admin-regular
printf '#!/bin/sh\nprintf "admin-link\\n"\n' > /opt/sw-apk-protection/admin-target
chmod 755 /opt/sw-apk-protection/admin-target
identity_snapshot() {
    for alias in syswarden syswarden-tui; do
        if [ -L "/usr/local/bin/$alias" ]; then readlink "/usr/local/bin/$alias"; else sha256sum "/usr/local/bin/$alias"; fi
        stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "/usr/local/bin/$alias"
    done
}
snapshot() {
    for alias in syswarden syswarden-tui; do
        sha256sum "/usr/local/bin/$alias"
        if [ -L "/usr/local/bin/$alias" ]; then readlink "/usr/local/bin/$alias"; fi
        stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "/usr/local/bin/$alias"
        "/usr/local/bin/$alias"
    done
}
parent_snapshot() {
    for parent in /usr /usr/local /usr/local/bin; do
        stat -c '%n:%d:%i:%f:%u:%g:%h:%s:%Y:%Z' "$parent"
    done
}
record_parent_snapshot() {
    parent_stage=$1
    parent_snapshot > "$parent_stage-parent"
    cut -d: -f1-6 "$parent_stage-parent" > "$parent_stage-parent-access"
    while IFS= read -r metadata; do
        printf 'PARENT_METADATA=%s:%s:%s:%s:%s\n' "$package" "$case_name" "$removal" "$parent_stage" "$metadata"
    done < "$parent_stage-parent"
}
for package in syswarden syswarden-base; do
    for case_name in fresh-directory same-directory omit-directory same-exact omit-exact incoming-rule preupgrade-rule omit-metadata-link-directory omit-metadata-regular-directory omit-overlay omit-metadata-regular-overlay omit-metadata-link-overlay; do
        for removal in remove purge; do
            rm -f /etc/apk/protected_paths.d/sw-lab.list
            case "$case_name" in
                fresh-*) ;;
                omit-metadata-regular-*) apk_cmd add "./$package-1-regular.apk" ;;
                *) apk_cmd add "./$package-1.apk" ;;
            esac
            case "$case_name" in
                omit-metadata-*)
                    # Keep the old native bytes/link target. Only metadata differs.
                    touch -h -t 202001020304 /usr/local/bin/syswarden /usr/local/bin/syswarden-tui
                    case "$case_name" in omit-metadata-regular-*) chmod 751 /usr/local/bin/syswarden /usr/local/bin/syswarden-tui ;; esac
                    ;;
                *)
                    rm -f /usr/local/bin/syswarden /usr/local/bin/syswarden-tui
                    cp admin-regular /usr/local/bin/syswarden
                    chmod 751 /usr/local/bin/syswarden
                    ln -s /opt/sw-apk-protection/admin-target /usr/local/bin/syswarden-tui
                    ;;
            esac
            identity_snapshot > before-identity
            snapshot > before
            record_parent_snapshot before
            case "$case_name" in
                *-directory) printf '+usr/local/bin\n' > /etc/apk/protected_paths.d/sw-lab.list ;;
                *-exact) printf '+usr/local/bin/syswarden\n+usr/local/bin/syswarden-tui\n' > /etc/apk/protected_paths.d/sw-lab.list ;;
            esac
            version=2
            case "$case_name" in omit-*) version=3 ;; incoming-rule) version=4 ;; preupgrade-rule) version=5 ;; esac
            case "$case_name" in
                *-overlay)
                    # Exact root-relative files, before APK reads installed ownership.
                    # The incoming package omits both aliases. No directory rule is used.
                    printf 'usr/local/bin/syswarden\nusr/local/bin/syswarden-tui\n' | apk_cmd --overlay-from-stdin add "./$package-$version.apk"
                    ;;
                *) apk_cmd add "./$package-$version.apk" ;;
            esac
            test "$(/opt/sw-apk-protection/vendor)" = "vendor-$version"
            snapshot > after 2>/dev/null || true
            identity_snapshot > after-identity 2>/dev/null || true
            record_parent_snapshot after
            identity_preserved=0
            cmp -s before-identity after-identity && identity_preserved=1
            preserved=0
            cmp -s before after && preserved=1
            owned=0
            for alias in syswarden syswarden-tui; do
                ownership=$(launcher_ownership "/usr/local/bin/$alias" "$package-$version.00.0-r0")
                printf 'OWNERSHIP_OBSERVATION=%s:%s:%s:%s:%s\n' "$package" "$case_name" "$removal" "$alias" "$ownership"
                if [ "$ownership" = owned ]; then owned=$((owned + 1)); fi
            done
            case "$owned" in 0) ;; 2) owned=1 ;; *) exit 82 ;; esac
            if [ "$removal" = purge ]; then apk_cmd del --purge "$package"; else apk_cmd del "$package"; fi
            if apk info -e "$package" >/dev/null 2>&1; then exit 81; else test "$?" -eq 1; fi
            test ! -e /opt/sw-apk-protection/vendor
            snapshot > removed 2>/dev/null || true
            identity_snapshot > removed-identity 2>/dev/null || true
            record_parent_snapshot removed
            identity_retained=0
            cmp -s before-identity removed-identity && identity_retained=1
            printf 'IDENTITY_OBSERVATION=%s:%s:%s:%s:%s\n' "$package" "$case_name" "$removal" "$identity_preserved" "$identity_retained"
            parent_preserved=0
            cmp -s before-parent-access after-parent-access && parent_preserved=1
            parent_retained=0
            cmp -s before-parent-access removed-parent-access && parent_retained=1
            printf 'PARENT_OBSERVATION=%s:%s:%s:%s:%s\n' "$package" "$case_name" "$removal" "$parent_preserved" "$parent_retained"
            retained=0
            cmp -s before removed && retained=1
            printf 'OBSERVATION=%s:%s:%s:%s:%s:%s\n' "$package" "$case_name" "$removal" "$preserved" "$owned" "$retained"
            # Each iteration starts a separate inert package lifecycle. Remove
            # only its fixed fixture paths inside this disposable container.
            rm -f /usr/local/bin/syswarden /usr/local/bin/syswarden-tui /usr/local/bin/syswarden.apk-new /usr/local/bin/syswarden-tui.apk-new /etc/apk/protected_paths.d/sw-lab.list
        done
    done
done
printf 'APK_PROTECTED_PATH_CHARACTERIZATION_PASS\n'
'''


def expected_observation(package: str, case: str, removal: str) -> dict:
    if package not in PACKAGE_NAMES or case not in CASES or removal not in REMOVALS:
        raise ValueError("unknown protected-path observation coordinate")
    preserved = case in ("fresh-directory", "same-directory", "omit-directory",
                         "omit-overlay", "omit-metadata-regular-overlay")
    owned = not case.startswith("omit-")
    retained = preserved and (removal == "remove" or case.startswith("omit-"))
    metadata_link = case.startswith("omit-metadata-link-")
    return {"package_name": package, "case": case, "removal": removal,
            "launcher_identity_preserved": preserved or metadata_link,
            "launcher_identity_preserved_after_removal": retained or metadata_link,
            "launcher_identity_and_effect_preserved": preserved,
            "launcher_owned_after_upgrade": owned,
            "launcher_identity_and_effect_preserved_after_removal": retained,
            "parent_identity_and_permissions_preserved": True,
            "parent_identity_and_permissions_preserved_after_removal": True}


def parse_result(output: bytes) -> list[dict]:
    if len(output) > 1 << 20:
        raise ValueError("protected-path output exceeds its evidence bound")
    lines = output.decode("utf-8", errors="strict").splitlines()
    if not lines or lines[-1] != PASS_MARKER or lines.count(PASS_MARKER) != 1:
        raise ValueError("missing or repeated protected-path completion marker")
    expected = [expected_observation(name, case, removal) for name in PACKAGE_NAMES for case in CASES for removal in REMOVALS]
    observations = {
        "OBSERVATION": ("launcher_identity_and_effect_preserved", "launcher_owned_after_upgrade",
                        "launcher_identity_and_effect_preserved_after_removal"),
        "IDENTITY_OBSERVATION": ("launcher_identity_preserved", "launcher_identity_preserved_after_removal"),
        "PARENT_OBSERVATION": ("parent_identity_and_permissions_preserved",
                               "parent_identity_and_permissions_preserved_after_removal"),
    }
    for prefix, keys in observations.items():
        observed = [line for line in lines if line.startswith(prefix + "=")]
        if len(observed) != len(expected):
            raise ValueError("incomplete or duplicated protected-path observations")
        for line, record in zip(observed, expected):
            fields = (record["package_name"], record["case"], record["removal"],
                      *(str(int(record[key])) for key in keys))
            if line != prefix + "=" + ":".join(fields):
                raise ValueError("native protected-path state differs from its observed contract")
    owners = [line.removeprefix("OWNERSHIP_OBSERVATION=").split(":") for line in lines if line.startswith("OWNERSHIP_OBSERVATION=")]
    parents = [line.removeprefix("PARENT_METADATA=").split(":") for line in lines if line.startswith("PARENT_METADATA=")]
    if len(owners) != len(expected) * len(ALIASES) or len(parents) != len(expected) * 3 * len(PARENTS):
        raise ValueError("incomplete or duplicated native ownership or parent metadata")
    for record_index, record in enumerate(expected):
        coordinate = [record["package_name"], record["case"], record["removal"]]
        record["native_ownership_observations"] = {}
        for alias_index, alias in enumerate(ALIASES):
            fields = owners[record_index * len(ALIASES) + alias_index]
            allowed = {"owned"} if record["launcher_owned_after_upgrade"] else {"unowned"}
            if record["case"].startswith("omit-metadata-link-"):
                allowed.add("target-owned")
            if len(fields) != 5 or fields[:4] != coordinate + [alias] or fields[4] not in allowed:
                raise ValueError("native file ownership differs from target ownership or expected state")
            record["native_ownership_observations"][alias] = fields[4]
        record["parent_metadata"] = {}
        for stage_index, stage in enumerate(("before", "after", "removed")):
            metadata = {}
            for parent_index, parent in enumerate(PARENTS):
                fields = parents[(record_index * 3 + stage_index) * len(PARENTS) + parent_index]
                if len(fields) != 14 or fields[:5] != coordinate + [stage, parent]:
                    raise ValueError("native parent metadata coordinate is ambiguous")
                for index, value in enumerate(fields[5:]):
                    pattern = r"[0-9a-f]{1,8}" if index == 2 else r"-?[0-9]{1,20}" if index >= 7 else r"[0-9]{1,20}"
                    if re.fullmatch(pattern, value) is None:
                        raise ValueError("native parent metadata value is malformed")
                values = dict(zip(("device", "inode", "mode", "uid", "gid", "links", "size", "mtime", "ctime"), fields[5:]))
                if int(values["mode"], 16) & 0o170000 != 0o040000:
                    raise ValueError("native parent is not a directory")
                metadata[parent] = values
            record["parent_metadata"][stage] = metadata
        for stage in ("after", "removed"):
            for parent in PARENTS:
                before = record["parent_metadata"]["before"][parent]
                actual = record["parent_metadata"][stage][parent]
                if any(before[key] != actual[key] for key in ("device", "inode", "mode", "uid", "gid")):
                    raise ValueError("native parent identity or permissions changed")
    return expected


def payload(root: Path, nfpm: Path) -> bytes:
    isolation.write_private(root / "cases.sh", SCRIPT.encode())
    isolation.write_private(root / "protected.list", b"+usr/local/bin\n")
    isolation.write_private(root / "preupgrade.sh", b'#!/bin/sh\nprintf "+usr/local/bin\\n" > /etc/apk/protected_paths.d/sw-lab.list\n', 0o700)
    packages = []
    for name in PACKAGE_NAMES:
        for version, regular in [(version, False) for version in range(1, 6)] + [(1, True)]:
            suffix = "-regular" if regular else ""
            vendor = root / f"{name}-vendor-{version}{suffix}"
            isolation.write_private(vendor, f'#!/bin/sh\nprintf "vendor-{version}\\n"\n'.encode())
            contents = [{"src": str(vendor), "dst": "/opt/sw-apk-protection/vendor", "file_info": {"mode": 0o755}}]
            if regular:
                contents.extend({"src": str(vendor), "dst": "/usr/local/bin/" + alias,
                                 "file_info": {"mode": 0o755}} for alias in ("syswarden", "syswarden-tui"))
            elif version != 3:
                contents.extend({"src": "/opt/sw-apk-protection/vendor", "dst": "/usr/local/bin/" + alias,
                                 "type": "symlink"} for alias in ("syswarden", "syswarden-tui"))
            if version == 4:
                contents.append({"src": str(root / "protected.list"), "dst": "/etc/apk/protected_paths.d/sw-lab.list"})
            spec = {"name": name, "arch": "amd64", "platform": "linux", "version": f"{version}.00.0",
                    "version_schema": "none", "release": "0", "description": "Inert protected-path fixture",
                    "maintainer": "SysWarden synthetic laboratory", "license": "MIT", "contents": contents}
            if version == 5:
                spec["apk"] = {"scripts": {"preupgrade": str(root / "preupgrade.sh")}}
            config, package = root / f"{name}-{version}{suffix}.json", root / f"{name}-{version}{suffix}.apk"
            isolation.write_private(config, (json.dumps(spec, indent=2) + "\n").encode())
            built = subprocess.run([str(nfpm), "pkg", "--config", str(config), "--packager", "apk", "--target", str(package)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, check=False)
            isolation.write_private(root / f"{name}-{version}{suffix}.build.log", built.stdout)
            if built.returncode:
                raise ValueError("inert protected-path fixture build failed")
            packages.append(package)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in [root / "cases.sh", *packages]:
            archive.add(path, arcname=path.name)
    return stream.getvalue()


def run(nfpm: Path, image: str, output: Path) -> None:
    if os.geteuid() == 0 or re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("unprivileged host and exact cached Linux AMD64 image required")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("existing caller-trusted nfpm executable required")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("new absolute private output directory required")
    helpers = isolation.isolation_helpers()
    podman = shutil.which("podman")
    if podman is None:
        raise ValueError("local rootless Podman required")
    rootless = helpers.execute_local(helpers.podman_command(podman, "info", "--format", "{{.Host.Security.Rootless}}"))
    if rootless.returncode or rootless.stdout.strip() != b"true":
        raise ValueError("independent rootless engine evidence required")
    inspected = helpers.execute_local(helpers.podman_command(podman, "image", "inspect", image))
    if inspected.returncode or len(inspected.stdout) > 1 << 20:
        raise ValueError("cached image inspection failed")
    images = json.loads(inspected.stdout)
    if len(images) != 1 or images[0].get("Id", "").removeprefix("sha256:") != image or images[0].get("Os") != "linux" or images[0].get("Architecture") != "amd64":
        raise ValueError("exact cached Linux AMD64 image required")
    output.mkdir(mode=0o700)
    isolation.write_private(output / "image.json", inspected.stdout)
    content = payload(output, nfpm)
    identity = helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + uuid.uuid4().hex, uuid.uuid4().hex, output / "container.cid")
    # Reuse the checked create/inspect/start contract. Its dispatch arguments are
    # unused by this independent script; no fresh-install acceptance is inferred.
    arguments = isolation.sandbox_command(podman, image, identity, "local", "syswarden", "apk")
    cid = None
    attempted = isolation_verified = False
    result = subprocess.CompletedProcess(arguments, 125, b"")
    failure = None
    cleanup = {"verified": False}
    try:
        if identity.cidfile.exists() or identity.cidfile.is_symlink() or helpers.container_exists(podman, identity.name):
            raise ValueError("disposable container identity collision")
        attempted = True
        created = helpers.execute_local(arguments, timeout=20)
        isolation.write_private(output / "create.log", created.stdout)
        if created.returncode or re.fullmatch(rb"[0-9a-f]{64}\n?", created.stdout) is None:
            raise ValueError("create did not return an exact original container ID")
        cid = created.stdout.decode("ascii").rstrip("\n")
        if helpers.read_container_id(identity.cidfile) != cid:
            raise ValueError("original container ID record differs")
        inspected = helpers.execute_local(helpers.podman_command(podman, "container", "inspect", cid))
        isolation.write_private(output / "created-container.json", inspected.stdout)
        if inspected.returncode or len(inspected.stdout) > 1 << 20:
            raise ValueError("created container inspection failed")
        entries = json.loads(inspected.stdout)
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
            raise ValueError("created container inspection is ambiguous")
        isolation.validate_isolation(entries[0], image, identity, cid, arguments)
        isolation_verified = True
        if helpers.read_container_id(identity.cidfile) != cid:
            raise ValueError("original container ID changed before start")
        result = helpers.execute_local(helpers.podman_command(podman, "start", "--attach", "--interactive", cid),
                                       timeout=75, input=content)
        if helpers.read_container_id(identity.cidfile) != cid:
            raise ValueError("original container ID changed during native execution")
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess(arguments, 124, error.stdout or b"")
        failure = "native protected-path operation timed out"
    except (OSError, ValueError) as error:
        failure = str(error)
    finally:
        if attempted:
            cleanup = isolation.cleanup_owned_container(podman, identity, cid)
        isolation.write_private(output / "container.json", (json.dumps({"name": identity.name,
            "owner_token": identity.token, "original_container_id": cid,
            "isolation_verified_before_start": isolation_verified, "cleanup": cleanup}, indent=2) + "\n").encode())
    isolation.write_private(output / "native.log", result.stdout)
    summary = {"image": image, "synthetic_only": True, "product_accepted": False, "direct_native_upgrade_qualified": False,
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(), "nfpm_binding": "caller-trusted-tool-observation-not-execution-attestation",
               "script_sha256": hashlib.sha256(SCRIPT.encode()).hexdigest(), "payload_sha256": hashlib.sha256(content).hexdigest(),
               "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "exit_status": result.returncode,
               "engine_default_mounts_attested": isolation_verified, "subprocess_output_byte_cap": None,
               "cleanup": cleanup, "passed": False}
    try:
        summary["observations"] = parse_result(result.stdout)
        summary["passed"] = result.returncode == 0 and cleanup["verified"] and isolation_verified and cid is not None and failure is None
    except (ValueError, UnicodeError) as error:
        failure = str(error)
    if failure is not None:
        summary["error"] = failure
    isolation.write_private(output / "results.json", (json.dumps(summary, indent=2) + "\n").encode())
    if not summary["passed"]:
        raise RuntimeError("native protected-path characterization failed; inspect retained results")
    print("PASS APK protected-path characterization", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--nfpm", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    run(options.nfpm, options.image, options.output)
