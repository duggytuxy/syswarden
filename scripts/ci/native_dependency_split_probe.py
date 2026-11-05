#!/usr/bin/env python3
"""Inert, opt-in native package identity split laboratory for Linux AMD64.

Qualification cases exercise a disjoint payload layout. Shared-path handoff and
script refusal are characterization only: native errors are never called rollback.
Unsigned synthetic fixtures are confined to disposable, offline rootless containers.
This laboratory neither builds nor accepts production SysWarden packages.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import uuid

import native_dependency_transition_probe as native

QUALIFICATION_CASES = ("fresh-base", "compatibility-upgrade", "compatibility-admin",
                       "solver-refusal")
CHARACTERIZATION_CASES = ("shared-handoff", "unprepared-shared-base", "script-refusal")
EXTRA_CASES = {"deb": ("compatibility-held",), "rpm": ("compatibility-group",),
               "apk": ("compatibility-pinned", "compatibility-tagged")}
ALL_CASES = QUALIFICATION_CASES + CHARACTERIZATION_CASES + tuple(
    case for cases in EXTRA_CASES.values() for case in cases)
CONTAINER_PREFIX = "sw-dependency-split-"
OWNER_LABEL = "io.syswarden.dependency-split-owner"


@dataclass(frozen=True)
class ContainerIdentity:
    name: str
    token: str
    cidfile: Path


def container_identity(output: Path, case: str) -> ContainerIdentity:
    if not output.is_absolute() or case not in ALL_CASES:
        raise ValueError("absolute output and supported case required")
    return ContainerIdentity(CONTAINER_PREFIX + uuid.uuid4().hex, uuid.uuid4().hex, output / f"{case}.cid")


def validate_container(identity: ContainerIdentity) -> None:
    if (re.fullmatch(CONTAINER_PREFIX + r"[0-9a-f]{32}", identity.name) is None
            or re.fullmatch(r"[0-9a-f]{32}", identity.token) is None or not identity.cidfile.is_absolute()):
        raise ValueError("invalid disposable container identity")


def podman_command(podman: str, *arguments: str) -> list[str]:
    return [podman, "--remote=false", *arguments]


def execute_local(arguments: list[str], *, timeout: int = 15, input: bytes | None = None) -> subprocess.CompletedProcess:
    if len(arguments) < 3 or arguments[1] != "--remote=false":
        raise ValueError("local Podman execution required")
    return subprocess.run(arguments, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, check=False)


def container_exists(podman: str, identifier: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{64}|" + CONTAINER_PREFIX + r"[0-9a-f]{32}", identifier) is None:
        raise ValueError("exact disposable container identity required")
    result = execute_local(podman_command(podman, "container", "exists", identifier))
    if result.returncode not in (0, 1) or result.stdout.strip():
        raise ValueError("container presence could not be verified")
    return result.returncode == 0


def read_container_id(path: Path) -> str | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as file:
        metadata = os.fstat(file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size not in (64, 65):
            raise ValueError("invalid disposable container ID file")
        content = file.read(66)
    if re.fullmatch(rb"[0-9a-f]{64}\n?", content) is None:
        raise ValueError("invalid disposable container ID")
    return content.decode("ascii").rstrip("\n")


def cleanup_container(podman: str, identity: ContainerIdentity, *, require_cid: bool) -> dict:
    validate_container(identity)
    result = {"name": identity.name, "ownership_verified": False, "removal_attempted": False,
              "name_absent": False, "id_absent": None, "verified": False}
    try:
        cid = read_container_id(identity.cidfile)
        result["container_id"] = cid
        present = container_exists(podman, identity.name)
        if present:
            inspection = execute_local(podman_command(podman, "container", "inspect", identity.name))
            if inspection.returncode or len(inspection.stdout) > 1 << 20:
                raise ValueError("container ownership inspection failed")
            entries = json.loads(inspection.stdout)
            if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
                raise ValueError("container ownership is ambiguous")
            item = entries[0]
            owned_id = item.get("Id")
            config = item.get("Config")
            labels = config.get("Labels") if isinstance(config, dict) else None
            if (not isinstance(owned_id, str) or re.fullmatch(r"[0-9a-f]{64}", owned_id) is None
                    or item.get("Name") not in (identity.name, "/" + identity.name)
                    or not isinstance(labels, dict) or labels.get(OWNER_LABEL) != identity.token
                    or cid is not None and cid != owned_id):
                raise ValueError("container ownership mismatch; no removal authorized")
            cid = owned_id
            result.update(container_id=cid, ownership_verified=True, removal_attempted=True)
            removal = execute_local(podman_command(podman, "rm", "--force", "--time", "5", cid))
            result["removal_exit"] = removal.returncode
            # Concurrent removal can race this cleanup. Only verified absence
            # establishes cleanup, never the remove command's exit status alone.
            present = container_exists(podman, identity.name)
        result["name_absent"] = not present
        if cid is not None:
            result["id_absent"] = not container_exists(podman, cid)
        if require_cid and cid is None:
            raise ValueError("completed container lacks its exact ID record")
        result["verified"] = not present and (cid is None or result["id_absent"])
        if not result["verified"]:
            result["error"] = "disposable container remains present"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    return result


def run_container(podman: str, image: str, format_name: str, case: str, output: Path, payload: bytes) -> tuple[subprocess.CompletedProcess, dict]:
    identity = container_identity(output, case)
    validate_container(identity)
    ownership = {"name": identity.name, "owner_label": OWNER_LABEL, "owner_token": identity.token,
                 "cidfile": identity.cidfile.name, "absent_before": False}
    ownership_path = output / f"{case}.container.json"
    ownership_path.write_text(json.dumps(ownership, indent=2) + "\n")
    attempted = False
    result = subprocess.CompletedProcess([], 125, b"")
    try:
        if identity.cidfile.exists() or identity.cidfile.is_symlink() or container_exists(podman, identity.name):
            raise ValueError("disposable container identity already exists; no run or cleanup authorized")
        ownership["absent_before"] = True
        ownership_path.write_text(json.dumps(ownership, indent=2) + "\n")
        attempted = True
        result = execute_local(sandbox_command(podman, image, format_name, case, identity), timeout=100, input=payload)
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess([], 124, error.stdout or b"")
    except (OSError, ValueError) as error:
        ownership["launch_error"] = str(error)
    finally:
        cleanup = cleanup_container(podman, identity, require_cid=result.returncode == 0) if attempted else {
            "name": identity.name, "verified": False, "removal_attempted": False,
            "error": "container launch refused before ownership acquisition"}
        ownership["cleanup"] = cleanup
        ownership_path.write_text(json.dumps(ownership, indent=2) + "\n")
    return result, ownership

SCRIPT = r'''#!/bin/sh
set -eu
umask 077
cd /tmp/sw-split-lab
format=$1
case_name=$2
test "$(uname -m)" = x86_64
transaction_exit=0
unrelated_cleanup=not-run
script_refusal=0
legacy_unchanged=0
dnf_generation=4
same_bytes() {
    # Minimal RPM images need not contain diffutils. Compare complete bytes,
    # including final newlines, using the already required SHA-256 tool.
    left=$(sha256sum "$1") || return 1
    right=$(sha256sum "$2") || return 1
    test "${left%% *}" = "${right%% *}"
}
apt_cmd() { apt-get -o APT::Sandbox::User=root -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=- -o Acquire::Retries=0 -o Dpkg::Use-Pty=0 "$@"; }
dnf_cmd() { dnf --noplugins --cacheonly --disablerepo='*' --setopt=localpkg_gpgcheck=0 --nogpgcheck "$@"; }
apk_cmd() { apk --no-network --repositories-file /tmp/sw-split-lab/repositories "$@"; }
: > repositories
case "$format" in
    deb) apt-get --version; dpkg --version ;;
    rpm)
        version=$(dnf --noplugins --version)
        printf '%s\n' "$version"
        rpm --version
        case "$version" in 'dnf5 version 5.'*) dnf_generation=5 ;; 4.*) ;; *) exit 1 ;; esac
        ;;
    apk) apk --version; test "$(apk --print-arch)" = x86_64 ;;
    *) exit 64 ;;
esac
installed() {
    case "$format" in
        deb) dpkg-query -W -f='${db:Status-Abbrev}\n' "$1" 2>/dev/null | grep -Eq '^[ih]i $' ;;
        rpm) rpm -q --quiet "$1" ;;
        apk) apk_cmd info --quiet -e "$1" ;;
    esac
}
registered_version() {
    # A dpkg unpacked/failed package still has a version. Record registration
    # separately from the success of its maintainer scripts.
    case "$format" in
        deb) dpkg-query -W -f='${Version}\n' "$1" 2>/dev/null ;;
        rpm) rpm -q --queryformat '%{VERSION}\n' "$1" 2>/dev/null ;;
        apk)
            awk -v name="$1" 'BEGIN { RS=""; FS="\n" } { p=""; v=""; for(i=1;i<=NF;i++) { if(substr($i,1,2)=="P:") p=substr($i,3); if(substr($i,1,2)=="V:") v=substr($i,3) } if(p==name) print v }' /lib/apk/db/installed
            ;;
    esac
}
assert_absent() {
    if installed "$1" > /tmp/sw-split-absent 2>&1; then exit 1; fi
    # Registration, including an incomplete native package, must be absent.
    value=$(registered_version "$1" || true)
    case "$value" in ''|"package $1 is not installed") ;; *) exit 1 ;; esac
}
reason() {
    case "$format" in
        deb)
            automatic=$(apt-mark showauto sw-lab-optional) || return 1
            held=$(apt-mark showhold sw-lab-optional) || return 1
            case "$automatic" in ''|sw-lab-optional) ;; *) return 1 ;; esac
            case "$held" in ''|sw-lab-optional) ;; *) return 1 ;; esac
            printf 'automatic=%s\nheld=%s\n' "$automatic" "$held"
            ;;
        # DNF5 prints backslash-t literally; pass an actual separator to both.
        rpm) dnf_cmd -q repoquery --installed --qf "$(printf '%%{name}\t%%{reason}')" sw-lab-optional ;;
        apk)
            # Include the full administrator token: bare, version-pinned or tagged.
            awk '/^sw-lab-optional($|[@<>=~])/ {print}' /etc/apk/world
            ;;
    esac
}
assert_expected_selection() {
    case "$format" in
        deb)
            expected_auto=sw-lab-optional
            expected_hold=
            if [ "$case_name" = compatibility-admin ]; then expected_auto=; fi
            if [ "$case_name" = compatibility-held ]; then expected_hold=sw-lab-optional; fi
            test "$(reason)" = "$(printf 'automatic=%s\nheld=%s\n' "$expected_auto" "$expected_hold")"
            ;;
        rpm)
            expected_reason=dependency
            case "$case_name" in compatibility-admin) expected_reason=user ;; compatibility-group) expected_reason=group ;; esac
            if [ "$dnf_generation" = 5 ]; then
                case "$expected_reason" in dependency) expected_reason=Dependency ;; user) expected_reason=User ;; group) expected_reason=Group ;; esac
            fi
            observed_reason=$(reason)
            printf 'SW_SPLIT_SELECTION %s\n' "$observed_reason"
            test "$observed_reason" = "$(printf 'sw-lab-optional\t%s\n' "$expected_reason")"
            ;;
        apk)
            expected_root=
            case "$case_name" in
                compatibility-admin) expected_root=sw-lab-optional ;;
                compatibility-pinned) expected_root='sw-lab-optional=1.0.0' ;;
                compatibility-tagged) expected_root='sw-lab-optional@local=1.0.0' ;;
            esac
            test "$(reason)" = "$expected_root"
            ;;
    esac
}
mark_auto() {
    case "$format" in
        deb) apt-mark auto "$1" ;;
        rpm)
            if [ "$dnf_generation" = 5 ]; then dnf_cmd -y mark dependency "$1"; else dnf_cmd mark remove "$1"; fi
            ;;
        *) exit 64 ;;
    esac
}
install_files() {
    case "$format" in
        deb) apt_cmd --no-install-recommends --no-remove install -y "$@" ;;
        rpm) dnf_cmd --setopt=install_weak_deps=False --setopt=clean_requirements_on_remove=False --setopt=obsoletes=False install -y "$@" ;;
        apk) apk_cmd --allow-untrusted add "$@" ;;
    esac
}
install_legacy() {
    if [ "$format" = apk ]; then
        mkdir -p repo/x86_64
        cp optional-1.0.0.apk repo/sw-lab-optional-1.0.0.apk
        cp unrelated-1.0.0.apk repo/sw-lab-unrelated-1.0.0.apk
        apk_cmd --allow-untrusted index -o repo/APKINDEX.tar.gz repo/*.apk
        cp repo/*.apk repo/APKINDEX.tar.gz repo/x86_64/
        apk_cmd --allow-untrusted --repository /tmp/sw-split-lab/repo add ./legacy-1.0.0.apk ./unrelated-root-1.0.0.apk
        test -z "$(reason)"
    else
        install_files "./optional-1.0.0.$format" "./unrelated-1.0.0.$format" "./legacy-1.0.0.$format"
        mark_auto sw-lab-optional
        mark_auto sw-lab-unrelated
    fi
    installed sw-lab-syswarden
    installed sw-lab-optional
    installed sw-lab-unrelated
    test "$(cat /opt/sw-split-lab/runtime)" = legacy-runtime-1.0.0
    printf 'effective_fixture_policy=preserve\n' > /etc/sw-split-admin.conf
    chmod 600 /etc/sw-split-admin.conf
    sha256sum /etc/sw-split-admin.conf /opt/sw-split-lab/runtime /opt/sw-split-lab/optional > before.sha256
    stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-split-admin.conf /opt/sw-split-lab/runtime /opt/sw-split-lab/optional > before.metadata
    sha256sum /etc/sw-split-admin.conf /opt/sw-split-lab/optional > sentinels.sha256
    stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-split-admin.conf /opt/sw-split-lab/optional > sentinels.metadata
    case "$case_name" in
        compatibility-admin)
            case "$format" in
                deb) apt-mark manual sw-lab-optional ;;
                rpm)
                    if [ "$dnf_generation" = 5 ]; then dnf_cmd -y mark user sw-lab-optional; else dnf_cmd mark install sw-lab-optional; fi
                    ;;
                apk) apk_cmd add sw-lab-optional ;;
            esac
            ;;
        compatibility-held) apt-mark hold sw-lab-optional ;;
        compatibility-pinned) apk_cmd add 'sw-lab-optional=1.0.0' ;;
        compatibility-tagged)
            printf '@local /tmp/sw-split-lab/repo\n' > repositories
            apk_cmd --allow-untrusted add 'sw-lab-optional@local=1.0.0'
            ;;
        compatibility-group)
            if [ "$dnf_generation" = 5 ]; then
                dnf --no-plugins --disable-repo='*' --repofrompath=swlab,file:///tmp/sw-split-lab/group-repo --enable-repo=swlab --nogpgcheck -y group install sw-lab-group
                dnf_cmd -y mark group sw-lab-group sw-lab-optional
            else
                dnf_cmd mark group sw-lab-optional
            fi
            ;;
    esac
    assert_expected_selection
    reason > reason.before
    owner /opt/sw-split-lab/runtime > owner.before
    test "$(cat owner.before)" = sw-lab-syswarden
}
owner() {
    case "$format" in
        deb) dpkg-query -S "$1" 2>/dev/null | sed 's/: .*//' ;;
        rpm) rpm -qf --queryformat '%{NAME}\n' "$1" 2>/dev/null ;;
        apk) apk_cmd info --who-owns "$1" 2>/dev/null | sed -n 's/^.* is owned by \(sw-lab-[a-z-]*\)-[0-9].*/\1/p' ;;
    esac
}
assert_sentinels() {
    installed sw-lab-optional
    sha256sum -c sentinels.sha256
    stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-split-admin.conf /opt/sw-split-lab/optional > sentinels.now
    same_bytes sentinels.metadata sentinels.now
    # The consumer reads the preserved configuration after every transaction.
    test "$(sed -n 's/^effective_fixture_policy=//p' /etc/sw-split-admin.conf)" = preserve
    reason > reason.after
    same_bytes reason.before reason.after
    assert_expected_selection
}
cleanup_unrelated() {
    case "$format" in
        deb) apt_cmd autoremove -y ;;
        rpm) dnf_cmd autoremove -y ;;
        # APK solves orphan removal during del; it has no separate autoremove.
        # The tagged local index is unsigned, like every inert fixture here.
        apk) apk_cmd --allow-untrusted del sw-lab-unrelated-root ;;
    esac
    assert_absent sw-lab-unrelated
    test ! -e /opt/sw-split-lab/unrelated
    unrelated_cleanup=verified
    assert_sentinels
}
observe_payload() {
    if [ -L "$1" ]; then printf '%s\n' unsafe
    elif [ ! -e "$1" ]; then printf '%s\n' absent
    elif [ -f "$1" ] && [ "$(cat "$1")" = "$2" ]; then printf '%s\n' intact
    else printf '%s\n' changed
    fi
}
observe_registration() {
    value=$(registered_version "$1" || true)
    case "$value" in
        1.0.0|2.0.0|3.0.0|4.0.0) printf '%s\n' "$value" ;;
        ''|"package $1 is not installed") printf '%s\n' absent ;;
        *) printf '%s\n' ambiguous ;;
    esac
}
observe_owner() {
    if [ ! -e /opt/sw-split-lab/runtime ]; then printf '%s\n' absent; return; fi
    value=$(owner /opt/sw-split-lab/runtime || true)
    case "$value" in
        sw-lab-syswarden) printf '%s\n' legacy ;;
        sw-lab-base) printf '%s\n' base ;;
        *) printf '%s\n' ambiguous ;;
    esac
}
for package in sw-lab-syswarden sw-lab-base sw-lab-optional sw-lab-unrelated sw-lab-unrelated-root; do
    assert_absent "$package"
done
test ! -e /opt/sw-split-lab && test ! -L /opt/sw-split-lab
test ! -e /etc/sw-split-admin.conf && test ! -L /etc/sw-split-admin.conf
case "$case_name" in
    fresh-base)
        install_files "./base-disjoint-2.0.0.$format"
        installed sw-lab-base
        assert_absent sw-lab-syswarden
        assert_absent sw-lab-optional
        test ! -e /opt/sw-split-lab/optional
        test ! -e /opt/sw-split-lab/runtime
        test "$(cat /opt/sw-split-lab/base-runtime)" = base-runtime-2.0.0
        test "$(owner /opt/sw-split-lab/base-runtime)" = sw-lab-base
        printf 'SW_SPLIT_RESULT optional_present=0\nSW_SPLIT_RESULT sentinels=not-applicable\n'
        ;;
    *)
        install_legacy
        case "$case_name" in
            compatibility-*)
                install_files "./base-disjoint-2.0.0.$format" "./compatibility-2.0.0.$format"
                installed sw-lab-syswarden
                installed sw-lab-base
                test "$(registered_version sw-lab-syswarden)" = 2.0.0
                test ! -e /opt/sw-split-lab/runtime
                test "$(cat /opt/sw-split-lab/base-runtime)" = base-runtime-2.0.0
                test "$(owner /opt/sw-split-lab/base-runtime)" = sw-lab-base
                assert_sentinels
                cleanup_unrelated
                ;;
            solver-refusal)
                if install_files "./base-disjoint-2.0.0.$format" "./solver-refused-3.0.0.$format"; then exit 1; else transaction_exit=$?; fi
                sha256sum -c before.sha256
                stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-split-admin.conf /opt/sw-split-lab/runtime /opt/sw-split-lab/optional > after.metadata
                same_bytes before.metadata after.metadata
                test "$(registered_version sw-lab-syswarden)" = 1.0.0
                installed sw-lab-syswarden
                installed sw-lab-unrelated
                assert_absent sw-lab-base
                test ! -e /opt/sw-split-lab/base-runtime
                owner /opt/sw-split-lab/runtime > owner.after
                same_bytes owner.before owner.after
                ;;
            shared-handoff)
                if install_files "./base-shared-2.0.0.$format" "./compatibility-2.0.0.$format"; then :; else transaction_exit=$?; fi
                ;;
            unprepared-shared-base)
                if install_files "./base-shared-2.0.0.$format"; then :; else transaction_exit=$?; fi
                ;;
            script-refusal)
                if install_files "./base-disjoint-2.0.0.$format" "./script-refused-4.0.0.$format"; then :; else transaction_exit=$?; fi
                test -f /tmp/sw-split-refusal-ran
                script_refusal=1
                ;;
            *) exit 64 ;;
        esac
        assert_sentinels
        if sha256sum -c before.sha256 > /tmp/sw-split-old-check 2>&1 &&
           stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-split-admin.conf /opt/sw-split-lab/runtime /opt/sw-split-lab/optional > old.now &&
           same_bytes before.metadata old.now; then legacy_unchanged=1; fi
        printf 'SW_SPLIT_RESULT optional_present=1\nSW_SPLIT_RESULT sentinels=preserved\n'
        ;;
esac
printf 'SW_SPLIT_RESULT transaction_exit=%s\n' "$transaction_exit"
printf 'SW_SPLIT_RESULT product_version=%s\n' "$(observe_registration sw-lab-syswarden)"
printf 'SW_SPLIT_RESULT base_version=%s\n' "$(observe_registration sw-lab-base)"
printf 'SW_SPLIT_RESULT legacy_payload=%s\n' "$(observe_payload /opt/sw-split-lab/runtime legacy-runtime-1.0.0)"
printf 'SW_SPLIT_RESULT shared_base_payload=%s\n' "$(observe_payload /opt/sw-split-lab/runtime base-runtime-2.0.0)"
printf 'SW_SPLIT_RESULT disjoint_base_payload=%s\n' "$(observe_payload /opt/sw-split-lab/base-runtime base-runtime-2.0.0)"
printf 'SW_SPLIT_RESULT runtime_owner=%s\n' "$(observe_owner)"
printf 'SW_SPLIT_RESULT unrelated_cleanup=%s\n' "$unrelated_cleanup"
printf 'SW_SPLIT_RESULT script_refusal=%s\n' "$script_refusal"
printf 'SW_SPLIT_RESULT legacy_unchanged=%s\n' "$legacy_unchanged"
printf 'SW_SPLIT_COMPLETE=%s\n' "$case_name"
'''


def cases_for(format_name: str) -> tuple[str, ...]:
    if format_name not in EXTRA_CASES:
        raise ValueError("supported native format required")
    return QUALIFICATION_CASES + EXTRA_CASES[format_name] + CHARACTERIZATION_CASES


def sandbox_command(podman: str, image: str, format_name: str, case: str, identity: ContainerIdentity) -> list[str]:
    if re.fullmatch(r"[0-9a-f]{64}", image) is None or case not in cases_for(format_name):
        raise ValueError("exact image identity and supported case required")
    validate_container(identity)
    # Preserve the CID file until explicit ownership-checked cleanup completes.
    # Podman's automatic removal also deletes that evidence before we read it.
    return podman_command(podman, "run", "--name", identity.name, "--label", OWNER_LABEL + "=" + identity.token,
            "--cidfile", str(identity.cidfile), "--image-volume=ignore", "--pull", "never", "--network", "none", "--cap-drop", "all",
            "--cap-add", "SYS_CHROOT", "--security-opt", "no-new-privileges", "--cpus", "2",
            "--memory", "512m", "--pids-limit", "64", "--timeout", "90", "--entrypoint", "/bin/sh",
            "-i", image, "-c", 'umask 077; mkdir /tmp/sw-split-lab && tar --no-same-owner -xf - -C /tmp/sw-split-lab && /bin/sh /tmp/sw-split-lab/cases.sh "$1" "$2"',
            "probe", format_name, case)


def requirement(name: str, version: str, format_name: str) -> str:
    return {"deb": f"{name} (= {version})", "rpm": f"{name} = {version}",
            "apk": f"{name}={version}"}[format_name]


def fixture_specs(root: Path, format_name: str) -> list[tuple[str, dict]]:
    cases_for(format_name)
    hook = root / "refuse.sh"
    hook.write_text('#!/bin/sh\nprintf "fixture refusal\\n" > /tmp/sw-split-refusal-ran\nexit 42\n')
    hook.chmod(0o700)
    roles = (("optional", "1.0.0", "sw-lab-optional", "optional", "optional-1.0.0"),
             ("unrelated", "1.0.0", "sw-lab-unrelated", "unrelated", "unrelated-1.0.0"),
             ("unrelated-root", "1.0.0", "sw-lab-unrelated-root", "unrelated-root", "unrelated-root-1.0.0"),
             ("legacy", "1.0.0", "sw-lab-syswarden", "runtime", "legacy-runtime-1.0.0"),
             ("base-disjoint", "2.0.0", "sw-lab-base", "base-runtime", "base-runtime-2.0.0"),
             ("base-shared", "2.0.0", "sw-lab-base", "runtime", "base-runtime-2.0.0"),
             ("compatibility", "2.0.0", "sw-lab-syswarden", "compatibility", "compatibility-2.0.0"),
             ("solver-refused", "3.0.0", "sw-lab-syswarden", "compatibility", "compatibility-3.0.0"),
             ("script-refused", "4.0.0", "sw-lab-syswarden", "compatibility", "compatibility-4.0.0"))
    specs = []
    for role, version, name, destination, content in roles:
        stem = f"{role}-{version}"
        payload = root / f"{stem}.txt"
        payload.write_text(content + "\n")
        spec = {"name": name, "arch": "amd64", "platform": "linux", "version": version,
                "maintainer": "SysWarden fixture laboratory", "license": "MIT",
                "description": "Inert native package identity split fixture",
                "contents": [{"src": str(payload), "dst": "/opt/sw-split-lab/" + destination}]}
        if role == "legacy":
            spec["depends"] = ["sw-lab-optional"]
        elif role == "unrelated-root":
            spec["depends"] = ["sw-lab-unrelated"]
        elif role in ("compatibility", "solver-refused", "script-refused"):
            spec["depends"] = [requirement("sw-lab-base", "2.0.0", format_name), "sw-lab-optional"]
        if role == "solver-refused":
            spec["depends"].append(requirement("sw-lab-unavailable", "1.0.0", format_name))
        if role == "script-refused":
            if format_name == "apk":
                spec["apk"] = {"scripts": {"preupgrade": str(hook)}}
            else:
                spec["scripts"] = {"preinstall": str(hook)}
        # Deliberately no Conflicts/Replaces/Obsoletes or force-overwrite flags.
        # The shared-payload cases observe native behavior without authorizing
        # automatic deletion of the legacy dependency root.
        specs.append((stem, spec))
    return specs


def fixtures(root: Path, nfpm: Path, format_name: str) -> bytes:
    package_paths = []
    for stem, spec in fixture_specs(root, format_name):
        config = root / f"{stem}.json"
        config.write_text(json.dumps(spec, indent=2) + "\n")
        package = root / f"{stem}.{format_name}"
        result = native.command([str(nfpm), "pkg", "--config", str(config), "--packager", format_name,
                                 "--target", str(package)])
        (root / f"{stem}.build.log").write_bytes(result.stdout)
        if result.returncode:
            raise RuntimeError("fixture build failed: " + stem)
        if not package.is_file():
            raise RuntimeError("fixture builder omitted package: " + stem)
        package_paths.append(package)
    script = root / "cases.sh"
    script.write_text(SCRIPT)
    group_paths = native.group_repository(root, "sw-lab-optional") if format_name == "rpm" else []
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in [*package_paths, script, *group_paths]:
            archive.add(path, arcname=str(path.relative_to(root)))
    return stream.getvalue()


FIELDS = {
    "optional_present": {"0", "1"}, "sentinels": {"preserved", "not-applicable"},
    "product_version": {"absent", "ambiguous", "1.0.0", "2.0.0", "3.0.0", "4.0.0"},
    "base_version": {"absent", "ambiguous", "2.0.0"},
    "legacy_payload": {"intact", "absent", "changed", "unsafe"},
    "shared_base_payload": {"intact", "absent", "changed", "unsafe"},
    "disjoint_base_payload": {"intact", "absent", "changed", "unsafe"},
    "runtime_owner": {"legacy", "base", "absent", "ambiguous"},
    "unrelated_cleanup": {"verified", "not-run"}, "script_refusal": {"0", "1"},
    "legacy_unchanged": {"0", "1"},
}


def observations(case: str, output: bytes, exit_status: int) -> dict:
    if case not in ALL_CASES:
        raise ValueError("unsupported split case")
    completion = f"SW_SPLIT_COMPLETE={case}\n".encode()
    if exit_status != 0 or output.count(b"SW_SPLIT_COMPLETE=") != 1 or not output.endswith(completion):
        raise ValueError("native case did not complete exactly once")
    record = {}
    for line in output.decode("utf-8", errors="strict").splitlines():
        if not line.startswith("SW_SPLIT_RESULT "):
            continue
        key, separator, value = line.removeprefix("SW_SPLIT_RESULT ").partition("=")
        if not separator or key in record or key not in {*FIELDS, "transaction_exit"}:
            raise ValueError("duplicate or unsupported native observation")
        if key == "transaction_exit":
            if not re.fullmatch(r"0|[1-9][0-9]{0,2}", value) or int(value) > 255:
                raise ValueError("invalid transaction exit")
        elif value not in FIELDS[key]:
            raise ValueError("invalid native observation value")
        record[key] = value
    if set(record) != {*FIELDS, "transaction_exit"}:
        raise ValueError("incomplete native observations")
    fresh = case == "fresh-base"
    if record["optional_present"] != ("0" if fresh else "1") or record["sentinels"] != ("not-applicable" if fresh else "preserved"):
        raise ValueError("dependency or administrator sentinel preservation failed")
    qualified = case not in CHARACTERIZATION_CASES
    if qualified:
        expected = {"script_refusal": "0", "legacy_unchanged": "0", "shared_base_payload": "absent", "legacy_payload": "absent",
                    "base_version": "2.0.0", "disjoint_base_payload": "intact", "runtime_owner": "absent",
                    "product_version": "absent" if fresh else "2.0.0",
                    "unrelated_cleanup": "not-run" if fresh else "verified", "transaction_exit": "0"}
        if case == "solver-refusal":
            expected.update(legacy_payload="intact", shared_base_payload="changed", base_version="absent",
                            disjoint_base_payload="absent", runtime_owner="legacy", product_version="1.0.0",
                            unrelated_cleanup="not-run", legacy_unchanged="1")
            expected.pop("transaction_exit")
            if record["transaction_exit"] == "0":
                raise ValueError("solver refusal unexpectedly succeeded")
        if any(record[key] != value for key, value in expected.items()):
            raise ValueError("qualification state does not match the required outcome")
        outcome = "qualified-disjoint-transition" if not fresh and case != "solver-refusal" else case
    else:
        if record["script_refusal"] != ("1" if case == "script-refusal" else "0"):
            raise ValueError("script refusal observation missing or unexpected")
        old_preserved = (record["product_version"] == "1.0.0" and record["legacy_payload"] == "intact"
                         and record["runtime_owner"] == "legacy" and record["legacy_unchanged"] == "1")
        if old_preserved:
            outcome = "old-payload-preserved" if record["base_version"] == "absent" else "partial-registration-old-payload-preserved"
        elif (case == "shared-handoff" and record["transaction_exit"] == "0" and record["product_version"] == "2.0.0"
              and record["base_version"] == "2.0.0" and record["shared_base_payload"] == "intact" and record["runtime_owner"] == "base"):
            outcome = "shared-handoff-observed"
        else:
            outcome = "partial-or-unsafe-transition"
    return {"kind": "qualification" if qualified else "characterization", "observations": record,
            "outcome": outcome, "observation_complete": True,
            "synthetic_contract_passed": qualified, "product_accepted": False}


def run(nfpm: Path, image: str, format_name: str, output: Path, cases: tuple[str, ...] | None = None) -> None:
    if os.geteuid() == 0:
        raise ValueError("run this laboratory as an unprivileged user")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("existing absolute executable nfpm required")
    if not output.is_absolute() or output.exists():
        raise ValueError("new absolute output directory required")
    podman = shutil.which("podman")
    if not podman:
        raise ValueError("rootless podman required")
    available = cases_for(format_name)
    selected = available if cases is None else cases
    if not selected or len(set(selected)) != len(selected) or any(case not in available for case in selected):
        raise ValueError("distinct supported cases for the selected format required")
    if re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("exact image identity required")
    rootless = execute_local(podman_command(podman, "info", "--format", "{{.Host.Security.Rootless}}"))
    if rootless.returncode or rootless.stdout.strip() != b"true":
        raise ValueError("rootless isolation required")
    inspection = execute_local(podman_command(podman, "image", "inspect", image))
    if inspection.returncode:
        raise ValueError("exact image must already be present")
    entries = json.loads(inspection.stdout)
    if len(entries) != 1:
        raise ValueError("one exact Linux AMD64 image required")
    info = entries[0]
    if info["Os"] != "linux" or info["Architecture"] != "amd64" or info["Id"].removeprefix("sha256:") != image:
        raise ValueError("exact Linux AMD64 image required")
    output.mkdir(mode=0o700)
    (output / "image.json").write_bytes(inspection.stdout)
    summary = {"schema": "syswarden-native-dependency-split-probe/v2", "image": image,
               "format": format_name, "architecture": "amd64", "synthetic_only": True,
               "product_accepted": False, "shared_payload_qualified": False,
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(),
               "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "requested_cases": list(selected), "cases": {}}
    payload = fixtures(output, nfpm, format_name)
    failures = []
    for case in selected:
        result, ownership = run_container(podman, image, format_name, case, output, payload)
        (output / f"{case}.log").write_bytes(result.stdout)
        try:
            record = observations(case, result.stdout, result.returncode)
        except (ValueError, UnicodeError) as error:
            failures.append(case)
            record = {"observation_complete": False, "synthetic_contract_passed": False,
                      "product_accepted": False, "error": str(error)}
        record["process_exit"] = result.returncode
        record["container"] = ownership
        if not ownership["cleanup"]["verified"]:
            if case not in failures:
                failures.append(case)
            record["synthetic_contract_passed"] = False
            record["error"] = "container cleanup unresolved; qualification refused"
        summary["cases"][case] = record
        (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
        status = record.get("outcome", "failed-observation") if ownership["cleanup"]["verified"] else "cleanup-unresolved"
        print(f"{case}: {status}", flush=True)
        if not ownership["cleanup"]["verified"]:
            break
    summary["selected_observations_complete"] = not failures
    required = set(QUALIFICATION_CASES + EXTRA_CASES[format_name])
    summary["synthetic_disjoint_contract_passed"] = required.issubset(summary["cases"]) and all(
        summary["cases"][case]["synthetic_contract_passed"] for case in required if case in summary["cases"])
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    if failures:
        raise RuntimeError("native split laboratory failed: " + ", ".join(failures))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--nfpm", type=Path, required=True)
    parser.add_argument("--image", required=True, help="existing exact 64-character Linux AMD64 image ID")
    parser.add_argument("--format", choices=("deb", "rpm", "apk"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=ALL_CASES, action="append",
                        help="run only these cases, in order; a subset cannot claim the complete synthetic contract")
    args = parser.parse_args()
    run(args.nfpm, args.image, args.format, args.output, None if args.case is None else tuple(args.case))
