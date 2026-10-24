#!/usr/bin/env python3
"""Opt-in inert DEB/RPM dependency transitions in disposable rootless containers.

This laboratory is not SysWarden lifecycle acceptance. Only synthetic local RPM
fixtures permit --nogpgcheck; no product updater command accepts that option.
Existing exact Linux AMD64 images are required. No network or host mounts are used.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

CASES = ("fresh", "default-upgrade", "guarded-upgrade", "retained-upgrade",
         "refused-upgrade", "guarded-conflict", "retained-remove", "retained-purge",
         "single-transaction")
NATIVE_CASES = ("native-upgrade", "native-failure", "native-remove", "native-purge",
                "native-admin-reason", "native-group-reason", "native-held-dependency", "native-minimal")

SCRIPT = r'''#!/bin/sh
set -eu
cd /tmp/sw-native-lab
format=$1
case_name=$2
test "$(uname -m)" = x86_64
dnf_generation=4
if [ "$format" = rpm ]; then
    version=$(dnf --noplugins --version)
    case "$version" in 'dnf5 version 5.'*) dnf_generation=5 ;; 4.*) ;; *) exit 1 ;; esac
fi
apt_cmd() { apt-get -o APT::Sandbox::User=root -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=- -o Acquire::Retries=0 -o Dpkg::Use-Pty=0 "$@"; }
dnf_cmd() { dnf --noplugins --cacheonly --disablerepo='*' --setopt=localpkg_gpgcheck=0 --nogpgcheck "$@"; }
dnf_automatic() {
    if [ "$dnf_generation" = 5 ]; then dnf_cmd -y mark dependency "$1"; else dnf_cmd mark remove "$1"; fi
}
dnf_group() {
    if [ "$dnf_generation" = 5 ]; then
        # The group is created through DNF itself from an inert local repository.
        # The container has no network and the repository has no packages.
        dnf --no-plugins --disable-repo='*' --repofrompath=swlab,file:///tmp/sw-native-lab/group-repo --enable-repo=swlab --nogpgcheck -y group install sw-lab-group
        dnf_cmd -y mark group sw-lab-group sw-lab-optional
    else
        dnf_cmd mark group sw-lab-optional
    fi
}
query_optional() {
    if [ "$format" = deb ]; then
        dpkg-query -W -f='${db:Status-Abbrev}\n' sw-lab-optional 2>/dev/null | grep -Eq '^[ih]i $'
    else
        rpm -q --quiet sw-lab-optional
    fi
}
assert_retained() {
    query_optional
    sha256sum -c /tmp/retained.sha256
    stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-lab-admin.conf /opt/sw-native-lab/optional > /tmp/now.metadata
    test "$(cat /tmp/retained.metadata)" = "$(cat /tmp/now.metadata)"
}
install_legacy() {
    if [ "$format" = deb ]; then
        apt_cmd install -y ./optional-1.0.0.deb ./model-1.0.0.deb
        apt-mark auto sw-lab-optional
        test "$(apt-mark showauto sw-lab-optional)" = sw-lab-optional
    else
        dnf_cmd install -y ./optional-1.0.0.rpm ./model-1.0.0.rpm
        dnf_automatic sw-lab-optional
        test -z "$(dnf_cmd -q repoquery --userinstalled --qf '%{name}' sw-lab-optional)"
    fi
    query_optional
    printf 'administrator-owned configuration\n' > /etc/sw-lab-admin.conf
    chmod 600 /etc/sw-lab-admin.conf
    sha256sum /etc/sw-lab-admin.conf /opt/sw-native-lab/optional > /tmp/retained.sha256
    stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-lab-admin.conf /opt/sw-native-lab/optional > /tmp/retained.metadata
}
retain_optional() {
    if [ "$format" = deb ]; then
        apt-mark manual sw-lab-optional
    else
        if [ "$dnf_generation" = 5 ]; then dnf_cmd -y mark user sw-lab-optional; else dnf_cmd mark install sw-lab-optional; fi
    fi
}
upgrade() {
    version=$1
    shift
    if [ "$format" = deb ]; then
        apt_cmd --no-install-recommends --no-remove install -y "./model-$version.deb" "$@"
    else
        dnf_cmd --setopt=install_weak_deps=False --setopt=clean_requirements_on_remove=False --setopt=obsoletes=False install -y "./model-$version.rpm" "$@"
    fi
}
if [ "$format" = deb ]; then apt-get --version; else dnf --version; fi
case "$case_name" in
    native-*)
        test -x ./retention.test
        if [ "$case_name" = native-minimal ]; then
            upgrade 2.0.0
        else
            install_legacy
        fi
        # This independently installed optional name is deliberately absent
        # from the model's Depends/Requires and must keep its automatic reason.
        if [ "$format" = deb ]; then
            apt_cmd install -y ./independent-1.0.0.deb
            apt-mark auto wireguard-tools
            manager=/usr/bin/apt-get
        else
            dnf_cmd install -y ./independent-1.0.0.rpm
            dnf_automatic wireguard-tools
            manager=/usr/bin/dnf
        fi
        case "$case_name" in
            native-admin-reason) retain_optional ;;
            native-group-reason) dnf_group ;;
            native-held-dependency) apt-mark hold sw-lab-optional ;;
        esac
        if [ "$case_name" = native-group-reason ]; then
            if [ "$dnf_generation" = 5 ]; then
                sha256sum /usr/lib/sysimage/libdnf5/*.toml /usr/lib/sysimage/libdnf5/comps_groups/groups/sw-lab-group.xml > /tmp/reasons-before.sha256
            else
                sha256sum /var/lib/dnf/history.sqlite > /tmp/reasons-before.sha256
            fi
        fi
        if [ "$case_name" = native-upgrade ] && [ "$format" = rpm ] && [ "$dnf_generation" = 5 ]; then
            dnf_cmd -y mark weak sw-lab-optional
            test "$(dnf_cmd -q repoquery --installed --qf '%{reason}' sw-lab-optional)" = 'Weak Dependency'
        fi
        expected_writes=1
        case "$case_name" in native-admin-reason|native-group-reason|native-minimal) expected_writes=0 ;; esac
        SYSWARDEN_NATIVE_RETENTION_WRITES="$expected_writes" SYSWARDEN_NATIVE_RETENTION_TEST=1 SYSWARDEN_NATIVE_RETENTION_MANAGER="$manager" \
            ./retention.test -test.run '^TestNativeDependencyRetentionOracle$' -test.v
        if [ "$case_name" = native-group-reason ]; then
            sha256sum -c /tmp/reasons-before.sha256
        fi
        if [ "$format" = deb ]; then
            test "$(apt-mark showauto wireguard-tools)" = wireguard-tools
        else
            test -z "$(dnf_cmd -q repoquery --userinstalled --qf '%{name}' wireguard-tools)"
        fi
        if [ "$case_name" = native-minimal ]; then
            if query_optional; then exit 1; fi
            test ! -e /opt/sw-native-lab/optional
        else
            assert_retained
            if [ "$case_name" = native-failure ]; then
                if upgrade 3.0.0; then exit 1; fi
                test "$(cat /opt/sw-native-lab/model)" = model-1.0.0
            else
                upgrade 2.0.0
            fi
            case "$case_name" in
                native-remove|native-purge)
                    if [ "$format" = deb ]; then
                        if [ "$case_name" = native-remove ]; then apt_cmd remove -y sw-lab-model; else apt_cmd purge -y sw-lab-model; fi
                    else
                        dnf_cmd remove -y sw-lab-model
                    fi
                    test ! -e /opt/sw-native-lab/model
                    ;;
            esac
            assert_retained
            if [ "$format" = deb ]; then
                test -z "$(apt-mark showauto sw-lab-optional)"
                if [ "$case_name" = native-held-dependency ]; then
                    test "$(apt-mark showhold sw-lab-optional)" = sw-lab-optional
                fi
            else
                expected_reason=user
                if [ "$case_name" = native-group-reason ]; then expected_reason=group; fi
                if [ "$dnf_generation" = 5 ]; then
                    expected_reason=User
                    if [ "$case_name" = native-group-reason ]; then expected_reason=Group; fi
                fi
                test "$(dnf_cmd -q repoquery --installed --qf '%{reason}' sw-lab-optional)" = "$expected_reason"
            fi
        fi
        printf 'CASE_PASS=%s\n' "$case_name"
        exit 0
        ;;
esac
if [ "$case_name" = fresh ]; then
    upgrade 2.0.0
    if query_optional; then exit 1; fi
    test ! -e /opt/sw-native-lab/optional
    test "$(cat /opt/sw-native-lab/model)" = model-2.0.0
else
    install_legacy
    case "$case_name" in
        retained-*) retain_optional ;;
    esac
    case "$case_name" in
        single-transaction) upgrade 2.0.0 sw-lab-optional ;;
        default-upgrade)
            if [ "$format" = deb ]; then apt_cmd install -y ./model-2.0.0.deb; else dnf_cmd install -y ./model-2.0.0.rpm; fi
            ;;
        refused-upgrade)
            if upgrade 3.0.0; then exit 1; fi
            test -f /tmp/sw-lab-preinstall-ran
            test "$(cat /opt/sw-native-lab/model)" = model-1.0.0
            assert_retained
            ;;
        guarded-conflict)
            if upgrade 4.0.0; then exit 1; fi
            test "$(cat /opt/sw-native-lab/model)" = model-1.0.0
            assert_retained
            ;;
        *) upgrade 2.0.0 ;;
    esac
    if [ "$case_name" != refused-upgrade ] && [ "$case_name" != guarded-conflict ]; then
        test "$(cat /opt/sw-native-lab/model)" = model-2.0.0
    fi
    # Record actual native behavior, including whether an old dependency was
    # dropped or became eligible for later autoremove. Never infer rollback.
    if query_optional; then
        assert_retained
        printf 'OPTIONAL_PRESENT=1\n'
        if [ "$format" = deb ]; then
            apt_cmd --simulate autoremove > /tmp/unneeded
            if grep -q '^Remv sw-lab-optional ' /tmp/unneeded; then printf 'OPTIONAL_UNNEEDED=1\n'; else printf 'OPTIONAL_UNNEEDED=0\n'; fi
        else
            dnf_cmd -q repoquery --unneeded --qf '%{name}' sw-lab-optional > /tmp/unneeded
            if grep -qx sw-lab-optional /tmp/unneeded; then printf 'OPTIONAL_UNNEEDED=1\n'; else printf 'OPTIONAL_UNNEEDED=0\n'; fi
        fi
    else
        test ! -e /opt/sw-native-lab/optional
        printf 'OPTIONAL_PRESENT=0\n'
    fi
    case "$case_name" in
        retained-*)
            assert_retained
            if grep -q sw-lab-optional /tmp/unneeded; then exit 1; fi
            ;;
    esac
    case "$case_name" in
        retained-remove|retained-purge)
            if [ "$format" = deb ]; then
                if [ "$case_name" = retained-remove ]; then apt_cmd remove -y sw-lab-model; else apt_cmd purge -y sw-lab-model; fi
            else
                # RPM has no separate purge command; record native erase only.
                dnf_cmd remove -y sw-lab-model
            fi
            test ! -e /opt/sw-native-lab/model
            assert_retained
            ;;
    esac
fi
printf 'CASE_PASS=%s\n' "$case_name"
'''


def command(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=100, check=False, **kwargs)


def sandbox_command(podman: str, image: str, format_name: str, case: str) -> list[str]:
    if re.fullmatch(r"[0-9a-f]{64}", image) is None or format_name not in ("deb", "rpm") or case not in CASES + NATIVE_CASES:
        raise ValueError("exact image, supported format and fixed case are required")
    return [podman, "run", "--rm", "--pull", "never", "--network", "none",
            "--cap-drop", "all", "--cap-add", "SYS_CHROOT", "--security-opt", "no-new-privileges",
            "--cpus", "2", "--memory", "512m", "--pids-limit", "64", "--timeout", "90",
            "--entrypoint", "/bin/sh", "-i", image, "-c",
            'umask 077; mkdir /tmp/sw-native-lab && tar --no-same-owner -xf - -C /tmp/sw-native-lab && /bin/sh /tmp/sw-native-lab/cases.sh "$1" "$2"',
            "probe", format_name, case]


def group_repository(root: Path, package: str) -> list[Path]:
    if package not in ("rsyslog", "sw-lab-optional"):
        raise ValueError("fixed inert group package required")
    directory = root / "group-repo" / "repodata"
    directory.mkdir(parents=True)
    documents = {
        "primary": b'<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" packages="0"></metadata>',
        "group": ('<?xml version="1.0"?><comps><group><id>sw-lab-group</id><name>Fixture group</name>'
                  '<description>Inert dependency fixture</description><default>false</default><uservisible>true</uservisible>'
                  '<packagelist><packagereq type="mandatory">' + package + '</packagereq></packagelist></group></comps>').encode(),
    }
    records = []
    paths = []
    for kind, raw in documents.items():
        packed = gzip.compress(raw, mtime=0)
        path = directory / (kind + ".xml.gz")
        path.write_bytes(packed)
        paths.append(path)
        records.append(f'<data type="{kind}"><checksum type="sha256">{hashlib.sha256(packed).hexdigest()}</checksum>'
                       f'<open-checksum type="sha256">{hashlib.sha256(raw).hexdigest()}</open-checksum>'
                       f'<location href="repodata/{path.name}"/><timestamp>1</timestamp><size>{len(packed)}</size>'
                       f'<open-size>{len(raw)}</open-size></data>')
    manifest = directory / "repomd.xml"
    manifest.write_text('<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>'
                        + ''.join(records) + '</repomd>')
    return paths + [manifest]


def fixtures(root: Path, nfpm: Path, format_name: str, retention_test: Path | None = None) -> bytes:
    hook = root / "refuse.sh"
    hook.write_text("#!/bin/sh\nprintf 'fixture refusal\\n' > /tmp/sw-lab-preinstall-ran\nexit 42\n")
    hook.chmod(0o700)
    for role, version in (("independent", "1.0.0"), ("optional", "1.0.0"), ("model", "1.0.0"), ("model", "2.0.0"), ("model", "3.0.0"), ("model", "4.0.0")):
        stem = f"{role}-{version}"
        payload = root / f"{stem}.txt"
        payload.write_text(stem + "\n")
        spec = {"name": "sw-lab-" + role, "arch": "amd64", "platform": "linux", "version": version,
                "maintainer": "SysWarden fixture laboratory", "description": "Inert dependency transition fixture",
                "license": "MIT", "contents": [{"src": str(payload), "dst": "/opt/sw-native-lab/" + role}]}
        if role == "model" and version == "1.0.0": spec["depends"] = ["sw-lab-optional"]
        if version == "3.0.0": spec["scripts"] = {"preinstall": str(hook)}
        if version == "4.0.0": spec["conflicts"] = ["sw-lab-optional"]
        if retention_test is not None:
            spec["name"] = {"independent": "wireguard-tools", "optional": "rsyslog", "model": "syswarden"}[role]
            if "depends" in spec: spec["depends"] = ["rsyslog"]
            if "conflicts" in spec: spec["conflicts"] = ["rsyslog"]
        config = root / f"{stem}.json"
        config.write_text(json.dumps(spec, indent=2) + "\n")
        built = command([str(nfpm), "pkg", "--config", str(config), "--packager", format_name,
                         "--target", str(root / f"{stem}.{format_name}")])
        (root / f"{stem}.build.log").write_bytes(built.stdout)
        if built.returncode: raise RuntimeError("fixture build failed: " + stem)
    script = root / "cases.sh"
    script.write_text(SCRIPT if retention_test is None else
                      SCRIPT.replace("sw-lab-optional", "rsyslog").replace("sw-lab-model", "syswarden"))
    group_paths = group_repository(root, "rsyslog" if retention_test is not None else "sw-lab-optional")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in [*sorted(root.glob(f"*.{format_name}")), script]: archive.add(path, arcname=path.name)
        for path in group_paths: archive.add(path, arcname=str(path.relative_to(root)))
        if retention_test is not None: archive.add(retention_test, arcname="retention.test")
    return stream.getvalue()


def run(nfpm: Path, image: str, format_name: str, output: Path, retention_test: Path | None = None) -> None:
    if os.geteuid() == 0: raise ValueError("run this laboratory as an unprivileged user")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("an existing absolute nfpm executable is required")
    if not output.is_absolute() or output.exists(): raise ValueError("a new absolute output directory is required")
    if retention_test is not None and (not retention_test.is_absolute() or
            not retention_test.is_file() or not os.access(retention_test, os.X_OK)):
        raise ValueError("existing absolute executable retention test required")
    podman = shutil.which("podman")
    if not podman: raise ValueError("rootless podman is required")
    sandbox_command(podman, image, format_name, CASES[0])
    rootless = command([podman, "info", "--format", "{{.Host.Security.Rootless}}"])
    if rootless.returncode or rootless.stdout.strip() != b"true": raise ValueError("rootless isolation is required")
    inspection = command([podman, "image", "inspect", image])
    if inspection.returncode: raise ValueError("image must already be present")
    info = json.loads(inspection.stdout)[0]
    if info["Architecture"] != "amd64" or info["Os"] != "linux" or info["Id"].removeprefix("sha256:") != image:
        raise ValueError("exact Linux AMD64 image identity required")
    output.mkdir(mode=0o700)
    (output / "image.json").write_bytes(inspection.stdout)
    summary = {"image": image, "format": format_name, "synthetic_only": True,
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(), "cases": {}}
    if retention_test is not None:
        summary["retention_test_sha256"] = hashlib.sha256(retention_test.read_bytes()).hexdigest()
    payload = fixtures(output, nfpm, format_name, retention_test)
    for case in NATIVE_CASES if retention_test is not None else CASES:
        if format_name == "rpm" and case in ("retained-purge", "native-purge", "native-held-dependency"): continue
        if format_name == "deb" and case == "native-group-reason": continue
        result = command(sandbox_command(podman, image, format_name, case), input=payload)
        (output / f"{case}.log").write_bytes(result.stdout)
        completed = result.returncode == 0 and result.stdout.endswith(f"CASE_PASS={case}\n".encode())
        observations = [line for line in result.stdout.decode(errors="replace").splitlines() if line.startswith("OPTIONAL_")]
        expected = [] if case == "fresh" else ["OPTIONAL_PRESENT=1", "OPTIONAL_UNNEEDED=" +
                   ("1" if case in ("default-upgrade", "guarded-upgrade") or
                    (format_name == "rpm" and case == "single-transaction") else "0")]
        if retention_test is not None:
            expected = []
            manager = "/usr/bin/apt-get" if format_name == "deb" else "/usr/bin/dnf"
            completed = completed and result.stdout.count(("NATIVE_RETENTION_PASS=" + manager + "\n").encode()) == 1
            completed = completed and b"--- SKIP:" not in result.stdout
        passed = completed and observations == expected
        summary["cases"][case] = {"passed": passed, "exit_status": result.returncode, "observations": observations}
        (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"{case}: passed={passed}, observations={observations}", flush=True)
        if not passed: raise RuntimeError("native fixture failed: " + case)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--nfpm", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--format", choices=("deb", "rpm"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--retention-test-binary", type=Path)
    args = parser.parse_args()
    run(args.nfpm, args.image, args.format, args.output, args.retention_test_binary)
