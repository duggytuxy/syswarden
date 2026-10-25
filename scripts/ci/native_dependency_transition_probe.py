#!/usr/bin/env python3
"""Opt-in inert DEB/RPM dependency transitions in disposable rootless containers.

This laboratory is not SysWarden lifecycle acceptance. Only synthetic local RPM
fixtures permit --nogpgcheck; no product updater command accepts that option.
Existing exact Linux AMD64 images are required. No network or host mounts are requested.
Engine-default mounts are not attested; subprocess output has no byte cap.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
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

CASES = ("fresh", "default-upgrade", "guarded-upgrade", "retained-upgrade",
         "refused-upgrade", "guarded-conflict", "retained-remove", "retained-purge",
         "single-transaction")
NATIVE_CASES = ("native-upgrade", "native-failure", "native-remove", "native-purge",
                "native-admin-reason", "native-group-reason", "native-held-dependency", "native-minimal", "native-minimal-upgrade")
PACKAGE_NAMES = ("syswarden", "syswarden-base")
MAX_ORACLE_BYTES = 256 * 1024 * 1024

SCRIPT = r'''#!/bin/sh
set -eu
cd /tmp/sw-native-lab
format=$1
case_name=$2
package_name=$3
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
assert_model() {
    if [ "$format" = deb ]; then
        test "$(dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' sw-lab-model)" = "$(printf 'sw-lab-model\t%s\tamd64\tii \n' "$1")"
        test "$(dpkg-query -S /opt/sw-native-lab/model)" = 'sw-lab-model: /opt/sw-native-lab/model'
    else
        test "$(rpm -q --queryformat '%{NAME}\t%{VERSION}\t%{ARCH}\n' sw-lab-model)" = "$(printf 'sw-lab-model\t%s\tx86_64\n' "$1")"
        test "$(rpm -qf --queryformat '%{NAME}\n' /opt/sw-native-lab/model)" = sw-lab-model
    fi
    test "$(cat /opt/sw-native-lab/model)" = "model-$1"
}
assert_rpm_minimal_unneeded() {
    # Do not rely on a DNF generation adding implicit query-format separators.
    # Request an explicit newline when selecting both unrelated packages.
    dnf_cmd -q repoquery --unneeded --qf '%{name}\n' sw-lab-optional wireguard-tools > "$1"
    if ! grep -qx sw-lab-optional "$1" || ! grep -qx wireguard-tools "$1"; then
        printf 'NATIVE_UNNEEDED_ASSERTION_FAILED: expected both unrelated automatic packages\n' >&2
        sed -n '1,16l' "$1" >&2
        return 1
    fi
}
assert_independent_automatic() {
    if [ "$format" = deb ]; then
        test "$(apt-mark showauto wireguard-tools)" = wireguard-tools
    else
        test -z "$(dnf_cmd -q repoquery --userinstalled --qf '%{name}' wireguard-tools)"
        rpm -q --quiet wireguard-tools
    fi
}
if [ "$format" = deb ]; then apt-get --version; else dnf --version; fi
case "$case_name" in
    native-*)
        test -x ./retention.test
        # A prepared image must not already contain product or fixture state.
        # Refuse instead of replacing an image's unrelated installed packages.
        for package in syswarden syswarden-base rsyslog wireguard-tools; do
            if [ "$format" = deb ]; then
                if dpkg-query -W "$package" >/dev/null 2>&1; then exit 1; fi
            else
                if rpm -q --quiet "$package"; then exit 1; fi
            fi
        done
        for path in /etc/sw-lab-admin.conf /opt/sw-native-lab; do
            test ! -e "$path" && test ! -L "$path"
        done
        if [ "$case_name" = native-minimal-upgrade ]; then
            # Both generations have no optional dependency. The optional package
            # is independently installed, so its reason must not be promoted.
            if [ "$format" = deb ]; then
                apt_cmd install -y ./optional-1.0.0.deb ./minimal-1.0.0.deb
                apt-mark auto sw-lab-optional
            else
                dnf_cmd install -y ./optional-1.0.0.rpm ./minimal-1.0.0.rpm
                dnf_automatic sw-lab-optional
            fi
            assert_model 1.0.0
            printf 'effective_fixture_policy=preserve\n' > /etc/sw-lab-admin.conf
            chmod 600 /etc/sw-lab-admin.conf
            sha256sum /etc/sw-lab-admin.conf /opt/sw-native-lab/optional > /tmp/retained.sha256
            stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-lab-admin.conf /opt/sw-native-lab/optional > /tmp/retained.metadata
        elif [ "$case_name" = native-minimal ]; then
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
        sha256sum /opt/sw-native-lab/independent > /tmp/independent.sha256
        stat -c '%a:%u:%g:%s:%Y:%i' /opt/sw-native-lab/independent > /tmp/independent.metadata
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
        case "$case_name" in native-admin-reason|native-group-reason|native-minimal|native-minimal-upgrade) expected_writes=0 ;; esac
        SYSWARDEN_NATIVE_RETENTION_PACKAGE="$package_name" SYSWARDEN_NATIVE_RETENTION_WRITES="$expected_writes" SYSWARDEN_NATIVE_RETENTION_TEST=1 SYSWARDEN_NATIVE_RETENTION_MANAGER="$manager" \
            ./retention.test -test.run '^TestNativeDependencyRetentionOracle$' -test.v
        if [ "$case_name" = native-group-reason ]; then
            sha256sum -c /tmp/reasons-before.sha256
        fi
        assert_independent_automatic
        if [ "$case_name" = native-minimal-upgrade ]; then
            assert_retained
            upgrade 2.0.0
            assert_model 2.0.0
            assert_retained
            test "$(sed -n 's/^effective_fixture_policy=//p' /etc/sw-lab-admin.conf)" = preserve
            assert_independent_automatic
            sha256sum -c /tmp/independent.sha256
            stat -c '%a:%u:%g:%s:%Y:%i' /opt/sw-native-lab/independent > /tmp/independent.now
            test "$(cat /tmp/independent.metadata)" = "$(cat /tmp/independent.now)"
            if [ "$format" = deb ]; then
                test "$(apt-mark showauto sw-lab-optional)" = sw-lab-optional
                apt_cmd --simulate autoremove > /tmp/unneeded
                grep -q '^Remv sw-lab-optional ' /tmp/unneeded
                grep -q '^Remv wireguard-tools ' /tmp/unneeded
            else
                test -z "$(dnf_cmd -q repoquery --userinstalled --qf '%{name}' sw-lab-optional)"
                assert_rpm_minimal_unneeded /tmp/unneeded
            fi
            printf 'NATIVE_MINIMAL_UPGRADE=%s\n' "$package_name"
        elif [ "$case_name" = native-minimal ]; then
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


def isolation_helpers():
    # The split laboratory imports our fixture builder. Delay the reverse import
    # until both modules are initialized, and reuse its ownership checks intact.
    import native_dependency_split_probe
    return native_dependency_split_probe


def selected_cases(format_name: str, native: bool, package_name: str, case: str | None = None) -> tuple[str, ...]:
    if format_name not in ("deb", "rpm") or package_name not in PACKAGE_NAMES:
        raise ValueError("supported format and exact product package name required")
    if package_name == "syswarden-base" and not native:
        raise ValueError("base selection requires the isolated native retention oracle")
    cases = (("native-minimal-upgrade",) if package_name == "syswarden-base" else
             NATIVE_CASES if native else CASES)
    cases = tuple(item for item in cases if not (
        format_name == "rpm" and item in ("retained-purge", "native-purge", "native-held-dependency") or
        format_name == "deb" and item == "native-group-reason"))
    if case is not None:
        if case not in cases:
            raise ValueError("case is not supported for the selected package, oracle and format")
        return (case,)
    return cases


def sandbox_command(podman: str, image: str, format_name: str, case: str, identity,
                    package_name: str = "syswarden") -> list[str]:
    if re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("exact image identity required")
    selected_cases(format_name, case in NATIVE_CASES, package_name, case)
    helpers = isolation_helpers()
    helpers.validate_container(identity)
    return helpers.podman_command(podman, "run", "--name", identity.name,
            "--label", helpers.OWNER_LABEL + "=" + identity.token, "--cidfile", str(identity.cidfile),
            "--image-volume=ignore", "--pull", "never", "--network", "none",
            "--cap-drop", "all", "--cap-add", "SYS_CHROOT", "--security-opt", "no-new-privileges",
            "--cpus", "2", "--memory", "512m", "--pids-limit", "64", "--timeout", "90",
            "--entrypoint", "/bin/sh", "-i", image, "-c",
            'umask 077; mkdir /tmp/sw-native-lab && tar --no-same-owner -xf - -C /tmp/sw-native-lab && /bin/sh /tmp/sw-native-lab/cases.sh "$1" "$2" "$3"',
            "probe", format_name, case, package_name)


def run_container(podman: str, image: str, format_name: str, case: str, output: Path,
                  payload: bytes, package_name: str = "syswarden") -> tuple[subprocess.CompletedProcess, dict]:
    helpers = isolation_helpers()
    identity = helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + uuid.uuid4().hex,
                                         uuid.uuid4().hex, output / f"{case}.cid")
    arguments = sandbox_command(podman, image, format_name, case, identity, package_name)
    ownership = {"name": identity.name, "owner_label": helpers.OWNER_LABEL, "owner_token": identity.token,
                 "cidfile": identity.cidfile.name, "absent_before": False}
    ownership_path = output / f"{case}.container.json"
    ownership_path.write_text(json.dumps(ownership, indent=2) + "\n")
    attempted = False
    result = subprocess.CompletedProcess([], 125, b"")
    try:
        if identity.cidfile.exists() or identity.cidfile.is_symlink() or helpers.container_exists(podman, identity.name):
            raise ValueError("disposable container identity already exists; no run or cleanup authorized")
        ownership["absent_before"] = True
        ownership_path.write_text(json.dumps(ownership, indent=2) + "\n")
        attempted = True
        result = helpers.execute_local(arguments, timeout=100, input=payload)
    except subprocess.TimeoutExpired as error:
        result = subprocess.CompletedProcess([], 124, error.stdout or b"")
    except (OSError, ValueError) as error:
        ownership["launch_error"] = str(error)
    finally:
        ownership["cleanup"] = helpers.cleanup_container(podman, identity, require_cid=result.returncode == 0) if attempted else {
            "name": identity.name, "verified": False, "removal_attempted": False,
            "error": "container launch refused before ownership acquisition"}
        ownership_path.write_text(json.dumps(ownership, indent=2) + "\n")
    return result, ownership


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


def binary_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


@dataclass(frozen=True)
class RetentionBinarySnapshot:
    path: Path
    identity: tuple[int, ...]
    data: bytes

    def recheck(self) -> None:
        if binary_identity(self.path.lstat()) != self.identity:
            raise ValueError("retention test source identity changed")


def snapshot_retention_binary(path: Path) -> RetentionBinarySnapshot:
    if not path.is_absolute():
        raise ValueError("absolute retention test path required")
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or not metadata.st_mode & 0o111 or not 0 < metadata.st_size <= MAX_ORACLE_BYTES):
        raise ValueError("retention test must be a bounded, singly-linked executable regular file")
    identity = binary_identity(metadata)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if binary_identity(os.fstat(descriptor)) != identity:
            raise ValueError("retention test changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(metadata.st_size + 1)
        if len(data) != metadata.st_size or binary_identity(os.fstat(descriptor)) != identity:
            raise ValueError("retention test changed while reading")
    finally:
        os.close(descriptor)
    snapshot = RetentionBinarySnapshot(path, identity, data)
    snapshot.recheck()
    return snapshot


def fixtures(root: Path, nfpm: Path, format_name: str, retention_test: RetentionBinarySnapshot | None = None,
             package_name: str = "syswarden") -> bytes:
    selected_cases(format_name, retention_test is not None, package_name)
    if retention_test is not None:
        if (type(retention_test) is not RetentionBinarySnapshot or type(retention_test.data) is not bytes
                or not 0 < len(retention_test.data) <= MAX_ORACLE_BYTES):
            raise ValueError("a bounded retention binary snapshot is required")
        retention_test.recheck()
    hook = root / "refuse.sh"
    hook.write_text("#!/bin/sh\nprintf 'fixture refusal\\n' > /tmp/sw-lab-preinstall-ran\nexit 42\n")
    hook.chmod(0o700)
    generations = [("independent", "1.0.0"), ("optional", "1.0.0"), ("model", "2.0.0")]
    if package_name == "syswarden":
        generations += [("model", "1.0.0"), ("model", "3.0.0"), ("model", "4.0.0")]
    if retention_test is not None:
        generations.append(("minimal", "1.0.0"))
    for fixture_role, version in generations:
        stem = f"{fixture_role}-{version}"
        role = "model" if fixture_role == "minimal" else fixture_role
        payload = root / f"{stem}.txt"
        payload.write_text(f"{role}-{version}\n")
        spec = {"name": "sw-lab-" + role, "arch": "amd64", "platform": "linux", "version": version,
                "maintainer": "SysWarden fixture laboratory", "description": "Inert dependency transition fixture",
                "license": "MIT", "contents": [{"src": str(payload), "dst": "/opt/sw-native-lab/" + role}]}
        if fixture_role == "model" and version == "1.0.0": spec["depends"] = ["sw-lab-optional"]
        if version == "3.0.0": spec["scripts"] = {"preinstall": str(hook)}
        if version == "4.0.0": spec["conflicts"] = ["sw-lab-optional"]
        if retention_test is not None:
            spec["name"] = {"independent": "wireguard-tools", "optional": "rsyslog", "model": package_name}[role]
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
                      SCRIPT.replace("sw-lab-optional", "rsyslog").replace("sw-lab-model", package_name))
    group_paths = group_repository(root, "rsyslog" if retention_test is not None else "sw-lab-optional")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in [*sorted(root.glob(f"*.{format_name}")), script]: archive.add(path, arcname=path.name)
        for path in group_paths: archive.add(path, arcname=str(path.relative_to(root)))
        if retention_test is not None:
            # Never let tar preserve a source symlink or reread a changing path.
            # The evidence digest and executable member share these exact bytes.
            member = tarfile.TarInfo("retention.test")
            member.size = len(retention_test.data)
            member.mode = 0o700
            archive.addfile(member, io.BytesIO(retention_test.data))
    if retention_test is not None:
        retention_test.recheck()
    return stream.getvalue()


def run(nfpm: Path, image: str, format_name: str, output: Path, retention_test: Path | None = None,
        package_name: str = "syswarden", case: str | None = None) -> None:
    if os.geteuid() == 0: raise ValueError("run this laboratory as an unprivileged user")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("an existing absolute nfpm executable is required")
    if not output.is_absolute() or output.exists(): raise ValueError("a new absolute output directory is required")
    retention_snapshot = snapshot_retention_binary(retention_test) if retention_test is not None else None
    cases = selected_cases(format_name, retention_test is not None, package_name, case)
    if re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("exact image identity required")
    helpers = isolation_helpers()
    podman = shutil.which("podman")
    if not podman: raise ValueError("rootless podman is required")
    rootless = helpers.execute_local(helpers.podman_command(podman, "info", "--format", "{{.Host.Security.Rootless}}"))
    if rootless.returncode or rootless.stdout.strip() != b"true": raise ValueError("rootless isolation is required")
    inspection = helpers.execute_local(helpers.podman_command(podman, "image", "inspect", image))
    if inspection.returncode: raise ValueError("image must already be present")
    info = json.loads(inspection.stdout)[0]
    if info["Architecture"] != "amd64" or info["Os"] != "linux" or info["Id"].removeprefix("sha256:") != image:
        raise ValueError("exact Linux AMD64 image identity required")
    output.mkdir(mode=0o700)
    (output / "image.json").write_bytes(inspection.stdout)
    summary = {"image": image, "format": format_name, "synthetic_only": True, "package_name": package_name,
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(),
               "nfpm_binding": "caller-trusted-tool-observation-not-execution-attestation",
               "isolation_scope": "no-requested-host-mounts; engine-default-mounts-not-attested",
               "output_scope": "bounded-runtime; subprocess-output-has-no-byte-cap", "cases": {}}
    if retention_snapshot is not None:
        summary["retention_test_sha256"] = hashlib.sha256(retention_snapshot.data).hexdigest()
        summary["retention_test_size"] = len(retention_snapshot.data)
    payload = fixtures(output, nfpm, format_name, retention_snapshot, package_name)
    for case in cases:
        if retention_snapshot is not None:
            retention_snapshot.recheck()
        result, ownership = run_container(podman, image, format_name, case, output, payload, package_name)
        (output / f"{case}.log").write_bytes(result.stdout)
        completed = result.returncode == 0 and result.stdout.endswith(f"CASE_PASS={case}\n".encode())
        observations = [line for line in result.stdout.decode(errors="replace").splitlines() if line.startswith("OPTIONAL_")]
        expected = [] if case == "fresh" else ["OPTIONAL_PRESENT=1", "OPTIONAL_UNNEEDED=" +
                   ("1" if case in ("default-upgrade", "guarded-upgrade") or
                    (format_name == "rpm" and case == "single-transaction") else "0")]
        if retention_test is not None:
            expected = []
            manager = "/usr/bin/apt-get" if format_name == "deb" else "/usr/bin/dnf"
            lines = result.stdout.splitlines()
            completed = completed and [line for line in lines if line.startswith(b"NATIVE_RETENTION_PASS=")] == [
                ("NATIVE_RETENTION_PASS=" + manager).encode()]
            completed = completed and [line for line in lines if line.startswith(b"NATIVE_RETENTION_PACKAGE=")] == [
                ("NATIVE_RETENTION_PACKAGE=" + package_name).encode()]
            completed = completed and b"--- SKIP:" not in result.stdout
            if case == "native-minimal-upgrade":
                completed = completed and [line for line in lines if line.startswith(b"NATIVE_MINIMAL_UPGRADE=")] == [
                    ("NATIVE_MINIMAL_UPGRADE=" + package_name).encode()]
        passed = completed and observations == expected and ownership["cleanup"]["verified"] is True
        summary["cases"][case] = {"passed": passed, "exit_status": result.returncode, "observations": observations, "container": ownership}
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
    parser.add_argument("--package-name", choices=PACKAGE_NAMES, default="syswarden",
                        help="base requires the native oracle and only qualifies minimal same-name upgrades")
    parser.add_argument("--case", choices=CASES + NATIVE_CASES)
    args = parser.parse_args()
    run(args.nfpm, args.image, args.format, args.output, args.retention_test_binary, args.package_name, args.case)
