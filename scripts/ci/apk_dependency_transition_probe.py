#!/usr/bin/env python3
"""Characterize APK dependency transitions in disposable rootless containers.

This synthetic oracle does not install SysWarden or establish native acceptance.
In particular, a failed package script is not a transaction rollback. Only this
isolated fixture laboratory permits unsigned packages. Product updaters must
continue to require native signatures and reject script/commit-hook bypasses.

Run explicitly with --run-native, an existing AMD64 image ID, an absolute nfpm
path and a new output directory. No image pull, host mount or host APK command
is performed. Every case receives its own container and repository over stdin.
Engine-default mounts are not attested; subprocess output has no byte cap.
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

import native_dependency_transition_probe as native


CASES = (
    "fresh",
    "unretained-upgrade",
    "refused-upgrade",
    "retained-upgrade",
    "retained-refused-upgrade",
    "retained-remove",
    "retained-purge",
    "precommit-refusal",
    "precommit-remove-refusal",
    "refused-package-remove",
    "retention-conflict",
    "retained-reinstall",
    "single-transaction",
    "single-transaction-refused",
    "single-transaction-pinned",
    "single-transaction-tagged",
    "single-transaction-conflict",
    "single-transaction-untrusted",
)

PACKAGE_NAMES = ("syswarden", "syswarden-base")
NATIVE_CASES = ("native-selected-upgrade", "native-selected-pinned-refusal", "native-selected-tagged-refusal")

SCRIPT = r'''#!/bin/sh
set -eu
cd /tmp/sw-apk-lab
test "$(apk --print-arch)" = x86_64
apk --version
apk_cmd() { apk --no-network --repositories-file /dev/null "$@"; }
check_retention_plan() {
    if [ -x ./retention.test ]; then
        SYSWARDEN_APK_RETENTION_NATIVE=1 SYSWARDEN_APK_RETENTION_EXPECT="$1" \
            ./retention.test -test.run '^TestAPKRetentionNativePlanner$' -test.v
    fi
}
install_legacy() {
    mkdir -p repo/x86_64
    cp optional-1.0.0.apk repo/sw-lab-optional-1.0.0.apk
    apk_cmd --allow-untrusted index -o repo/APKINDEX.tar.gz repo/*.apk
    cp repo/*.apk repo/APKINDEX.tar.gz repo/x86_64/
    apk_cmd --allow-untrusted --repository /tmp/sw-apk-lab/repo add ./model-1.0.0.apk
    if grep -q '^sw-lab-optional' /etc/apk/world; then exit 1; else test "$?" -eq 1; fi
    apk_cmd info --quiet -e sw-lab-optional
    printf 'administrator data\n' > /etc/sw-lab-admin.conf
    chmod 600 /etc/sw-lab-admin.conf
    sha256sum /etc/sw-lab-admin.conf /opt/sw-lab/optional > /tmp/retained.sha256
    stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-lab-admin.conf /opt/sw-lab/optional > /tmp/retained.metadata
}
assert_absent() {
    if apk_cmd info --quiet -e "$1" > /tmp/absent-query 2>&1; then
        exit 1
    else
        test "$?" -eq 1
        test ! -s /tmp/absent-query
    fi
}
assert_retained() {
    apk_cmd info --quiet -e sw-lab-optional
    sha256sum -c /tmp/retained.sha256
    stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-lab-admin.conf /opt/sw-lab/optional > /tmp/current.metadata
    cmp /tmp/retained.metadata /tmp/current.metadata
}
retain_existing() {
    apk_cmd add 'sw-lab-optional=1.0.0'
    assert_retained
    cp /etc/apk/world /tmp/world.retained
    apk_cmd add 'sw-lab-optional=1.0.0'
    cmp /etc/apk/world /tmp/world.retained
}
case "$1" in
    fresh)
        apk_cmd --allow-untrusted add ./model-2.0.0.apk
        assert_absent sw-lab-optional
        test ! -e /opt/sw-lab/optional
        test "$(cat /opt/sw-lab/model)" = model-2.0.0
        check_retention_plan ""
        ;;
    unretained-upgrade|refused-upgrade)
        install_legacy
        if [ "$1" = refused-upgrade ]; then
            if apk_cmd --allow-untrusted add ./model-3.0.0.apk; then exit 1; fi
            test -f /tmp/sw-lab-package-hook-ran
            test "$(cat /opt/sw-lab/model)" = model-3.0.0
        else
            apk_cmd --allow-untrusted add ./model-2.0.0.apk
            test "$(cat /opt/sw-lab/model)" = model-2.0.0
        fi
        assert_absent sw-lab-optional
        test ! -e /opt/sw-lab/optional
        ;;
    single-transaction*)
        install_legacy
        check_retention_plan sw-lab-optional
        case "$1" in
            single-transaction-refused)
                if apk_cmd --allow-untrusted add ./model-3.0.0.apk sw-lab-optional; then exit 1; fi
                test -f /tmp/sw-lab-package-hook-ran
                test "$(cat /opt/sw-lab/model)" = model-3.0.0
                grep -x sw-lab-optional /etc/apk/world
                ;;
            single-transaction-pinned)
                apk_cmd add 'sw-lab-optional=1.0.0'
                check_retention_plan ""
                apk_cmd --allow-untrusted add ./model-2.0.0.apk
                grep -x 'sw-lab-optional=1.0.0' /etc/apk/world
                ;;
            single-transaction-tagged)
                printf '@local /tmp/sw-apk-lab/repo\n' > /tmp/local-repositories
                apk --no-network --repositories-file /tmp/local-repositories --allow-untrusted add 'sw-lab-optional@local=1.0.0'
                check_retention_plan ""
                apk --no-network --repositories-file /tmp/local-repositories --allow-untrusted add ./model-2.0.0.apk
                grep -x 'sw-lab-optional@local=1.0.0' /etc/apk/world
                ;;
            single-transaction-conflict|single-transaction-untrusted)
                sha256sum /etc/apk/world /lib/apk/db/installed /opt/sw-lab/model > /tmp/pre.sha256
                if [ "$1" = single-transaction-conflict ]; then
                    if apk_cmd --allow-untrusted add ./model-2.0.0.apk 'sw-lab-optional=9.0.0'; then exit 1; fi
                else
                    # Signature refusal precedes retention as well as replacement.
                    if apk_cmd add ./model-2.0.0.apk sw-lab-optional; then exit 1; fi
                fi
                sha256sum -c /tmp/pre.sha256
                assert_retained
                printf 'CASE_PASS=%s\n' "$1"
                exit 0
                ;;
            *)
                apk_cmd --allow-untrusted add ./model-2.0.0.apk sw-lab-optional
                grep -x sw-lab-optional /etc/apk/world
                ;;
        esac
        assert_retained
        # This characterizes native removal of the synthetic model, not the
        # independent complete SysWarden uninstall/remove/purge contracts.
        if [ "$1" = single-transaction-tagged ]; then
            apk --no-network --repositories-file /tmp/local-repositories --allow-untrusted del --purge sw-lab-model
        else
            apk_cmd del --purge sw-lab-model
        fi
        assert_absent sw-lab-model
        assert_retained
        ;;
    retained-*)
        install_legacy
        retain_existing
        if [ "$1" = retained-refused-upgrade ]; then
            if apk_cmd --allow-untrusted add ./model-3.0.0.apk; then exit 1; fi
            test -f /tmp/sw-lab-package-hook-ran
            test "$(cat /opt/sw-lab/model)" = model-3.0.0
        else
            apk_cmd --allow-untrusted add ./model-2.0.0.apk
            test "$(cat /opt/sw-lab/model)" = model-2.0.0
        fi
        assert_retained
        case "$1" in
            retained-remove) apk_cmd del sw-lab-model ;;
            retained-purge) apk_cmd del --purge sw-lab-model ;;
            retained-reinstall)
                cp model-2.0.0.apk repo/sw-lab-model-2.0.0.apk
                apk_cmd --allow-untrusted index -o repo/APKINDEX.tar.gz repo/*.apk
                cp repo/*.apk repo/APKINDEX.tar.gz repo/x86_64/
                apk_cmd --allow-untrusted --repository /tmp/sw-apk-lab/repo fix --reinstall sw-lab-model
                test "$(cat /opt/sw-lab/model)" = model-2.0.0
                ;;
        esac
        case "$1" in
            retained-remove|retained-purge)
                assert_absent sw-lab-model
                test ! -e /opt/sw-lab/model
                ;;
        esac
        assert_retained
        ;;
    precommit-*)
        install_legacy
        sha256sum /etc/apk/world /lib/apk/db/installed /opt/sw-lab/model > /tmp/pre.sha256
        mkdir -p /etc/apk/commit_hooks.d
        printf '#!/bin/sh\n[ "$1" != pre-commit ] || exit 42\n' > /etc/apk/commit_hooks.d/sw-lab-refuse
        chmod 700 /etc/apk/commit_hooks.d/sw-lab-refuse
        # A repeated aborted attempt must also leave the old state intact.
        for attempt in 1 2; do
            if [ "$1" = precommit-remove-refusal ]; then
                if apk_cmd del sw-lab-model; then exit 1; fi
            else
                if apk_cmd --allow-untrusted add ./model-2.0.0.apk; then exit 1; fi
            fi
            sha256sum -c /tmp/pre.sha256
            assert_retained
        done
        # Remove only this fixture hook, then prove a prepared retry works.
        rm /etc/apk/commit_hooks.d/sw-lab-refuse
        retain_existing
        apk_cmd --allow-untrusted add ./model-2.0.0.apk
        assert_retained
        ;;
    refused-package-remove)
        apk_cmd --allow-untrusted add ./model-3.0.0.apk
        apk_cmd del sw-lab-model
        test -f /tmp/sw-lab-package-hook-ran
        assert_absent sw-lab-model
        test ! -e /opt/sw-lab/model
        ;;
    retention-conflict)
        install_legacy
        sha256sum /etc/apk/world /lib/apk/db/installed /opt/sw-lab/model > /tmp/pre.sha256
        if apk_cmd add 'sw-lab-optional=9.0.0'; then exit 1; fi
        sha256sum -c /tmp/pre.sha256
        assert_retained
        ;;
    *) exit 64 ;;
esac
printf 'CASE_PASS=%s\n' "$1"
'''

NATIVE_SCRIPT = r'''#!/bin/sh
set -eu
cd /tmp/sw-apk-lab
case_name=$1
package_name=$2
case "$package_name" in syswarden|syswarden-base) ;; *) exit 64 ;; esac
case "$case_name" in native-selected-upgrade|native-selected-pinned-refusal|native-selected-tagged-refusal) ;; *) exit 64 ;; esac
test "$(uname -m)" = x86_64
apk --version
apk_cmd() { apk --no-network --repositories-file /dev/null "$@"; }
assert_absent() {
    if apk_cmd info --quiet -e "$1" > /tmp/absent-query 2>&1; then exit 1; else
        test "$?" -eq 1 && test ! -s /tmp/absent-query
    fi
}
for name in syswarden syswarden-base rsyslog wireguard-tools sw-lab-admin sw-lab-independent-root; do assert_absent "$name"; done
for path in /opt/sw-apk-lab /etc/sw-lab-admin.conf /var/tmp/syswarden-update-oracle; do test ! -e "$path" && test ! -L "$path"; done
capture_mandatory() {
    : > "$1"
    for name in bash-completion cronie cronie-openrc curl jq nftables openrc procps-ng shadow wget; do
        printf 'PACKAGE=%s\n' "$name" >> "$1"
        awk -v name="$name" 'BEGIN { RS=""; FS="\n" } { for (i=1;i<=NF;i++) if ($i=="P:" name) print $0 "\n" }' /lib/apk/db/installed >> "$1"
    done
}
capture_mandatory /tmp/mandatory.before
printf 'PREREQUISITE_SCOPE=preexisting-record-preservation-only\n'
cat /tmp/mandatory.before
mkdir -p repo/x86_64
for role in optional independent admin anchor; do
    case "$role" in optional) name=rsyslog ;; independent) name=wireguard-tools ;; admin) name=sw-lab-admin ;; anchor) name=sw-lab-independent-root ;; esac
    cp "$role-1.0.0.apk" "repo/x86_64/$name-1.0.0-r0.apk"
done
cp model-1.0.0.apk "repo/x86_64/$package_name-1.0.0-r0.apk"
apk_cmd --allow-untrusted index -o repo/x86_64/APKINDEX.tar.gz repo/x86_64/*.apk
apk_cmd --allow-untrusted --repository /tmp/sw-apk-lab/repo add ./model-1.0.0.apk ./anchor-1.0.0.apk 'sw-lab-admin=1.0.0-r0'
test "$(cat /opt/sw-apk-lab/model)" = model-1.0.0
printf 'effective_fixture_policy=preserve\n' > /etc/sw-lab-admin.conf
chmod 600 /etc/sw-lab-admin.conf
sha256sum /etc/sw-lab-admin.conf /opt/sw-apk-lab/optional /opt/sw-apk-lab/independent /opt/sw-apk-lab/admin > /tmp/sentinel.sha256
stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-lab-admin.conf /opt/sw-apk-lab/optional /opt/sw-apk-lab/independent /opt/sw-apk-lab/admin > /tmp/sentinel.metadata
capture_identity() {
    awk -v name="$1" 'BEGIN { RS=""; FS="\n" } { found=0; for (i=1;i<=NF;i++) if ($i=="P:" name) found=1; if (found) for (i=1;i<=NF;i++) if ($i ~ /^[PVAC]:/) print $i }' /lib/apk/db/installed
}
capture_identity wireguard-tools > /tmp/independent.before
capture_identity rsyslog > /tmp/optional.before
capture_identity "$package_name" > /tmp/product.before
checksum=$(sed -n 's/^C://p' /tmp/product.before)
test -n "$checksum"
grep -Fx "$package_name><$checksum" /etc/apk/world
printf 'SELECTED_WORLD_BEFORE=%s><%s\n' "$package_name" "$checksum"
cat /tmp/product.before
case "$case_name" in
    native-selected-pinned-refusal)
        apk_cmd --allow-untrusted --repository /tmp/sw-apk-lab/repo add "$package_name=1.0.0-r0"
        grep -Fx "$package_name=1.0.0-r0" /etc/apk/world
        ;;
    native-selected-tagged-refusal)
        printf '@fixture /tmp/sw-apk-lab/repo\n' > /tmp/sw-apk-lab/tag.repositories
        apk --no-network --repositories-file /tmp/sw-apk-lab/tag.repositories --allow-untrusted add "$package_name@fixture=1.0.0-r0"
        grep -Fx "$package_name@fixture=1.0.0-r0" /etc/apk/world
        ;;
esac
grep -Fx 'sw-lab-admin=1.0.0-r0' /etc/apk/world
if grep -Eq '^wireguard-tools([<>=~@]|$)' /etc/apk/world; then exit 1; fi
if grep -Eq '^rsyslog([<>=~@]|$)' /etc/apk/world; then exit 1; fi
# Only the selected checksum root may change; compatibility retention may add
# its one declared historical dependency. Other complete world lines must match.
awk -v selected="$package_name" '$0 !~ "^" selected "([<>=~@]|$)" && $0!="rsyslog"' /etc/apk/world > /tmp/unrelated-world.before
sha256sum /etc/apk/world /lib/apk/db/installed /opt/sw-apk-lab/model > /tmp/transaction.before.sha256
stat -c '%a:%u:%g:%s:%Y:%i' /etc/apk/world /lib/apk/db/installed /opt/sw-apk-lab/model > /tmp/transaction.before.metadata
mkdir -m 700 /var/tmp/syswarden-update-oracle
cp model-2.0.0.apk /var/tmp/syswarden-update-oracle/package.apk
chmod 600 /var/tmp/syswarden-update-oracle/package.apk
SYSWARDEN_APK_SELECTED_RETENTION_NATIVE=1 SYSWARDEN_APK_SELECTED_PACKAGE="$package_name" SYSWARDEN_APK_SELECTED_CASE="$case_name" \
    ./retention.test -test.run '^TestAPKSelectedRetentionNativeTransaction$' -test.v
case "$case_name" in
    native-selected-upgrade)
        test "$(cat /opt/sw-apk-lab/model)" = model-2.0.0
        test "$(apk_cmd info --who-owns /opt/sw-apk-lab/model)" = "/opt/sw-apk-lab/model is owned by $package_name-2.0.0-r0"
        capture_identity "$package_name" > /tmp/product.after
        grep -Fx "P:$package_name" /tmp/product.after
        grep -Fx 'V:2.0.0-r0' /tmp/product.after
        grep -Fx 'A:x86_64' /tmp/product.after
        next_checksum=$(sed -n 's/^C://p' /tmp/product.after)
        test -n "$next_checksum" && test "$next_checksum" != "$checksum"
        grep -Fx "$package_name><$next_checksum" /etc/apk/world
        printf 'SELECTED_WORLD_AFTER=%s><%s\n' "$package_name" "$next_checksum"
        cat /tmp/product.after
        case "$package_name" in
            syswarden) grep -Fx rsyslog /etc/apk/world ;;
            syswarden-base) if grep -Eq '^rsyslog([<>=~@]|$)' /etc/apk/world; then exit 1; fi ;;
        esac
        ;;
    *)
        sha256sum -c /tmp/transaction.before.sha256
        stat -c '%a:%u:%g:%s:%Y:%i' /etc/apk/world /lib/apk/db/installed /opt/sw-apk-lab/model > /tmp/transaction.after.metadata
        cmp /tmp/transaction.before.metadata /tmp/transaction.after.metadata
        ;;
esac
sha256sum -c /tmp/sentinel.sha256
stat -c '%a:%u:%g:%s:%Y:%i' /etc/sw-lab-admin.conf /opt/sw-apk-lab/optional /opt/sw-apk-lab/independent /opt/sw-apk-lab/admin > /tmp/sentinel.after.metadata
cmp /tmp/sentinel.metadata /tmp/sentinel.after.metadata
capture_identity wireguard-tools > /tmp/independent.after
capture_identity rsyslog > /tmp/optional.after
cmp /tmp/independent.before /tmp/independent.after
cmp /tmp/optional.before /tmp/optional.after
awk -v selected="$package_name" '$0 !~ "^" selected "([<>=~@]|$)" && $0!="rsyslog"' /etc/apk/world > /tmp/unrelated-world.after
cmp /tmp/unrelated-world.before /tmp/unrelated-world.after
if grep -Eq '^wireguard-tools([<>=~@]|$)' /etc/apk/world; then exit 1; fi
capture_mandatory /tmp/mandatory.after
cmp /tmp/mandatory.before /tmp/mandatory.after
if [ "$case_name" = native-selected-upgrade ]; then
    # Independent automatic packages must remain eligible for native cleanup.
    # This deliberately removes only the inert fixture root after preservation
    # has been checked, without treating removal as product lifecycle proof.
    apk_cmd del sw-lab-independent-root
    assert_absent wireguard-tools
    case "$package_name" in syswarden) apk_cmd info --quiet -e rsyslog ;; syswarden-base) assert_absent rsyslog ;; esac
    capture_mandatory /tmp/mandatory.after-cleanup
    cmp /tmp/mandatory.before /tmp/mandatory.after-cleanup
    grep -Fx 'sw-lab-admin=1.0.0-r0' /etc/apk/world
    test "$(cat /etc/sw-lab-admin.conf)" = effective_fixture_policy=preserve
fi
printf 'CASE_PASS=%s\n' "$case_name"
'''


def selected_cases(native_oracle: bool, package_name: str, case: str | None) -> tuple[str, ...]:
    if package_name not in PACKAGE_NAMES:
        raise ValueError("exact allowlisted product identity required")
    if package_name == "syswarden-base" and not native_oracle:
        raise ValueError("base selection requires the native planner oracle")
    if case is not None:
        if case in NATIVE_CASES and native_oracle:
            return (case,)
        if case in CASES and package_name == "syswarden":
            return (case,)
        raise ValueError("case is unsupported for the selected identity and oracle")
    return NATIVE_CASES if package_name == "syswarden-base" else CASES


def sandbox_command(podman: str, image: str, case: str, identity, package_name: str = "syswarden") -> list[str]:
    if re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("exact image ID required")
    selected_cases(True, package_name, case)
    helpers = native.isolation_helpers()
    helpers.validate_container(identity)
    return helpers.podman_command(podman, "run", "--name", identity.name,
        "--label", helpers.OWNER_LABEL + "=" + identity.token, "--cidfile", str(identity.cidfile),
        "--image-volume=ignore", "-i", "--pull", "never", "--network", "none",
        "--cap-drop", "all", "--cap-add", "SYS_CHROOT",
        "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "256m",
        "--pids-limit", "64", "--timeout", "60", "--entrypoint", "/bin/sh",
        image, "-c",
        'umask 077; mkdir /tmp/sw-apk-lab && cd /tmp/sw-apk-lab && tar --no-same-owner -xf - && sh cases.sh "$1" "$2"',
        "probe", case, package_name)


def run_container(podman: str, image: str, case: str, output: Path, payload: bytes, package_name: str) -> tuple[subprocess.CompletedProcess, dict]:
    helpers = native.isolation_helpers()
    identity = helpers.ContainerIdentity(helpers.CONTAINER_PREFIX + uuid.uuid4().hex,
                                         uuid.uuid4().hex, output / f"{case}.cid")
    arguments = sandbox_command(podman, image, case, identity, package_name)
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
        result = helpers.execute_local(arguments, timeout=90, input=payload)
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


def command(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=90, check=False, **kwargs)


def fixtures(root: Path, nfpm: Path, retention_test: native.RetentionBinarySnapshot | None = None,
             package_name: str = "syswarden", selected: bool = False) -> bytes:
    if package_name not in PACKAGE_NAMES or selected and retention_test is None or package_name == "syswarden-base" and not selected:
        raise ValueError("selected native fixture identity is invalid")
    if retention_test is not None:
        if type(retention_test) is not native.RetentionBinarySnapshot:
            raise ValueError("exact retention binary snapshot required")
        retention_test.recheck()
    if selected:
        return selected_fixtures(root, nfpm, retention_test, package_name)
    hook = root / "refuse.sh"
    hook.write_text('#!/bin/sh\nprintf "HOOK_REFUSED\\n" >&2\n'
                    ': > /tmp/sw-lab-package-hook-ran\nexit 42\n')
    hook.chmod(0o700)
    for role, version, dependency, guard in (
        ("optional", "1.0.0", False, False),
        ("model", "1.0.0", True, False),
        ("model", "2.0.0", False, False),
        ("model", "3.0.0", False, True),
    ):
        stem = f"{role}-{version}"
        payload = root / f"{stem}.txt"
        payload.write_text(stem + "\n")
        spec = {
            "name": "sw-lab-" + role, "arch": "amd64", "platform": "linux",
            "version": version, "maintainer": "SysWarden synthetic test",
            "description": "Disposable synthetic package transaction fixture",
            "license": "MIT",
            "contents": [{"src": str(payload), "dst": "/opt/sw-lab/" + role}],
        }
        if dependency:
            spec["depends"] = ["sw-lab-optional"]
        if guard:
            spec["apk"] = {"scripts": {"preupgrade": str(hook)}}
            spec["scripts"] = {"preremove": str(hook)}
        if retention_test is not None:
            # These remain synthetic payloads in a disposable container. Exact
            # product/dependency names exercise the production inventory parser.
            spec["name"] = "rsyslog" if role == "optional" else "syswarden"
            if dependency:
                spec["depends"] = ["rsyslog"]
        config = root / f"{stem}.json"
        config.write_text(json.dumps(spec, indent=2) + "\n")
        result = command([str(nfpm), "pkg", "--config", str(config),
                          "--packager", "apk", "--target", str(root / f"{stem}.apk")])
        (root / f"{stem}.build.log").write_bytes(result.stdout)
        if result.returncode:
            raise RuntimeError("fixture build failed: " + stem)
    script = root / "cases.sh"
    script.write_text(SCRIPT if retention_test is None else
                      SCRIPT.replace("sw-lab-model", "syswarden").replace("sw-lab-optional", "rsyslog"))
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in [*sorted(root.glob("*.apk")), script]:
            archive.add(path, arcname=path.name)
        if retention_test is not None:
            add_retention_binary(archive, retention_test)
    if retention_test is not None:
        retention_test.recheck()
    return stream.getvalue()


def add_retention_binary(archive: tarfile.TarFile, snapshot: native.RetentionBinarySnapshot) -> None:
    if type(snapshot) is not native.RetentionBinarySnapshot or not 0 < len(snapshot.data) <= native.MAX_ORACLE_BYTES:
        raise ValueError("bounded executable snapshot required")
    snapshot.recheck()
    member = tarfile.TarInfo("retention.test")
    member.size = len(snapshot.data)
    member.mode = 0o700
    archive.addfile(member, io.BytesIO(snapshot.data))


def selected_fixtures(root: Path, nfpm: Path, snapshot: native.RetentionBinarySnapshot, package_name: str) -> bytes:
    selected_cases(True, package_name, NATIVE_CASES[0])
    roles = (("optional", "rsyslog"), ("independent", "wireguard-tools"),
             ("admin", "sw-lab-admin"), ("anchor", "sw-lab-independent-root"),
             ("model", package_name))
    packages = []
    for role, name in roles:
        for version in (("1.0.0", "2.0.0") if role == "model" else ("1.0.0",)):
            stem = f"{role}-{version}"
            payload = root / f"{stem}.txt"
            payload.write_text(stem + "\n")
            spec = {"name": name, "arch": "amd64", "platform": "linux", "version": version,
                    "version_schema": "none", "release": "0", "maintainer": "SysWarden fixture laboratory",
                    "description": "Inert selected APK retention fixture", "license": "MIT",
                    "contents": [{"src": str(payload), "dst": "/opt/sw-apk-lab/" + role}]}
            if role == "model" and version == "1.0.0" and package_name == "syswarden":
                spec["depends"] = ["rsyslog"]
            if role == "anchor":
                spec["depends"] = ["wireguard-tools"] + (["rsyslog"] if package_name == "syswarden-base" else [])
            config = root / f"{stem}.json"
            config.write_text(json.dumps(spec, indent=2) + "\n")
            package = root / f"{stem}.apk"
            built = command([str(nfpm), "pkg", "--config", str(config), "--packager", "apk", "--target", str(package)])
            (root / f"{stem}.build.log").write_bytes(built.stdout)
            if built.returncode:
                raise RuntimeError("selected fixture build failed: " + stem)
            packages.append(package)
    script = root / "cases.sh"
    script.write_text(NATIVE_SCRIPT)
    marker = root / ".selected-retention-oracle-v1"
    marker.write_bytes(b"SYSWARDEN-ISOLATED-APK-RETENTION-V1\n")
    marker.chmod(0o600)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in [*packages, script, marker]:
            archive.add(path, arcname=path.name)
        add_retention_binary(archive, snapshot)
    snapshot.recheck()
    return stream.getvalue()


def run(nfpm: Path, image: str, output: Path, retention_test: Path | None = None,
        package_name: str = "syswarden", case: str | None = None) -> None:
    if os.geteuid() == 0:
        raise ValueError("run this laboratory as an unprivileged user")
    cases = selected_cases(retention_test is not None, package_name, case)
    if re.fullmatch(r"[0-9a-f]{64}", image) is None:
        raise ValueError("exact Linux AMD64 image identity required")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("an existing absolute nfpm executable is required")
    if not output.is_absolute() or output.exists():
        raise ValueError("a new absolute output directory is required")
    snapshot = native.snapshot_retention_binary(retention_test) if retention_test is not None else None
    podman = shutil.which("podman")
    if podman is None:
        raise ValueError("rootless podman is required")
    helpers = native.isolation_helpers()
    info = helpers.execute_local(helpers.podman_command(podman, "info", "--format", "{{.Host.Security.Rootless}}"))
    if info.returncode or info.stdout.strip() != b"true":
        raise ValueError("podman rootless isolation is required")
    inspection = helpers.execute_local(helpers.podman_command(podman, "image", "inspect", image))
    if inspection.returncode:
        raise ValueError("image must already be present; this probe never pulls")
    inspected = json.loads(inspection.stdout)[0]
    if (inspected["Architecture"] != "amd64" or inspected["Os"] != "linux"
            or inspected["Id"].removeprefix("sha256:") != image):
        raise ValueError("exact Linux AMD64 image identity required")
    output.mkdir(mode=0o700)
    (output / "image.json").write_bytes(inspection.stdout)
    summary = {"image": image, "architecture": "amd64", "package_name": package_name,
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(),
               "synthetic_only": True, "prerequisite_scope": "preexisting-record-preservation-only",
               "engine_default_mounts_attested": False, "subprocess_output_byte_cap": None, "cases": {}}
    if snapshot is not None:
        summary["retention_test_sha256"] = hashlib.sha256(snapshot.data).hexdigest()
    selected = cases[0] in NATIVE_CASES
    payload = fixtures(output, nfpm, snapshot, package_name, selected)
    for selected_case in cases:
        if snapshot is not None:
            snapshot.recheck()
        result, ownership = run_container(podman, image, selected_case, output, payload, package_name)
        (output / f"{selected_case}.log").write_bytes(result.stdout)
        expected_plans = 0
        observed_plans = result.stdout.count(b"APK_RETENTION_NATIVE_PASS=")
        selected_markers_valid = True
        if selected:
            marker = f"APK_SELECTED_RETENTION_NATIVE_PASS={package_name}:{selected_case}".encode()
            expected_plans = 1
            markers = [line for line in result.stdout.splitlines() if line.startswith(b"APK_SELECTED_RETENTION_NATIVE_PASS=")]
            observed_plans = markers.count(marker)
            selected_markers_valid = markers == [marker]
        elif snapshot is not None and (selected_case == "fresh" or selected_case.startswith("single-transaction")):
            expected_plans = 2 if selected_case in ("single-transaction-pinned", "single-transaction-tagged") else 1
        passed = (result.returncode == 0 and result.stdout.endswith(f"CASE_PASS={selected_case}\n".encode())
                  and observed_plans == expected_plans and selected_markers_valid and b"--- SKIP:" not in result.stdout
                  and ownership["cleanup"]["verified"])
        summary["cases"][selected_case] = {"passed": passed, "exit_status": result.returncode,
                                           "cleanup_verified": ownership["cleanup"]["verified"]}
        if snapshot is not None:
            summary["cases"][selected_case]["native_planner_passes"] = observed_plans
        (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
        if not passed:
            raise RuntimeError("native characterization failed: " + selected_case)
        print("PASS " + selected_case, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--nfpm", type=Path, required=True)
    parser.add_argument("--image", required=True, help="existing 64-character AMD64 image ID")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--retention-test-binary", type=Path,
                        help="optional static system-package test binary for the production inventory oracle")
    parser.add_argument("--package-name", choices=PACKAGE_NAMES, default="syswarden")
    parser.add_argument("--case", choices=CASES + NATIVE_CASES, help="run exactly one bounded native case")
    options = parser.parse_args()
    run(options.nfpm, options.image, options.output, options.retention_test_binary, options.package_name, options.case)
