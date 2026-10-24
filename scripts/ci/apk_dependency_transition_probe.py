#!/usr/bin/env python3
"""Characterize APK dependency transitions in disposable rootless containers.

This synthetic oracle does not install SysWarden or establish native acceptance.
In particular, a failed package script is not a transaction rollback. Only this
isolated fixture laboratory permits unsigned packages. Product updaters must
continue to require native signatures and reject script/commit-hook bypasses.

Run explicitly with --run-native, an existing AMD64 image ID, an absolute nfpm
path and a new output directory. No image pull, host mount or host APK command
is performed. Every case receives its own container and repository over stdin.
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


def sandbox_command(podman: str, image: str, case: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{64}", image) or case not in CASES:
        raise ValueError("exact image ID and supported case required")
    return [
        podman, "run", "--rm", "-i", "--pull", "never", "--network", "none",
        "--cap-drop", "all", "--cap-add", "SYS_CHROOT",
        "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "256m",
        "--pids-limit", "64", "--timeout", "60", "--entrypoint", "/bin/sh",
        image, "-c",
        'mkdir /tmp/sw-apk-lab && cd /tmp/sw-apk-lab && tar xf - && sh cases.sh "$1"',
        "sh", case,
    ]


def command(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=90, check=False, **kwargs)


def fixtures(root: Path, nfpm: Path, retention_test: Path | None = None) -> bytes:
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
            archive.add(retention_test, arcname="retention.test")
    return stream.getvalue()


def run(nfpm: Path, image: str, output: Path, retention_test: Path | None = None) -> None:
    if os.geteuid() == 0:
        raise ValueError("run this laboratory as an unprivileged user")
    if not nfpm.is_absolute() or not nfpm.is_file() or not os.access(nfpm, os.X_OK):
        raise ValueError("an existing absolute nfpm executable is required")
    if not output.is_absolute() or output.exists():
        raise ValueError("a new absolute output directory is required")
    if retention_test is not None and (not retention_test.is_absolute() or
            not retention_test.is_file() or not os.access(retention_test, os.X_OK)):
        raise ValueError("an existing absolute static Linux AMD64 system test binary is required")
    podman = shutil.which("podman")
    if podman is None:
        raise ValueError("rootless podman is required")
    sandbox_command(podman, image, CASES[0])
    info = command([podman, "info", "--format", "{{.Host.Security.Rootless}}"])
    if info.returncode or info.stdout.strip() != b"true":
        raise ValueError("podman rootless isolation is required")
    inspection = command([podman, "image", "inspect", image])
    if inspection.returncode:
        raise ValueError("image must already be present; this probe never pulls")
    inspected = json.loads(inspection.stdout)[0]
    if (inspected["Architecture"] != "amd64" or inspected["Os"] != "linux"
            or inspected["Id"].removeprefix("sha256:") != image):
        raise ValueError("exact Linux AMD64 image identity required")
    output.mkdir(mode=0o700)
    (output / "image.json").write_bytes(inspection.stdout)
    summary = {"image": image, "architecture": "amd64",
               "nfpm_sha256": hashlib.sha256(nfpm.read_bytes()).hexdigest(),
               "synthetic_only": True, "cases": {}}
    if retention_test is not None:
        summary["retention_test_sha256"] = hashlib.sha256(retention_test.read_bytes()).hexdigest()
    payload = fixtures(output, nfpm, retention_test)
    for case in CASES:
        result = command(sandbox_command(podman, image, case), input=payload)
        (output / f"{case}.log").write_bytes(result.stdout)
        expected_plans = 0
        if retention_test is not None:
            if case == "fresh" or case.startswith("single-transaction"):
                expected_plans = 2 if case in ("single-transaction-pinned", "single-transaction-tagged") else 1
        observed_plans = result.stdout.count(b"APK_RETENTION_NATIVE_PASS=")
        passed = (result.returncode == 0 and result.stdout.endswith(f"CASE_PASS={case}\n".encode())
                  and observed_plans == expected_plans and b"--- SKIP:" not in result.stdout)
        summary["cases"][case] = {"passed": passed, "exit_status": result.returncode}
        if retention_test is not None:
            summary["cases"][case]["native_planner_passes"] = observed_plans
        (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
        if not passed:
            raise RuntimeError("native characterization failed: " + case)
        print("PASS " + case, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", required=True)
    parser.add_argument("--nfpm", type=Path, required=True)
    parser.add_argument("--image", required=True, help="existing 64-character AMD64 image ID")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--retention-test-binary", type=Path,
                        help="optional static system-package test binary for the production inventory oracle")
    options = parser.parse_args()
    run(options.nfpm, options.image, options.output, options.retention_test_binary)
