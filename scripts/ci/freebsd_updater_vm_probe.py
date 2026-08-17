#!/usr/bin/env python3
"""Prove the signed FreeBSD updater against exact release inputs in the VM."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

import freebsd_vm_lab as vm_lab


SCHEMA_VERSION = 1
TEST_NAME = "TestFreeBSDSignedUpdaterRealPackageTransition_SW_UPD_002"
TEST_BINARY_NAME = "syswarden-updater-freebsd.test"
MANIFEST_NAME = "syswarden-update-manifest-v1.json"
SIGNATURE_NAME = MANIFEST_NAME + ".sig"
EVIDENCE_KEYS = frozenset(
    {
        "MARKER_MATCH",
        "LAB_LOCK_ACQUIRED",
        "INPUT_SHA_MATCH",
        "PREVIOUS_SHA256",
        "CANDIDATE_SHA256",
        "TEST_BINARY_SHA256",
        "MANIFEST_SHA256",
        "SIGNATURE_SHA256",
        "LAB_BASELINE_CLEAN",
        "INITIAL_PACKAGE_ABSENT",
        "PREVIOUS_INSTALL_RC",
        "PREVIOUS_VERSION",
        "SOURCE_SHA",
        "UPDATER_RC",
        "UPDATER_RESULT_SHA256",
        "UPDATER_RESULT_EXACT",
        "UPDATER_RESULT_LINE",
        "CANDIDATE_VERSION",
        "CORE_ENABLED",
        "WEB_ENABLED",
        "CORE_STATUS_RC",
        "WEB_STATUS_RC",
        "CLEANUP_RC",
        "PACKAGE_ABSENT",
        "PF_BASELINE_STATUS",
        "PF_BASELINE_EMPTY",
        "PF_FINAL_STATUS",
        "PF_FINAL_EMPTY",
        "PF_FILTER_MATCH",
        "PF_NAT_MATCH",
        "PF_TABLES_MATCH",
        "PF_SYSWARDEN_ABSENT",
        "PF_METADATA_ABSENT",
        "RUNTIME_PATHS_ABSENT",
        "SERVICE_PROCESSES_ABSENT",
        "PID_FILES_ABSENT",
        "WEB_SOCKET_MATCH",
        "SYSRC_FLAGS_ABSENT",
        "SYSRC_INVENTORY_MATCH",
        "MANAGED_CRON_ABSENT",
        "RSYSLOG_FILES_ABSENT",
        "OPERATOR_STATE_PRESERVED",
        "HARNESS_RESET_COMPLETE",
        "LAB_LOCK_RELEASED",
        "REMOTE_WORKSPACE_REMOVED",
    }
)


class FreeBSDUpdaterProbeError(RuntimeError):
    """Raised when signed-updater evidence cannot be trusted."""


REMOTE_ROOT_PREPARE_SCRIPT = r'''
set -eu
umask 077
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH
token="${token:?VM marker token was not supplied through stdin}"
work="$1"
transport_user="$2"
lock_path=/var/run/syswarden-lot0-lab.lock
remote_nonce="${work#/tmp/syswarden-freebsd-lot0-}"
if [ "$work" != "/tmp/syswarden-freebsd-lot0-${remote_nonce}" ] || \
   [ "${#remote_nonce}" -ne 32 ]; then
    exit 90
fi
case "$remote_nonce" in *[!a-f0-9]*) exit 90 ;; esac
case "$transport_user" in
    [a-z_]*) ;;
    *) exit 90 ;;
esac
case "$transport_user" in *[!a-z0-9_-]*) exit 90 ;; esac
marker="$(/bin/cat /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
if [ "$marker" != "SYSWARDEN_LOT0_DISPOSABLE_VM=${token}" ]; then
    exit 91
fi
[ -d /tmp ] && [ ! -L /tmp ]
[ "$(stat -f '%HT|%u|%g|%Mp|%Lp' /tmp)" = 'Directory|0|0|1|777' ]
if [ -e "$work" ] || [ -L "$work" ]; then
    exit 92
fi
prepared=0
cleanup_prepare() {
    if [ "$prepared" -eq 0 ]; then
        rm -rf "$work"
        if [ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ] && \
           [ "$(cat "$lock_path/owner" 2>/dev/null)" = "$remote_nonce" ]; then
            rm -f "$lock_path/owner"
            rmdir "$lock_path" >/dev/null 2>&1 || true
        fi
    fi
}
trap cleanup_prepare EXIT HUP INT TERM
mkdir "$lock_path"
chown 0:0 "$lock_path"
chmod 700 "$lock_path"
printf '%s\n' "$remote_nonce" >"$lock_path/owner"
chown 0:0 "$lock_path/owner"
chmod 600 "$lock_path/owner"
id -u "$transport_user" >/dev/null
mkdir "$work"
chown 0:0 "$work"
chmod 733 "$work"
prepared=1
trap - EXIT HUP INT TERM
'''.strip()


REMOTE_ROOT_CLEANUP_SCRIPT = r'''
set -eu
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH
token="${token:?VM marker token was not supplied through stdin}"
work="$1"
lock_path=/var/run/syswarden-lot0-lab.lock
remote_nonce="${work#/tmp/syswarden-freebsd-lot0-}"
if [ "$work" != "/tmp/syswarden-freebsd-lot0-${remote_nonce}" ] || \
   [ "${#remote_nonce}" -ne 32 ]; then
    exit 90
fi
case "$remote_nonce" in *[!a-f0-9]*) exit 90 ;; esac
marker="$(/bin/cat /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
if [ "$marker" != "SYSWARDEN_LOT0_DISPOSABLE_VM=${token}" ]; then
    exit 91
fi
work_exists=0
lock_exists=0
if [ -e "$work" ] || [ -L "$work" ]; then
    work_exists=1
fi
if [ -e "$lock_path" ] || [ -L "$lock_path" ]; then
    lock_exists=1
fi
if [ "$work_exists:$lock_exists" = "0:0" ]; then
    exit 0
fi
if [ "$work_exists:$lock_exists" != "1:1" ]; then
    exit 92
fi
[ -d "$lock_path" ] && [ ! -L "$lock_path" ]
[ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ]
[ "$(stat -f '%HT|%u|%g|%Lp' "$lock_path")" = 'Directory|0|0|700' ]
[ "$(stat -f '%HT|%u|%g|%Lp|%l' "$lock_path/owner")" = 'Regular File|0|0|600|1' ]
[ "$(cat "$lock_path/owner")" = "$remote_nonce" ]
[ -d "$work" ] && [ ! -L "$work" ]
[ "$(stat -f '%HT|%u|%g|%Lp' "$work")" = 'Directory|0|0|733' ]
rm -rf "$work"
rm -f "$lock_path/owner"
rmdir "$lock_path"
[ ! -e "$work" ] && [ ! -L "$work" ]
[ ! -e "$lock_path" ] && [ ! -L "$lock_path" ]
'''.strip()


REMOTE_PROBE_SCRIPT = r'''
set +e
umask 077
export LC_ALL=C
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH
token="${token:?VM marker token was not supplied through stdin}"

work="$1"
previous_name="$2"
previous_sha="$3"
previous_version="$4"
candidate_name="$5"
candidate_sha="$6"
candidate_version="$7"
test_binary_name="$8"
test_binary_sha="$9"
manifest_name="${10}"
manifest_sha="${11}"
signature_name="${12}"
signature_sha="${13}"
command_timeout="${14}"
test_name="${15}"
source_sha="${16}"
transport_user="${17}"
lock_path=/var/run/syswarden-lot0-lab.lock
lock_acquired=0
package_cleanup_authorized=0
updater_pid=0
filter_pid=0
var_lib_created=0

emit() {
    encoded="$(printf '%s' "$2" | /usr/bin/base64 | tr -d '\n')"
    printf 'SWL0\t%s\t%s\n' "$1" "$encoded"
}
safe_root_directory() {
    path="$1"
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    metadata="$(stat -f '%HT|%u|%g|%Lp' "$path" 2>/dev/null)" || return 1
    case "$metadata" in
        'Directory|0|0|'*) ;;
        *) return 1 ;;
    esac
    mode="${metadata##*|}"
    case "$mode" in
        ''|*[!0-7]*|*[2367][0-7]|*[0-7][2367]) return 1 ;;
    esac
    return 0
}
capture_operator_file_state() {
    path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    metadata="$(stat -f '%HT|%u|%g|%Lp|%l' "$path" 2>/dev/null)" || return 1
    [ "$metadata" = 'Regular File|0|0|600|1' ] || return 1
    digest="$(sha256 -q "$path" 2>/dev/null)" || return 1
    [ "${#digest}" -eq 64 ] || return 1
    printf '%s|%s\n' "$metadata" "$digest"
}
capture_operator_directory_state() {
    path="$1"
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    metadata="$(stat -f '%HT|%u|%g|%Lp' "$path" 2>/dev/null)" || return 1
    [ "$metadata" = 'Directory|0|0|700' ] || return 1
    printf '%s\n' "$metadata"
}
capture_cron_root_state() {
    path=/var/cron/tabs/root
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf '%s\n' absent
        return 0
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    metadata="$(stat -f '%HT|%u|%g|%Lp|%l' "$path" 2>/dev/null)" || return 1
    [ "$metadata" = 'Regular File|0|0|600|1' ] || return 1
    digest="$(sha256 -q "$path" 2>/dev/null)" || return 1
    [ "${#digest}" -eq 64 ] || return 1
    printf '%s|%s\n' "$metadata" "$digest"
}
capture_cron_allow_state() {
    path=/var/cron/allow
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf '%s\n' absent
        return 0
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    metadata="$(stat -f '%HT|%u|%g|%Lp|%l' "$path" 2>/dev/null)" || return 1
    case "$metadata" in
        'Regular File|0|0|600|1'|'Regular File|0|0|640|1') ;;
        *) return 1 ;;
    esac
    digest="$(sha256 -q "$path" 2>/dev/null)" || return 1
    [ "${#digest}" -eq 64 ] || return 1
    printf '%s|%s\n' "$metadata" "$digest"
}
capture_cron_deny_state() {
    path=/var/cron/deny
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf '%s\n' absent
        return 0
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    metadata="$(stat -f '%HT|%u|%g|%Lp|%l' "$path" 2>/dev/null)" || return 1
    case "$metadata" in
        'Regular File|0|0|600|1'|'Regular File|0|0|640|1') ;;
        *) return 1 ;;
    esac
    digest="$(sha256 -q "$path" 2>/dev/null)" || return 1
    [ "${#digest}" -eq 64 ] || return 1
    printf '%s|%s\n' "$metadata" "$digest"
}
cron_has_managed_syswarden_line() {
    path=/var/cron/tabs/root
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    grep -E '/(usr/local|opt)/syswarden/bin/syswarden-cli([[:space:]]|$)' \
        "$path" >/dev/null 2>&1
}
cleanup_workspace() {
    if [ "$updater_pid" -gt 0 ]; then
        kill "$updater_pid" >/dev/null 2>&1 || true
        wait "$updater_pid" >/dev/null 2>&1 || true
        updater_pid=0
    fi
    if [ "$filter_pid" -gt 0 ]; then
        kill "$filter_pid" >/dev/null 2>&1 || true
        wait "$filter_pid" >/dev/null 2>&1 || true
        filter_pid=0
    fi
    rm -f "$work/updater-output.pipe"
    if [ "$package_cleanup_authorized" -eq 1 ]; then
        service syswardenwebtui onestop >/dev/null 2>&1 || true
        service syswarden onestop >/dev/null 2>&1 || true
        env ASSUME_ALWAYS_YES=yes pkg delete -fy syswarden >/dev/null 2>&1
        # A failed transition intentionally retains the root-owned workspace,
        # recovery metadata, and guest lock for forensic inspection. Only the
        # fully verified success path below is allowed to release the lock.
        return 0
    fi
    if [ "$lock_acquired" -eq 1 ]; then
        if [ ! -f "$lock_path/owner" ] || [ -L "$lock_path/owner" ] || \
           [ "$(cat "$lock_path/owner" 2>/dev/null)" != "$remote_nonce" ]; then
            return 0
        fi
        rm -f "$lock_path/owner"
        if ! rmdir "$lock_path" >/dev/null 2>&1; then
            return 0
        fi
        lock_acquired=0
    fi
    rm -rf "$work"
}

remote_nonce="${work#/tmp/syswarden-freebsd-lot0-}"
if [ "$work" != "/tmp/syswarden-freebsd-lot0-${remote_nonce}" ] || \
   [ "${#remote_nonce}" -ne 32 ]; then
    exit 90
fi
case "$remote_nonce" in *[!a-f0-9]*) exit 90 ;; esac
trap cleanup_workspace EXIT
trap 'exit 101' HUP INT TERM
marker="$(/bin/cat /var/run/syswarden-lot0-disposable.marker 2>/dev/null)"
if [ "$marker" != "SYSWARDEN_LOT0_DISPOSABLE_VM=${token}" ]; then
    emit MARKER_MATCH 0
    exit 91
fi
emit MARKER_MATCH 1
if [ ! -d "$lock_path" ] || [ -L "$lock_path" ] || \
   [ "$(stat -f '%HT|%u|%g|%Lp' "$lock_path" 2>/dev/null)" != 'Directory|0|0|700' ] || \
   [ ! -f "$lock_path/owner" ] || [ -L "$lock_path/owner" ] || \
   [ "$(stat -f '%HT|%u|%g|%Lp|%l' "$lock_path/owner" 2>/dev/null)" != \
     'Regular File|0|0|600|1' ] || \
   [ "$(cat "$lock_path/owner" 2>/dev/null)" != "$remote_nonce" ]; then
    emit LAB_LOCK_ACQUIRED 0
    exit 96
fi
lock_acquired=1
emit LAB_LOCK_ACQUIRED 1

[ -d "$work" ] && [ ! -L "$work" ] || exit 92
[ "$(stat -f '%HT|%u|%g|%Lp' "$work" 2>/dev/null)" = 'Directory|0|0|733' ] || exit 92
transport_uid="$(id -u "$transport_user" 2>/dev/null)" || exit 92
transport_gid="$(id -g "$transport_user" 2>/dev/null)" || exit 92
incoming_count="$(find "$work" -mindepth 1 -maxdepth 1 -print 2>/dev/null | wc -l | tr -d '[:space:]')"
[ "$incoming_count" = "5" ] || exit 92
chmod 700 "$work" >/dev/null 2>&1 || exit 92
sealed="$work/sealed"
mkdir "$sealed" >/dev/null 2>&1 || exit 92
chown 0:0 "$sealed" >/dev/null 2>&1 || exit 92
chmod 700 "$sealed" >/dev/null 2>&1 || exit 92
for fixture in \
    "$previous_name" "$candidate_name" "$test_binary_name" \
    "$manifest_name" "$signature_name"; do
    [ -f "$work/$fixture" ] && [ ! -L "$work/$fixture" ] || exit 92
    [ "$(stat -f '%u|%g' "$work/$fixture" 2>/dev/null)" = \
      "${transport_uid}|${transport_gid}" ] || exit 92
    cp -P "$work/$fixture" "$sealed/$fixture" >/dev/null 2>&1 || exit 92
    [ -f "$sealed/$fixture" ] && [ ! -L "$sealed/$fixture" ] || exit 92
    chown 0:0 "$sealed/$fixture" >/dev/null 2>&1 || exit 92
    chmod 600 "$sealed/$fixture" >/dev/null 2>&1 || exit 92
done
chmod 700 "$sealed/$test_binary_name" >/dev/null 2>&1 || exit 92
for fixture in \
    "$previous_name" "$candidate_name" "$test_binary_name" \
    "$manifest_name" "$signature_name"; do
    rm -f "$work/$fixture" >/dev/null 2>&1 || exit 92
done

input_sha_match=1
observed_previous_sha="$(sha256 -q "$sealed/$previous_name" 2>/dev/null)"
observed_candidate_sha="$(sha256 -q "$sealed/$candidate_name" 2>/dev/null)"
observed_test_binary_sha="$(sha256 -q "$sealed/$test_binary_name" 2>/dev/null)"
observed_manifest_sha="$(sha256 -q "$sealed/$manifest_name" 2>/dev/null)"
observed_signature_sha="$(sha256 -q "$sealed/$signature_name" 2>/dev/null)"
emit PREVIOUS_SHA256 "$observed_previous_sha"
emit CANDIDATE_SHA256 "$observed_candidate_sha"
emit TEST_BINARY_SHA256 "$observed_test_binary_sha"
emit MANIFEST_SHA256 "$observed_manifest_sha"
emit SIGNATURE_SHA256 "$observed_signature_sha"
[ "$observed_previous_sha" = "$previous_sha" ] || input_sha_match=0
[ "$observed_candidate_sha" = "$candidate_sha" ] || input_sha_match=0
[ "$observed_test_binary_sha" = "$test_binary_sha" ] || input_sha_match=0
[ "$observed_manifest_sha" = "$manifest_sha" ] || input_sha_match=0
[ "$observed_signature_sha" = "$signature_sha" ] || input_sha_match=0
emit INPUT_SHA_MATCH "$input_sha_match"
if [ "$input_sha_match" -ne 1 ]; then
    exit 93
fi
if [ "$test_name" != "TestFreeBSDSignedUpdaterRealPackageTransition_SW_UPD_002" ]; then
    exit 96
fi
[ "${#source_sha}" -eq 40 ] || exit 96
case "$source_sha" in *[!0-9a-f]*) exit 96 ;; esac
emit SOURCE_SHA "$source_sha"

lab_baseline_clean=1
safe_root_directory /etc || lab_baseline_clean=0
safe_root_directory /var || lab_baseline_clean=0
safe_root_directory /var/cron || lab_baseline_clean=0
safe_root_directory /var/cron/tabs || lab_baseline_clean=0
if [ -e /var/lib ] || [ -L /var/lib ]; then
    safe_root_directory /var/lib || lab_baseline_clean=0
fi
for path in \
    /etc/syswarden \
    /var/lib/syswarden \
    /usr/local/syswarden \
    /opt/syswarden \
    /var/db/syswarden \
    /var/log/syswarden \
    /usr/local/bin/syswarden \
    /usr/local/bin/syswarden-tui \
    /usr/local/etc/rc.d/syswarden \
    /usr/local/etc/rc.d/syswardenwebtui \
    /usr/local/etc/rsyslog.d/99-syswarden-siem.conf \
    /usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf \
    /var/run/syswarden.pid \
    /var/run/syswardenwebtui.pid \
    /var/run/syswarden.sock \
    /var/db/syswarden/pf-policy-snapshot.json \
    /var/db/syswarden/.pf-policy-snapshot.tmp \
    /var/db/syswarden/pf-transition-v4.02.8; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        lab_baseline_clean=0
    fi
done
cron_root_before="$(capture_cron_root_state)" || lab_baseline_clean=0
cron_allow_baseline="$(capture_cron_allow_state)" || lab_baseline_clean=0
cron_deny_baseline="$(capture_cron_deny_state)" || lab_baseline_clean=0
if [ "$cron_allow_baseline" != "absent" ] || [ "$cron_deny_baseline" != "absent" ]; then
    lab_baseline_clean=0
fi
cron_has_managed_syswarden_line
cron_managed_rc=$?
case "$cron_managed_rc" in
    0) lab_baseline_clean=0 ;;
    1) ;;
    *) lab_baseline_clean=0 ;;
esac
sysrc -a >"$work/sysrc-before" 2>/dev/null || lab_baseline_clean=0
if [ "$lab_baseline_clean" -eq 1 ]; then
    grep -E '^syswarden(webtui)?_enable:' "$work/sysrc-before" >/dev/null 2>&1
    sysrc_baseline_grep_rc=$?
    case "$sysrc_baseline_grep_rc" in
        0) lab_baseline_clean=0 ;;
        1) ;;
        *) lab_baseline_clean=0 ;;
    esac
fi
emit LAB_BASELINE_CLEAN "$lab_baseline_clean"
if [ "$lab_baseline_clean" -ne 1 ]; then
    exit 94
fi

kldload pf >/dev/null 2>&1 || true
pfctl -s info >"$work/pf-info-before" 2>&1 || exit 99
pfctl -a '*' -sr >"$work/pf-filter-before" 2>&1 || exit 99
pfctl -a '*' -sn >"$work/pf-nat-before" 2>&1 || exit 99
pfctl -a '*' -s Tables >"$work/pf-tables-before" 2>&1 || exit 99
sockstat -46l -P tcp -p 62027 >"$work/web-socket-before" 2>&1 || exit 99
pf_baseline_status="$(awk '/^Status:/{print $2; exit}' "$work/pf-info-before")"
emit PF_BASELINE_STATUS "$pf_baseline_status"
pf_baseline_empty=0
grep -Eq '[^[:space:]]' "$work/pf-filter-before" "$work/pf-nat-before" "$work/pf-tables-before"
pf_baseline_content_rc=$?
if [ "$pf_baseline_status" = "Disabled" ] && [ "$pf_baseline_content_rc" -eq 1 ]; then
    pf_baseline_empty=1
fi
emit PF_BASELINE_EMPTY "$pf_baseline_empty"
if [ "$pf_baseline_empty" -ne 1 ]; then
    exit 99
fi

initial_absent=0
pkg query -a '%n' >"$work/pkg-names-before" 2>/dev/null || exit 94
grep -Fx syswarden "$work/pkg-names-before" >/dev/null 2>&1
initial_query_rc=$?
case "$initial_query_rc" in
    0) ;;
    1) initial_absent=1 ;;
    *) exit 94 ;;
esac
emit INITIAL_PACKAGE_ABSENT "$initial_absent"
if [ "$initial_absent" -ne 1 ]; then
    exit 94
fi
package_cleanup_authorized=1

if [ ! -e /var/lib ] && [ ! -L /var/lib ]; then
    mkdir /var/lib >/dev/null 2>&1 || exit 94
    chown 0:0 /var/lib >/dev/null 2>&1 || exit 94
    chmod 755 /var/lib >/dev/null 2>&1 || exit 94
    var_lib_created=1
fi
safe_root_directory /var/lib || exit 94
mkdir /etc/syswarden /etc/syswarden/config /var/lib/syswarden >/dev/null 2>&1 || exit 94
chown 0:0 /etc/syswarden /etc/syswarden/config /var/lib/syswarden >/dev/null 2>&1 || exit 94
chmod 700 /etc/syswarden /etc/syswarden/config /var/lib/syswarden >/dev/null 2>&1 || exit 94
printf '%s\n' 'syswarden-updater-probe-user-config-v1' \
    >/etc/syswarden/config/updater-probe-user.conf || exit 94
printf '%s\n' 'syswarden-updater-probe-user-state-v1' \
    >/var/lib/syswarden/updater-probe-user.state || exit 94
chmod 600 \
    /etc/syswarden/config/updater-probe-user.conf \
    /var/lib/syswarden/updater-probe-user.state || exit 94
chown 0:0 \
    /etc/syswarden/config/updater-probe-user.conf \
    /var/lib/syswarden/updater-probe-user.state || exit 94
operator_config_before="$(capture_operator_file_state /etc/syswarden/config/updater-probe-user.conf)" || exit 94
operator_data_before="$(capture_operator_file_state /var/lib/syswarden/updater-probe-user.state)" || exit 94
operator_config_root_before="$(capture_operator_directory_state /etc/syswarden)" || exit 94
operator_config_directory_before="$(capture_operator_directory_state /etc/syswarden/config)" || exit 94
operator_data_directory_before="$(capture_operator_directory_state /var/lib/syswarden)" || exit 94
printf '%s\n' root nobody >/var/cron/allow || exit 94
printf '%s\n' daemon >/var/cron/deny || exit 94
chown 0:0 /var/cron/allow /var/cron/deny || exit 94
chmod 600 /var/cron/allow /var/cron/deny || exit 94
cron_allow_operator_before="$(capture_cron_allow_state)" || exit 94
cron_deny_operator_before="$(capture_cron_deny_state)" || exit 94

env ASSUME_ALWAYS_YES=yes SYSWARDEN_PKG_INSTALL=1 \
    timeout "$command_timeout" pkg add -f "$sealed/$previous_name" \
    >/dev/null 2>&1
previous_install_rc=$?
emit PREVIOUS_INSTALL_RC "$previous_install_rc"
if [ "$previous_install_rc" -ne 0 ]; then
    exit 95
fi
observed_previous="$(pkg query '%v' syswarden 2>/dev/null)"
emit PREVIOUS_VERSION "$observed_previous"
if [ "$observed_previous" != "$previous_version" ]; then
    exit 95
fi

mkfifo "$work/updater-output.pipe" || exit 97
awk -v test_name="$test_name" '
    $0 == "=== RUN   " test_name ||
    index($0, "--- PASS: " test_name " ") == 1 ||
    $0 == "PASS" { print }
' <"$work/updater-output.pipe" >"$work/updater-result.log" &
filter_pid=$!
timeout "$command_timeout" env \
    SYSWARDEN_FREEBSD_UPDATER_E2E=1 \
    SYSWARDEN_FREEBSD_UPDATER_MANIFEST="$sealed/$manifest_name" \
    SYSWARDEN_FREEBSD_UPDATER_SIGNATURE="$sealed/$signature_name" \
    SYSWARDEN_FREEBSD_UPDATER_PACKAGE="$sealed/$candidate_name" \
    SYSWARDEN_FREEBSD_UPDATER_RELEASE="v${candidate_version}" \
    SYSWARDEN_FREEBSD_UPDATER_PREVIOUS="v${previous_version}" \
    SYSWARDEN_FREEBSD_UPDATER_SOURCE_SHA="$source_sha" \
    "$sealed/$test_binary_name" \
    -test.run "^${test_name}$" -test.count=1 -test.v \
    >"$work/updater-output.pipe" 2>&1 &
updater_pid=$!
wait "$updater_pid"
updater_rc=$?
updater_pid=0
wait "$filter_pid"
filter_rc=$?
filter_pid=0
rm -f "$work/updater-output.pipe"
if [ "$filter_rc" -ne 0 ]; then
    updater_rc=98
fi
emit UPDATER_RC "$updater_rc"
emit UPDATER_RESULT_SHA256 "$(sha256 -q "$work/updater-result.log" 2>/dev/null)"
result_exact=0
if [ "$(wc -l <"$work/updater-result.log" | tr -d ' ')" -eq 3 ] && \
   [ "$(sed -n '1p' "$work/updater-result.log")" = "=== RUN   ${test_name}" ] && \
   grep -Eq "^--- PASS: ${test_name} \([0-9]+(\.[0-9]+)?s\)$" "$work/updater-result.log" && \
   [ "$(sed -n '3p' "$work/updater-result.log")" = "PASS" ]; then
    result_exact=1
fi
emit UPDATER_RESULT_EXACT "$result_exact"
emit UPDATER_RESULT_LINE "$(grep -F -- '--- PASS: TestFreeBSDSignedUpdaterRealPackageTransition_SW_UPD_002' "$work/updater-result.log" | tail -n 1)"

observed_candidate="$(pkg query '%v' syswarden 2>/dev/null)"
core_enabled="$(sysrc -n syswarden_enable 2>/dev/null)"
web_enabled="$(sysrc -n syswardenwebtui_enable 2>/dev/null)"
emit CANDIDATE_VERSION "$observed_candidate"
emit CORE_ENABLED "$core_enabled"
emit WEB_ENABLED "$web_enabled"
service syswarden onestatus >/dev/null 2>&1
core_status_rc=$?
emit CORE_STATUS_RC "$core_status_rc"
service syswardenwebtui onestatus >/dev/null 2>&1
web_status_rc=$?
emit WEB_STATUS_RC "$web_status_rc"

env ASSUME_ALWAYS_YES=yes timeout "$command_timeout" pkg delete -fy syswarden \
    >/dev/null 2>&1
cleanup_rc=$?
emit CLEANUP_RC "$cleanup_rc"
package_absent=0
pkg query -a '%n' >"$work/pkg-names-after" 2>/dev/null || exit 99
grep -Fx syswarden "$work/pkg-names-after" >/dev/null 2>&1
final_query_rc=$?
case "$final_query_rc" in
    0) ;;
    1) package_absent=1 ;;
    *) exit 99 ;;
esac
emit PACKAGE_ABSENT "$package_absent"

operator_state_preserved=0
operator_config_after="$(capture_operator_file_state /etc/syswarden/config/updater-probe-user.conf)"
operator_config_after_rc=$?
operator_data_after="$(capture_operator_file_state /var/lib/syswarden/updater-probe-user.state)"
operator_data_after_rc=$?
operator_config_root_after="$(capture_operator_directory_state /etc/syswarden)"
operator_config_root_after_rc=$?
operator_config_directory_after="$(capture_operator_directory_state /etc/syswarden/config)"
operator_config_directory_after_rc=$?
operator_data_directory_after="$(capture_operator_directory_state /var/lib/syswarden)"
operator_data_directory_after_rc=$?
safe_root_directory /var/lib
operator_data_parent_after_rc=$?
if [ "$operator_config_after_rc" -eq 0 ] && [ "$operator_data_after_rc" -eq 0 ] && \
   [ "$operator_config_root_after_rc" -eq 0 ] && \
   [ "$operator_config_directory_after_rc" -eq 0 ] && \
   [ "$operator_data_directory_after_rc" -eq 0 ] && [ "$operator_data_parent_after_rc" -eq 0 ] && \
   [ "$operator_config_after" = "$operator_config_before" ] && \
   [ "$operator_data_after" = "$operator_data_before" ] && \
   [ "$operator_config_root_after" = "$operator_config_root_before" ] && \
   [ "$operator_config_directory_after" = "$operator_config_directory_before" ] && \
   [ "$operator_data_directory_after" = "$operator_data_directory_before" ]; then
    operator_state_preserved=1
fi
emit OPERATOR_STATE_PRESERVED "$operator_state_preserved"

pfctl -s info >"$work/pf-info-after" 2>&1 || exit 99
pfctl -a '*' -sr >"$work/pf-filter-after" 2>&1 || exit 99
pfctl -a '*' -sn >"$work/pf-nat-after" 2>&1 || exit 99
pfctl -a '*' -s Tables >"$work/pf-tables-after" 2>&1 || exit 99
pf_final_status="$(awk '/^Status:/{print $2; exit}' "$work/pf-info-after")"
emit PF_FINAL_STATUS "$pf_final_status"
pf_final_empty=0
grep -Eq '[^[:space:]]' "$work/pf-filter-after" "$work/pf-nat-after" "$work/pf-tables-after"
pf_final_content_rc=$?
if [ "$pf_final_status" = "Disabled" ] && [ "$pf_final_content_rc" -eq 1 ]; then
    pf_final_empty=1
fi
emit PF_FINAL_EMPTY "$pf_final_empty"
pf_filter_match="$(cmp -s "$work/pf-filter-before" "$work/pf-filter-after" && printf 1 || printf 0)"
pf_nat_match="$(cmp -s "$work/pf-nat-before" "$work/pf-nat-after" && printf 1 || printf 0)"
pf_tables_match="$(cmp -s "$work/pf-tables-before" "$work/pf-tables-after" && printf 1 || printf 0)"
emit PF_FILTER_MATCH "$pf_filter_match"
emit PF_NAT_MATCH "$pf_nat_match"
emit PF_TABLES_MATCH "$pf_tables_match"
pf_syswarden_absent=1
grep -Fi 'syswarden' "$work/pf-filter-after" "$work/pf-nat-after" "$work/pf-tables-after" >/dev/null 2>&1
pf_syswarden_query_rc=$?
case "$pf_syswarden_query_rc" in
    0) pf_syswarden_absent=0 ;;
    1) ;;
    *) pf_syswarden_absent=0 ;;
esac
emit PF_SYSWARDEN_ABSENT "$pf_syswarden_absent"
pf_metadata_absent=1
for path in \
    /var/db/syswarden/pf-policy-snapshot.json \
    /var/db/syswarden/.pf-policy-snapshot.tmp \
    /var/db/syswarden/pf-transition-v4.02.8; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        pf_metadata_absent=0
    fi
done
emit PF_METADATA_ABSENT "$pf_metadata_absent"

runtime_paths_absent=1
for path in \
    /usr/local/syswarden \
    /opt/syswarden \
    /usr/local/bin/syswarden \
    /usr/local/bin/syswarden-tui \
    /usr/local/etc/rc.d/syswarden \
    /usr/local/etc/rc.d/syswardenwebtui \
    /usr/local/syswarden/bin/syswarden-cli \
    /usr/local/syswarden/bin/syswarden-core \
    /usr/local/syswarden/bin/syswarden-tui \
    /usr/local/syswarden/signatures.json \
    /var/run/syswarden.sock; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        runtime_paths_absent=0
    fi
done
emit RUNTIME_PATHS_ABSENT "$runtime_paths_absent"

service_processes_absent=1
for pattern in \
    '^/usr/local/syswarden/bin/syswarden-core($| )' \
    '^/usr/local/syswarden/bin/syswarden-tui($| )' \
    '^/usr/local/syswarden/bin/syswarden-cli web-tui($| )' \
    '^/opt/syswarden/bin/syswarden-core($| )' \
    '^/opt/syswarden/bin/syswarden-tui($| )' \
    '^/opt/syswarden/bin/syswarden-cli web-tui($| )'; do
    pgrep -f "$pattern" >/dev/null 2>&1
    process_query_rc=$?
    case "$process_query_rc" in
        0) service_processes_absent=0 ;;
        1) ;;
        *) service_processes_absent=0 ;;
    esac
done
emit SERVICE_PROCESSES_ABSENT "$service_processes_absent"

pid_files_absent=1
for path in /var/run/syswarden.pid /var/run/syswardenwebtui.pid; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        pid_files_absent=0
    fi
done
emit PID_FILES_ABSENT "$pid_files_absent"

sockstat -46l -P tcp -p 62027 >"$work/web-socket-after" 2>&1 || exit 99
web_socket_match="$(cmp -s "$work/web-socket-before" "$work/web-socket-after" && printf 1 || printf 0)"
emit WEB_SOCKET_MATCH "$web_socket_match"

sysrc_flags_absent=1
sysrc -a >"$work/sysrc-after" 2>/dev/null || exit 99
grep -E '^syswarden(webtui)?_enable:' "$work/sysrc-after" >/dev/null 2>&1
sysrc_flags_grep_rc=$?
case "$sysrc_flags_grep_rc" in
    0) sysrc_flags_absent=0 ;;
    1) ;;
    *) sysrc_flags_absent=0 ;;
esac
emit SYSRC_FLAGS_ABSENT "$sysrc_flags_absent"
sysrc_inventory_match="$(cmp -s "$work/sysrc-before" "$work/sysrc-after" && printf 1 || printf 0)"
emit SYSRC_INVENTORY_MATCH "$sysrc_inventory_match"

managed_cron_absent=1
cron_root_after="$(capture_cron_root_state)"
cron_root_after_rc=$?
cron_allow_after="$(capture_cron_allow_state)"
cron_allow_after_rc=$?
cron_deny_after="$(capture_cron_deny_state)"
cron_deny_after_rc=$?
cron_has_managed_syswarden_line
cron_after_managed_rc=$?
if [ "$cron_root_after_rc" -ne 0 ] || [ "$cron_root_after" != "$cron_root_before" ] || \
   [ "$cron_allow_after_rc" -ne 0 ] || [ "$cron_allow_after" != "$cron_allow_operator_before" ] || \
   [ "$cron_deny_after_rc" -ne 0 ] || [ "$cron_deny_after" != "$cron_deny_operator_before" ]; then
    managed_cron_absent=0
fi
case "$cron_after_managed_rc" in
    0) managed_cron_absent=0 ;;
    1) ;;
    *) managed_cron_absent=0 ;;
esac
emit MANAGED_CRON_ABSENT "$managed_cron_absent"

rsyslog_files_absent=1
for path in \
    /usr/local/etc/rsyslog.d/99-syswarden-siem.conf \
    /usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        rsyslog_files_absent=0
    fi
done
emit RSYSLOG_FILES_ABSENT "$rsyslog_files_absent"

if [ "$updater_rc" -ne 0 ] || [ "$result_exact" -ne 1 ] || \
   [ "$observed_candidate" != "$candidate_version" ] || \
   [ "$core_enabled" != "YES" ] || [ "$web_enabled" != "YES" ] || \
   [ "$core_status_rc" -ne 0 ] || [ "$web_status_rc" -ne 0 ] || \
   [ "$cleanup_rc" -ne 0 ] || [ "$package_absent" -ne 1 ] || \
   [ "$operator_state_preserved" -ne 1 ] || \
   [ "$pf_final_status" != "Disabled" ] || [ "$pf_final_empty" -ne 1 ] || \
   [ "$pf_filter_match" -ne 1 ] || [ "$pf_nat_match" -ne 1 ] || \
   [ "$pf_tables_match" -ne 1 ] || [ "$pf_syswarden_absent" -ne 1 ] || \
   [ "$pf_metadata_absent" -ne 1 ] || [ "$runtime_paths_absent" -ne 1 ] || \
   [ "$service_processes_absent" -ne 1 ] || [ "$pid_files_absent" -ne 1 ] || \
   [ "$web_socket_match" -ne 1 ] || [ "$sysrc_flags_absent" -ne 1 ] || \
   [ "$sysrc_inventory_match" -ne 1 ] || \
   [ "$managed_cron_absent" -ne 1 ] || [ "$rsyslog_files_absent" -ne 1 ]; then
    exit 100
fi

rm -rf \
    /usr/local/syswarden \
    /opt/syswarden \
    /etc/syswarden \
    /var/lib/syswarden \
    /var/db/syswarden \
    /var/log/syswarden
rm -f /var/run/syswarden.pid /var/run/syswardenwebtui.pid /var/run/syswarden.sock
rm -f /var/cron/allow /var/cron/deny
if [ "$var_lib_created" -eq 1 ]; then
    rmdir /var/lib >/dev/null 2>&1 || exit 100
fi
harness_reset_complete=0
if [ ! -e /usr/local/syswarden ] && [ ! -L /usr/local/syswarden ] && \
   [ ! -e /opt/syswarden ] && [ ! -L /opt/syswarden ] && \
   [ ! -e /etc/syswarden ] && [ ! -L /etc/syswarden ] && \
   [ ! -e /var/lib/syswarden ] && [ ! -L /var/lib/syswarden ] && \
   [ ! -e /var/db/syswarden ] && [ ! -L /var/db/syswarden ] && \
   [ ! -e /var/log/syswarden ] && [ ! -L /var/log/syswarden ] && \
   [ ! -e /var/run/syswarden.pid ] && [ ! -L /var/run/syswarden.pid ] && \
   [ ! -e /var/run/syswardenwebtui.pid ] && [ ! -L /var/run/syswardenwebtui.pid ] && \
   [ ! -e /var/run/syswarden.sock ] && [ ! -L /var/run/syswarden.sock ] && \
   [ ! -e /var/cron/allow ] && [ ! -L /var/cron/allow ] && \
   [ ! -e /var/cron/deny ] && [ ! -L /var/cron/deny ]; then
    harness_reset_complete=1
fi
emit HARNESS_RESET_COMPLETE "$harness_reset_complete"
if [ "$harness_reset_complete" -ne 1 ]; then
    exit 100
fi

package_cleanup_authorized=0
lock_released=0
if [ -f "$lock_path/owner" ] && [ ! -L "$lock_path/owner" ] && \
   [ "$(cat "$lock_path/owner" 2>/dev/null)" = "$remote_nonce" ] && \
   rm -f "$lock_path/owner" && rmdir "$lock_path" 2>/dev/null; then
    lock_released=1
    lock_acquired=0
fi
emit LAB_LOCK_RELEASED "$lock_released"
if [ "$lock_released" -ne 1 ]; then
    exit 96
fi
rm -rf "$work"
workspace_removed=0
if [ ! -e "$work" ] && [ ! -L "$work" ]; then
    workspace_removed=1
fi
emit REMOTE_WORKSPACE_REMOVED "$workspace_removed"
if [ "$workspace_removed" -ne 1 ]; then
    exit 96
fi
exit 0
'''.strip()

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_release_sha(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise FreeBSDUpdaterProbeError("release SHA is not a canonical full commit SHA")
    return value


def validate_freebsd_amd64_elf(path: Path) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64:
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary has a truncated ELF header")
        identity = header[:16]
        if (
            identity[:4] != b"\x7fELF"
            or identity[4] != 2
            or identity[5] != 1
            or identity[6] != 1
            or identity[7] != 9
        ):
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary is not a FreeBSD ELF64 LSB file")
        (
            file_type,
            machine,
            version,
            _entry,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_names,
        ) = struct.unpack("<HHIQQQIHHHHHH", header[16:])
        if file_type != 2 or machine != 62 or version != 1 or header_size != 64:
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary is not an amd64 executable")
        if program_entry_size != 56 or program_count < 1 or program_count > 128:
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary has invalid program headers")
        if program_offset < 64 or program_offset + (program_entry_size * program_count) > path.stat().st_size:
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary program headers are out of bounds")
        stream.seek(program_offset)
        for _ in range(program_count):
            program_header = stream.read(program_entry_size)
            if len(program_header) != program_entry_size:
                raise FreeBSDUpdaterProbeError("FreeBSD updater test binary program headers are truncated")
            if struct.unpack("<I", program_header[:4])[0] == 3:
                raise FreeBSDUpdaterProbeError("FreeBSD updater test binary unexpectedly has a PT_INTERP loader")


def read_go_build_metadata(path: Path) -> str:
    go_program = shutil.which("go")
    if go_program is None:
        raise FreeBSDUpdaterProbeError("Go is required to verify the updater test binary provenance")
    metadata_environment = os.environ.copy()
    metadata_environment.update({"GOENV": "off", "GOTOOLCHAIN": "local", "LC_ALL": "C"})
    result = subprocess.run(
        (str(Path(go_program).resolve()), "version", "-m", str(path)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
        env=metadata_environment,
    )
    if result.returncode != 0 or result.stderr:
        raise FreeBSDUpdaterProbeError("Go rejected the updater test binary build metadata")
    return result.stdout


def validate_go_build_metadata(metadata: str, release_sha: str) -> None:
    lines = metadata.splitlines()
    if not lines or not re.fullmatch(r".+: go1\.26\.6", lines[0]):
        raise FreeBSDUpdaterProbeError("updater test binary Go toolchain identity is not exact")
    path_lines = [line for line in lines if line.startswith("\tpath\t")]
    if path_lines != ["\tpath\tsyswarden-cli/pkg/system.test"]:
        raise FreeBSDUpdaterProbeError("updater test binary package identity is not exact")
    module_lines = [line for line in lines if line.startswith("\tmod\t")]
    if module_lines != ["\tmod\tsyswarden-cli\t(devel)\t"]:
        raise FreeBSDUpdaterProbeError("updater test binary module identity is not exact")
    if any(
        not line.startswith(("\tpath\t", "\tmod\t", "\tbuild\t"))
        for line in lines[1:]
    ):
        raise FreeBSDUpdaterProbeError("updater test binary contains unexpected Go module metadata")
    build: dict[str, str] = {}
    for line in lines:
        if not line.startswith("\tbuild\t"):
            continue
        entry = line.removeprefix("\tbuild\t")
        if "=" not in entry:
            raise FreeBSDUpdaterProbeError("updater test binary contains malformed Go build metadata")
        key, value = entry.split("=", 1)
        if key in build:
            raise FreeBSDUpdaterProbeError("updater test binary contains duplicate Go build metadata")
        build[key] = value
    expected = {
        "-buildmode": "exe",
        "-compiler": "gc",
        "-ldflags": f"-X=syswarden-cli/pkg/system.freeBSDUpdaterQualificationSourceSHA={release_sha}",
        "CGO_ENABLED": "0",
        "GOARCH": "amd64",
        "GOOS": "freebsd",
        "GOAMD64": "v1",
        "vcs": "git",
        "vcs.modified": "false",
        "vcs.revision": release_sha,
    }
    expected_keys = set(expected) | {"vcs.time"}
    if set(build) != expected_keys or any(build.get(key) != value for key, value in expected.items()):
        raise FreeBSDUpdaterProbeError("updater test binary Go build target is not exact")
    vcs_time = build["vcs.time"]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", vcs_time):
        raise FreeBSDUpdaterProbeError("updater test binary commit time is not canonical UTC")
    try:
        datetime.strptime(vcs_time, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise FreeBSDUpdaterProbeError("updater test binary commit time is invalid") from exc


def require_probe_file(path: Path, label: str, maximum_size: int) -> Path:
    candidate = vm_lab.require_regular_file(path, label)
    metadata = candidate.stat()
    if metadata.st_size < 1 or metadata.st_size > maximum_size:
        raise FreeBSDUpdaterProbeError(f"{label} size is outside the accepted range")
    return candidate


def validate_test_binary(path: Path, release_sha: str) -> Path:
    binary = require_probe_file(path, "FreeBSD updater test binary", 256 << 20)
    if stat.S_IMODE(binary.stat().st_mode) & 0o111 == 0:
        raise FreeBSDUpdaterProbeError("FreeBSD updater test binary is not executable")
    validate_freebsd_amd64_elf(binary)
    validate_go_build_metadata(read_go_build_metadata(binary), release_sha)
    return binary


@contextlib.contextmanager
def validated_test_binary_snapshot(path: Path, release_sha: str):
    source = vm_lab.require_regular_file(path, "FreeBSD updater test binary")
    if source.name != TEST_BINARY_NAME:
        raise FreeBSDUpdaterProbeError("FreeBSD updater test binary name is not canonical")
    source_parent = vm_lab.require_real_directory(
        source.parent, "FreeBSD updater test binary directory"
    )
    source_root_fd = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY)
    source_fd = -1
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        source_metadata = source.lstat()
        if (
            source_metadata.st_size < 1
            or source_metadata.st_size > 256 << 20
            or stat.S_IMODE(source_metadata.st_mode) & 0o111 == 0
        ):
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary is not a bounded executable")
        source_fd = os.open(
            source.name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=source_root_fd,
        )
        opened_metadata = os.fstat(source_fd)
        if not stat.S_ISREG(opened_metadata.st_mode) or not os.path.samestat(
            source_metadata, opened_metadata
        ):
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary identity changed while opening")
        temporary = tempfile.TemporaryDirectory(prefix="syswarden-freebsd-updater-snapshot-")
        temporary_root = Path(temporary.name)
        temporary_root.chmod(0o700)
        snapshot = temporary_root / TEST_BINARY_NAME
        destination_fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(source_fd, "rb", closefd=True) as source_stream, os.fdopen(
            destination_fd, "wb", closefd=True
        ) as destination_stream:
            source_fd = -1
            shutil.copyfileobj(source_stream, destination_stream, length=1 << 20)
            destination_stream.flush()
            os.fsync(destination_stream.fileno())
        snapshot.chmod(0o700)
        if snapshot.stat().st_size != opened_metadata.st_size:
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary changed while snapshotting")
        snapshot_digest = sha256_file(snapshot)
        validated = validate_test_binary(snapshot, release_sha)
        if sha256_file(validated) != snapshot_digest:
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary changed during validation")
        yield validated, snapshot_digest
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        os.close(source_root_fd)
        if temporary is not None:
            temporary.cleanup()


def build_report(
    evidence: dict[str, str],
    candidate: vm_lab.PackageArtifact,
    previous: vm_lab.PackageArtifact,
    manifest: Path,
    signature: Path,
    test_binary: Path,
    digests: dict[str, str],
    release_sha: str,
) -> dict[str, object]:
    expected_candidate = candidate.version
    expected_previous = previous.version
    conditions = {
        "disposable VM marker revalidated": evidence["MARKER_MATCH"] == "1",
        "exclusive VM lab lock acquired and released": evidence["LAB_LOCK_ACQUIRED"] == "1"
        and evidence["LAB_LOCK_RELEASED"] == "1"
        and evidence["REMOTE_WORKSPACE_REMOVED"] == "1",
        "all transferred bytes SHA-256 bound": evidence["INPUT_SHA_MATCH"] == "1"
        and evidence["PREVIOUS_SHA256"] == digests["previous"]
        and evidence["CANDIDATE_SHA256"] == digests["candidate"]
        and evidence["TEST_BINARY_SHA256"] == digests["test_binary"]
        and evidence["MANIFEST_SHA256"] == digests["manifest"]
        and evidence["SIGNATURE_SHA256"] == digests["signature"],
        "disposable VM product baseline was clean and safely rooted": evidence["LAB_BASELINE_CLEAN"] == "1",
        "VM started without a registered SysWarden package": evidence["INITIAL_PACKAGE_ABSENT"] == "1",
        "exact previous package installed and registered before updater": evidence["PREVIOUS_INSTALL_RC"] == "0"
        and evidence["PREVIOUS_VERSION"] == expected_previous,
        "qualification binary is linked to the release commit": evidence["SOURCE_SHA"] == release_sha,
        "signed updater test completed": evidence["UPDATER_RC"] == "0",
        "signed updater test output is bound and names the exact test": bool(
            re.fullmatch(r"[0-9a-f]{64}", evidence["UPDATER_RESULT_SHA256"])
        )
        and evidence["UPDATER_RESULT_EXACT"] == "1"
        and bool(
            re.fullmatch(
                rf"--- PASS: {re.escape(TEST_NAME)} \([0-9]+(?:\.[0-9]+)?s\)",
                evidence["UPDATER_RESULT_LINE"],
            )
        ),
        "candidate package version installed": evidence["CANDIDATE_VERSION"] == expected_candidate,
        "core rc.d service enabled and running": evidence["CORE_ENABLED"] == "YES"
        and evidence["CORE_STATUS_RC"] == "0",
        "Web-TUI rc.d service enabled and running": evidence["WEB_ENABLED"] == "YES"
        and evidence["WEB_STATUS_RC"] == "0",
        "probe cleanup removed package registration": evidence["CLEANUP_RC"] == "0"
        and evidence["PACKAGE_ABSENT"] == "1",
        "PF state returned to the clean updater-probe baseline": evidence["PF_BASELINE_STATUS"] == "Disabled"
        and evidence["PF_BASELINE_EMPTY"] == "1"
        and evidence["PF_FINAL_STATUS"] == "Disabled"
        and evidence["PF_FINAL_EMPTY"] == "1"
        and evidence["PF_FILTER_MATCH"] == "1"
        and evidence["PF_NAT_MATCH"] == "1"
        and evidence["PF_TABLES_MATCH"] == "1"
        and evidence["PF_SYSWARDEN_ABSENT"] == "1"
        and evidence["PF_METADATA_ABSENT"] == "1",
        "package-owned runtime and integration artifacts were removed": evidence["RUNTIME_PATHS_ABSENT"] == "1"
        and evidence["SERVICE_PROCESSES_ABSENT"] == "1"
        and evidence["PID_FILES_ABSENT"] == "1"
        and evidence["WEB_SOCKET_MATCH"] == "1"
        and evidence["SYSRC_FLAGS_ABSENT"] == "1"
        and evidence["SYSRC_INVENTORY_MATCH"] == "1"
        and evidence["MANAGED_CRON_ABSENT"] == "1"
        and evidence["RSYSLOG_FILES_ABSENT"] == "1",
        "operator-owned configuration and data survived the transition and package removal": evidence[
            "OPERATOR_STATE_PRESERVED"
        ]
        == "1",
        "disposable VM state was reset only after product evidence": evidence["HARNESS_RESET_COMPLETE"] == "1",
    }
    ready = all(conditions.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "harness_status": "pass",
        "product_status": "pass" if ready else "fail",
        "release_ready": ready,
        "blocker_ids": [] if ready else ["SW-UPD-FBSD-001"],
        "inputs": {
            "release_sha": release_sha,
            "candidate": {"name": candidate.path.name, "version": candidate.version, "sha256": digests["candidate"]},
            "previous": {"name": previous.path.name, "version": previous.version, "sha256": digests["previous"]},
            "manifest": {"name": manifest.name, "sha256": digests["manifest"]},
            "signature": {"name": signature.name, "sha256": digests["signature"]},
            "test_binary": {"name": test_binary.name, "sha256": digests["test_binary"]},
        },
        "observed": evidence,
        "harness_conditions": conditions,
    }


def _run_probe_from_snapshot(
    args: argparse.Namespace,
    test_binary_digest: str,
    *,
    runner: vm_lab.CommandRunner | None = None,
) -> dict[str, object]:
    ssh_program = vm_lab.validate_transport_program(args.ssh, "ssh")
    scp_program = vm_lab.validate_transport_program(args.scp, "scp")
    marker_token = vm_lab.resolve_marker_token(args)
    host, identity, known_hosts = vm_lab.validate_transport_inputs(
        args.ssh_host,
        args.ssh_port,
        args.ssh_user,
        args.identity_file,
        args.known_hosts_file,
        marker_token,
    )
    if args.command_timeout < 60 or args.command_timeout > 1800:
        raise FreeBSDUpdaterProbeError("command timeout must be between 60 and 1800 seconds")
    release_sha = validate_release_sha(args.release_sha)
    candidate, previous = vm_lab.discover_package_pair(
        args.packages_dir, args.previous_packages_dir
    )
    manifest = require_probe_file(args.manifest, "signed update manifest", 64 << 10)
    signature = require_probe_file(args.signature, "signed update signature", 256)
    test_binary = validate_test_binary(args.test_binary, release_sha)
    if manifest.name != MANIFEST_NAME or signature.name != SIGNATURE_NAME:
        raise FreeBSDUpdaterProbeError("signed update asset names are not canonical")
    if test_binary.name != TEST_BINARY_NAME:
        raise FreeBSDUpdaterProbeError("FreeBSD updater test binary name is not canonical")
    if sha256_file(test_binary) != test_binary_digest:
        raise FreeBSDUpdaterProbeError("FreeBSD updater test binary changed before transport")
    digests = {
        "previous": previous.sha256,
        "candidate": candidate.sha256,
        "test_binary": test_binary_digest,
        "manifest": sha256_file(manifest),
        "signature": sha256_file(signature),
    }

    active_runner = runner or vm_lab.CommandRunner()
    ssh_base = vm_lab.ssh_arguments(
        ssh_program, host, args.ssh_port, args.ssh_user, identity, known_hosts
    )
    probe = active_runner.run(
        ssh_base + ("/bin/sh", "-s", "--"),
        timeout=45,
        input_text=vm_lab.script_stdin_with_token(vm_lab.PROBE_SCRIPT, marker_token),
    )
    vm_lab.require_transport_success(probe, "FreeBSD updater VM prerequisite probe")
    vm_lab.validate_probe(vm_lab.parse_markers(probe.stdout, vm_lab.PROBE_KEYS))

    remote_root = f"/tmp/syswarden-freebsd-lot0-{uuid.uuid4().hex}"
    prepared = active_runner.run(
        ssh_base + ("sudo", "-n", "/bin/sh", "-s", "--", remote_root, args.ssh_user),
        timeout=30,
        input_text=vm_lab.script_stdin_with_token(REMOTE_ROOT_PREPARE_SCRIPT, marker_token),
    )
    vm_lab.require_transport_success(prepared, "prepare FreeBSD updater workspace")

    inputs = (previous.path, candidate.path, test_binary, manifest, signature)
    remote: vm_lab.CommandResult | None = None
    evidence: dict[str, str] | None = None
    in_band_cleanup_proven = False
    primary_error: BaseException | None = None
    primary_traceback = None
    try:
        for source in inputs:
            copied = active_runner.run(
                vm_lab.scp_arguments(
                    scp_program,
                    host,
                    args.ssh_port,
                    args.ssh_user,
                    identity,
                    known_hosts,
                    source,
                    f"{remote_root}/{source.name}",
                ),
                timeout=180,
            )
            vm_lab.require_transport_success(copied, f"copy {source.name} into updater VM")
        remote = active_runner.run(
            ssh_base
            + (
                "sudo",
                "-n",
                "/bin/sh",
                "-s",
                "--",
                remote_root,
                previous.path.name,
                previous.sha256,
                previous.version,
                candidate.path.name,
                candidate.sha256,
                candidate.version,
                test_binary.name,
                digests["test_binary"],
                manifest.name,
                digests["manifest"],
                signature.name,
                digests["signature"],
                str(args.command_timeout),
                TEST_NAME,
                release_sha,
                args.ssh_user,
            ),
            timeout=(args.command_timeout * 3) + 180,
            input_text=vm_lab.script_stdin_with_token(REMOTE_PROBE_SCRIPT, marker_token),
        )
        vm_lab.require_transport_success(remote, "FreeBSD signed-updater transition probe")
        evidence = vm_lab.parse_markers(remote.stdout, EVIDENCE_KEYS)
        vm_lab.require_in_band_transport_cleanup(evidence)
        in_band_cleanup_proven = True
    except BaseException as exc:
        primary_error = exc
        primary_traceback = exc.__traceback__

    cleanup_error: vm_lab.FreeBSDVMLabError | None = None
    if not in_band_cleanup_proven:
        try:
            vm_lab.cleanup_transport_workspace(
                active_runner,
                ssh_base,
                remote_root,
                marker_token,
                cleanup_script=REMOTE_ROOT_CLEANUP_SCRIPT,
            )
        except vm_lab.FreeBSDVMLabError as exc:
            cleanup_error = exc

    if primary_error is not None:
        if cleanup_error is not None and isinstance(primary_error, Exception):
            raise vm_lab.FreeBSDVMLabError(
                f"{primary_error}; {cleanup_error}"
            ) from primary_error
        raise primary_error.with_traceback(primary_traceback)
    if cleanup_error is not None:
        raise cleanup_error
    if remote is None or evidence is None:
        raise FreeBSDUpdaterProbeError(
            "FreeBSD signed-updater transition did not produce a result"
        )
    return build_report(
        evidence,
        candidate,
        previous,
        manifest,
        signature,
        test_binary,
        digests,
        release_sha,
    )


def run_probe(
    args: argparse.Namespace, *, runner: vm_lab.CommandRunner | None = None
) -> dict[str, object]:
    release_sha = validate_release_sha(args.release_sha)
    with validated_test_binary_snapshot(args.test_binary, release_sha) as snapshot:
        test_binary, test_binary_digest = snapshot
        snapshot_args = argparse.Namespace(**vars(args))
        snapshot_args.test_binary = test_binary
        return _run_probe_from_snapshot(
            snapshot_args,
            test_binary_digest,
            runner=runner,
        )


def error_report(exc: Exception) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "harness_status": "fail",
        "product_status": "not_evaluated",
        "release_ready": False,
        "blocker_ids": ["SW-UPD-FBSD-001"],
        "error": str(exc),
    }


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise FreeBSDUpdaterProbeError(f"signed-updater report contains duplicate key {key!r}")
        decoded[key] = value
    return decoded


def reject_json_constant(value: str) -> object:
    raise FreeBSDUpdaterProbeError(f"signed-updater report contains invalid constant {value!r}")


def read_probe_report(path: Path) -> dict[str, object]:
    report_path = require_probe_file(path, "signed-updater report", 2 << 20)
    try:
        encoded = report_path.read_text(encoding="utf-8")
        decoded = json.loads(
            encoded,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except UnicodeError as exc:
        raise FreeBSDUpdaterProbeError("signed-updater report is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise FreeBSDUpdaterProbeError("signed-updater report is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise FreeBSDUpdaterProbeError("signed-updater report root is not an object")
    return decoded


def validate_report_timestamp(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00", value
    ):
        raise FreeBSDUpdaterProbeError("signed-updater report timestamp is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise FreeBSDUpdaterProbeError("signed-updater report timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise FreeBSDUpdaterProbeError("signed-updater report timestamp is not UTC")
    return value


def verify_probe_report(args: argparse.Namespace) -> None:
    release_sha = validate_release_sha(args.release_sha)
    candidate, previous = vm_lab.discover_package_pair(
        args.packages_dir, args.previous_packages_dir
    )
    manifest = require_probe_file(args.manifest, "signed update manifest", 64 << 10)
    signature = require_probe_file(args.signature, "signed update signature", 256)
    if manifest.name != MANIFEST_NAME or signature.name != SIGNATURE_NAME:
        raise FreeBSDUpdaterProbeError("signed update asset names are not canonical")
    with validated_test_binary_snapshot(args.test_binary, release_sha) as snapshot:
        test_binary, test_binary_digest = snapshot
        if sha256_file(test_binary) != test_binary_digest:
            raise FreeBSDUpdaterProbeError("FreeBSD updater test binary changed before report verification")
        digests = {
            "previous": previous.sha256,
            "candidate": candidate.sha256,
            "test_binary": test_binary_digest,
            "manifest": sha256_file(manifest),
            "signature": sha256_file(signature),
        }
        report = read_probe_report(args.report)
        if type(report.get("schema_version")) is not int:
            raise FreeBSDUpdaterProbeError("signed-updater report schema version type is invalid")
        if type(report.get("release_ready")) is not bool:
            raise FreeBSDUpdaterProbeError("signed-updater report readiness type is invalid")
        evidence = report.get("observed")
        if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_KEYS or any(
            not isinstance(value, str) for value in evidence.values()
        ):
            raise FreeBSDUpdaterProbeError("signed-updater report evidence inventory is not exact")
        conditions = report.get("harness_conditions")
        if not isinstance(conditions, dict) or any(
            type(value) is not bool for value in conditions.values()
        ):
            raise FreeBSDUpdaterProbeError("signed-updater report conditions are not exact booleans")
        generated_at = validate_report_timestamp(report.get("generated_at"))
        expected = build_report(
            evidence,
            candidate,
            previous,
            manifest,
            signature,
            test_binary,
            digests,
            release_sha,
        )
        expected["generated_at"] = generated_at
        if report != expected:
            raise FreeBSDUpdaterProbeError("signed-updater report does not recompute exactly")


def add_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--packages-dir", type=Path, required=True)
    parser.add_argument("--previous-packages-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--test-binary", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="execute the real signed-updater transition")
    add_artifact_arguments(run_parser)
    run_parser.add_argument("--ssh-host", required=True)
    run_parser.add_argument("--ssh-port", type=int, required=True)
    run_parser.add_argument("--ssh-user", required=True)
    run_parser.add_argument("--identity-file", type=Path, required=True)
    run_parser.add_argument("--known-hosts-file", type=Path, required=True)
    run_parser.add_argument("--vm-marker-token-file", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--ssh", default="ssh")
    run_parser.add_argument("--scp", default="scp")
    run_parser.add_argument("--command-timeout", type=int, default=600)
    run_parser.add_argument("--pretty", action="store_true")
    verify_parser = commands.add_parser("verify", help="recompute a sealed signed-updater report")
    add_artifact_arguments(verify_parser)
    verify_parser.add_argument("--report", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "verify":
        try:
            verify_probe_report(args)
        except (FreeBSDUpdaterProbeError, vm_lab.FreeBSDVMLabError, OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        return 0
    try:
        report = run_probe(args)
    except (FreeBSDUpdaterProbeError, vm_lab.FreeBSDVMLabError, OSError, ValueError) as exc:
        report = error_report(exc)
    vm_lab.write_report(args.output, report, args.pretty)
    return 0 if report.get("release_ready") is True else 2


if __name__ == "__main__":
    sys.exit(main())
