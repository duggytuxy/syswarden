#!/usr/bin/bash -p
case "$-" in
    *p*) ;;
    *) printf 'ERROR: privileged Bash mode is required\n' >&2; exit 2 ;;
esac
if [[ -n "${LD_PRELOAD-}" || -n "${LD_AUDIT-}" ]]; then
    printf 'ERROR: trusted launch environment must not define LD_PRELOAD or LD_AUDIT\n' >&2
    exit 2
fi
set -euo pipefail
umask 077
PATH='/usr/bin:/bin'
export PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONHOME PYTHONPATH PYTHONSTARTUP \
    PYTHONINSPECT PYTHONWARNINGS PYTHONBREAKPOINT PYTHONUSERBASE PYTHONEXECUTABLE \
    LD_PRELOAD LD_AUDIT

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

usage() {
    cat >&2 <<'EOF'
Usage: source_allocation_sandbox.sh \
  --repository ABSOLUTE_REPOSITORY \
  --candidate-commit FULL_SHA \
  --toolchain-archive ABSOLUTE_GO_ARCHIVE \
  --module-cache ABSOLUTE_READ_ONLY_MODULE_CACHE \
  --output-root ABSENT_ABSOLUTE_OUTPUT_ROOT
EOF
    exit 2
}

repository=''
candidate_commit=''
toolchain_archive=''
module_cache=''
output_root=''

while (($#)); do
    case "$1" in
        --repository|--candidate-commit|--toolchain-archive|--module-cache|--output-root)
            (($# >= 2)) || usage
            case "$1" in
                --repository) repository="$2" ;;
                --candidate-commit) candidate_commit="$2" ;;
                --toolchain-archive) toolchain_archive="$2" ;;
                --module-cache) module_cache="$2" ;;
                --output-root) output_root="$2" ;;
            esac
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ "${candidate_commit}" =~ ^[0-9a-f]{40}$ ]] || fail 'candidate commit must be one lowercase full SHA'
[[ -n "${repository}" && -n "${toolchain_archive}" ]] || usage
[[ -n "${module_cache}" && -n "${output_root}" ]] || usage

canonical_existing() {
    local value="$1"
    local label="$2"
    local resolved
    [[ "${value}" == /* ]] || fail "${label} must be absolute"
    resolved="$(realpath -e -- "${value}")" || fail "${label} does not exist"
    [[ "${resolved}" == "${value}" ]] || fail "${label} must be canonical and contain no symbolic link"
}

path_is_within() {
    local candidate="$1"
    local ancestor="$2"
    [[ "${candidate}" == "${ancestor}" ]] || \
        [[ "${ancestor}" == / && "${candidate}" == /* ]] || \
        [[ "${candidate}" == "${ancestor}/"* ]]
}

paths_overlap() {
    path_is_within "$1" "$2" || path_is_within "$2" "$1"
}

canonical_existing "${repository}" 'repository'
canonical_existing "${toolchain_archive}" 'toolchain archive'
canonical_existing "${module_cache}" 'module cache'
os_release_source="$(realpath -e -- /etc/os-release)" || fail 'system os-release cannot be resolved'
canonical_existing "${os_release_source}" 'system os-release'
[[ -f "${os_release_source}" && ! -L "${os_release_source}" ]] || fail 'system os-release is unsafe'
[[ "$(stat -c '%u' -- "${os_release_source}")" == 0 ]] || fail 'system os-release owner is unsafe'
os_release_permissions="$(stat -c '%a' -- "${os_release_source}")"
(( (8#${os_release_permissions} & 8#022) == 0 )) || fail 'system os-release is group or world writable'
[[ -d "${repository}" && ! -L "${repository}" ]] || fail 'repository must be one real directory'
[[ -d "${module_cache}" && ! -L "${module_cache}" ]] || fail 'module cache must be one real directory'
repository_identity="$(stat -c '%d:%i:%f:%u:%g' -- "${repository}")"
module_cache_identity="$(stat -c '%d:%i:%f:%u:%g' -- "${module_cache}")"
[[ -f "${toolchain_archive}" && ! -L "${toolchain_archive}" ]] || \
    fail "unsafe input file: ${toolchain_archive}"
[[ "$(stat -c '%h' -- "${toolchain_archive}")" == 1 ]] || \
    fail "multiply linked input file: ${toolchain_archive}"

output_parent="$(dirname -- "${output_root}")"
[[ "${output_root}" == /* ]] || fail 'output root must be absolute'
[[ "$(realpath -m -- "${output_root}")" == "${output_root}" ]] || fail 'output root must be canonical'
canonical_existing "${output_parent}" 'output parent'
[[ ! -e "${output_root}" && ! -L "${output_root}" ]] || fail 'output root must not already exist'
[[ "$(stat -c '%u' -- "${output_parent}")" == "$(id -u)" ]] || fail 'output parent owner is unsafe'
[[ "$(stat -c '%a' -- "${output_parent}")" == 700 ]] || fail 'output parent must use mode 0700'
for protected_input in "${repository}" "${module_cache}" "${toolchain_archive}"; do
    ! paths_overlap "${output_root}" "${protected_input}" || \
        fail "output root overlaps protected input: ${protected_input}"
done

for system_parent in / /usr /usr/bin; do
    [[ -d "${system_parent}" && ! -L "${system_parent}" ]] || \
        fail "system executable parent is unsafe: ${system_parent}"
    [[ "$(stat -c '%u' -- "${system_parent}")" == 0 ]] || \
        fail "system executable parent owner is unsafe: ${system_parent}"
    parent_permissions="$(stat -c '%a' -- "${system_parent}")"
    (( (8#${parent_permissions} & 8#022) == 0 )) || \
        fail "system executable parent is group or world writable: ${system_parent}"
done

shell_executable='/usr/bin/bash'
canonical_existing "${shell_executable}" 'Bash executable'
[[ "$(realpath -e -- "/proc/$$/exe")" == "${shell_executable}" ]] || \
    fail 'launcher is not running under the canonical system Bash executable'
[[ -f "${shell_executable}" && -x "${shell_executable}" && ! -L "${shell_executable}" ]] || \
    fail 'Bash executable is unsafe'
[[ "$(stat -c '%u' -- "${shell_executable}")" == 0 ]] || fail 'Bash executable owner is unsafe'
[[ "$(stat -c '%h' -- "${shell_executable}")" == 1 ]] || fail 'Bash executable is multiply linked'
shell_permissions="$(stat -c '%a' -- "${shell_executable}")"
(( (8#${shell_permissions} & 8#022) == 0 )) || fail 'Bash executable is group or world writable'
shell_identity="$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%h' -- "${shell_executable}")"
shell_sha256="$(sha256sum -- "${shell_executable}" | awk '{print $1}')"
[[ "${shell_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'cannot attest the system Bash executable'

verify_system_shell() {
    [[ "$(realpath -e -- "/proc/$$/exe")" == "${shell_executable}" ]] || \
        fail 'launcher Bash process identity changed'
    [[ "$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%h' -- "${shell_executable}")" == "${shell_identity}" ]] || \
        fail 'system Bash executable identity changed'
    [[ "$(sha256sum -- "${shell_executable}" | awk '{print $1}')" == "${shell_sha256}" ]] || \
        fail 'system Bash executable digest changed'
}

sandbox_executable='/usr/bin/bwrap'
canonical_existing "${sandbox_executable}" 'bubblewrap executable'
[[ -f "${sandbox_executable}" && -x "${sandbox_executable}" && ! -L "${sandbox_executable}" ]] || fail 'bubblewrap executable is unsafe'
[[ "$(stat -c '%h' -- "${sandbox_executable}")" == 1 ]] || fail 'bubblewrap executable is multiply linked'
sandbox_owner="$(stat -c '%u' -- "${sandbox_executable}")"
[[ "${sandbox_owner}" == 0 ]] || fail 'bubblewrap executable owner is unsafe'
permissions="$(stat -c '%a' -- "${sandbox_executable}")"
(( (8#${permissions} & 8#022) == 0 )) || fail 'bubblewrap executable is group or world writable'
sandbox_identity="$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%h' -- "${sandbox_executable}")"
sandbox_sha256="$(sha256sum -- "${sandbox_executable}" | awk '{print $1}')"
[[ "${sandbox_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'cannot attest the system bubblewrap executable'

python_entry='/usr/bin/python3'
[[ -e "${python_entry}" || -L "${python_entry}" ]] || fail 'system python3 entrypoint is absent'
[[ "$(stat -c '%u' -- "${python_entry}")" == 0 ]] || fail 'system python3 entrypoint owner is unsafe'
python_executable="$(realpath -e -- "${python_entry}")" || fail 'system python3 target cannot be resolved'
[[ "${python_executable}" =~ ^/usr/bin/python3(\.[0-9]+)?$ ]] || fail 'system python3 target path is unsafe'
canonical_existing "${python_executable}" 'system python3 target'
[[ -f "${python_executable}" && -x "${python_executable}" && ! -L "${python_executable}" ]] || fail 'system python3 target is unsafe'
[[ "$(stat -c '%u' -- "${python_executable}")" == 0 ]] || fail 'system python3 target owner is unsafe'
[[ "$(stat -c '%h' -- "${python_executable}")" == 1 ]] || fail 'system python3 target is multiply linked'
python_permissions="$(stat -c '%a' -- "${python_executable}")"
(( (8#${python_permissions} & 8#022) == 0 )) || fail 'system python3 target is group or world writable'
python_identity="$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%h' -- "${python_executable}")"
python_sha256="$(sha256sum -- "${python_executable}" | awk '{print $1}')"
[[ "${python_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail 'cannot attest the system python3 target'

verify_system_python() {
    [[ "$(realpath -e -- "${python_entry}")" == "${python_executable}" ]] || \
        fail 'system python3 entrypoint target changed'
    [[ "$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%h' -- "${python_executable}")" == "${python_identity}" ]] || \
        fail 'system python3 target identity changed'
    [[ "$(sha256sum -- "${python_executable}" | awk '{print $1}')" == "${python_sha256}" ]] || \
        fail 'system python3 target digest changed'
}

verify_system_python
"${python_executable}" -I - "${repository}" "${module_cache}" <<'PY'
import os
import stat
import sys

maximum_entries = 500_000
for root_name in sys.argv[1:]:
    root_info = os.lstat(root_name)
    pending = [root_name]
    entries = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > maximum_entries:
                    raise SystemExit(f"protected input tree exceeds entry bound: {root_name}")
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != root_info.st_dev:
                    raise SystemExit(f"protected input tree contains a nested filesystem: {entry.path}")
                if info.st_uid != root_info.st_uid or stat.S_IMODE(info.st_mode) & 0o022:
                    raise SystemExit(f"protected input tree contains an unsafe owner or mode: {entry.path}")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(entry.path)
                elif not stat.S_ISREG(info.st_mode):
                    raise SystemExit(f"protected input tree contains a special entry: {entry.path}")
    after = os.lstat(root_name)
    before_identity = (root_info.st_dev, root_info.st_ino, root_info.st_mode, root_info.st_uid, root_info.st_gid)
    after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid)
    if after_identity != before_identity:
        raise SystemExit(f"protected input tree root changed during scan: {root_name}")
PY

producer="${repository}/scripts/ci/source_allocation_producer.py"
contract="${repository}/scripts/ci/source_allocation_contract_v4.10.0.json"
benchmark="${repository}/scripts/ci/source_allocation_probe.go"
fixture="${repository}/scripts/ci/fixtures/source-allocation/waap-event-v1.json"
catalog="${repository}/scripts/ci/fixtures/source-allocation/signatures-v1.json"
gate="${repository}/scripts/ci/source_allocation_gate.py"
for source_file in "${producer}" "${contract}" "${benchmark}" "${fixture}" "${catalog}" "${gate}"; do
    canonical_existing "${source_file}" "repository input ${source_file}"
    [[ -f "${source_file}" && ! -L "${source_file}" ]] || fail "unsafe repository input: ${source_file}"
    [[ "$(stat -c '%h' -- "${source_file}")" == 1 ]] || fail "multiply linked repository input: ${source_file}"
done

install -d -m 0700 -- "${output_root}"
control_root="$(mktemp -d "${output_parent}/.syswarden-allocation-control.XXXXXXXX")"
! paths_overlap "${output_root}" "${control_root}" || fail 'output root overlaps execution control root'
unix_canary_root="$(mktemp -d /tmp/.syswarden-allocation-unix-canary.XXXXXXXX)"
unix_canary_path="${unix_canary_root}/host.sock"
cleanup_control() {
    rm -f -- "${control_root}/execution-control.json"
    rmdir -- "${control_root}" 2>/dev/null || true
    rm -f -- "${unix_canary_path}"
    rmdir -- "${unix_canary_root}" 2>/dev/null || true
}
trap cleanup_control EXIT HUP INT TERM
recorded_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
control_attestation="${control_root}/execution-control.json"

outer_sandbox_arguments=(
    --die-with-parent
    --new-session
    --unshare-user
    --unshare-net
    --unshare-pid
    --unshare-ipc
    --unshare-uts
    --ro-bind /usr /usr
    --ro-bind /lib /lib
    --ro-bind-try /lib64 /lib64
    --ro-bind "${os_release_source}" /etc/os-release
    --dir /run
    --tmpfs /tmp
    --dir /var
    --tmpfs /var/tmp
    --bind "${output_root}" "${output_root}"
    --ro-bind "${repository}" "${repository}"
    --ro-bind "${toolchain_archive}" "${toolchain_archive}"
    --ro-bind "${module_cache}" "${module_cache}"
    --ro-bind "${control_root}" "${control_root}"
    --proc /proc
    --dev /dev
    --clearenv
    --setenv PATH /usr/bin:/bin
    --setenv LC_ALL C
    --setenv LANG C
    --setenv TZ UTC
)

verify_system_python
verify_system_shell
"${python_executable}" -I - "${unix_canary_path}" <<'PY'
import socket
import sys

canary = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    canary.bind(sys.argv[1])
finally:
    canary.close()
PY
[[ -S "${unix_canary_path}" ]] || fail 'host Unix socket canary was not created'
"${sandbox_executable}" "${outer_sandbox_arguments[@]}" \
    -- "${python_executable}" -I - "${unix_canary_path}" <<'PY'
import errno
import socket
import sys

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    client.connect(sys.argv[1])
except OSError as error:
    if error.errno != errno.ENOENT:
        raise
else:
    raise SystemExit("host Unix socket remained visible inside the outer sandbox")
finally:
    client.close()
PY

verify_system_python
verify_system_shell
"${python_executable}" -I - "${control_attestation}" "${candidate_commit}" "${recorded_at}" \
    "${sandbox_sha256}" "${python_executable}" "${python_sha256}" \
    "${shell_executable}" "${shell_sha256}" <<'PY'
import json
import os
import sys

(
    path,
    candidate_commit,
    recorded_at,
    sandbox_sha256,
    python_executable,
    python_sha256,
    shell_executable,
    shell_sha256,
) = sys.argv[1:]
document = {
    "schema_version": 1,
    "schema_id": "syswarden-allocation-execution-control-attestation/v1",
    "candidate_commit": candidate_commit,
    "architecture": "linux/amd64",
    "recorded_at": recorded_at,
    "attested_by": "syswarden-source-allocation-sandbox",
    "producer_egress_denied": True,
    "repository_source_read_only": True,
    "build_checkouts_producer_writable": True,
    "persistent_writes_limited_to_evidence_root": True,
    "probe_egress_denied": True,
    "probe_persistent_filesystem_read_only": True,
    "sandbox_kind": "bubblewrap-minimal-root-unshared-network/v2",
    "sandbox_executable_path": "/usr/bin/bwrap",
    "sandbox_executable_sha256": sandbox_sha256,
    "python_executable_path": python_executable,
    "python_executable_sha256": python_sha256,
    "shell_executable_path": shell_executable,
    "shell_executable_sha256": shell_sha256,
    "outer_unix_socket_canary_passed": True,
    "probe_unix_socket_canary_required": True,
    "runner_threat_model": "protected-dedicated-runner-trusted-launch-environment-no-hostile-same-uid-process/v1",
}
wire = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
descriptor = os.open(
    path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
    0o600,
)
try:
    view = memoryview(wire)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("short attestation write")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY

verify_system_python
verify_system_shell
"${sandbox_executable}" \
    "${outer_sandbox_arguments[@]}" \
    --chdir "${repository}" \
    -- "${python_executable}" -I "${producer}" \
        --repository "${repository}" \
        --candidate-commit "${candidate_commit}" \
        --contract "${contract}" \
        --benchmark-source "${benchmark}" \
        --fixture "${fixture}" \
        --signature-catalog "${catalog}" \
        --toolchain-archive "${toolchain_archive}" \
        --module-cache "${module_cache}" \
        --execution-control-attestation "${control_attestation}" \
        --probe-sandbox-executable "${sandbox_executable}" \
        --output-root "${output_root}" \
        --prepared-output-root

[[ "$(stat -c '%d:%i:%s:%Y:%Z:%f:%u:%g:%h' -- "${sandbox_executable}")" == "${sandbox_identity}" ]] || \
    fail 'system bubblewrap executable changed during production'
[[ "$(sha256sum -- "${sandbox_executable}" | awk '{print $1}')" == "${sandbox_sha256}" ]] || \
    fail 'system bubblewrap executable digest changed during production'
[[ "$(stat -c '%d:%i:%f:%u:%g' -- "${repository}")" == "${repository_identity}" ]] || \
    fail 'repository root identity changed during production'
[[ "$(stat -c '%d:%i:%f:%u:%g' -- "${module_cache}")" == "${module_cache_identity}" ]] || \
    fail 'module cache root identity changed during production'
verify_system_python
verify_system_shell
PYTHONDONTWRITEBYTECODE=1 "${python_executable}" -I "${gate}" validate-raw \
    --contract "${contract}" \
    --bundle-root "${output_root}" \
    --candidate-commit "${candidate_commit}"
verify_system_python
verify_system_shell
printf 'Source allocation bundle produced and validated under enforced controls: %s\n' "${output_root}"
