#!/usr/bin/env bash
# Qualify the installed SysWarden OSINT path against the deterministic TLS fixture.
#
# Use only on a disposable lab or isolated CI host. Before running this script,
# an outer harness must start osint_tls_fixture.py on HTTPS port 443, map the
# supported origin names to that server, and trust its temporary CA through the
# operating system trust mechanism. The installed candidate and its normal
# configuration must already be ready. This script invokes the real
# `syswarden update-feeds` command, including its normal firewall reapply. It
# never supplies a product URL, downloader, validation, or trust bypass.
#
# Example:
#   sudo bash scripts/ci/osint_tls_qualification_lab.sh \
#     --cli /opt/syswarden/bin/syswarden-cli \
#     --mode-file /var/lib/syswarden-osint-fixture/mode \
#     --list-root /etc/syswarden/lists \
#     --evidence-dir /var/lib/syswarden-osint-fixture/evidence
#
# The runner preserves evidence on both success and failure. It atomically
# restores the original fixture mode on exit. The outer harness remains the
# owner of server, DNS, CA, and disposable-host cleanup. Do not delete product
# state from this runner.
set -euo pipefail
IFS=$'\n\t'
export LC_ALL=C
export LANG=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

readonly EXPECTED_WARNING='[WARNING] OSINT source https://lists.blocklist.de ignored 1 non-public or special-use CIDR entry.'
readonly EXPECTED_MALFORMED='invalid CIDR at line 5'
readonly EXPECTED_BELOW_MINIMUM='feed contains 3 canonical entries after ignoring 1 non-public or special-use entries, minimum is 4'
readonly SIX_TO_FOUR='2002:982a:b983::982a:b983'
readonly NO_PROXY_NAMES='cinsscore.com,lists.blocklist.de,raw.githubusercontent.com,gitlab.com,cdn.jsdelivr.net,bitbucket.org,codeberg.org'
SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly SCRIPT_ROOT
readonly FIXTURE_SCRIPT=${SCRIPT_ROOT}/osint_tls_fixture.py

usage() {
  cat >&2 <<'USAGE'
usage: osint_tls_qualification_lab.sh --cli ABSOLUTE_PATH --mode-file ABSOLUTE_PATH --list-root ABSOLUTE_PATH --evidence-dir ABSOLUTE_PATH [--config ABSOLUTE_PATH]
USAGE
}

CLI_PATH=
MODE_PATH=
LIST_ROOT=
EVIDENCE_ROOT=
CONFIG_PATH=
while [[ $# -gt 0 ]]; do
  case $1 in
    --cli|--mode-file|--list-root|--evidence-dir|--config)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case $1 in
        --cli) CLI_PATH=$2 ;;
        --mode-file) MODE_PATH=$2 ;;
        --list-root) LIST_ROOT=$2 ;;
        --evidence-dir) EVIDENCE_ROOT=$2 ;;
        --config) CONFIG_PATH=$2 ;;
      esac
      shift 2
      ;;
    *) usage; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "OSINT TLS qualification must run as root on an isolated lab host" >&2
  exit 1
fi
for required in CLI_PATH MODE_PATH LIST_ROOT EVIDENCE_ROOT; do
  if [[ -z ${!required} ]]; then
    usage
    exit 2
  fi
done

python3 - "${CLI_PATH}" "${MODE_PATH}" "${LIST_ROOT}" "${EVIDENCE_ROOT}" "${FIXTURE_SCRIPT}" "${CONFIG_PATH}" <<'PY'
import os
import stat
import sys

cli, mode, list_root, evidence, fixture, config = sys.argv[1:]
for label, path in (
    ("CLI", cli),
    ("mode file", mode),
    ("list root", list_root),
    ("evidence directory", evidence),
    ("fixture script", fixture),
):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise SystemExit(f"{label} path must be canonical and absolute")
for label, path in (("CLI", cli), ("mode file", mode), ("fixture script", fixture)):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"{label} must be one real regular file")
if not os.access(cli, os.X_OK):
    raise SystemExit("CLI is not executable")
cli_info = os.lstat(cli)
if cli_info.st_uid != 0 or stat.S_IMODE(cli_info.st_mode) & 0o022:
    raise SystemExit("installed CLI must be root-owned and not group or world writable")
mode_info = os.lstat(mode)
mode_parent = os.lstat(os.path.dirname(mode))
if (
    mode_info.st_uid != 0
    or not 1 <= mode_info.st_size <= 64
    or stat.S_IMODE(mode_info.st_mode) & 0o022
    or not stat.S_ISDIR(mode_parent.st_mode)
    or stat.S_ISLNK(mode_parent.st_mode)
    or mode_parent.st_uid != 0
    or stat.S_IMODE(mode_parent.st_mode) & 0o022
):
    raise SystemExit("mode file or its parent has unsafe ownership, size, or permissions")
root_info = os.lstat(list_root)
if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
    raise SystemExit("list root must be one real directory")
if root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) & 0o022:
    raise SystemExit("list root must be root-owned and not group or world writable")
if os.path.lexists(evidence):
    raise SystemExit("evidence directory already exists")
parent = os.path.dirname(evidence)
parent_info = os.lstat(parent)
if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
    raise SystemExit("evidence parent must be one real directory")
if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
    raise SystemExit("evidence parent must be owner-controlled and not group or world writable")
if config:
    if not os.path.isabs(config) or os.path.normpath(config) != config:
        raise SystemExit("config path must be canonical and absolute")
    config_info = os.lstat(config)
    if not stat.S_ISREG(config_info.st_mode) or stat.S_ISLNK(config_info.st_mode):
        raise SystemExit("config must be one real regular file")
PY

install -d -m 0700 -o root -g root "${EVIDENCE_ROOT}"

ORIGINAL_MODE=$(python3 - "${MODE_PATH}" <<'PY'
from pathlib import Path
import sys

mode = Path(sys.argv[1]).read_text(encoding="ascii").strip()
if mode not in {"safe", "success", "malformed", "below-minimum"}:
    raise SystemExit(f"unsupported initial fixture mode: {mode!r}")
print(mode)
PY
)

write_fixture_mode() {
  local next_mode=$1
  python3 - "${MODE_PATH}" "${next_mode}" <<'PY'
import os
import secrets
import stat
import sys

path, mode = sys.argv[1:]
if mode not in {"safe", "success", "malformed", "below-minimum"}:
    raise SystemExit("refusing an unsupported fixture mode")
parent, name = os.path.split(path)
directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
temporary = f".{name}.qualification-{secrets.token_hex(8)}"
descriptor = -1
try:
    directory_info = os.fstat(directory)
    if directory_info.st_uid != 0 or stat.S_IMODE(directory_info.st_mode) & 0o022:
        raise SystemExit("fixture mode parent became unsafe")
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_nlink != 1:
        raise SystemExit("fixture mode changed to an unsafe object")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        stat.S_IMODE(current.st_mode),
        dir_fd=directory,
    )
    os.fchown(descriptor, current.st_uid, current.st_gid)
    os.fchmod(descriptor, stat.S_IMODE(current.st_mode))
    wire = (mode + "\n").encode("ascii")
    written = 0
    while written < len(wire):
        written += os.write(descriptor, wire[written:])
    os.fsync(descriptor)
    os.close(descriptor)
    descriptor = -1
    os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(temporary, dir_fd=directory)
    except FileNotFoundError:
        pass
    os.close(directory)
PY
}

seal_evidence() {
  local exit_code=$1
  printf 'exit_code=%s\n' "${exit_code}" > "${EVIDENCE_ROOT}/qualification.status"
  python3 - "${EVIDENCE_ROOT}" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
lines = []
for path in sorted(root.rglob("*")):
    relative = path.relative_to(root)
    if relative.as_posix() == "evidence-files.sha256":
        continue
    info = path.lstat()
    if stat.S_ISDIR(info.st_mode):
        continue
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"unsafe evidence object: {relative}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {relative.as_posix()}\n")
(root / "evidence-files.sha256").write_text("".join(lines), encoding="ascii")
for path in root.rglob("*"):
    if path.is_file():
        path.chmod(0o600)
for path in sorted((path for path in root.rglob("*") if path.is_dir()), reverse=True):
    path.chmod(0o700)
root.chmod(0o700)
PY
}

finish() {
  local status=$?
  trap - EXIT
  set +e
  write_fixture_mode "${ORIGINAL_MODE}"
  local restore_status=$?
  if [[ ${restore_status} -ne 0 ]]; then
    echo "failed to restore the original fixture mode" >&2
    [[ ${status} -ne 0 ]] || status=1
  fi
  seal_evidence "${status}"
  local seal_status=$?
  if [[ ${seal_status} -ne 0 ]]; then
    echo "failed to seal qualification evidence" >&2
    [[ ${status} -ne 0 ]] || status=1
  fi
  exit "${status}"
}
trap finish EXIT

sha256sum -- "${CLI_PATH}" "${FIXTURE_SCRIPT}" "${BASH_SOURCE[0]}" \
  > "${EVIDENCE_ROOT}/qualification-inputs.sha256"
printf '%s\n' \
  'schema_version=1' \
  'qualification=syswarden-osint-tls' \
  "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "cli_path=${CLI_PATH}" \
  "mode_path=${MODE_PATH}" \
  "list_root=${LIST_ROOT}" \
  "original_mode=${ORIGINAL_MODE}" \
  > "${EVIDENCE_ROOT}/provenance.meta"

feed_manifest() {
  local destination=$1
  python3 - "${LIST_ROOT}" "${destination}" <<'PY'
import hashlib
import os
import stat
import sys

root, destination = sys.argv[1:]
records = []
for name in ("syswarden_threatintel.ipv4", "syswarden_threatintel.ipv6"):
    path = os.path.join(root, name)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"unsafe feed evidence object: {name}")
    with open(path, "rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    records.append(f"{digest}  {name}\n")
if not records:
    raise SystemExit("no published threat-intelligence feed exists")
with open(destination, "w", encoding="ascii", newline="") as handle:
    handle.writelines(records)
PY
}

assert_single_literal_occurrence() {
  local path=$1
  local expected=$2
  python3 - "${path}" "${expected}" <<'PY'
from pathlib import Path
import sys

content = Path(sys.argv[1]).read_bytes()
needle = sys.argv[2].encode("utf-8")
count = content.count(needle)
if count != 1:
    raise SystemExit(f"expected one exact diagnostic occurrence, found {count}")
PY
}

assert_fixture_entry_not_published() {
  python3 - "${LIST_ROOT}" "${SIX_TO_FOUR}" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
needle = sys.argv[2].encode("ascii")
for name in ("syswarden_threatintel.ipv4", "syswarden_threatintel.ipv6"):
    path = root / name
    if path.exists() and needle in path.read_bytes():
        raise SystemExit(f"6to4 fixture entry was published in {name}")
PY
}

run_update() {
  local destination=$1
  local -a command=("${CLI_PATH}")
  if [[ -n ${CONFIG_PATH} ]]; then
    command+=(--config "${CONFIG_PATH}")
  fi
  command+=(update-feeds)
  env \
    HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= http_proxy= https_proxy= all_proxy= \
    NO_PROXY="${NO_PROXY_NAMES}" no_proxy="${NO_PROXY_NAMES}" \
    "${command[@]}" > "${destination}" 2>&1
}

probe_fixture() {
  local url=$1
  local destination=$2
  env \
    HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= http_proxy= https_proxy= all_proxy= \
    NO_PROXY="${NO_PROXY_NAMES}" no_proxy="${NO_PROXY_NAMES}" \
    curl --fail --silent --show-error --proto '=https' --tlsv1.3 \
      --connect-timeout 2 --max-time 5 "${url}" > "${destination}"
}

# Scenario 1: valid source volume plus one syntactically valid 6to4 entry.
write_fixture_mode success
probe_fixture https://cinsscore.com/list/ci-badguys.txt "${EVIDENCE_ROOT}/fixture-success-cins.body"
probe_fixture https://lists.blocklist.de/lists/all.txt "${EVIDENCE_ROOT}/fixture-success-blocklist.body"
grep -Fxq -- "${SIX_TO_FOUR}" "${EVIDENCE_ROOT}/fixture-success-blocklist.body"
[[ $(wc -l < "${EVIDENCE_ROOT}/fixture-success-cins.body") -eq 4 ]]
[[ $(wc -l < "${EVIDENCE_ROOT}/fixture-success-blocklist.body") -eq 5 ]]
run_update "${EVIDENCE_ROOT}/positive.log"
assert_single_literal_occurrence "${EVIDENCE_ROOT}/positive.log" "${EXPECTED_WARNING}"
if grep -Fq -- "${SIX_TO_FOUR}" "${EVIDENCE_ROOT}/positive.log"; then
  echo "positive warning exposed the discarded raw 6to4 entry" >&2
  exit 1
fi
assert_fixture_entry_not_published
feed_manifest "${EVIDENCE_ROOT}/feeds.after-positive.sha256"

# Scenario 2: malformed syntax must fail and preserve the positive feed bytes.
write_fixture_mode malformed
probe_fixture https://lists.blocklist.de/lists/all.txt "${EVIDENCE_ROOT}/fixture-malformed.body"
if run_update "${EVIDENCE_ROOT}/negative-malformed.log"; then
  echo "malformed OSINT input was accepted unexpectedly" >&2
  exit 1
fi
assert_single_literal_occurrence "${EVIDENCE_ROOT}/negative-malformed.log" "${EXPECTED_MALFORMED}"
feed_manifest "${EVIDENCE_ROOT}/feeds.after-malformed.sha256"
cmp --silent -- \
  "${EVIDENCE_ROOT}/feeds.after-positive.sha256" \
  "${EVIDENCE_ROOT}/feeds.after-malformed.sha256"

# Scenario 3: every line is valid syntax, but the public post-filter volume is three.
write_fixture_mode below-minimum
probe_fixture https://lists.blocklist.de/lists/all.txt "${EVIDENCE_ROOT}/fixture-below-minimum.body"
python3 - "${EVIDENCE_ROOT}/fixture-below-minimum.body" "${SIX_TO_FOUR}" \
  > "${EVIDENCE_ROOT}/fixture-below-minimum-proof.json" <<'PY'
import ipaddress
import json
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding="ascii").splitlines()
addresses = [ipaddress.ip_address(line) for line in lines]
special = ipaddress.ip_address(sys.argv[2])
if len(addresses) != 4 or addresses.count(special) != 1:
    raise SystemExit("below-minimum fixture shape is not exact")
public = [address for address in addresses if address != special and address.is_global]
if len(public) != 3 or not special in ipaddress.ip_network("2002::/16"):
    raise SystemExit("below-minimum fixture does not prove three public entries plus 6to4")
json.dump(
    {"all_entries_syntactically_valid": True, "public_entries_after_filter": 3, "six_to_four_entries": 1},
    sys.stdout,
    indent=2,
    sort_keys=True,
)
sys.stdout.write("\n")
PY
if run_update "${EVIDENCE_ROOT}/negative-below-minimum.log"; then
  echo "below-minimum OSINT input was accepted unexpectedly" >&2
  exit 1
fi
assert_single_literal_occurrence "${EVIDENCE_ROOT}/negative-below-minimum.log" "${EXPECTED_BELOW_MINIMUM}"
feed_manifest "${EVIDENCE_ROOT}/feeds.after-below-minimum.sha256"
cmp --silent -- \
  "${EVIDENCE_ROOT}/feeds.after-positive.sha256" \
  "${EVIDENCE_ROOT}/feeds.after-below-minimum.sha256"
assert_fixture_entry_not_published

python3 - "${EVIDENCE_ROOT}/qualification-result.json" "${EXPECTED_WARNING}" <<'PY'
import json
from pathlib import Path
import sys

result = {
    "fixture": "syswarden-osint-tls",
    "product_bypass_used": False,
    "scenarios": [
        "success-with-filtered-6to4",
        "reject-malformed-syntax",
        "reject-valid-volume-below-minimum",
    ],
    "schema_version": 1,
    "status": "passed",
    "warning": sys.argv[2],
}
Path(sys.argv[1]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
printf 'completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${EVIDENCE_ROOT}/provenance.meta"
echo "SysWarden deterministic OSINT TLS qualification passed"
