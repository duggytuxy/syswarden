#!/usr/bin/env bash
# Collect candidate-bound, reproducible NODE02 evidence for the native feed gate.
# Run only as root on the disposable Ubuntu 26.04 AMD64 qualification host.
set -euo pipefail
IFS=$'\n\t'
export LC_ALL=C
export LANG=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

readonly CLI_PATH=/opt/syswarden/bin/syswarden-cli
readonly LIST_ROOT=/etc/syswarden/lists
readonly HOST_PUBLIC_KEY=/etc/ssh/ssh_host_ed25519_key.pub
readonly OWNED_CRON=/etc/cron.d/syswarden
readonly CAMPAIGN_LOCK=/run/lock/syswarden-native-feed-qualification.lock
readonly FIREWALL_LOCK=/run/syswarden-firewall.lock
readonly HOSTS_PATH=/etc/hosts
readonly CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
readonly QUALIFICATION_CA=/usr/local/share/ca-certificates/syswarden-native-feed-qualification.crt
readonly QUARANTINE_MARKER=/var/lib/syswarden/.native-feed-snapshot-restore-required
readonly QUARANTINE_DROPIN_NAME=90-syswarden-native-feed-quarantine.conf
readonly -a QUARANTINE_UNITS=(cron.service syswarden-core.service syswarden-firewall.service)
readonly EXPECTED_WARNING='[WARNING] OSINT source https://lists.blocklist.de ignored 1 non-public or special-use CIDR entry.'
readonly EXPECTED_MALFORMED='invalid CIDR at line 5'
readonly EXPECTED_BELOW_MINIMUM='feed contains 3 canonical entries after ignoring 1 non-public or special-use entries, minimum is 4'
readonly EXPECTED_REAPPLY='[WARNING] Threat-intelligence refresh or validation failed. Reapplying configured policy before returning failure...'
readonly SIX_TO_FOUR='2002:982a:b983::982a:b983'
SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly SCRIPT_ROOT
readonly FIXTURE_SCRIPT=${SCRIPT_ROOT}/osint_tls_fixture.py
readonly EVIDENCE_TOOL=${SCRIPT_ROOT}/native_feed_evidence.py
readonly SIGNATURE_GATE=${SCRIPT_ROOT}/native_package_signature_gate.py
readonly CONTRACT_PATH=${SCRIPT_ROOT}/native_feed_contract_v4.10.0.json

usage() {
  cat >&2 <<'USAGE'
usage: osint_tls_qualification_lab.sh --mode-file ABSOLUTE_PATH --evidence-dir ABSOLUTE_PATH --candidate-sha SHA40 --deb-package ABSOLUTE_PATH --deb-signature ABSOLUTE_PATH --signature-policy ABSOLUTE_PATH --signature-inventory ABSOLUTE_PATH --deb-key-id ID --deb-signature-date YYYY-MM-DD --fixture-cert ABSOLUTE_PATH --fixture-key ABSOLUTE_PATH --fixture-ca ABSOLUTE_PATH --node02-ssh-host-key-sha256 SHA256:FINGERPRINT --campaign-id ID [--config ABSOLUTE_PATH]
USAGE
}

MODE_PATH=
EVIDENCE_ROOT=
CONFIG_PATH=
CANDIDATE_SHA=
DEB_PACKAGE=
DEB_SIGNATURE=
SIGNATURE_POLICY=
SIGNATURE_INVENTORY=
DEB_KEY_ID=
DEB_SIGNATURE_DATE=
FIXTURE_CERT=
FIXTURE_KEY=
FIXTURE_CA=
NODE02_SSH_HOST_KEY_SHA256=
CAMPAIGN_ID=
while [[ $# -gt 0 ]]; do
  case $1 in
    --mode-file|--evidence-dir|--config|--candidate-sha|--deb-package|--deb-signature|--signature-policy|--signature-inventory|--deb-key-id|--deb-signature-date|--fixture-cert|--fixture-key|--fixture-ca|--node02-ssh-host-key-sha256|--campaign-id)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case $1 in
        --mode-file) MODE_PATH=$2 ;;
        --evidence-dir) EVIDENCE_ROOT=$2 ;;
        --config) CONFIG_PATH=$2 ;;
        --candidate-sha) CANDIDATE_SHA=$2 ;;
        --deb-package) DEB_PACKAGE=$2 ;;
        --deb-signature) DEB_SIGNATURE=$2 ;;
        --signature-policy) SIGNATURE_POLICY=$2 ;;
        --signature-inventory) SIGNATURE_INVENTORY=$2 ;;
        --deb-key-id) DEB_KEY_ID=$2 ;;
        --deb-signature-date) DEB_SIGNATURE_DATE=$2 ;;
        --fixture-cert) FIXTURE_CERT=$2 ;;
        --fixture-key) FIXTURE_KEY=$2 ;;
        --fixture-ca) FIXTURE_CA=$2 ;;
        --node02-ssh-host-key-sha256) NODE02_SSH_HOST_KEY_SHA256=$2 ;;
        --campaign-id) CAMPAIGN_ID=$2 ;;
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
for required in MODE_PATH EVIDENCE_ROOT CANDIDATE_SHA DEB_PACKAGE DEB_SIGNATURE SIGNATURE_POLICY SIGNATURE_INVENTORY DEB_KEY_ID DEB_SIGNATURE_DATE FIXTURE_CERT FIXTURE_KEY FIXTURE_CA NODE02_SSH_HOST_KEY_SHA256 CAMPAIGN_ID; do
  [[ -n ${!required} ]] || { usage; exit 2; }
done

python3 - "${MODE_PATH}" "${EVIDENCE_ROOT}" "${CONFIG_PATH}" "${CANDIDATE_SHA}" \
  "${DEB_PACKAGE}" "${DEB_SIGNATURE}" "${SIGNATURE_POLICY}" \
  "${SIGNATURE_INVENTORY}" "${DEB_KEY_ID}" "${DEB_SIGNATURE_DATE}" \
  "${FIXTURE_CERT}" "${FIXTURE_KEY}" "${FIXTURE_CA}" \
  "${NODE02_SSH_HOST_KEY_SHA256}" "${CAMPAIGN_ID}" "${CLI_PATH}" \
  "${LIST_ROOT}" "${HOST_PUBLIC_KEY}" <<'PY'
import os
import re
import stat
import sys
from datetime import date

(
    mode, evidence, config, candidate, package, signature, policy, inventory,
    key_id, signature_date, certificate, private_key, ca, host_pin, campaign,
    cli, lists, host_public_key,
) = sys.argv[1:]
for label, path in (
    ("mode", mode), ("evidence", evidence), ("package", package),
    ("signature", signature), ("policy", policy), ("inventory", inventory),
    ("fixture certificate", certificate), ("fixture private key", private_key),
    ("fixture CA", ca), ("CLI", cli), ("list root", lists),
    ("SSH host public key", host_public_key),
):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise SystemExit(f"{label} path must be canonical and absolute")
if cli != "/opt/syswarden/bin/syswarden-cli":
    raise SystemExit("CLI path is not the fixed product path")
if lists != "/etc/syswarden/lists":
    raise SystemExit("list root is not the fixed product path")
for label, path in (
    ("mode", mode), ("package", package), ("signature", signature),
    ("policy", policy), ("inventory", inventory), ("fixture certificate", certificate),
    ("fixture private key", private_key), ("fixture CA", ca), ("CLI", cli),
    ("SSH host public key", host_public_key),
):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"{label} must be one real single-link regular file")
private_info = os.lstat(private_key)
private_parent = os.lstat(os.path.dirname(private_key))
if (
    private_info.st_uid != 0
    or private_info.st_gid != 0
    or stat.S_IMODE(private_info.st_mode) != 0o600
    or not stat.S_ISDIR(private_parent.st_mode)
    or stat.S_ISLNK(private_parent.st_mode)
    or private_parent.st_uid != 0
    or private_parent.st_gid != 0
    or stat.S_IMODE(private_parent.st_mode) != 0o700
):
    raise SystemExit("fixture private key and its immediate directory must be root-private")
if not os.access(cli, os.X_OK):
    raise SystemExit("installed CLI is not executable")
cli_info = os.lstat(cli)
if cli_info.st_uid != 0 or stat.S_IMODE(cli_info.st_mode) != 0o750:
    raise SystemExit("installed CLI must be root-owned with mode 0750")
root_info = os.lstat(lists)
if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
    raise SystemExit("list root must be one real directory")
if root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) & 0o022:
    raise SystemExit("list root must be root-owned and not group or world writable")
if os.path.lexists(evidence):
    raise SystemExit("evidence directory must be new")
parent = os.path.dirname(evidence)
parent_info = os.lstat(parent)
if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
    raise SystemExit("evidence parent must be one real directory")
if parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) & 0o022:
    raise SystemExit("evidence parent must be root-controlled")
if config:
    if not os.path.isabs(config) or os.path.normpath(config) != config:
        raise SystemExit("config path must be canonical and absolute")
    info = os.lstat(config)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SystemExit("config must be one real regular file")
if not re.fullmatch(r"[0-9a-f]{40}", candidate):
    raise SystemExit("candidate SHA is invalid")
if os.path.basename(package) != "syswarden_4.10.0_amd64.deb":
    raise SystemExit("candidate DEB filename is not exact")
if os.path.basename(signature) != "syswarden_4.10.0_amd64.deb.asc":
    raise SystemExit("candidate DEB signature filename is not exact")
if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", key_id):
    raise SystemExit("DEB key id is invalid")
date.fromisoformat(signature_date)
if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", host_pin):
    raise SystemExit("NODE02 SSH host-key pin is invalid")
if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", campaign):
    raise SystemExit("campaign id is invalid")
PY

readonly RAW_ROOT=${EVIDENCE_ROOT}/raw
install -d -m 0700 -o root -g root "${EVIDENCE_ROOT}" "${RAW_ROOT}"
python3 - "${CONTRACT_PATH}" "${RAW_ROOT}" <<'PY'
import json
import os
import sys
from pathlib import Path

contract = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(sys.argv[2])
for relative in contract["raw_evidence"]["inventory"]:
    parent = root / Path(relative).parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
for path in root.rglob("*"):
    if path.is_dir():
        os.chmod(path, 0o700)
PY

# Claim a root-private directory atomically. A pathname redirection is not safe
# here because it would follow and truncate a pre-created symlink before the
# object could be attested. The directory remains until the disposable host is
# restored, so a second campaign cannot reuse this product-mutating clone.
/usr/bin/python3 -I - "${CAMPAIGN_LOCK}" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
if path != "/run/lock/syswarden-native-feed-qualification.lock":
    raise SystemExit("campaign lock path is not exact")
parent, name = os.path.split(path)
directory = os.open(
    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
try:
    parent_info = os.fstat(directory)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or parent_info.st_gid != 0
        or stat.S_IMODE(parent_info.st_mode) & 0o002
    ):
        raise SystemExit("campaign lock parent is unsafe")
    try:
        os.mkdir(name, 0o700, dir_fd=directory)
    except FileExistsError as exc:
        raise SystemExit("another native feed qualification campaign is active") from exc
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=directory,
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        resolved = os.stat(name, dir_fd=directory, follow_symlinks=False)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
        )
        if (
            identity(opened) != identity(resolved)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_nlink != 2
        ):
            raise SystemExit("campaign lock identity is unsafe")
        os.fsync(directory)
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
PY

readonly -a UNTRUSTED_ENV=(
  ALL_PROXY CURL_CA_BUNDLE CURL_HOME CURL_SSL_BACKEND GIT_SSL_CAINFO
  GIT_SSL_CAPATH GIT_SSL_NO_VERIFY GODEBUG HTTPS_PROXY HTTP_PROXY NO_PROXY
  OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_ENGINES OPENSSL_MODULES
  REQUESTS_CA_BUNDLE SSLKEYLOGFILE SSL_CERT_DIR SSL_CERT_FILE all_proxy
  http_proxy https_proxy no_proxy
)
: > "${RAW_ROOT}/transport/environment.txt"
UNSET_ARGUMENTS=()
for name in "${UNTRUSTED_ENV[@]}"; do
  if [[ -n ${!name+x} ]]; then
    echo "refusing present proxy or trust environment variable: ${name}" >&2
    exit 1
  fi
  unset "${name}"
  UNSET_ARGUMENTS+=(-u "${name}")
  printf '%s=unset\n' "${name}" >> "${RAW_ROOT}/transport/environment.txt"
done
LC_ALL=C sort -c "${RAW_ROOT}/transport/environment.txt"

run_clean() {
  env "${UNSET_ARGUMENTS[@]}" "$@"
}

ORIGINAL_MODE=$(python3 - "${MODE_PATH}" <<'PY'
from pathlib import Path
import sys
mode = Path(sys.argv[1]).read_text(encoding="ascii").strip()
if mode not in {"safe", "success", "malformed", "below-minimum"}:
    raise SystemExit("initial fixture mode is invalid")
print(mode)
PY
)
FIXTURE_PID=
CRON_PID=
CORE_PID=
CRON_SUSPENDED=false
CORE_SUSPENDED=false
HOSTS_CONFIGURED=false
CA_INSTALLED=false
QUARANTINE_INSTALLED=false
readonly HOSTS_BACKUP_PATH=/etc/.hosts.syswarden-native-feed-${CAMPAIGN_ID}.backup
if [[ -e ${HOSTS_BACKUP_PATH} || -L ${HOSTS_BACKUP_PATH} ]]; then
  echo "refusing unresolved hosts backup from another qualification campaign" >&2
  exit 1
fi
if [[ -e ${QUALIFICATION_CA} || -L ${QUALIFICATION_CA} ]]; then
  echo "refusing pre-existing qualification CA target" >&2
  exit 1
fi
if [[ -e ${QUARANTINE_MARKER} || -L ${QUARANTINE_MARKER} ]]; then
  echo "refusing a node already marked for snapshot restoration" >&2
  exit 1
fi
for unit in "${QUARANTINE_UNITS[@]}"; do
  dropin=/etc/systemd/system/${unit}.d/${QUARANTINE_DROPIN_NAME}
  if [[ -e ${dropin} || -L ${dropin} ]]; then
    echo "refusing a pre-existing native feed quarantine drop-in: ${dropin}" >&2
    exit 1
  fi
done

write_fixture_mode() {
  local next_mode=$1
  python3 - "${MODE_PATH}" "${next_mode}" <<'PY'
import os
import secrets
import stat
import sys

path, mode = sys.argv[1:]
if mode not in {"safe", "success", "malformed", "below-minimum"}:
    raise SystemExit("unsupported fixture mode")
parent, name = os.path.split(path)
directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
temporary = f".{name}.native-feed-{secrets.token_hex(8)}"
descriptor = -1
try:
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_nlink != 1:
        raise SystemExit("fixture mode object became unsafe")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, stat.S_IMODE(current.st_mode), dir_fd=directory)
    os.fchown(descriptor, current.st_uid, current.st_gid)
    os.write(descriptor, (mode + "\n").encode("ascii"))
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

capture_hosts_state() {
  local output=$1
  python3 - "${HOSTS_PATH}" "${output}" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

path, output = sys.argv[1:]
info = os.lstat(path)
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0:
    raise SystemExit("/etc/hosts is not one root-owned single-link regular file")
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    opened = os.fstat(descriptor)
    wire = b""
    while len(wire) <= 1048576:
        chunk = os.read(descriptor, min(65536, 1048577 - len(wire)))
        if not chunk:
            break
        wire += chunk
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink, value.st_size)
if identity(info) != identity(opened) or identity(opened) != identity(after) or len(wire) != opened.st_size or len(wire) > 1048576:
    raise SystemExit("/etc/hosts changed while it was attested")
document = {
    "device": info.st_dev,
    "gid": info.st_gid,
    "inode": info.st_ino,
    "mode": f"{stat.S_IMODE(info.st_mode):04o}",
    "nlink": info.st_nlink,
    "sha256": hashlib.sha256(wire).hexdigest(),
    "size": len(wire),
    "uid": info.st_uid,
}
Path(output).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

configure_fixture_hosts() {
  python3 - "${HOSTS_PATH}" "${HOSTS_BACKUP_PATH}" \
    "${RAW_ROOT}/transport/hosts-fixture.txt" <<'PY'
import os
import secrets
import stat
import sys

path, backup_path, fixture_path = sys.argv[1:]
directory_path, name = os.path.split(path)
backup_directory, backup_name = os.path.split(backup_path)
if directory_path != backup_directory:
    raise SystemExit("hosts backup must remain on the /etc filesystem")
fixture = open(fixture_path, "rb").read()
if not fixture.endswith(b"\n") or len(fixture) > 4096:
    raise SystemExit("fixture hosts record is not canonical")
hosts = {
    b"bitbucket.org", b"cdn.jsdelivr.net", b"cinsscore.com", b"codeberg.org",
    b"gitlab.com", b"lists.blocklist.de", b"raw.githubusercontent.com",
}
directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
temporary = f".{name}.native-feed-{secrets.token_hex(8)}"
descriptor = -1
renamed = False
try:
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or current.st_uid != 0:
        raise SystemExit("/etc/hosts is not safe to replace")
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        original = b""
        while len(original) <= 1048576:
            chunk = os.read(source, min(65536, 1048577 - len(original)))
            if not chunk:
                break
            original += chunk
    finally:
        os.close(source)
    if len(original) > 1048576 or b"syswarden-native-feed-qualification" in original.lower():
        raise SystemExit("/etc/hosts contains a conflicting qualification mapping")
    if original and not original.endswith(b"\n"):
        raise SystemExit("/etc/hosts must end with one newline before fixture isolation")
    for line in original.splitlines():
        fields = line.split(b"#", 1)[0].split()
        if any(field.lower() in hosts for field in fields[1:]):
            raise SystemExit("/etc/hosts already maps a fixture origin")
    os.rename(name, backup_name, src_dir_fd=directory, dst_dir_fd=directory)
    renamed = True
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        stat.S_IMODE(current.st_mode),
        dir_fd=directory,
    )
    os.fchmod(descriptor, stat.S_IMODE(current.st_mode))
    os.fchown(descriptor, current.st_uid, current.st_gid)
    active = original + fixture
    os.write(descriptor, active)
    os.fsync(descriptor)
    os.close(descriptor)
    descriptor = -1
    os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
except BaseException:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(temporary, dir_fd=directory)
    except FileNotFoundError:
        pass
    if renamed:
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(backup_name, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
    raise
finally:
    os.close(directory)
PY
}

restore_fixture_hosts() {
  python3 - "${HOSTS_PATH}" "${HOSTS_BACKUP_PATH}" <<'PY'
import os
import secrets
import stat
import sys

path, backup_path = sys.argv[1:]
directory_path, name = os.path.split(path)
backup_directory, backup_name = os.path.split(backup_path)
if directory_path != backup_directory:
    raise SystemExit("hosts backup is not colocated")
directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
active_name = f".{name}.native-feed-active-{secrets.token_hex(8)}"
moved_active = False
try:
    backup = os.stat(backup_name, dir_fd=directory, follow_symlinks=False)
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(backup.st_mode) or backup.st_nlink != 1 or backup.st_uid != 0:
        raise SystemExit("saved /etc/hosts is unsafe")
    if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or current.st_uid != 0:
        raise SystemExit("active /etc/hosts is unsafe")
    os.rename(name, active_name, src_dir_fd=directory, dst_dir_fd=directory)
    moved_active = True
    try:
        os.rename(backup_name, name, src_dir_fd=directory, dst_dir_fd=directory)
    except BaseException:
        os.rename(active_name, name, src_dir_fd=directory, dst_dir_fd=directory)
        moved_active = False
        raise
    os.unlink(active_name, dir_fd=directory)
    moved_active = False
    os.fsync(directory)
finally:
    if moved_active:
        try:
            os.rename(active_name, name, src_dir_fd=directory, dst_dir_fd=directory)
        except OSError:
            pass
    os.close(directory)
PY
}

install_quarantine_barrier() {
  python3 - "${QUARANTINE_MARKER}" "${QUARANTINE_DROPIN_NAME}" \
    "${QUARANTINE_UNITS[@]}" <<'PY'
import os
import stat
import sys

marker, dropin_name, *units = sys.argv[1:]

def create_exact(path: str, wire: bytes, mode: int) -> None:
    parent, name = os.path.split(path)
    directory = os.open(
        parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    parent_info = os.fstat(directory)
    if parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) & 0o022:
        os.close(directory)
        raise SystemExit(f"quarantine parent is unsafe: {parent}")
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=directory,
    )
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        if os.write(descriptor, wire) != len(wire):
            raise SystemExit(f"short write while creating quarantine object: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)
    os.close(directory)

dropin_wire = f"[Unit]\nConditionPathExists=!{marker}\n".encode("ascii")
systemd_root_path = "/etc/systemd/system"
systemd_root = os.open(
    systemd_root_path,
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
)
try:
    root_info = os.fstat(systemd_root)
    if (
        root_info.st_uid != 0
        or root_info.st_gid != 0
        or stat.S_IMODE(root_info.st_mode) & 0o022
    ):
        raise SystemExit("systemd configuration root is unsafe")
    for unit in units:
        name = f"{unit}.d"
        created = False
        try:
            os.mkdir(name, 0o755, dir_fd=systemd_root)
            created = True
        except FileExistsError:
            pass
        directory = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=systemd_root,
        )
        try:
            if created:
                os.fchown(directory, 0, 0)
                os.fchmod(directory, 0o755)
                os.fsync(directory)
                # Persist the directory entry before the later marker can make
                # every protected unit fail its start condition.
                os.fsync(systemd_root)
            info = os.fstat(directory)
            resolved = os.stat(name, dir_fd=systemd_root, follow_symlinks=False)
            if (
                (info.st_dev, info.st_ino) != (resolved.st_dev, resolved.st_ino)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise SystemExit(f"quarantine drop-in directory is unsafe: {name}")
        finally:
            os.close(directory)
        create_exact(
            os.path.join(systemd_root_path, name, dropin_name), dropin_wire, 0o644
        )
finally:
    os.close(systemd_root)
PY
  systemctl daemon-reload
  local unit dropin loaded
  for unit in "${QUARANTINE_UNITS[@]}"; do
    dropin=/etc/systemd/system/${unit}.d/${QUARANTINE_DROPIN_NAME}
    loaded=$(systemctl show "${unit}" --property=DropInPaths --value)
    case " ${loaded} " in
      *" ${dropin} "*) ;;
      *) echo "systemd did not load the quarantine drop-in for ${unit}" >&2; return 1 ;;
    esac
  done
  python3 - "${QUARANTINE_MARKER}" "${CAMPAIGN_ID}" "${CANDIDATE_SHA}" <<'PY'
import os
import stat
import sys

marker, campaign, candidate = sys.argv[1:]
parent, name = os.path.split(marker)
directory = os.open(
    parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
parent_info = os.fstat(directory)
if parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) & 0o022:
    os.close(directory)
    raise SystemExit("quarantine marker parent is unsafe")
wire = (
    f"campaign_id={campaign}\n"
    f"candidate_sha={candidate}\n"
    "snapshot_restore_required=true\n"
).encode("ascii")
descriptor = os.open(
    name,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
    0o600,
    dir_fd=directory,
)
try:
    os.fchmod(descriptor, 0o600)
    os.fchown(descriptor, 0, 0)
    if os.write(descriptor, wire) != len(wire):
        raise SystemExit("short write while creating the quarantine marker")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
os.fsync(directory)
os.close(directory)
PY
}

capture_quarantine_barrier() {
  python3 - "${RAW_ROOT}/concurrency/quarantine-barrier.json" \
    "${QUARANTINE_MARKER}" "${QUARANTINE_DROPIN_NAME}" \
    "${CAMPAIGN_ID}" "${CANDIDATE_SHA}" "${QUARANTINE_UNITS[@]}" <<'PY'
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

output, marker, dropin_name, campaign, candidate, *units = sys.argv[1:]
expected_marker = (
    f"campaign_id={campaign}\n"
    f"candidate_sha={candidate}\n"
    "snapshot_restore_required=true\n"
).encode("ascii")
expected_dropin = f"[Unit]\nConditionPathExists=!{marker}\n".encode("ascii")

def attest(path: str, expected: bytes, mode: int) -> dict[str, object]:
    info = os.lstat(path)
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise SystemExit(f"quarantine object is unsafe: {path}")
    wire = Path(path).read_bytes()
    if wire != expected:
        raise SystemExit(f"quarantine object content is invalid: {path}")
    return {
        "gid": info.st_gid,
        "mode": f"{mode:04o}",
        "nlink": info.st_nlink,
        "path": path,
        "sha256": hashlib.sha256(wire).hexdigest(),
        "size": len(wire),
        "uid": info.st_uid,
    }

document = {
    "marker": attest(marker, expected_marker, 0o600),
    "schema": "syswarden-native-feed-quarantine/v1",
    "snapshot_restore_required": True,
    "units": {},
}
for unit in units:
    path = f"/etc/systemd/system/{unit}.d/{dropin_name}"
    loaded = subprocess.run(
        ["/usr/bin/systemctl", "show", unit, "--property=DropInPaths", "--value"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip().split()
    if path not in loaded:
        raise SystemExit(f"systemd did not load the quarantine drop-in for {unit}")
    document["units"][unit] = {**attest(path, expected_dropin, 0o644), "loaded": True}
Path(output).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

capture_nft() {
  local directory=$1 prefix=${2:-nft}
  nft --json list set inet syswarden syswarden_blacklist > "${directory}/${prefix}-ipv4.json"
  nft --json list set inet syswarden syswarden_blacklist6 > "${directory}/${prefix}-ipv6.json"
  python3 - "${directory}/${prefix}-ipv4.json" "${directory}/${prefix}-ipv6.json" \
    "${directory}/${prefix}-canonical.json" <<'PY'
import json
import sys
from pathlib import Path

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in sorted(value.items()) if key not in {"bytes", "expires", "handle", "packets"}}
    if isinstance(value, list):
        items = [normalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return value

documents = []
for source in sys.argv[1:3]:
    document = json.loads(Path(source).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    statements = document.get("nftables")
    if not isinstance(statements, list):
        raise SystemExit("nftables capture does not contain a statement array")
    sets = [statement["set"] for statement in statements if isinstance(statement, dict) and isinstance(statement.get("set"), dict)]
    if len(sets) != 1:
        raise SystemExit("nftables capture does not contain one exact set")
    documents.append(sets[0])
Path(sys.argv[3]).write_text(json.dumps(normalize(documents), sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

capture_service_state() {
  local output=$1 temporary
  temporary=$(mktemp)
  systemctl show cron.service syswarden-core.service \
    --property=Id,ActiveState,SubState,UnitFileState,FragmentPath,MainPID \
    > "${temporary}"
  python3 - "${temporary}" "${output}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

groups = []
values = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if not line:
        if values:
            groups.append(values)
            values = {}
        continue
    key, separator, value = line.partition("=")
    if not separator or key in values:
        raise SystemExit("systemd state is malformed")
    values[key] = value
if values:
    groups.append(values)
expected = {"Id", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "MainPID"}
document = {}
for group in groups:
    if set(group) != expected or group["Id"] not in {"cron.service", "syswarden-core.service"}:
        raise SystemExit("systemd state inventory is incomplete")
    pid = int(group["MainPID"])
    if group["ActiveState"] != "active" or pid <= 1:
        raise SystemExit(f"required native writer service is not active: {group['Id']}")
    executable = os.stat(f"/proc/{pid}/exe")
    stat_fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    state_match = re.search(r"^State:\s+([A-Z])", status, re.MULTILINE)
    if state_match is None:
        raise SystemExit(f"cannot derive process state for {group['Id']}")
    document[group["Id"]] = {
        "active_state": group["ActiveState"],
        "exe_device": executable.st_dev,
        "exe_inode": executable.st_ino,
        "exe_path": os.readlink(f"/proc/{pid}/exe"),
        "fragment_path": group["FragmentPath"],
        "main_pid": pid,
        "process_state": state_match.group(1),
        "start_time_ticks": int(stat_fields[21]),
        "sub_state": group["SubState"],
        "unit_file_state": group["UnitFileState"],
    }
if set(document) != {"cron.service", "syswarden-core.service"}:
    raise SystemExit("required native writer service set is incomplete")
Path(sys.argv[2]).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
os.chmod(sys.argv[2], 0o600)
PY
  rm -f -- "${temporary}"
}

scan_feed_writers() {
  python3 - "${CLI_PATH}" <<'PY'
import os
import sys
from pathlib import Path

reference = os.stat(sys.argv[1])
reference_identity = (reference.st_dev, reference.st_ino)
records = []
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    try:
        before = (entry / "stat").read_text(encoding="ascii").split()[21]
        executable = os.stat(entry / "exe")
        first = (entry / "cmdline").read_bytes()
        second = (entry / "cmdline").read_bytes()
        after = (entry / "stat").read_text(encoding="ascii").split()[21]
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if before != after or first != second or (executable.st_dev, executable.st_ino) != reference_identity:
        continue
    fields = first.split(b"\0")
    if fields and any(command in fields[1:] for command in (b"update-feeds", b"install", b"reload")):
        records.append((int(entry.name), b" ".join(fields[:-1]).decode("utf-8", "strict")))
for pid, command in sorted(records):
    print(f"{pid}\t{command}")
PY
}

restore_runtime() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  local cleanup_failed=0
  if [[ -n ${FIXTURE_PID} ]]; then
    kill -TERM "${FIXTURE_PID}" 2>/dev/null
    wait "${FIXTURE_PID}" 2>/dev/null
    FIXTURE_PID=
  fi
  write_fixture_mode "${ORIGINAL_MODE}"
  if [[ ${HOSTS_CONFIGURED} == true || -e ${HOSTS_BACKUP_PATH} ]]; then
    restore_fixture_hosts || cleanup_failed=1
    HOSTS_CONFIGURED=false
  fi
  if [[ ${CA_INSTALLED} == true || -e ${QUALIFICATION_CA} ]]; then
    rm -f -- "${QUALIFICATION_CA}" || cleanup_failed=1
    run_clean update-ca-certificates >/dev/null 2>&1 || cleanup_failed=1
    CA_INSTALLED=false
  fi
  if [[ ${QUARANTINE_INSTALLED} == true || -e ${QUARANTINE_MARKER} || \
    ${CRON_SUSPENDED} == true || ${CORE_SUSPENDED} == true ]]; then
    echo "NODE02 remains quarantined; restore its clean Linode snapshot before reuse" >&2
    echo "Emergency process resumption invalidates this qualification campaign" >&2
  fi
  if [[ ${cleanup_failed} -ne 0 ]]; then
    status=1
  fi
  exit "${status}"
}
trap restore_runtime EXIT INT TERM

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
readonly STARTED_UTC

# Derive and retain the native host profile and pinned public identity.
cp --dereference --preserve=mode,timestamps /etc/os-release "${RAW_ROOT}/host/os-release"
chmod 0600 "${RAW_ROOT}/host/os-release"
dpkg --print-architecture > "${RAW_ROOT}/host/dpkg-architecture.txt"
systemctl --version | awk 'NR == 1 {print $1, $2}' > "${RAW_ROOT}/host/systemd-version.txt"
nft --version | awk 'NR == 1 {print $1, $2}' > "${RAW_ROOT}/host/nft-version.txt"
uname -a > "${RAW_ROOT}/host/uname.txt"
install -m 0600 -- "${HOST_PUBLIC_KEY}" "${RAW_ROOT}/host/ssh-host-ed25519.pub"
ssh-keygen -E sha256 -lf "${HOST_PUBLIC_KEY}" > "${RAW_ROOT}/host/ssh-host-ed25519.fingerprint"
grep -Fq -- "${NODE02_SSH_HOST_KEY_SHA256}" "${RAW_ROOT}/host/ssh-host-ed25519.fingerprint"

# Verify the exact signed DEB with the shared native signing gate before execution.
install -m 0600 -- "${SIGNATURE_INVENTORY}" "${RAW_ROOT}/package/signature-inventory.json"
sha256sum -- "${SIGNATURE_POLICY}" | awk '{print $1}' > "${RAW_ROOT}/package/signature-policy.sha256"
bootstrap_args=()
if [[ $(jq -er '.deb.implementation' "${SIGNATURE_POLICY}") == implemented-not-qualified ]]; then
  bootstrap_args+=(--bootstrap-qualification)
fi
PYTHONDONTWRITEBYTECODE=1 python3 "${SIGNATURE_GATE}" deb \
  --policy "${SIGNATURE_POLICY}" --inventory "${SIGNATURE_INVENTORY}" \
  --package "${DEB_PACKAGE}" --signature "${DEB_SIGNATURE}" \
  --release v4.10.0 --key-id "${DEB_KEY_ID}" --as-of "${DEB_SIGNATURE_DATE}" \
  --purpose qualification "${bootstrap_args[@]}" \
  --gpgv-status-output "${RAW_ROOT}/package/gpgv.status" \
  --gpgv-logger-output "${RAW_ROOT}/package/gpgv.stderr" \
  --evidence-output "${RAW_ROOT}/package/native-signature-evidence.json"
sha256sum -- "${DEB_PACKAGE}" | sed "s#  .*#  syswarden_4.10.0_amd64.deb#" > "${RAW_ROOT}/package/deb.sha256"
sha256sum -- "${DEB_SIGNATURE}" | sed "s#  .*#  syswarden_4.10.0_amd64.deb.asc#" > "${RAW_ROOT}/package/signature.sha256"
stat -c '%s' -- "${DEB_PACKAGE}" > "${RAW_ROOT}/package/deb.size"
deb_control_package=$(dpkg-deb --field "${DEB_PACKAGE}" Package)
deb_control_version=$(dpkg-deb --field "${DEB_PACKAGE}" Version)
deb_control_architecture=$(dpkg-deb --field "${DEB_PACKAGE}" Architecture)
[[ ${deb_control_package} == syswarden && ${deb_control_version} == 4.10.0 && \
  ${deb_control_architecture} == amd64 ]]
printf '%s\t%s\t%s\n' "${deb_control_package}" "${deb_control_version}" \
  "${deb_control_architecture}" > "${RAW_ROOT}/package/dpkg-deb-fields.txt"
PYTHONDONTWRITEBYTECODE=1 python3 "${EVIDENCE_TOOL}" inspect-deb \
  --deb-package "${DEB_PACKAGE}" \
  --output "${RAW_ROOT}/package/payload-inspection.json" \
  > "${RAW_ROOT}/package/extraction.stdout" \
  2> "${RAW_ROOT}/package/extraction.stderr"
jq -er '.payload.sha256' "${RAW_ROOT}/package/payload-inspection.json" | \
  awk '{print $1 "  opt/syswarden/bin/syswarden-cli"}' \
  > "${RAW_ROOT}/package/extracted-cli.sha256"
sha256sum -- "${CLI_PATH}" | sed "s#  .*#  /opt/syswarden/bin/syswarden-cli#" \
  > "${RAW_ROOT}/package/installed-cli.sha256"
cmp --silent -- <(cut -d' ' -f1 "${RAW_ROOT}/package/extracted-cli.sha256") \
  <(cut -d' ' -f1 "${RAW_ROOT}/package/installed-cli.sha256")
dpkg-query --show --showformat='${Package}\t${Version}\t${Architecture}\t${Status}\n' \
  syswarden > "${RAW_ROOT}/package/dpkg-query.tsv"
dpkg-query --search "${CLI_PATH}" > "${RAW_ROOT}/package/dpkg-owner.txt"
dpkg-query --control-show syswarden md5sums > "${RAW_ROOT}/package/dpkg-md5sums.txt"
set +e
dpkg --verify syswarden > "${RAW_ROOT}/package/dpkg-verify.stdout" \
  2> "${RAW_ROOT}/package/dpkg-verify.stderr"
dpkg_verify_exit=$?
set -e
printf '%s\n' "${dpkg_verify_exit}" > "${RAW_ROOT}/package/dpkg-verify.exit"
[[ ${dpkg_verify_exit} -eq 0 ]]
test ! -s "${RAW_ROOT}/package/dpkg-verify.stdout"
test ! -s "${RAW_ROOT}/package/dpkg-verify.stderr"
python3 - "${CLI_PATH}" "${RAW_ROOT}/package/installed-cli.stat" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

info = os.lstat(sys.argv[1])
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit("installed CLI is not a regular file")
document = {"gid": info.st_gid, "mode": f"{stat.S_IMODE(info.st_mode):04o}", "nlink": info.st_nlink, "path": sys.argv[1], "size": info.st_size, "type": "regular", "uid": info.st_uid}
Path(sys.argv[2]).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

# Prove fixture certificate/key binding without ever transporting private material.
install -m 0600 -- "${FIXTURE_CERT}" "${RAW_ROOT}/transport/fixture-cert.pem"
install -m 0600 -- "${FIXTURE_CA}" "${RAW_ROOT}/transport/fixture-ca.pem"
run_clean openssl x509 -in "${FIXTURE_CERT}" -noout -subject -issuer -serial -startdate -enddate \
  -fingerprint -sha256 -ext subjectAltName > "${RAW_ROOT}/transport/fixture-cert-details.txt"
run_clean openssl x509 -in "${FIXTURE_CA}" -noout -subject -issuer -serial -startdate -enddate \
  -fingerprint -sha256 > "${RAW_ROOT}/transport/fixture-ca-details.txt"
cert_public_sha=$(run_clean openssl x509 -in "${FIXTURE_CERT}" -pubkey -noout | \
  run_clean openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')
key_public_sha=$(run_clean openssl pkey -in "${FIXTURE_KEY}" -pubout -outform DER | \
  sha256sum | awk '{print $1}')
test "${cert_public_sha}" = "${key_public_sha}"
printf 'certificate_public_key_sha256=%s\nprivate_key_public_key_sha256=%s\n' \
  "${cert_public_sha}" "${key_public_sha}" \
  > "${RAW_ROOT}/transport/certificate-key-match.sha256"
run_clean openssl verify -CAfile "${FIXTURE_CA}" "${FIXTURE_CERT}" \
  > "${RAW_ROOT}/transport/supplied-ca.verify.log" 2>&1

# Capture the exact host and default trust state before any fixture mutation.
capture_hosts_state "${RAW_ROOT}/transport/hosts-before.json"
printf '# syswarden-native-feed-qualification campaign=%s\n' "${CAMPAIGN_ID}" \
  > "${RAW_ROOT}/transport/hosts-fixture.txt"
for host in bitbucket.org cdn.jsdelivr.net cinsscore.com codeberg.org gitlab.com \
  lists.blocklist.de raw.githubusercontent.com; do
  printf '127.0.0.1 %s\n' "${host}" >> "${RAW_ROOT}/transport/hosts-fixture.txt"
done
sha256sum -- "${CA_BUNDLE}" | sed 's#  .*#  ca-certificates.crt#' \
  > "${RAW_ROOT}/transport/ca-bundle-before.sha256"
set +e
run_clean openssl verify "${FIXTURE_CERT}" \
  > "${RAW_ROOT}/transport/ca-before.verify.log" 2>&1
ca_before_exit=$?
set -e
printf '%s\n' "${ca_before_exit}" > "${RAW_ROOT}/transport/ca-before.verify.exit"
[[ ${ca_before_exit} -ge 1 && ${ca_before_exit} -le 255 ]]

# Stop the only supported scheduler and prove no update-feeds writer remains.
capture_service_state "${RAW_ROOT}/concurrency/service-before.txt"
install -m 0600 -- "${OWNED_CRON}" "${RAW_ROOT}/concurrency/cron-before.txt"
if crontab -l -u root 2>/dev/null | grep -F -- '/opt/syswarden/bin/syswarden-cli update-feeds' \
  > "${RAW_ROOT}/concurrency/root-crontab.txt"; then
  echo "legacy root crontab contains a competing update-feeds schedule" >&2
  exit 1
else
  : > "${RAW_ROOT}/concurrency/root-crontab.txt"
fi
python3 - "${OWNED_CRON}" "${RAW_ROOT}/concurrency/schedule-conflicts.txt" <<'PY'
import os
import sys
from pathlib import Path

owned = os.path.realpath(sys.argv[1])
roots = (
    "/etc/crontab", "/etc/anacrontab", "/etc/cron.d", "/etc/cron.hourly",
    "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
    "/var/spool/cron", "/var/spool/cron/crontabs",
)
matches = []
for raw_root in roots:
    root = Path(raw_root)
    paths = [root] if root.is_file() else sorted(root.rglob("*")) if root.is_dir() else []
    for path in paths:
        try:
            if not path.is_file() or os.path.realpath(path) == owned:
                continue
            wire = path.read_bytes()
        except (OSError, UnicodeError):
            continue
        if b"update-feeds" in wire:
            matches.append(str(path))
Path(sys.argv[2]).write_text("".join(f"{path}\n" for path in sorted(set(matches))), encoding="utf-8")
PY
{
  grep -RsnI --include='*.service' --include='*.timer' -- 'update-feeds' \
    /etc/systemd/system /run/systemd/system /lib/systemd/system \
    /usr/lib/systemd/system 2>/dev/null || true
} | LC_ALL=C sort -u > "${RAW_ROOT}/concurrency/timers.txt"
test ! -s "${RAW_ROOT}/concurrency/schedule-conflicts.txt"
test ! -s "${RAW_ROOT}/concurrency/timers.txt"
scan_feed_writers > "${RAW_ROOT}/concurrency/process-before.txt"
test ! -s "${RAW_ROOT}/concurrency/process-before.txt"
CRON_PID=$(systemctl show -p MainPID --value cron.service)
CORE_PID=$(systemctl show -p MainPID --value syswarden-core.service)
[[ ${CRON_PID} =~ ^[1-9][0-9]*$ && ${CORE_PID} =~ ^[1-9][0-9]*$ ]]

# Install a durable fail-closed quarantine before any product mutation. Only
# restoring the clean Linode snapshot removes this marker and these drop-ins.
install_quarantine_barrier
QUARANTINE_INSTALLED=true

python3 - "${FIREWALL_LOCK}" <<'PY'
import os
import stat
import sys

info = os.lstat(sys.argv[1])
if (
    not stat.S_ISREG(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or info.st_nlink != 1
    or info.st_uid != 0
    or stat.S_IMODE(info.st_mode) & 0o022
):
    raise SystemExit("firewall runtime lock is unsafe")
PY
exec 7<>"${FIREWALL_LOCK}"
[[ $(stat -Lc '%d:%i' -- "${FIREWALL_LOCK}") == $(stat -Lc '%d:%i' -- "/proc/$$/fd/7") ]]
flock --exclusive --wait 60 7
exec 8<"${LIST_ROOT}"
flock --exclusive --wait 60 8
systemctl kill --kill-whom=main --signal=SIGSTOP cron.service
CRON_SUSPENDED=true
systemctl kill --kill-whom=main --signal=SIGSTOP syswarden-core.service
CORE_SUSPENDED=true
capture_service_state "${RAW_ROOT}/concurrency/service-quiesced.txt"
python3 - "${RAW_ROOT}/concurrency/service-before.txt" \
  "${RAW_ROOT}/concurrency/service-quiesced.txt" <<'PY'
import json
import sys
from pathlib import Path

before, after = (json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:])
for unit in ("cron.service", "syswarden-core.service"):
    baseline = dict(before[unit])
    quiesced = dict(after[unit])
    if quiesced.pop("process_state", None) != "T":
        raise SystemExit(f"{unit} main process is not suspended")
    baseline.pop("process_state", None)
    if quiesced != baseline:
        raise SystemExit(f"{unit} identity changed during suspension")
PY
flock --unlock 8
exec 8<&-
flock --unlock 7
exec 7<&-
for _ in $(seq 1 30); do
  if ! scan_feed_writers | grep -q .; then
    break
  fi
  sleep 1
done
scan_feed_writers > "${RAW_ROOT}/concurrency/process-drained.txt"
test ! -s "${RAW_ROOT}/concurrency/process-drained.txt"

# Own the fixture DNS and Ubuntu trust-store lifecycle while every feed writer is suspended.
configure_fixture_hosts
HOSTS_CONFIGURED=true
capture_hosts_state "${RAW_ROOT}/transport/hosts-active.json"
install -m 0644 -o root -g root -- "${FIXTURE_CA}" "${QUALIFICATION_CA}"
CA_INSTALLED=true
run_clean update-ca-certificates > "${RAW_ROOT}/transport/ca-install.log" 2>&1
sha256sum -- "${CA_BUNDLE}" | sed 's#  .*#  ca-certificates.crt#' \
  > "${RAW_ROOT}/transport/ca-bundle-active.sha256"
set +e
run_clean openssl verify "${FIXTURE_CERT}" \
  > "${RAW_ROOT}/transport/ca-active.verify.log" 2>&1
ca_active_exit=$?
set -e
printf '%s\n' "${ca_active_exit}" > "${RAW_ROOT}/transport/ca-active.verify.exit"
[[ ${ca_active_exit} -eq 0 ]]

python3 - "${RAW_ROOT}/transport/resolution.json" <<'PY'
import json
import socket
import sys
from pathlib import Path

hosts = sorted({"cinsscore.com", "lists.blocklist.de", "raw.githubusercontent.com", "gitlab.com", "cdn.jsdelivr.net", "bitbucket.org", "codeberg.org"})
result = {}
for host in hosts:
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if addresses != ["127.0.0.1"]:
        raise SystemExit(f"fixture host is not exactly loopback isolated: {host}={addresses}")
    result[host] = addresses
Path(sys.argv[1]).write_text(json.dumps({"hosts": result, "schema": "syswarden-osint-fixture-resolution/v1"}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

write_fixture_mode safe
: > "${RAW_ROOT}/transport/fixture.stdout.log"
: > "${RAW_ROOT}/transport/fixture.stderr.log"
run_clean python3 "${FIXTURE_SCRIPT}" --cert "${FIXTURE_CERT}" --key "${FIXTURE_KEY}" \
  --mode "${MODE_PATH}" --bind 127.0.0.1 --port 443 \
  > "${RAW_ROOT}/transport/fixture.stdout.log" \
  2> "${RAW_ROOT}/transport/fixture.stderr.log" &
FIXTURE_PID=$!
for _ in $(seq 1 20); do
  if run_clean curl --disable --fail --silent --show-error --proto '=https' \
    --tlsv1.3 --tls-max 1.3 \
    --connect-timeout 1 --max-time 2 https://raw.githubusercontent.com/ \
    > "${RAW_ROOT}/transport/readiness.body" 2>/dev/null; then
    break
  fi
  sleep 0.25
done
test "$(cat "${RAW_ROOT}/transport/readiness.body")" = fixture-ready
run_clean openssl s_client -connect 127.0.0.1:443 -servername lists.blocklist.de \
  -tls1_3 -verify_return_error < /dev/null \
  > "${RAW_ROOT}/transport/default-trust.verify.log" 2>&1
run_clean curl --disable --fail --silent --show-error --verbose --proto '=https' \
  --tlsv1.3 --tls-max 1.3 \
  --connect-timeout 2 --max-time 5 https://lists.blocklist.de/lists/all.txt \
  > /dev/null 2> "${RAW_ROOT}/transport/tls13.probe.log"
grep -Fq -- 'TLSv1.3' "${RAW_ROOT}/transport/default-trust.verify.log"
grep -Fq -- 'Verify return code: 0 (ok)' "${RAW_ROOT}/transport/default-trust.verify.log"

feed_manifest() {
  local destination=$1
  python3 - "${LIST_ROOT}" "${destination}" <<'PY'
import hashlib
import os
import stat
import sys

records = []
for name in ("syswarden_threatintel.ipv4", "syswarden_threatintel.ipv6"):
    path = os.path.join(sys.argv[1], name)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise SystemExit("feed evidence object is unsafe")
    with open(path, "rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    records.append(f"{digest}  {name}\n")
if not records or records[0].split()[1] != "syswarden_threatintel.ipv4":
    raise SystemExit("active IPv4 feed is missing")
with open(sys.argv[2], "w", encoding="ascii", newline="") as output:
    output.writelines(records)
PY
}

copy_feed_state() {
  local destination=$1
  install -m 0600 -- "${LIST_ROOT}/syswarden_threatintel.ipv4" "${destination}/ipv4.feed"
  if [[ -f ${LIST_ROOT}/syswarden_threatintel.ipv6 ]]; then
    install -m 0600 -- "${LIST_ROOT}/syswarden_threatintel.ipv6" "${destination}/ipv6.feed"
  else
    : > "${destination}/ipv6.feed"
  fi
  install -m 0600 -- "${LIST_ROOT}/syswarden_threatintel.ipv4.provenance.json" \
    "${destination}/provenance.json"
  local snapshot
  snapshot=$(python3 - "${destination}/provenance.json" "${LIST_ROOT}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit("duplicate provenance key")
        value[key] = item
    return value

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
digest = document.get("sha256")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit("provenance digest is invalid")
print(os.path.join(sys.argv[2], ".syswarden_threatintel.ipv4.syswarden-snapshot-" + digest))
PY
)
  install -m 0600 -- "${snapshot}" "${destination}/ipv4.snapshot"
  feed_manifest "${destination}/feeds.sha256"
}

assert_occurrences() {
  local path=$1 text=$2 expected=$3
  [[ $(grep -Foc -- "${text}" "${path}") -eq ${expected} ]]
}

probe_fixture() {
  local url=$1 output=$2
  run_clean curl --disable --fail --silent --show-error --proto '=https' \
    --tlsv1.3 --tls-max 1.3 \
    --connect-timeout 2 --max-time 5 "${url}" > "${output}"
}

run_update() {
  local output=$1
  scan_feed_writers | grep -q . && {
    echo "a concurrent update-feeds writer appeared" >&2
    return 1
  }
  local -a command=("${CLI_PATH}")
  [[ -z ${CONFIG_PATH} ]] || command+=(--config "${CONFIG_PATH}")
  command+=(update-feeds)
  run_clean "${command[@]}" > "${output}" 2>&1
}

capture_scenario() {
  local id=$1 sequence=$2 mode=$3 exit_code=$4 started_at=$5
  local directory="${RAW_ROOT}/scenarios/${id}"
  local -a audit_command=("${CLI_PATH}")
  [[ -z ${CONFIG_PATH} ]] || audit_command+=(--config "${CONFIG_PATH}")
  audit_command+=(audit)
  run_clean "${audit_command[@]}" > "${directory}/audit.log" 2>&1
  copy_feed_state "${directory}"
  capture_nft "${directory}"
  python3 - "${directory}/result.json" "${id}" "${sequence}" "${mode}" \
    "${exit_code}" "${started_at}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output, identifier, sequence, mode, exit_code, started_at = sys.argv[1:]
document = {"command_exit_code": int(exit_code), "fixture_mode": mode, "id": identifier, "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "sequence": int(sequence), "started_at": started_at, "status": "pass"}
Path(output).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

# Scenario 1 publishes a current feed while filtering the valid 6to4 entry.
positive="${RAW_ROOT}/scenarios/success-with-filtered-6to4"
positive_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
write_fixture_mode success
probe_fixture https://cinsscore.com/list/ci-badguys.txt "${positive}/fixture-cins.body"
probe_fixture https://lists.blocklist.de/lists/all.txt "${positive}/fixture-blocklist.body"
grep -Fxq -- "${SIX_TO_FOUR}" "${positive}/fixture-blocklist.body"
run_update "${positive}/command.log"
assert_occurrences "${positive}/command.log" "${EXPECTED_WARNING}" 1
capture_scenario success-with-filtered-6to4 1 success 0 "${positive_started}"
if grep -Fq -- "${SIX_TO_FOUR}" "${positive}/ipv4.feed" "${positive}/ipv6.feed"; then
  echo "6to4 fixture entry entered a published feed" >&2
  exit 1
fi

# Scenario 2 rejects malformed syntax and preserves the exact LKG and nft state.
malformed="${RAW_ROOT}/scenarios/reject-malformed-syntax"
malformed_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
write_fixture_mode malformed
probe_fixture https://cinsscore.com/list/ci-badguys.txt "${malformed}/fixture-cins.body"
probe_fixture https://lists.blocklist.de/lists/all.txt "${malformed}/fixture-blocklist.body"
set +e
run_update "${malformed}/command.log"
malformed_exit=$?
set -e
[[ ${malformed_exit} -ge 1 && ${malformed_exit} -le 255 ]]
assert_occurrences "${malformed}/command.log" "${EXPECTED_MALFORMED}" 2
assert_occurrences "${malformed}/command.log" "${EXPECTED_REAPPLY}" 1
capture_scenario reject-malformed-syntax 2 malformed "${malformed_exit}" "${malformed_started}"

# Scenario 3 rejects a valid but post-filter undersized source and preserves LKG.
below="${RAW_ROOT}/scenarios/reject-valid-volume-below-minimum"
below_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
write_fixture_mode below-minimum
probe_fixture https://cinsscore.com/list/ci-badguys.txt "${below}/fixture-cins.body"
probe_fixture https://lists.blocklist.de/lists/all.txt "${below}/fixture-blocklist.body"
set +e
run_update "${below}/command.log"
below_exit=$?
set -e
[[ ${below_exit} -ge 1 && ${below_exit} -le 255 ]]
assert_occurrences "${below}/command.log" "${EXPECTED_BELOW_MINIMUM}" 2
assert_occurrences "${below}/command.log" "${EXPECTED_REAPPLY}" 1
capture_scenario reject-valid-volume-below-minimum 3 below-minimum "${below_exit}" "${below_started}"

for refused in "${malformed}" "${below}"; do
  for relative in ipv4.feed ipv4.snapshot ipv6.feed feeds.sha256 nft-canonical.json; do
    cmp --silent -- "${positive}/${relative}" "${refused}/${relative}"
  done
done

write_fixture_mode "${ORIGINAL_MODE}"
fixture_stopped_pid=${FIXTURE_PID}
kill -TERM "${fixture_stopped_pid}"
set +e
wait "${fixture_stopped_pid}"
fixture_exit=$?
set -e
[[ ${fixture_exit} -eq 0 || ${fixture_exit} -eq 143 ]]
test ! -e "/proc/${fixture_stopped_pid}"
FIXTURE_PID=
python3 - "${RAW_ROOT}/transport/fixture-stopped.json" \
  "${fixture_stopped_pid}" "${fixture_exit}" <<'PY'
import json
import sys
from pathlib import Path

output, pid, exit_code = sys.argv[1:]
document = {
    "exit_code": int(exit_code),
    "pid": int(pid),
    "proc_absent": True,
    "schema": "syswarden-native-feed-fixture-stop/v1",
}
Path(output).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

# Remove the temporary DNS and trust mutations while native writers remain quarantined.
restore_fixture_hosts
HOSTS_CONFIGURED=false
capture_hosts_state "${RAW_ROOT}/transport/hosts-restored.json"
cmp --silent -- "${RAW_ROOT}/transport/hosts-before.json" \
  "${RAW_ROOT}/transport/hosts-restored.json"

rm -f -- "${QUALIFICATION_CA}"
run_clean update-ca-certificates > "${RAW_ROOT}/transport/ca-remove.log" 2>&1
sha256sum -- "${CA_BUNDLE}" | sed 's#  .*#  ca-certificates.crt#' \
  > "${RAW_ROOT}/transport/ca-bundle-restored.sha256"
cmp --silent -- "${RAW_ROOT}/transport/ca-bundle-before.sha256" \
  "${RAW_ROOT}/transport/ca-bundle-restored.sha256"
set +e
run_clean openssl verify "${FIXTURE_CERT}" \
  > "${RAW_ROOT}/transport/ca-restored.verify.log" 2>&1
ca_restored_exit=$?
set -e
printf '%s\n' "${ca_restored_exit}" > "${RAW_ROOT}/transport/ca-restored.verify.exit"
[[ ${ca_restored_exit} -ge 1 && ${ca_restored_exit} -le 255 ]]
CA_INSTALLED=false

# The feed and nftables state are deliberately left synthetic. The disposable
# clone stays fail-closed until the operator exports evidence and restores its
# clean Linode snapshot. Resuming either process invalidates this campaign.
capture_service_state "${RAW_ROOT}/concurrency/service-quarantined.txt"
scan_feed_writers > "${RAW_ROOT}/concurrency/process-quarantined.txt"
test ! -s "${RAW_ROOT}/concurrency/process-quarantined.txt"
python3 - "${RAW_ROOT}/concurrency/service-before.txt" \
  "${RAW_ROOT}/concurrency/service-quarantined.txt" <<'PY'
import json
import sys
from pathlib import Path

before, after = (json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:])
for unit in ("cron.service", "syswarden-core.service"):
    baseline = dict(before[unit])
    quarantined = dict(after[unit])
    if quarantined.pop("process_state", None) != "T":
        raise SystemExit(f"{unit} main process left quarantine")
    baseline.pop("process_state", None)
    if quarantined != baseline:
        raise SystemExit(f"{unit} identity changed during qualification")
PY
capture_quarantine_barrier
python3 - "${RAW_ROOT}/product/disposition.json" <<'PY'
import json
import sys
from pathlib import Path

document = {
    "product_state_restored": False,
    "runtime_resumed": False,
    "schema": "syswarden-native-feed-disposition/v1",
    "snapshot_restore_required": True,
}
Path(sys.argv[1]).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

COMPLETED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
readonly COMPLETED_UTC
python3 - "${RAW_ROOT}/campaign.json" "${CAMPAIGN_ID}" "${STARTED_UTC}" \
  "${COMPLETED_UTC}" "${CANDIDATE_SHA}" <<'PY'
import json
import sys
from pathlib import Path

output, campaign, started, completed, candidate = sys.argv[1:]
document = {
    "candidate_sha": candidate,
    "completed_at": completed,
    "id": campaign,
    "observation_origin": "real-native-node02-lab-only",
    "runtime_quarantined": True,
    "snapshot_restore_required": True,
    "started_at": started,
    "synthetic": False,
}
Path(output).write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

python3 - "${BASH_SOURCE[0]}" "${FIXTURE_SCRIPT}" "${CONTRACT_PATH}" \
  "${RAW_ROOT}/transport/fixture-cert.pem" "${RAW_ROOT}/transport/fixture-ca.pem" \
  "${RAW_ROOT}/inputs.sha256" <<'PY'
import hashlib
import sys
from pathlib import Path

names = (
    "scripts/ci/osint_tls_qualification_lab.sh",
    "scripts/ci/osint_tls_fixture.py",
    "scripts/ci/native_feed_contract_v4.10.0.json",
    "fixture-cert.pem",
    "fixture-ca.pem",
)
records = []
for path, name in zip(sys.argv[1:6], names, strict=True):
    records.append(f"{hashlib.sha256(Path(path).read_bytes()).hexdigest()}  {name}\n")
Path(sys.argv[6]).write_text("".join(records), encoding="ascii")
PY

python3 - "${CONTRACT_PATH}" "${RAW_ROOT}" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

contract = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(sys.argv[2])
inventory = contract["raw_evidence"]["inventory"]
actual = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
if actual != inventory:
    missing = sorted(set(inventory) - set(actual))
    extra = sorted(set(actual) - set(inventory))
    raise SystemExit(f"raw evidence inventory mismatch: missing={missing}, extra={extra}")
records = []
for relative in inventory:
    path = root / relative
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"unsafe raw evidence file: {relative}")
    os.chmod(path, 0o600)
    records.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
manifest = root / contract["raw_evidence"]["manifest"]
manifest.write_text("".join(records), encoding="ascii")
os.chmod(manifest, 0o600)
PY

PYTHONDONTWRITEBYTECODE=1 python3 "${EVIDENCE_TOOL}" assemble \
  --contract "${CONTRACT_PATH}" --raw-root "${RAW_ROOT}" \
  --candidate-sha "${CANDIDATE_SHA}" --deb-package "${DEB_PACKAGE}" \
  --deb-signature "${DEB_SIGNATURE}" --signature-policy "${SIGNATURE_POLICY}" \
  --deb-key-id "${DEB_KEY_ID}" --deb-signature-date "${DEB_SIGNATURE_DATE}" \
  --node02-ssh-host-key-sha256 "${NODE02_SSH_HOST_KEY_SHA256}" \
  --output-evidence "${EVIDENCE_ROOT}/EVIDENCE.json" \
  --output-verdict "${EVIDENCE_ROOT}/VERDICT.json"

trap - EXIT INT TERM
echo "Native NODE02 feed qualification evidence passed and was sealed."
echo "NODE02 remains quarantined; restore its clean Linode snapshot before reuse."
