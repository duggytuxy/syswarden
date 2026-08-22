<div align="center">
  <img src="assets/syswarden_hero.svg" alt="SysWarden Linux host defense and release qualification overview" width="100%">
</div>

# SysWarden

SysWarden is a Linux host firewall orchestrator and out-of-band security-log
analysis toolkit. It combines an authoritative nftables policy with bounded
firewalld or UFW compatibility, local threat-intelligence lists, WAAP log
analysis, host telemetry, authenticated HA exchange and a native local terminal
dashboard.

It is not an inline HTTP proxy, a traffic sanitizer or a regulatory
certification product.

Current source version: **v4.03.2**.

Target candidate: **v4.03.2**. This documentation describes the candidate
contract. It does not claim that v4.03.2 is qualified, tagged or published.
Publication remains blocked until every protected gate passes on one exact
merged commit.

LOT 2 combines the completed Linux-only surface reduction in LOT 2A, the
six-package reproducibility work in LOT 2B and the bounded security remediation
in LOT 2S. Its technical closure becomes effective only for the exact merged
commit that passes the protected main and qualification gates. Closing LOT 2
does not authorize a tag or public Release.

The historical v4.03.1 candidate completed its protected technical
qualification but was deliberately left untagged and unpublished. Its evidence
does not authorize or replace a fresh v4.03.2 qualification.

<div align="center">
  <img src="assets/syswarden_architecture.svg" alt="SysWarden Linux host architecture with local TUI, nftables and authenticated HA migration fence" width="100%">
</div>

## Supported targets and qualification

| Target | Candidate artifact | Required release proof |
| --- | --- | --- |
| Debian or Ubuntu amd64 | `syswarden_4.03.2_amd64.deb` | Native install, upgrade, restart, removal and rollback lifecycle |
| Debian or Ubuntu arm64 | `syswarden_4.03.2_arm64.deb` | Native ARM64 lifecycle on the exact candidate package |
| Fedora or RHEL-family x86_64 | `syswarden-4.03.2-1.x86_64.rpm` | Native install, upgrade, restart, removal and rollback lifecycle |
| Fedora or RHEL-family aarch64 | `syswarden-4.03.2-1.aarch64.rpm` | Native ARM64 lifecycle on the exact candidate package |
| Alpine x86_64 | `syswarden_4.03.2_x86_64.apk` | Native OpenRC lifecycle with the dedicated CGO-free executable |
| Alpine aarch64 | `syswarden_4.03.2_aarch64.apk` | Native ARM64 OpenRC lifecycle with the dedicated CGO-free executable |

The package workflow is configured to generate two DEB, two RPM and two APK
packages plus `SHA256SUMS.txt`. No current package or updater route exists
outside this Linux matrix. ARM64 qualification uses a native runner, not CPU
emulation.

## Exact release inventory

A qualified v4.03.2 Release contains exactly thirteen public assets:

1. `syswarden_4.03.2_amd64.deb`
2. `syswarden_4.03.2_arm64.deb`
3. `syswarden-4.03.2-1.x86_64.rpm`
4. `syswarden-4.03.2-1.aarch64.rpm`
5. `syswarden_4.03.2_x86_64.apk`
6. `syswarden_4.03.2_aarch64.apk`
7. `SHA256SUMS.txt`
8. `RELEASE_SHA256SUMS.txt`
9. `syswarden-release.tar.gz`
10. `syswarden-sbom.spdx.json`
11. `plumber-report.zip`
12. `syswarden-update-manifest-v1.json`
13. `syswarden-update-manifest-v1.json.sig`

The release manager rejects missing, duplicate or unexpected assets. The
package checksum inventory, release checksum inventory and detached Ed25519
update signature are verified before publication.

## Core behavior

- The CLI maintains persistent whitelist, blocklist and SSH-exception
  registries using exact canonical IP, CIDR and supported service entries, then
  reapplies host firewall policy after controlled changes.
- The core analyzes configured logs out of band and can persist WAAP decisions
  into the host firewall state.
- The current Linux package builds, validates and commits one authoritative
  nftables ruleset. If exactly one supported firewalld or UFW frontend is
  already active, SysWarden reconciles only its bounded trusted-source and
  HA-port compatibility rules. Installed but inactive tools are not activated.
- `core.firewall_backend = "keep"` is the fresh-install default and never
  transitions an operator-managed firewall service. Policy mutation is refused
  while an iptables-services or netfilter-persistent service is active or
  enabled. Operational mutation requires an active, unambiguous supported
  service manager. Package hooks running with no service-manager runtime defer
  `install` and `reload` instead of invoking host firewall or kernel tools.
  `nftables` is a validation-only assertion that requires an already active and
  enabled nftables service. It refuses any active or enabled firewalld, UFW,
  iptables-services or netfilter-persistent frontend and never performs an
  automatic service transition.
- The `iptables` value remains parseable for configuration compatibility, but
  it is not an operational policy mode in v4.03.2. Operational firewall policy
  mutation paths reject this choice before changing persistent policy inputs
  or kernel firewall state. Automatic firewall service migration is outside
  the qualified v4.03.2 contract.
- WireGuard requires the explicit `nftables` backend. The bounded firewalld and
  UFW compatibility path does not open the WireGuard UDP port or forwarding
  rules.
- The TUI reads local telemetry and HA status. It runs inside the invoking
  terminal and opens no listening socket.
- The HA API uses TLS 1.3, a bearer token and a configurable port whose default
  is TCP 62026.
- The BunkerWeb extension is disabled by default and requires authenticated HA
  before TTL and provenance operations are enabled.

## Local terminal boundary

Run the native dashboard from a trusted local console or SSH session:

```console
sudo syswarden tui
```

The current product contains no browser terminal, HTTPS or WebSocket terminal
bridge, remote PTY route, token-management command or network terminal service.
SysWarden owns no listener and no generated firewall permission on TCP 62027.

Upgrade cleanup is deliberately bounded: it removes only verified historical
SysWarden state, preserves unrelated configuration and must not stop an
unrelated process that happens to use the same port.

## Installation and upgrade

Use only assets attached to the intended GitHub Release. Replace the example
version only after that tag is public and its complete inventory is visible.

```console
VERSION=4.03.2
TAG="v${VERSION}"
```

Download exactly one package for the host plus `SHA256SUMS.txt`, then verify the
package before invoking the native package manager:

```console
sha256sum --check --ignore-missing SHA256SUMS.txt
```

Stop if the selected package is not reported as valid. Then use the matching
native command:

```console
sudo apt-get install -y ./syswarden_4.03.2_amd64.deb
sudo dnf install -y ./syswarden-4.03.2-1.x86_64.rpm
sudo apk add --allow-untrusted ./syswarden_4.03.2_x86_64.apk
```

Run only the command for the actual distribution and architecture. For APK,
`--allow-untrusted` is acceptable only after the exact SHA-256 verification has
succeeded.

The historical public v4.02.8 binary predates the signed updater protocol. Its
first hop to v4.03.2 must use a separately downloaded and checksum-verified
Linux package. After a qualified signed-protocol release is installed,
`syswarden update` verifies the canonical manifest, detached Ed25519 signature,
platform identity, package size and SHA-256 digest before installation.

Before any upgrade:

1. retain verified local console or SSH access;
2. back up `/etc/syswarden`, required list files and HA trust material;
3. save the current firewall service state, nftables ruleset and package version;
4. verify that TCP 62027 is blocked at the host boundary;
5. test the rollback package and recovery access on a representative host.

## Optional RHEL-compatible image staging extension

The [RHEL image staging extension](extensions/rhel-image/README.md) is an
additive, opt-in path for an extracted, fresh and unmounted RHEL-family 9 or
newer image root. It is not called by the normal build, package installation,
update or reload workflows.

The extension accepts one local RPM and its expected SHA-256. It verifies the
target RPM database, dependencies, packaged Cronie provider and persistent
`crond.service` enablement, then installs only that RPM with package scripts,
triggers and RPM plugins disabled. It never enters the image root or runs a
product binary, dependency-resolving package manager, service manager,
firewall command, kernel-policy command, cron command, network request or
process signal while staging.

Use this reference sequence for a RHEL-family 9 image. The root must be a fresh,
disposable and unmounted directory tree:

```bash
set -euo pipefail
IMAGE_ROOT=/srv/image-root
CANDIDATE_RPM=/srv/image-input/syswarden-4.03.2-1.x86_64.rpm
# Copy this value from the independently authenticated package inventory.
EXPECTED_RPM_SHA256=REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS

[[ "${EXPECTED_RPM_SHA256}" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "${EXPECTED_RPM_SHA256}" "${CANDIDATE_RPM}" | sha256sum --check --strict -
sudo extensions/rhel-image/stage-syswarden-rhel-image.sh \
  --preflight-root \
  --root "${IMAGE_ROOT}"

sudo dnf -y --installroot="${IMAGE_ROOT}" --releasever=9 \
  --setopt=install_weak_deps=False install \
  nftables ipset curl wget rsyslog cronie bash-completion \
  wireguard-tools qrencode jq checkpolicy policycoreutils-python-utils \
  dnf-automatic procps-ng e2fsprogs firewalld
sudo systemctl --root="${IMAGE_ROOT}" enable crond.service firewalld.service
sudo systemctl --root="${IMAGE_ROOT}" disable nftables.service

printf '%s  %s\n' "${EXPECTED_RPM_SHA256}" "${CANDIDATE_RPM}" | sha256sum --check --strict -
sudo extensions/rhel-image/stage-syswarden-rhel-image.sh \
  --root "${IMAGE_ROOT}" \
  --rpm "${CANDIDATE_RPM}" \
  --sha256 "${EXPECTED_RPM_SHA256}"
```

The read-only `--preflight-root` call must run before `dnf` or
`systemctl --root`. It rejects `/`, a non-canonical or symlinked root, unsafe
ancestor directories, mounts below the image root and live runtime markers.
Stop on any failure. The extension performs no image or host mutation in this
mode.

The `dnf` and `systemctl --root` steps belong to the image recipe, not the
extension. They prepare dependencies and persistent boot state without
starting services on the builder. Unmount temporary image-builder mounts before
invoking the extension. Do not install or enable `iptables-services` for this
firewalld-preserving profile.

Never derive `EXPECTED_RPM_SHA256` from the candidate RPM. Obtain it from the
separately authenticated package inventory so the check establishes artifact
identity rather than only detecting a later copy race.

After the extension succeeds, prepare three protected source files under
`/srv/image-input/syswarden-config`. This must happen after staging because the
extension accepts only a fresh image at entry. Save this first block as
`config.toml` with owner `root:root` and mode `0640`:

```toml
schema_version = 1

[core]
config_dir = "/etc/syswarden/config/modules"
enterprise_mode = false
log_level = "INFO"
```

Save this block as `modules/00-core.toml` with owner `root:root` and mode
`0640`:

```toml
[core]
firewall_backend = "keep"
hardening_enabled = false
cis_l2_hardening = false
secure_wipe_conf = false
ssh_port = ""
```

Save this block as `modules/10-network.toml` with owner `root:root` and mode
`0640`. It selects standard
blocklist choice `1`, automatic infrastructure protection and explicit country
and ASN deny sets while keeping remote monitor allowlisting and WireGuard off:

<!-- syswarden-doc-toml-expect-invalid-asn -->
```toml
[network]
whitelist_infra = true
lan_subnets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
whitelist_ips = []
interfaces = ""

[network.geo]
enabled = true
blocked_countries = ["ru", "cn", "kp", "ir"]
allowed_countries = []

[network.asn]
enabled = true
# This intentionally invalid value blocks first boot until it is replaced.
blocked_asns = ["REPLACE_WITH_APPROVED_HIGH_RISK_ASN"]
allowed_asns = []

[network.saas]
allow_monitors = false

[network.blocklists]
list_choice = "1"
custom_url = ""
custom_url_ipv6 = ""
custom_hash = ""
custom_hash_ipv6 = ""
use_spamhaus = false

[network.wireguard]
enabled = false
port = "51820"
subnet = ""
```

The country set is a reviewable example, not a universal traffic policy.
Remove any country required by the deployed services. Replace the intentionally
invalid ASN marker with the exact high-risk ASN values from the image owner's
current approved risk register. Until it is replaced, configuration validation
fails and the first-boot marker is retained.
The repository does not label network operators as high risk.

After replacing the ASN marker in the protected source file, publish all three
configuration files as one directory transaction from a trusted root shell:

```bash
set -euo pipefail
umask 077
if (( EUID != 0 )) || [[ "${GROUPS[0]}" != 0 ]]; then
  printf '%s\n' 'Run this complete configuration publication block as root.' >&2
  exit 1
fi
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH
PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL
IMAGE_ROOT=/srv/image-root
CONFIG_SOURCE=/srv/image-input/syswarden-config
CONFIG_DESTINATION="${IMAGE_ROOT}/etc/syswarden/config"
CONFIG_STAGE="${IMAGE_ROOT}/etc/syswarden/.config.pending-v1"
CONFIG_FILES=(config.toml modules/00-core.toml modules/10-network.toml)

extensions/rhel-image/stage-syswarden-rhel-image.sh \
  --preflight-root \
  --root "${IMAGE_ROOT}"
for SOURCE_DIRECTORY in \
  /srv \
  /srv/image-input \
  "${CONFIG_SOURCE}" \
  "${CONFIG_SOURCE}/modules"; do
  [[ -d "${SOURCE_DIRECTORY}" && ! -L "${SOURCE_DIRECTORY}" ]]
  [[ "$(/usr/bin/stat -c '%u:%g' -- "${SOURCE_DIRECTORY}")" == "0:0" ]]
  SOURCE_MODE=$(/usr/bin/stat -c '%a' -- "${SOURCE_DIRECTORY}")
  (( (8#${SOURCE_MODE} & 8#022) == 0 ))
done
for CONFIG_FILE in "${CONFIG_FILES[@]}"; do
  SOURCE_FILE="${CONFIG_SOURCE}/${CONFIG_FILE}"
  [[ -f "${SOURCE_FILE}" && ! -L "${SOURCE_FILE}" ]]
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "${SOURCE_FILE}")" == "0:0:640:1" ]]
done

SYSWARDEN_PARENT="${IMAGE_ROOT}/etc/syswarden"
[[ ! -L "${SYSWARDEN_PARENT}" ]]
[[ ! -e "${SYSWARDEN_PARENT}" || -d "${SYSWARDEN_PARENT}" ]]
/usr/bin/install -d -o root -g root -m 0750 "${SYSWARDEN_PARENT}"
[[ ! -e "${CONFIG_DESTINATION}" && ! -L "${CONFIG_DESTINATION}" ]]
[[ ! -e "${CONFIG_STAGE}" && ! -L "${CONFIG_STAGE}" ]]
/usr/bin/install -d -o root -g root -m 0750 "${CONFIG_STAGE}/modules"
for CONFIG_FILE in "${CONFIG_FILES[@]}"; do
  /usr/bin/install -o root -g root -m 0640 \
    "${CONFIG_SOURCE}/${CONFIG_FILE}" "${CONFIG_STAGE}/${CONFIG_FILE}"
  /usr/bin/cmp --silent -- \
    "${CONFIG_SOURCE}/${CONFIG_FILE}" "${CONFIG_STAGE}/${CONFIG_FILE}"
done
/usr/bin/mv --no-clobber --no-target-directory \
  "${CONFIG_STAGE}" "${CONFIG_DESTINATION}"
[[ ! -e "${CONFIG_STAGE}" && -d "${CONFIG_DESTINATION}" && ! -L "${CONFIG_DESTINATION}" ]]
[[ "$(/usr/bin/stat -c '%u:%g:%a' -- "${CONFIG_DESTINATION}")" == "0:0:750" ]]
[[ "$(/usr/bin/stat -c '%u:%g:%a' -- "${CONFIG_DESTINATION}/modules")" == "0:0:750" ]]
for CONFIG_FILE in "${CONFIG_FILES[@]}"; do
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' -- "${CONFIG_DESTINATION}/${CONFIG_FILE}")" == "0:0:640:1" ]]
  /usr/bin/cmp --silent -- \
    "${CONFIG_SOURCE}/${CONFIG_FILE}" "${CONFIG_DESTINATION}/${CONFIG_FILE}"
done
```

If this block fails or leaves a pending directory, discard and rebuild the
disposable image root.

Each configured country and ASN requires a matching non-empty IPv4 and IPv6
file in `/etc/syswarden/lists`, for example `ru.ipv4`, `ru.ipv6`, and one pair
named after each approved ASN. Generate canonical CIDRs through an authenticated
local pipeline and verify an exact `SHA256SUMS` manifest before publishing the
list directory. Runtime validation rejects missing or empty files,
mixed-family entries, default routes, IPv4 prefixes broader than `/24`, and
IPv6 prefixes broader than `/64` before nftables policy publication. The
general persistent-list grammar permits canonical private unicast ranges. For
these country and ASN deny files, the authenticated image-owner pipeline must
exclude private and other non-public ranges because they do not establish
country or ASN ownership. Direct GeoIP, RADB or single-origin ASN reputation is
not accepted as authenticated authority for deny policy.

Publish the exact policy set as one exclusive transaction from a trusted root
shell. The block refuses partial per-command elevation. Replace the invalid ASN
in both the TOML and `APPROVED_ASNS` before running it:

```bash
set -euo pipefail
umask 077
if (( EUID != 0 )) || [[ "${GROUPS[0]}" != 0 ]]; then
  printf '%s\n' 'Run this complete policy publication block as root.' >&2
  exit 1
fi
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH
PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL
IMAGE_ROOT=/srv/image-root
POLICY_SOURCE=/srv/image-input/policy-lists
extensions/rhel-image/stage-syswarden-rhel-image.sh \
  --preflight-root \
  --root "${IMAGE_ROOT}"
POLICY_DESTINATION="${IMAGE_ROOT}/etc/syswarden/lists"
POLICY_STAGE="${IMAGE_ROOT}/etc/syswarden/.lists.pending-v1"
# Copy this value from the authenticated image-owner policy inventory.
EXPECTED_POLICY_MANIFEST_SHA256=REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS
COUNTRY_CODES=(ru cn kp ir)
APPROVED_ASNS=(REPLACE_WITH_APPROVED_HIGH_RISK_ASN)

[[ "${EXPECTED_POLICY_MANIFEST_SHA256}" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "${EXPECTED_POLICY_MANIFEST_SHA256}" \
  "${POLICY_SOURCE}/SHA256SUMS" | /usr/bin/sha256sum --check --strict -

POLICY_FILES=()
for COUNTRY_CODE in "${COUNTRY_CODES[@]}"; do
  [[ "${COUNTRY_CODE}" =~ ^[a-z]{2}$ ]]
  POLICY_FILES+=("${COUNTRY_CODE}.ipv4" "${COUNTRY_CODE}.ipv6")
done
for APPROVED_ASN in "${APPROVED_ASNS[@]}"; do
  [[ "${APPROVED_ASN}" =~ ^AS[1-9][0-9]{0,9}$ ]]
  ASN_NUMBER="${APPROVED_ASN#AS}"
  (( 10#${ASN_NUMBER} <= 4294967295 ))
  POLICY_FILES+=("${APPROVED_ASN}.ipv4" "${APPROVED_ASN}.ipv6")
done

mapfile -t MANIFEST_LINES < "${POLICY_SOURCE}/SHA256SUMS"
MANIFEST_FILES=()
declare -A EXPECTED_POLICY_SET=()
for POLICY_FILE in "${POLICY_FILES[@]}"; do
  [[ -z "${EXPECTED_POLICY_SET[${POLICY_FILE}]+x}" ]]
  EXPECTED_POLICY_SET["${POLICY_FILE}"]=1
done
declare -A MANIFEST_POLICY_SET=()
for MANIFEST_LINE in "${MANIFEST_LINES[@]}"; do
  [[ "${MANIFEST_LINE}" =~ ^[0-9a-f]{64}\ \ ([A-Za-z0-9]+\.(ipv4|ipv6))$ ]]
  MANIFEST_FILE="${BASH_REMATCH[1]}"
  [[ -z "${MANIFEST_POLICY_SET[${MANIFEST_FILE}]+x}" ]]
  MANIFEST_POLICY_SET["${MANIFEST_FILE}"]=1
  MANIFEST_FILES+=("${MANIFEST_FILE}")
done
(( ${#EXPECTED_POLICY_SET[@]} == ${#MANIFEST_POLICY_SET[@]} ))
for POLICY_FILE in "${POLICY_FILES[@]}"; do
  [[ -n "${MANIFEST_POLICY_SET[${POLICY_FILE}]+x}" ]]
done

(
  cd "${POLICY_SOURCE}"
  /usr/bin/sha256sum --check --strict SHA256SUMS
)
[[ ! -e "${POLICY_DESTINATION}" && ! -L "${POLICY_DESTINATION}" ]]
[[ ! -e "${POLICY_STAGE}" && ! -L "${POLICY_STAGE}" ]]
/usr/bin/install -d -o root -g root -m 0750 "${POLICY_STAGE}"
for POLICY_FILE in "${POLICY_FILES[@]}"; do
  [[ -f "${POLICY_SOURCE}/${POLICY_FILE}" && ! -L "${POLICY_SOURCE}/${POLICY_FILE}" ]]
  /usr/bin/install -o root -g root -m 0640 \
    "${POLICY_SOURCE}/${POLICY_FILE}" "${POLICY_STAGE}/${POLICY_FILE}"
done
/usr/bin/install -o root -g root -m 0640 \
  "${POLICY_SOURCE}/SHA256SUMS" "${POLICY_STAGE}/SHA256SUMS"
printf '%s  %s\n' "${EXPECTED_POLICY_MANIFEST_SHA256}" \
  "${POLICY_STAGE}/SHA256SUMS" | /usr/bin/sha256sum --check --strict -
(
  cd "${POLICY_STAGE}"
  /usr/bin/sha256sum --check --strict SHA256SUMS
)
/usr/bin/mv --no-clobber --no-target-directory \
  "${POLICY_STAGE}" "${POLICY_DESTINATION}"
[[ ! -e "${POLICY_STAGE}" && -d "${POLICY_DESTINATION}" && ! -L "${POLICY_DESTINATION}" ]]
printf '%s  %s\n' "${EXPECTED_POLICY_MANIFEST_SHA256}" \
  "${POLICY_DESTINATION}/SHA256SUMS" | /usr/bin/sha256sum --check --strict -
(
  cd "${POLICY_DESTINATION}"
  /usr/bin/sha256sum --check --strict SHA256SUMS
)
```

The block copies no glob and no unlisted input. If it fails or leaves a pending
directory, discard and rebuild the disposable image root.

After payload verification, the extension enables a marker-guarded first-boot
unit that requires `crond.service`. The real host then runs the normal `install`
and `reload` workflows. The pinned `keep` profile preserves firewalld. If
exactly one supported firewalld frontend is active, the bounded compatibility
path may use it without changing its service state. nftables remains the
authoritative SysWarden policy engine.

Run the image builder's normal SELinux relabel, ownership, bootloader and ISO
assembly stages, then boot a disposable target. Verify `crond.service` and
`firewalld.service` are active and enabled, inspect
`syswarden-image-firstboot.service`, run `syswarden config validate`, inspect
`nft -j list table inet syswarden`, and confirm
`/var/lib/syswarden/image/firstboot.pending` is absent. Offline staging does not
establish runtime readiness or widen the qualified package matrix. Image assembly,
signing and target-host validation remain image-builder responsibilities. The
extension README contains the exact list-file and recovery checks.

## Configuration

The modular configuration root is `/etc/syswarden/config`. Later module
filenames have higher precedence. Back up the complete directory before an
edit, validate the candidate and apply it only after reviewing the effective
diff.

`schema_version = 1` is the current modular schema. When `schema_version` is
absent, the configuration is treated as historical input. An explicit future,
negative or non-integer schema version fails closed.

Validate without editing files or applying environment overrides:

```console
sudo syswarden config validate --path /etc/syswarden/config
```

`syswarden config validate` is read-only. All unknown and deprecated keys are
reported as diagnostics; a semantic or structural violation still fails
validation. The CLI validator and core loader enforce the same semantic matrix
for blocklist choice, URL and hash combinations, Wazuh endpoint completeness,
compliance intervals, SHA-256 prefixes, trimmed HA peers and SSH/HA port
separation while WireGuard is enabled.

Preview a historical-to-modular migration before publishing any file:

```console
sudo syswarden config migrate \
  --source /opt/syswarden/syswarden-auto.conf \
  --output /etc/syswarden/config \
  --dry-run
```

`syswarden config migrate --dry-run` performs zero source or destination
writes, including when a previous migration transaction requires recovery.
`syswarden migrate-config` remains a compatibility alias with the same
transactional and dry-run contract.

A historical `SYSWARDEN_FIREWALL_BACKEND="firewalld"` value migrates to
`core.firewall_backend = "keep"` so the existing service is preserved without
an automatic transition. A historical configuration that enables WireGuard
with any backend other than `nftables` is rejected for operator remediation;
the migration never changes that security choice silently.

The official SaaS monitor setting is disabled unless explicitly enabled:

```toml
[network.saas]
allow_monitors = false
```

`network.saas.allow_monitors` takes precedence over the deprecated
`integrations.saas.enabled` alias; if neither is set, monitor allowlisting is
disabled. Enabled monitor feeds must use absolute HTTPS URLs without
credentials or fragments. TLS 1.3 is required, redirects are rejected and each
download is bounded to 10 seconds, 1 MiB, 1,024 bytes per line, 20,000 lines
and 10,000 entries. A required-feed, syntax or bound failure preserves the
previous lists. Valid canonical IPv4 and IPv6 results are published as one
lock-coordinated atomic pair with an SHA-256 pair manifest and rollback on
publication failure.

WAAP log settings use canonical single-space-separated absolute patterns.
Configured globs are reduced to verified exact real regular-file matches. The
core opens them descriptor-relative without following links and revalidates the
file identity and type after every rotation; it never creates a missing target.
Rsyslog inputs are emitted only for paths that pass the same validation at
configuration time, but rsyslog later reopens those names itself, so operators
must keep every parent directory protected against untrusted replacement.
Rsyslog strings and WireGuard values are validated and encoded for their
destination grammars before configuration publication.

## Persistent list grammar

Blocklist, whitelist and SSH-exception values use exact canonical IPv4 or IPv6
addresses and masked CIDRs. Hostnames, address zones, IPv4-mapped IPv6 values,
invalid ports, control characters and ambiguous substring matches are rejected.
The address family must match the destination list.

Use the explicit flag to limit a whitelist entry to one TCP service:

```console
sudo syswarden whitelist 192.0.2.10 --port 443
```

`--port` scopes a whitelist entry to one TCP service; omitting it creates an
address-wide whitelist entry. SSH exceptions are rendered only for the
effective SSH port. A port-qualified SSH entry must equal that effective port,
and a changed-port mismatch fails closed before candidate policy application.
Reconcile the SSH exception registry from verified console access before
applying an SSH port change.

Minimal authenticated HA and BunkerWeb example:

```toml
[integrations.ha]
enabled = true
peer_ips = ["192.0.2.10", "192.0.2.11"]
peer_port = 62026
token = "replace-with-a-secret-from-a-protected-channel"

[integrations.bunkerweb]
enabled = true
```

Do not commit a real HA token. Exact peer IPs may be dialed. Canonical CIDRs are
inbound authorization ranges only and are never outbound destinations. When
`/etc/syswarden/ha-ca.pem` exists, clients use that explicit trust bundle;
otherwise they use the system trust store.

## HA dialect and ownership rules

One authenticated `GET /ha/status` selects the dialect independently for each
peer and for one serialized synchronization cycle. Enriched operations require
both `sync_ttl` and `sync_provenance`. A missing, partial, malformed or failed
capability response stops the handoff for that peer and never downgrades TLS or
bearer authentication.

The ownership stores and delete operations remain separate:

- `DELETE {"bans": [...]}` removes provenance ledger entries only;
- `DELETE {"ips": [...]}` explicitly removes historical static entries;
- neither operation cascades into another peer;
- the integrator cleans only addresses present in its durable, peer-specific
  record of historical submissions;
- ownership is never inferred from `GET /ha/sync`, provenance pagination or an
  effective union returned by a peer.

This separation prevents an integrator from deleting a local operator entry,
a WAAP-owned entry or another producer's durable claim.

## HA migration fence

Historical-to-provenance cleanup is a cluster campaign, even though every HA
mutation remains peer-scoped. The operator owns the complete member and
external-writer inventory. SysWarden owns the per-node native-sync fence. The
integrator owns the durable per-peer journal, explicit cleanup requests and
completion decision.

### Operator workflow

One trusted control host creates one protected activation manifest and
distributes that same file to every member and to the integrator:

```console
sudo syswarden ha-fence manifest create \
  --inventory /root/syswarden-ha-inventory.json \
  --output /root/syswarden-ha-manifest.json \
  --assert-complete
sudo syswarden ha-fence manifest verify \
  --manifest /root/syswarden-ha-manifest.json
sudo syswarden ha-fence engage \
  --manifest /root/syswarden-ha-manifest.json
sudo syswarden ha-fence status --json
```

Manifest files are strict, canonical, owner-only inputs. Creation performs a
fresh authenticated and challenge-bound status request to every exact member,
verifies the live TLS leaf identity and records one random campaign epoch. A
member, endpoint, certificate or external-writer change requires a new
manifest and resets every partner observation window.

Release is root-only and requires the unchanged manifest plus durable terminal
closure evidence for every external legacy writer:

```console
sudo syswarden ha-fence release \
  --manifest /root/syswarden-ha-manifest.json \
  --writer-closure /root/syswarden-ha-writer-closure.json
```

Use `ha-fence recover` with the same manifest after an interrupted engagement.
Never engage a retired epoch and never reconstruct a manifest from peer output.

### Integrator verification

The capability `native_sync_fence_v1` announces schema support only. It is not
evidence that a fence is active or drained.

For every manifest member, the integrator obtains one fresh authenticated,
challenge-bound `GET /ha/status` response over the verified and leaf-pinned TLS
connection. It accepts fence evidence only when all of these values match the
operator manifest and the same response:

- `native_sync_fence.state` is `active_drained`;
- the challenge echo matches the unique request challenge;
- the live leaf certificate SHA-256 matches the manifest member;
- `epoch` equals the manifest epoch;
- `membership_sha256` equals the manifest membership digest;
- `legacy_writer_inventory_sha256` equals the manifest writer digest;
- the `X-SysWarden-HA-Fence-Condition` response header equals the JSON
  `condition` value;
- server instance, generation, condition and membership remain stable for the
  accepted observation.

The integrator treats the epoch and both digest values as opaque,
case-sensitive strings. It compares them for exact equality and does not
recalculate either digest or reimplement SysWarden canonicalization.

Every explicit historical cleanup request sends the observed value in:

```text
X-SysWarden-HA-Fence-Condition: <condition>
```

While the fence is active and drained, a missing condition receives HTTP 428,
a malformed condition receives HTTP 400 and a stale condition receives HTTP
412. Each rejection performs no mutation. HTTP 412 means the fence changed;
the integrator stops, refreshes the complete all-member proof and requires an
operator decision instead of blindly retrying.

An unavailable member, blind interval, changed membership, changed certificate,
changed server instance, changed generation or reappearing address resets the
partner observation. A one-hour continuous absence window is additional
evidence only. It is never proof of drain and never permits claim release from
a partial cluster view.

## Operator commands

The table lists product commands only. Cobra help and shell-completion utilities
remain available separately.

| Command | Purpose |
| --- | --- |
| `alerts` | Stream kernel and WAAP alert events |
| `allow-ssh` | Add an address to the SSH exception registry |
| `audit` | Run a bounded local operational diagnostic |
| `block` | Add addresses or CIDRs to the persistent blocklist |
| `check` | Inspect recorded firewall state for an address |
| `config` | Validate, inspect and migrate modular configuration |
| `config-get` | Read one effective configuration key |
| `ha-fence` | Administer a cluster migration fence |
| `ha-sync` | Push missing local durable entries to exact peers |
| `install` | Run the host-mutating installation pipeline |
| `list` | Display local registries and active HA bans |
| `manual` | Display the built-in operator reference |
| `migrate-config` | Run the compatible legacy configuration migration entry point |
| `reload` | Reapply policy and normally restart the core |
| `revoke-ssh` | Remove an address from the SSH exception registry |
| `tui` | Launch the native local terminal dashboard |
| `unblock` | Remove addresses or CIDRs from the blocklist |
| `uninstall` | Delete SysWarden services, rules, configuration, data and logs |
| `unwhitelist` | Remove addresses or CIDRs from the whitelist |
| `update` | Install an update verified by the signed manifest |
| `update-feeds` | Download configured feeds and reapply firewall policy |
| `whitelist` | Add addresses or CIDRs to the persistent whitelist |
| `whitelist-infra` | Detect and add local infrastructure addresses |

Use `syswarden <command> --help` before any host-mutating action.

## Files, services and ports

| Surface | Linux path or default |
| --- | --- |
| Modular configuration | `/etc/syswarden/config` |
| Legacy configuration input | `/opt/syswarden/syswarden-auto.conf` |
| HA client trust bundle | `/etc/syswarden/ha-ca.pem` |
| HA server identity | `/var/lib/syswarden/ha/server.crt` and `server.key` |
| Local telemetry | `/var/lib/syswarden/ui/data.json` |
| Persistent IP registries | `/etc/syswarden/lists` |
| Logs | `/var/log/syswarden` |
| Core service | `syswarden-core.service` or OpenRC equivalent |
| Firewall service | `syswarden-firewall.service` or OpenRC equivalent |
| HA API | TCP 62026 by default, configurable |
| Native TUI | No listening port |

Never copy `server.key` to a client. Transfer only the public certificate or CA
material through a trusted channel and verify its fingerprint before trust is
enabled.

## Security posture and limitations

- Keep recovery access before applying firewall, SSH, package or migration
  changes. Test from a second session before closing the first.
- `reload` validates the configured backend before host mutation, commits a
  validated nftables candidate, reconciles at most one active firewalld or UFW
  compatibility frontend and normally restarts the core. It is not a
  zero-interruption guarantee.
- `audit` inspects selected local services, files, firewall state and
  configuration. It is not a compliance certification.
- WAAP decisions are derived from logs already written by another service.
  SysWarden does not proxy or sanitize live HTTP requests.
- Log-driven enforcement requires one validated authoritative source address.
  Ambiguous, conflicting or hostless records fail closed before firewall
  mutation.
- SysWarden internal security records use process-local authentication and do
  not copy raw attacker-controlled payloads into the ingestion path.
- Feed and SaaS allowlist publication is bounded and retains the last known
  good state when source authority, quorum, integrity or target policy fails.
- HA requires a complete operator inventory. A peer list, status response or
  effective union cannot prove cluster completeness.
- BunkerWeb migration cleanup remains limited to the partner's durable
  ownership journal. Ambiguous co-ownership requires operator review.
- SIEM, webhook and external feed security also depends on the configured
  remote endpoint, trust material and network policy.
- On Alpine Linux, SysWarden does not configure automatic operating-system
  security updates. Repository selection and the `apk` update policy remain
  an explicit operator responsibility.
- `uninstall` removes configuration, state and logs and does not restore every
  prior host setting. Back up required data before use.
- A downgrade is a controlled emergency action. Keep TCP 62027 blocked and do
  not restore retired authentication material.
- Support and qualification claims apply only to the exact package matrix and
  evidence described in this document.

## Release evidence and report

The [v4.03.2 public release readiness report](docs/reports/PUBLIC_RELEASE_READINESS_REPORT_v4.03.2.md)
records the exact package and asset inventory, migration contract, security
limits and remaining release gates.

Maintainers must complete the
[local release preflight and prequalification procedure](docs/maintainers/LOCAL_RELEASE_PREFLIGHT.md)
before pushing a release candidate or dispatching protected qualification. The
local mirror never authorizes a tag or public Release.

The report and this README remain candidate documentation until protected
qualification passes and the maintainer authorizes the immutable tag.

## License

See [LICENSE](LICENSE).
