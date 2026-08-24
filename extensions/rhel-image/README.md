# RHEL image staging extension

This directory contains an optional, additive image-builder extension. Its
production staging entry point is not hooked into normal SysWarden build,
package installation, update, or reload paths. Nothing changes in an image
unless an image builder invokes the script explicitly. Release qualification
runs only the isolated fake-tool contract harness described below.

The extension stages one local SysWarden RPM into a fresh, offline
RHEL-family 9 or newer filesystem tree. It is intended for an extracted image
root before ISO assembly, not for a running host and not for an upgrade.

## Interface

Run the extension with all three required values:

```console
sudo extensions/rhel-image/stage-syswarden-rhel-image.sh \
  --root /srv/image-root \
  --rpm /srv/image-input/syswarden-4.03.2-1.x86_64.rpm \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Use the digest from the trusted package inventory. The digest proves that the
local bytes match the selected artifact; it does not by itself prove publisher
identity. Keep the RPM outside the image root in a root-owned directory. The
script must run as root with primary group root. The RPM, the image root, and
every real ancestor directory of the RPM parent and image root must be
root-owned and must not be group or world writable. Paths must be absolute,
canonical, and contain no whitespace.

The extension is deliberately native-architecture only. The RPM architecture
must already appear in the target RPM database, and the local `rpm` tool must
accept it without an architecture override.

## Reference RHEL 9+ image recipe

The following procedure keeps image construction separate from first-boot
runtime convergence. Run the image-builder commands against a disposable,
unmounted directory tree. Do not bind-mount `proc`, `sys`, `run`, or another
runtime filesystem below that tree.

1. Define the local inputs and install the RPM prerequisites into the image
   root with the repositories approved for that image:

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
   ```

   The read-only preflight must be the first root-level operation in the
   recipe. It rejects `/`, host-directory shapes such as `/etc`, a
   non-canonical or symlinked root, unsafe ancestor directories, mounts below
   the image root, live runtime markers, and roots without exact RHEL-family
   9+ `/usr/lib/os-release` metadata. Stop on any failure. It performs no image
   or host mutation and does not require RPM tooling or installed image
   dependencies.

   Enable Cronie and the preferred RHEL firewall frontend in the image without
   starting either service on the builder:

   ```bash
   set -euo pipefail
   IMAGE_ROOT=/srv/image-root
   sudo extensions/rhel-image/stage-syswarden-rhel-image.sh \
     --preflight-root \
     --root "${IMAGE_ROOT}"
   sudo systemctl --root="${IMAGE_ROOT}" enable crond.service firewalld.service
   sudo systemctl --root="${IMAGE_ROOT}" disable nftables.service
   ```

   Do not install or enable `iptables-services`. SysWarden's `keep` mode
   preserves firewalld and refuses active or enabled iptables service units.

2. Unmount any temporary image-builder mounts, verify the candidate bytes, and
   run the extension:

   ```bash
   set -euo pipefail
   IMAGE_ROOT=/srv/image-root
   CANDIDATE_RPM=/srv/image-input/syswarden-4.03.2-1.x86_64.rpm
   # Copy this value from the independently authenticated package inventory.
   EXPECTED_RPM_SHA256=REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS

   [[ "${EXPECTED_RPM_SHA256}" =~ ^[0-9a-f]{64}$ ]]
   printf '%s  %s\n' "${EXPECTED_RPM_SHA256}" "${CANDIDATE_RPM}" | sha256sum --check --strict -
   sudo extensions/rhel-image/stage-syswarden-rhel-image.sh \
     --root "${IMAGE_ROOT}" \
     --rpm "${CANDIDATE_RPM}" \
     --sha256 "${EXPECTED_RPM_SHA256}"
   ```

   Never derive the expected digest from the candidate RPM. The expected value
   must come from the separately authenticated package inventory.

3. Only after the extension succeeds, add the image-owner configuration. The
   extension requires a fresh root at entry, so configuration is deliberately
   a separate image-recipe step. Prepare protected source files below
   `/srv/image-input/syswarden-config`. Save this first block as `config.toml`
   with owner `root:root` and mode `0640`:

   ```toml
   schema_version = 1

   [core]
   config_dir = "/etc/syswarden/config/modules"
   enterprise_mode = false
   log_level = "INFO"
   ```

   Save this block as `modules/00-core.toml` with owner `root:root` and mode
   `0640` to pin the firewalld-preserving backend:

   ```toml
   [core]
   firewall_backend = "keep"
   hardening_enabled = false
   cis_l2_hardening = false
   secure_wipe_conf = false
   ssh_port = ""
   ```

   Save this block as `modules/10-network.toml` with owner `root:root` and mode
   `0640`. This reference selects
   standard blocklist choice `1`, keeps automatic infrastructure protection,
   disables remote monitor allowlisting and WireGuard, and requests explicit
   country and ASN deny sets:

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

   The country codes are a reviewable example, not a universal traffic policy.
   Remove any country required by the image's service routes. Replace the
   intentionally invalid ASN marker with the exact high-risk ASN values from the
   image owner's current approved risk register. Until it is replaced,
   configuration validation fails and the first-boot marker is retained. The
   repository does not assign risk labels to network operators.

   After replacing the ASN marker in the protected source file, publish all
   three configuration files as one directory transaction from a trusted root
   shell:

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

4. Provide the policy data before first boot. Every configured country and ASN
   requires one non-empty canonical IPv4 file and one non-empty canonical IPv6
   file under `/etc/syswarden/lists`. Names are deterministic after the ASN
   marker has been replaced:

   ```text
   ru.ipv4             ru.ipv6
   cn.ipv4             cn.ipv6
   kp.ipv4             kp.ipv6
   ir.ipv4             ir.ipv6
   AS<approved>.ipv4   AS<approved>.ipv6
   ```

   Replace the invalid marker in both the TOML file and the recipe variable.
   Each list contains one canonical IP or CIDR per line for that exact country
   or ASN. Runtime validation rejects an empty or missing file, mixed-family
   entries, default routes, IPv4 prefixes broader than `/24`, and IPv6 prefixes
   broader than `/64` before nftables policy publication. The general
   persistent-list grammar permits canonical private unicast ranges. For these
   country and ASN deny files, the authenticated image-owner pipeline must
   exclude private and other non-public ranges because they do not establish
   country or ASN ownership.

   Generate these files through an authenticated image-owner pipeline and
   record exactly the expected filenames in `SHA256SUMS`. The following recipe
   rejects the placeholder, rejects missing or extra manifest entries, copies
   only manifest-listed regular files into a private staging directory,
   verifies the staged bytes, and atomically publishes that directory. Run the
   complete block from a trusted root shell; it refuses partial per-command
   elevation:

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

   Run this block as one exclusive image-recipe transaction. If it fails or a
   pending directory remains, discard and rebuild the disposable image root.

   Direct GeoIP, RADB, or single-origin ASN downloads are not treated as
   authenticated authority for deny policy. Existing verified files are
   preserved instead. Do not enable a source and assume that its reputation
   alone authorizes kernel policy.

5. Run the image builder's normal SELinux relabel, ownership, bootloader,
   package inventory, and ISO assembly stages. The extension intentionally does
   not perform those product-specific steps.

6. Boot a disposable target from the resulting image. Before accepting the
   image, verify the first-boot transaction and effective policy:

   ```console
   sudo systemctl is-active crond.service firewalld.service
   sudo systemctl is-enabled crond.service firewalld.service
   sudo systemctl status syswarden-image-firstboot.service
   sudo journalctl -u syswarden-image-firstboot.service --no-pager
   sudo syswarden config validate --path /etc/syswarden/config
   sudo nft -j list table inet syswarden
   sudo test ! -e /var/lib/syswarden/image/firstboot.pending
   ```

   Confirm recovery access and expected business traffic before reusing the
   image recipe. A failed first-boot unit retains its marker and retries on the
   next boot; inspect and correct the cause instead of deleting the marker.

## Staging contract

Before any package transaction or first-boot publication, the script:

- refuses `/` as the image root;
- refuses symlink components in the root and RPM input paths;
- refuses unsafe ownership or modes on security-critical inputs;
- accepts only an `ID` or `ID_LIKE` in the RHEL family with major version 9 or
  newer;
- refuses a mount whose target is exactly the image root or is below it;
- refuses live or ambiguous runtime paths under `run`, `proc`, or `sys`;
- refuses any installed SysWarden package, SysWarden-named path, or SysWarden
  cron state;
- refuses nested cron symlinks, special files, and oversized cron files rather
  than following or reading them;
- requires an offline systemd image with a regular `systemd` executable and a
  regular marker-removal utility;
- requires the packaged `crond.service` unit and `crond` daemon from the same
  installed `cronie` version, plus an exact persistent enablement link;
- resolves production tools only from root-owned, non-writable `/usr/bin`,
  uses fixed root-owned RPM configuration files, and clears ambient RPM
  configuration variables;
- requires `rpm --noplugins` support and exactly one safe target RPM database
  layout: real `/var/lib/rpm` for RHEL-family 9, or real
  `/usr/lib/sysimage/rpm` plus the exact compatibility link for version 10 and
  newer; and
- snapshots the local RPM into a private extension directory and verifies the
  required SHA-256 before trusting package metadata.

An ancestor mount such as `/home` or `/srv` does not make a child staging
directory a mount point. The script refuses only the target itself and mounts
inside it, including bind-mounted runtime trees.

The target database path is derived from the attested target OS version, never
from the builder's RPM defaults, and is passed explicitly to every rooted RPM
operation. The script reads the RPM dependency capabilities and proves that
each one is already provided by that target database. It never installs a
dependency. It also requires an exact allowlist of package payload paths and
refuses unsafe payload-parent or RPM-database paths before the transaction. It
then runs a test transaction followed by exactly one local installation:

```text
rpm --noplugins --rcfile SYSTEM_RPMRC --macros SYSTEM_MACROS --root IMAGE_ROOT --dbpath TARGET_RPM_DBPATH --install --test --noscripts --notriggers LOCAL_RPM
rpm --noplugins --rcfile SYSTEM_RPMRC --macros SYSTEM_MACROS --root IMAGE_ROOT --dbpath TARGET_RPM_DBPATH --install        --noscripts --notriggers LOCAL_RPM
```

No dependency bypass, forced replacement, or package replacement option is
used. Package scriptlets and triggers are disabled for both transactions. The
extension does not enter the root, execute a product binary, scan or signal a
process, edit cron, call a service manager, or call a firewall or kernel policy
tool during image staging.

After installation, the script compares the installed package identity with
the local RPM, asks RPM to verify the installed payload with verification
scripts disabled, and independently checks the expected binaries,
`signatures.json`, modes, ownership, and command links under the image root.

## First boot

Only after payload verification succeeds does the extension publish these
image-owned artifacts:

```text
/etc/systemd/system/syswarden-image-firstboot.service
/etc/systemd/system/multi-user.target.wants/syswarden-image-firstboot.service
/var/lib/syswarden/image/firstboot.pending
```

The enablement link is created last. The unit is a oneshot guarded by
`ConditionPathExists` on the marker. On the real first boot it runs the normal
active-host commands in this order. It requires and starts after
`crond.service`, so the CLI can prove an active, enabled Cronie provider before
any host mutation:

```text
/opt/syswarden/bin/syswarden-cli install
/opt/syswarden/bin/syswarden-cli reload
```

The marker is removed only by `ExecStartPost`, after both commands succeed. A
failure leaves the marker in place, so a later boot retries. Once the marker is
gone, the condition makes the still-enabled unit idempotently inactive.

The unit does not order itself before, require, or want the SysWarden core and
firewall units. This avoids a dependency cycle when `install` publishes and
starts those services. It waits for `network-online.target` and is ordered
after `firewalld.service` if that unit is part of the boot transaction, but it
does not start or enable firewalld.

The unit sets the supported package-install context marker
`SYSWARDEN_PKG_INSTALL=1`. This matches the normal RPM post-install context and
prevents `install` from invoking dnf or yum to resolve dependencies that the
staging transaction already proved. It is not a firewall-backend override.
First boot still runs the normal install and reload commands and may use the
network for their configured sources, including mirror checks or feed
downloads.

Because this path accepts only a fresh image with no SysWarden configuration,
the normal first-boot `install` command generates the current default
`core.firewall_backend = "keep"` configuration before firewall mutation. The
extension does not attempt an unsupported firewall-backend environment
override. The `keep` behavior preserves the operator-managed firewall service
state. If firewalld is already active, the normal SysWarden compatibility path
can use it; this extension neither selects service state nor establishes
runtime qualification.

## Limits and tradeoffs

- This is a fresh-image staging path only. Existing product package, payload,
  configuration, state, logs, service files, or cron entries cause refusal.
- The target must be an unmounted directory tree. Mounting pseudo-filesystems,
  bind-mounting runtime directories, or operating on a live root is rejected.
- Dependencies must already be installed. This avoids suppressing maintainer
  scripts for newly installed dependencies, at the cost of requiring the image
  recipe to prepare them first.
- Package scripts are intentionally skipped. Normal host initialization is
  deferred to the image-owned first-boot unit.
- RPM plugins are disabled. The image recipe must perform its normal final
  SELinux labeling pass; this module does not claim that builder-side file
  labels are suitable for the target host.
- Immediately before the RPM transaction, the extension publishes a private,
  root-owned transaction journal. A caught failure or abrupt interruption
  after package installation leaves the image inert because the first-boot
  enablement link is published last. Re-running the exact command with the
  exact RPM and digest reattests the journal, package, payload, and bounded
  partial extension state, then resumes publication idempotently. The journal
  is removed last.
- An abrupt interruption before journal publication can leave only a private
  RPM snapshot. On the next explicit invocation, the extension removes it only
  when its directory name, ownership, mode, regular-file names, and file modes
  match the exact extension-owned format. A symlink or unknown entry fails
  closed without traversal.
- A transaction journal with a different artifact, modified payload, unknown
  SysWarden state, or an RPM-level partial install without one exact installed
  package fails closed. Rebuild the fresh image root in that case; the extension
  never guesses at an erase or upgrade rollback.
- This module stages an extracted root. ISO creation, signing, bootloader
  assembly, and image publication remain the image builder's responsibility.

## Tests

Run the adversarial test harness from the repository root:

```console
extensions/rhel-image/tests/test-stage.sh
```

The harness uses fake RPM and mount tools. It proves the required transaction
flags, version-specific RPM database selection, explicit rooted database paths,
first-boot order and retry marker semantics, fresh-image refusal,
mount-boundary behavior, input hardening, interruption recovery, and absence of
image-time process, service, firewall, cron, or kernel-policy commands. It also
runs Bash syntax and static forbidden-command checks.

The protected Linux release-qualification workflow runs this harness. That is
offline fake-tool contract evidence; it is not RHEL target-host runtime
qualification and does not activate a service or firewall on the runner.
