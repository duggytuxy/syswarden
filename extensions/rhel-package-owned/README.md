# RHEL package-owned runtime profile

This directory defines the second, anonymous RHEL 9 or newer image profile.
It is additive and explicitly opt-in. The default SysWarden package builder,
package lifecycle and first RHEL image extension remain unchanged when the
profile flag is absent.

Status: implemented, included in the v4.10.0 candidate scope and not yet
qualified. Release publication remains blocked until the exact signed profile
RPM passes the protected AlmaLinux 9 and AlmaLinux 10 native campaigns.

## Contract

The alternate RPM owns the operating-system integration while the Go binaries
remain runtime components:

- the RPM owns the two systemd units, the SysWarden-only preset and the
  protected configuration, state and log directories;
- the four expected RPM scriptlets are reviewed flat shell sources, never call
  a SysWarden binary, and every other transaction, verification and trigger
  script section must be absent;
- initial installation presets only `syswarden-firewall.service` and
  `syswarden-core.service` and does not start them during the package
  transaction;
- a `mock`, `dnf --installroot` or chroot transaction does not require a
  running systemd manager and performs no network or host firewall mutation;
- upgrade does not reapply presets or override an administrator's enablement
  decision or configuration files;
- upgrade from the standard v4.04.3 RPM accepts only its exact protected
  `/etc/systemd/system` units, preserves the administrator's enablement choice,
  and makes the package-owned vendor units authoritative;
- verified removal is deliberately two phase: `syswarden uninstall` cleans
  mutable runtime state and publishes the exact erase-ready boundary, then the
  native RPM erase removes the package-owned payload;
- final RPM removal rejects a missing cleanup boundary, removes only the two
  SysWarden enablement links, and attests that the services are inactive and
  unqueued when a live systemd manager is present;
- no scriptlet calls `firewall-cmd`, changes SELinux policy, or enables,
  disables, starts or stops `firewalld.service` or `nftables.service`;
- the RPM requires systemd, while the existing generic nftables dependency
  remains authoritative. It does not force installation of firewalld.

Dynamic policy compilation and enforcement still occur when the packaged
SysWarden services run. That is runtime work, not package installation work.

The reviewed service sources are flat under:

```text
src/init/systemd/
src/init/openrc/
```

The OpenRC files are checksum-bound review sources. They are intentionally not
installed in this RHEL payload.

## Build the opt-in RPM

Run the normal local builder with the one explicit profile flag:

```console
./build_packages.sh --rhel-package-owned-profile
```

The flag changes only the RPM inputs. The DEB and APK paths continue to use
their normal payload and lifecycle. The standard and package-owned variants
intentionally share the RPM package name `syswarden`, making them mutually
exclusive, but use distinct releases and filenames:

```text
syswarden-4.10.0-1.x86_64.rpm
syswarden-4.10.0-1.rhelpo.x86_64.rpm
```

The package-owned filename, NEVRA, bytes and RPM signing identity are bound to
profile-specific provenance. It is published as a separate opt-in asset and is
never selected by `syswarden update`.

The builder performs these profile-specific operations:

1. atomically stages the digest-bound profile inventory;
2. refuses collisions with the profile-owned unit, preset and identity file;
3. overlays only the declared RPM payload;
4. selects the four package-owned scriptlets;
5. fixes private directory ownership metadata to `root:root` and mode `0750`;
6. requires SHA-256 RPM file digests;
7. disables automatic `/usr/lib/.build-id` links because this profile ships no
   debuginfo and exact reversible payload ownership takes precedence;
8. verifies the built RPM without installing it.

Without `--rhel-package-owned-profile`, the historical builder sources and
arguments remain selected.

## Stage build inputs without building a package

The stager is useful for an isolated image or package pipeline. Its output path
must be absolute and must not already exist:

```console
WORK_DIRECTORY="$(mktemp -d /tmp/syswarden-rhel-profile.XXXXXXXXXX)"
PROFILE_STAGE="${WORK_DIRECTORY}/profile"
python3 extensions/rhel-package-owned/stage.py \
  --enable-rhel-package-owned-profile \
  --output "${PROFILE_STAGE}"
```

The stager validates the complete inventory before publication, reads only
canonical owner-controlled regular sources, rejects hard links and symlinks,
uses a private sibling directory, fsyncs the result and publishes it with one
atomic no-replace rename. It never invokes a package manager, service manager,
firewall tool or SysWarden binary.

The output contains:

```text
assembly-manifest.json
payload/
reviewed-sources/openrc/
rpm-scriptlets/
```

`inventory.json` is the source of truth. Every managed entry declares its
object type, mode, target UID and GID, link target, SHA-256 content identity,
role, RPM ownership class and RPM package identity. Directory checksums and
link targets are null because directories have no file bytes and this profile
does not install symlinks. Parent transport directories created by the stager
are not product-owned RPM entries.

## Verify a built RPM

Use an independently recorded digest for the opt-in RPM:

```console
python3 extensions/rhel-package-owned/verify-rpm.py \
  --rpm /absolute/path/syswarden-4.10.0-1.rhelpo.x86_64.rpm \
  --sha256 REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS
```

The verifier is read-only. It checks the package bytes, identity, architecture,
SHA-256 payload digest algorithm, required dependencies, the exhaustive RPM
path allowlist, types, modes, owners, single-link metadata, link targets, file
digests, file flags, empty capabilities and contexts, and all four expected
scriptlet bytes. It also proves every other transaction,
verification and trigger script section is absent, and rejects unsafe
integration-path parents, undeclared service-manager payload, an OpenRC
payload, a forced firewalld dependency and any SysWarden binary or
firewall-frontend transition in scriptlets.

The supplied digest alone does not establish publisher identity. Release
qualification also requires the complete sealed signing sub-bundle, its native
RPM verification and its profile-specific provenance.

## Image pipeline use

An image pipeline may opt in only to the exact v4.10.0 profile artifact that
passed release qualification. It can be installed through a normal RHEL
`mock` or chroot image transaction without a running systemd instance. The RPM
owns the configuration, firewall integration files, units and preset; its
scriptlets never execute a SysWarden binary. On an offline install root,
`systemctl preset` writes only the two SysWarden enablement links. The first
real boot must then prove that both services start correctly. On a live system,
the same preset is applied only for the initial install. The package never
selects or transitions the host's firewall frontend.

The image owner remains responsible for selecting and configuring the desired
frontend before first boot. Existing firewalld deployments are preserved.
Direct nftables deployments remain valid. Ambiguous or conflicting firewall
frontends must still fail through the normal SysWarden runtime checks.

The distribution-owned `/usr/lib` parent may retain its native root-owned
`0555` mode or use `0755`. Installation, runtime attestation and erase preserve
that mode. This allowance applies only to that shared parent; dedicated product
directories, ownership, symlink rejection and all other metadata checks remain
exact.

The package deliberately owns only the protected configuration directories,
not an administrator's TOML files. This makes an image pipeline free to seed
its approved configuration after the RPM transaction. Later RPM upgrades do
not replace those files and do not re-enable a service disabled by the image
owner. Dynamic nftables policy is compiled only when the packaged firewall
service starts on the real system.

On a configured host, do not erase this variant directly. Run
`syswarden uninstall` first and require its package-owned erase-ready result,
then erase the exact `syswarden` RPM with the native package manager. The final
scriptlet accepts only that protected boundary and an empty mutable-state
inventory. It removes the boundary and the exact empty vendor drop-in directory
after RPM payload removal. Any substituted unit, residual runtime state or
unexpected directory content fails closed for operator review.

The package-executed `%postun` wrapper invokes the digest-bound durable helper
with the exact private `rpm-postun-v1` mode. It deliberately does not query the
RPM database from inside the running RPM transaction, where nested queries are
backend- and version-dependent. Its authority is the exact PREUN package
identity, ownership, payload and barrier attestation, followed by the reviewed
POSTUN wrapper's exact helper path, metadata and bytes. The no-argument operator
replay runs outside the RPM transaction and is the only mode that requires the
canonical `rpm -q syswarden` absence proof with empty stderr.

If RPM reports a final `%postun` failure after the package record has already
been removed, the protected replay helper remains on disk. Confirm that
`LC_ALL=C rpm -q syswarden` returns exactly `package syswarden is not installed`,
then verify the helper before executing it:

```bash
sudo stat -Lc '%u:%g:%a:%h:%s' -- \
  /var/lib/.syswarden-rhelpo-postun-recovery-v1
# Expected: 0:0:700:1:9843
sudo sha256sum -- /var/lib/.syswarden-rhelpo-postun-recovery-v1
# Expected SHA-256: 64aa4a61059a5b6dcf82b9bf6eeb1edfb402e0a5bf2ba262a99608b4eabcd75c
sudo /bin/sh /var/lib/.syswarden-rhelpo-postun-recovery-v1
```

The helper refuses an installed SysWarden RPM, altered authorization state,
unexpected residue, or modified directory metadata. Before the erase-ready
marker is durably consumed, a failure retains both the helper and marker. After
marker consumption, a late helper-removal failure may retain only the exact
helper; the same no-argument replay then verifies that the package and every
product residue are absent before removing that terminal helper.

Do not combine this profile with the first RHEL image extension in one image.
They represent different ownership models.

## Native qualification required for v4.10.0

Before this profile can be called qualified or distributable, first establish
its distinct package identity and signed provenance, then run the approved RHEL
9 and RHEL 10 matrix with the exact signed v4.10.0 candidate RPM and capture
evidence for:

- clean installation and configuration under SELinux Enforcing;
- upgrade from the supported stable baseline;
- two consecutive reboots;
- rollback to the supported baseline;
- final removal and purge expectations;
- exact RPM file and scriptlet verification;
- preservation of the operator-selected firewalld or nftables frontend;
- absence of new product-caused SELinux AVC denials;
- HIDS, HIPS, WAAP, ASN, GEO, OSINT and firewall runtime behavior;
- CPU, RSS, latency, throughput and I/O performance gates.

No VPS or image is mutated by the repository tests in this directory. Passing
those source and assembly tests does not qualify the profile.
