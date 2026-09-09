# Offline candidate qualification channel

## Purpose

The offline candidate channel permits a protected native lab to install an
unpublished SysWarden candidate without changing the production update
discovery contract. It is selected only by an explicit command:

```console
syswarden update \
  --qualification-bundle /root/syswarden-v4.10.0-qualification \
  --candidate-version v4.10.0
```

Both flags are mandatory together. Positional arguments are rejected. A normal
`syswarden update` still uses the stable GitHub release channel and is not
affected by this qualification-only path.

The normalized evidence invocation is exactly
`syswarden update --qualification-bundle /absolute/path --candidate-version v4.10.0`.

## Bundle contract

The protected `candidate-update-bundle.yml` workflow produces one non-public
artifact for the exact untagged `main` SHA and the exact qualified native
signing artifact. Its root contains the canonical descriptor, checksum file,
the `node01/` qualification bundle and the `verification/` material needed to
verify the producer attestation and detached DEB signature. The workflow does
not create a tag or GitHub Release. The protected native-evidence and release
qualification workflows must independently resolve the same immutable
artifact by run and artifact ID and revalidate it before accepting evidence.
Before it may use the updater signing key, the workflow requires the committed
native package policy to be qualified and explicitly approved for future
publishing. That approval only establishes eligibility. This workflow retains
read-only repository permissions and cannot create a tag, Release or public
asset. Requiring the decision before this bundle ensures that the package,
candidate update, native evidence and final qualification all share one exact
source SHA.

Only the exact host subdirectory is passed to `syswarden update`. For NODE01,
that directory is `node01/` and has the three-file contract below.

The bundle path must be canonical and absolute. Every path component is opened
from the filesystem root through descriptor-rooted traversal and symbolic-link
components are rejected. The final directory must be owned by the effective
operator UID and have mode `0700`.

The directory contains exactly three files for the current host:

```text
syswarden-update-manifest-v1.json
syswarden-update-manifest-v1.json.sig
<the exact DEB, RPM, or APK selected for this host>
```

Every file must be regular, non-symlinked, owned by the effective operator UID,
have mode `0600`, and have a link count of one. Unexpected entries are rejected.
The manifest and signature are reread and compared immediately before package
installation. The selected package is copied by an already-open descriptor into
the existing protected update workspace, then its size and SHA-256 digest are
verified again immediately before the package manager is invoked.

Before that transaction, the updater derives the expected CLI SHA-256 directly
from the authenticated open package descriptor. It requires exactly one regular
`opt/syswarden/bin/syswarden-cli` payload owned by root, with mode `0750` and a
nonempty bounded size. DEB qualification accepts the repository's produced
`data.tar.gz` member only; another DEB data compression is rejected rather than
decoded through an unpinned helper. RPM decoding receives the authenticated
descriptor on standard input, and APK decoding reads that same descriptor. A
missing, duplicate, linked, misowned, over-permissive, or changed payload fails
before installation. The installed CLI digest must then match this package
payload digest exactly after installation and immediately before activation.

The protected lab consumes the detached `.deb.asc` signature only from a
`qualified-policy` signed package bundle. A `bootstrap-qualification` bundle is
not eligible for candidate installation or release qualification. Before
extracting or executing the candidate CLI, the lab externally verifies the
exact selected DEB key ID, complete primary fingerprint and public-key SHA-256
sealed in native signing provenance against the committed policy. During a
rotation overlap, it does not infer a key by counting non-revoked policy
records. This external result does not claim that the candidate self-verified
its own native package trust root.

The canonical v1 manifest must be signed by an Ed25519 key already embedded in
SysWarden. The explicit candidate version, platform identity, package filename,
size, and SHA-256 digest must all match. The candidate must be at least the first
signed-updater version and strictly newer than the installed host version.

## Installed-version attestation

The candidate CLI does not use its own compiled version as the source version.
After bundle authentication, it keeps the fixed installed CLI
`/opt/syswarden/bin/syswarden-cli` open and requires a regular, nonempty file
with the exact owner UID, mode `0750`, and link count one. Its inode, device,
size, metadata, and SHA-256 digest must remain stable during package-manager
attestation.

The complete package-manager attestation has a positive two-minute deadline.
A blocked query, verification process, cancellation, or deadline expiry fails
before package installation. Qualification commands run in a dedicated process
group. Cancellation terminates and reaps the command group, and a command that
leaves a live descendant is rejected.

The DEB path compares installed package state and version, fixed-path ownership,
and `dpkg` verification. The RPM path requires the package query and fixed-file
owner query to return the same package, version, and architecture, followed by
RPM verification. The APK path requires its installed package version and the
fixed-file owner version to match exactly. DEB and RPM verification may report
operator changes only when the package manager explicitly classifies each
record as a declared conffile. Any non-conffile drift, including a changed CLI,
is rejected.

After the native package transaction returns success, the updater repeats the
same fixed-path package ownership, version, integrity, file identity, and CLI
SHA-256 attestation. The resulting version must equal the candidate exactly.
Service activation cannot begin before that post-install proof succeeds.

## Pre-publication evidence boundary

The v4.04.3 binary predates these flags and cannot be modified retroactively.
A pre-publication v4.04.3 to v4.10.0 lab therefore runs the candidate CLI that
was extracted from the same candidate package only after external verification
of the manifest, signature, package digest, and candidate CLI digest against the
trust material available to v4.04.3. The lab must record that candidate CLI
identity and the exact protected source commit.

This proves the offline qualification channel and candidate package transition.
It does not prove that the installed v4.04.3 updater executed the transition.
The real production `syswarden update` transition from v4.04.3 to v4.10.0 can
only be proven after the stable release is published. Release evidence must keep
these two attestations distinct.

## Preflight and network boundary

With both qualification flags present, the root command skips automatic
configuration loading and firewall recovery until the bundle is authenticated.
It retains the read-only removal-tombstone guard. Incomplete qualification flags
fail before the updater or any preflight hook runs.

The qualification updater has no HTTP client, release API URL, download URL, or
network fallback. Its package-manager command is also separate from production:
DEB uses direct `dpkg --install` so no cached dependency package can be added;
DNF and YUM disable plugins and require `--cacheonly`,
`--disablerepo=*`, and `--setopt=localpkg_gpgcheck=1`; APK requires
`--no-network --no-cache --repositories-file /dev/null` and retains native
package-key verification without `--allow-untrusted`. Every declared native package dependency is queried from
the installed package database under the same bounded attestation deadline,
and required runtime executables receive a second local identity check. Missing
dependencies or a missing native trust key
fail the qualification instead of enabling repository access or bypassing
package signatures. The production updater emitted by v4.10.0 also requires
`localpkg_gpgcheck=1` for a local RPM and no longer permits the APK
`--allow-untrusted` bypass.

DNF, YUM, and APK do not expose one portable, machine-readable transaction
contract that proves a local install will modify only the candidate when their
caches already contain other packages. A protected qualification lab must
therefore enforce and attest host-level egress denial from before this command
until post-install package and CLI attestation completes. This external control
also contains any maintainer script from a cached dependency selected by the
native solver. The updater does not claim that its package-manager flags alone
prove a candidate-only transaction.

The package-manager process receives a private qualification marker. A package
maintainer script recognizes it only together with `SYSWARDEN_PKG_INSTALL=1`.
This first phase stages the package without starting services, timers, network
probes, or feed jobs. Only after the updater has repeated the exact package and
CLI attestation does it invoke the fixed installed CLI for activation with a
separate private marker. Activation does not benchmark mirrors or invoke the
feed downloader. It validates and reuses the active, owner-only, digest-bound
last-known-good feed snapshots already on the upgrade host. A required missing,
malformed, substituted, or provenance-inconsistent snapshot fails closed.
Production installation without the private marker keeps the existing online
refresh behavior.

A custom last-known-good feed must match both the SHA-256 identity of the exact
configured HTTPS URL and the configured digest of the raw authority bytes that
were accepted during publication. The separately recorded canonical snapshot
digest must also match the active policy bytes. A disabled threat feed, LAN
mode, or unselected custom address family removes its owned active snapshot and
provenance before policy activation, then attests its absence. The offline path
never silently applies an obsolete remote deny list.

Built-in feed reuse is bound independently for IPv4 and IPv6 to the exact
selected Data-Shield profile and OSINT source identities. A custom snapshot, a
snapshot from the other built-in profile, an unsupported provenance quality,
or an extra source is retired before refresh or activation. This also prevents
a custom IPv6 snapshot from being merged into a later built-in OSINT result.

Install-time webhook connectivity checks and WireGuard endpoint discovery or
interface activation are deferred in qualification mode. Existing configuration
and attested WireGuard state are preserved. The normal production install path
retains those operations. Production package-manager children are explicitly
stripped of the private qualification markers, so caller environment variables
cannot select the offline post-install branch.

The updater itself performs no release discovery, package retrieval,
package-manager repository access, mirror benchmarking, feed refresh, webhook
verification, or WireGuard endpoint discovery in this channel. A total
transaction count of zero additionally requires the mandatory lab egress deny
described above. Restarting the installed service after exact post-install
attestation can resume separately configured runtime traffic such as HA peer
communication. Evidence must measure and classify that runtime boundary
separately; a total host count of zero is valid only when those runtime features
are disabled or isolated in the lab. Native evidence must also record unchanged
operator and firewall state before validation, installation beginning only
after bundle validation, the external egress control, and the full normalized
invocation.
