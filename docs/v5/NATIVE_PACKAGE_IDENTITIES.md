# Native package identities and dependency retention

Development design for issue #422 and consolidated PR452. This document does not
establish production package support, migration readiness or v5.00.0 IVVQ
acceptance. Published v4 release package metadata and canonical signatures remain unchanged.
Local opt-in metadata generation, unsigned v5 workflow generation and the v5
signed identity contract are intermediate implementations.
SysWarden supports Linux AMD64 only.

## Identity boundary

The intended fresh package identity is `syswarden-base`. Its native requirements
contain the independently verified base runtime and lifecycle prerequisites.
Optional VPN, Wazuh and hardening features require explicit configuration and
their separate prerequisite checks. Mandatory Alpine components, including
nftables, OpenRC, Cronie, `cronie-openrc`, process tools and account tools, remain
required.

Existing installations retain the full `syswarden` compatibility package. It
continues to require its historical dependencies and owns the complete runtime
payload. The fresh `syswarden-base` package owns the same complete runtime paths
with only base prerequisites. Neither variant depends on the other. Keeping the
historical dependency graph rooted avoids converting every
installed optional package into a manual administrator selection. Existing
manual, group, hold, version-pin and repository-tag choices must survive.
Unrelated automatically installed packages must remain eligible for their normal
native cleanup.

The fresh installation command must explicitly select the new identity. Two
artifacts with the same native name but different dependency promises are not a
safe substitute. Same-identity upgrades preserve ownership: `syswarden` stays
`syswarden`, and `syswarden-base` stays `syswarden-base`. There is no automatic
cross-variant transition. Removing the compatibility package is a separate
prepared operation: native dependency retention must succeed before its
requirements disappear. Keeping that package after a claimed complete product
removal is not acceptable.

## Local builder support

`./build_packages.sh` retains the compatibility identity and historical dependency
sets. `./build_packages.sh --minimal-package` generates the base identity in
`dist/packages/minimal`, with its own `SHA256SUMS.txt`. It cannot be combined with
`--rhel-package-owned-profile`. Both modes build an exact committed source snapshot
using the existing pinned toolchain. Commit the metadata helper and builder
together before a complete local build.

The helper `scripts/ci/package_variant_metadata.sh` selects the name,
dependencies and mutual conflict for local and v5 workflow builds. It declares no provider alias, replacement,
obsoletion or dependency between the two identities. The runtime staging paths,
service names, launchers and recovery hook path remain unchanged. The generated
Debian changelog uses its native package name. Alpine install, upgrade and removal
context selectors are bound to the selected identity during script generation.

| Native format | Direct base dependencies |
| --- | --- |
| DEB | `bash-completion`, `cron`, `curl`, `jq`, `nftables`, `procps`, `wget` |
| RPM | `bash-completion`, `cronie`, `curl`, `jq`, `nftables`, `procps-ng`, `wget` |
| APK | `bash-completion`, `cronie`, `cronie-openrc`, `curl`, `jq`, `nftables`, `openrc`, `procps-ng`, `shadow`, `wget` |

These sets match the manual base resolver. They are direct requirements, not a
claim about a distribution's transitive dependency graph. Local metadata tests
execute the builder's FPM argument generation with a stub and its nfpm
configuration generation without installing packages. They verify exact names,
dependencies, conflicts, unchanged staging selections and hook context routing.
They do not establish native install, update or removal acceptance.

The public package workflow preserves the historical three-artifact build for
v4. The v5 unsigned build produces both complete identities, in compatibility
DEB/RPM/APK then base DEB/RPM/APK order. Each has separate staged hooks and payload
provenance extraction. Exact native names, versions, architectures, dependency
profiles, conflicts and hook contents are checked for both identities before
checksum publication. Unsupported generation majors are refused.

The pinned nfpm APK writer does not emit its generic conflict field. APK variants
therefore declare the other identity as an explicit negative native dependency.
DEB and RPM retain their native conflict metadata. This does not authorize a
cross-variant solver transition or prove its safety.

Unsigned inventory validation accepts exactly the versioned package set. V5
release preparation and publication remain refused before staging because the
native signing and release-evidence consumers still require coordinated
identity-bound proofs. Native payload and lifecycle qualification remain open.
Do not deploy opt-in base artifacts as accepted packages until those paths pass.

Standalone uninstall now checks both native names on DEB, RPM and APK. It refuses
direct payload removal while either name is registered, including partial Debian
states, and reports the corresponding native removal command. Coexisting names
or conflicting package authorities require repair. The historical optional RPM
profile's runtime-only removal exception remains limited to `syswarden`.
DEB and RPM systemd payload ownership checks select the registered variant and
bind the file inventory and release evidence to that exact name. They refuse
cross-variant ownership, coexistence and unproven state. The historical Debian
recovery exception also remains limited to `syswarden`.

Online and offline updaters require one fully installed compatibility package
before reading release metadata or opening a qualification bundle, then recheck
the identity before installation. `syswarden-base` is explicitly refused until
identity-aware dependency retention, native attestation and public generation
are qualified together. Unregistered/manual installations are
also refused and must use their documented installation procedure. Package
registration checks are bounded read-only queries; they do not authorize an
automatic variant switch or implement base updates. Native lifecycle qualification
remains required for these source changes.

The registered native database authority also determines the package format and
frontend. An available APT frontend cannot select a DEB for an RPM-owned
installation, and a missing matching frontend cannot fall back to another
authority. DNF and YUM remain alternatives within the same RPM authority. The
current-version integrity check uses the same binding. Immediately before an
online or offline installation, the package name, installed state and authority
must still match the original observation. This comparison detects observed
identity drift; it is not a native package database lock or permission to convert
between the two package names. Published v4 signed manifest bytes and artifact names remain unchanged.

Online updates also derive the expected CLI digest from the authenticated open
package before installation. Native-manager success is followed by a repeated
selected-package registration check and exact installed version, ownership and
CLI-byte attestation. A mismatch, failed observation or cancellation prevents
post-install finalization and a success message. This does not undo a partial
native transaction or establish runtime health; durable APK transition recovery
and complete payload/lifecycle qualification remain separate requirements.

## Signed identity and installed ownership

The v5 producer and consumer use `syswarden-update-manifest/v3`. Its exact ordered
inventory is compatibility DEB/RPM/APK followed by base DEB/RPM/APK, with explicit
`package_name` values, format-specific filenames and Linux AMD64 identities.
Missing variants, duplicates, unknown names, reordered records or a filename for
the other variant are refused. The dependency-retention contract remains
mandatory. V4 retains its exact three-artifact v1 encoding and signatures.

Artifact matching compares the attested native name as well as platform, format
and filename. Installed-package version and CLI ownership queries also use the
selected native name; another variant cannot satisfy their owner proof. Queries
are restricted to the two known names and fixed read-only native operations.
DEB installed evidence must contain exactly the selected name, fully installed
status, canonical version and `amd64`. APK uses a bounded offline installed-list
query and requires one exact selected-name/version record with `x86_64` and
installed status before querying CLI ownership. Its origin and license are
display metadata, not identity authority. Duplicate records, malformed output,
foreign names and unsupported architecture values are refused. RPM retains its
exact selected-name/version/`x86_64` binding to CLI ownership.

The DEB and APK query formats have been observed on existing
packages in isolated Linux AMD64 Debian 13 and Alpine 3.22/3.24 containers.
Those observations validate query compatibility only. Regression fixtures bind
both SysWarden names and prove that invalid DEB/APK identity evidence cannot
reach the ownership query. Neither proves downloaded payload headers,
dependency retention, runtime behavior or migration acceptance. The production
native transaction matrix remains open.

## Selected native preparation

The unsigned package build also runs the updater's native header reader against
its actual generated standard artifacts: three compatibility packages for v4,
or both identities in all three formats for v5. It checks exact native name,
version/revision and AMD64 architecture, rejects the other identity or release,
and verifies unchanged bytes, metadata and descriptor offsets. A separate report
gate requires every expected case to run and pass without skips, then binds each
reported digest to the actual package. Missing tests, duplicated cases and stale
reports cannot satisfy this gate. This inspection does not install packages,
execute maintainer scripts or establish native signature or lifecycle acceptance.

The separate `native_package_identity_evidence.py` component verifies a
qualification-only schema 2 evidence bundle for all six standard v5 coordinates.
The caller must independently authenticate the release commit, evidence seal,
signature policy and selected keys. The verifier requires exact ordered native
inventories, identity-specific signature records and complete file bindings.
It rechecks native signatures through the existing offline verification adapters
and refuses cross-identity substitution. DEB detached signatures preserve the
original package bytes; APK signing must add only the selected signature prefix
to the exact unsigned bytes. RPM signing may change only its signature header
and canonical zero padding. A bounded v4 framing reader independently compares
the actual lead, entire main header and compressed payload using their sizes and
SHA-256 digests, before any native verifier is invoked. A matching builder proof
cannot authorize a changed content region, even if the seal is rebound to it.
The comparison does not decompress or extract files. Native metadata and the
proof's uncompressed CPIO digest remain caller-authenticated assertions; this
framing check does not replace native signature or package-identity validation.

Native RPM verification accepts the bounded RSA/SHA256 verdict forms from RPM 4
and RPM 6. RPM 6 reports the full OpenPGP fingerprint; the verifier binds it to
one valid signing key in the separately selected certificate. Historical short
key IDs must still resolve uniquely. Conflicting signers, unknown or weak
signature lines, missing signatures and failed verdicts remain refused. This
supports the verifier output change documented in the
[RPM 6.0 release notes](https://rpm.org/releases/6.0.0); it does not enable RPM v6
package framing, OpenPGP v6 keys, another algorithm or production publication.

Native verifier execution limits each output channel to 1 MiB while reading,
with a 60-second execution deadline and closed standard input. A private process
group is stopped before its original leader is reaped; successful output cannot
leave ordinary inherited descendants holding the pipes. Native adapters that
launch external container daemons still own their container cleanup. Kernel
stalls and processes deliberately escaping the group are outside this userspace
execution guarantee. DEB status and logger evidence retain their exact bytes,
including line endings; diagnostics never copy rejected tool output.

Six inert v5 packages have also passed the actual native signature adapters and
the updater identity reader, using disposable keys for both package names. The
sealed bundle repeats all six verifications, preserves DEB bytes and the APK
unsigned suffix, and compares RPM content and uncompressed CPIO. RPM 4 and RPM 6,
plus APK on Alpine 3.22 and 3.24, reject altered or unsigned packages; DEB signatures
cannot be substituted between variants. These are signature interoperability
checks on inert payloads, not full product installation or migration acceptance.

The component has no publishing mode or production updater entry. Its bundle
tests and native observations are scoped evidence. Each RPM verification uses an
isolated trust database. No fixture installs a package or uses a release key.
V4 serializers remain unchanged, and v5 public signing and publication remain
closed pending coordinated full-product qualification.

The retention components explicitly select one known native owner. DEB and RPM
queries bind identity and historical requirements to that name; product records
must have the supported native architecture. A correctly generated base package
has no historical optional dependencies to promote. Independently installed
optional packages retain their existing reasons and are not inspected as owned
dependencies merely because their names are known.

The native retention oracle exercises the actual Go preparation component with
inert local packages in offline Debian 13, AlmaLinux 10 and Fedora 44 containers.
Both compatibility dependency retention and minimal same-name upgrades preserve
administrator sentinels and the unrelated packages' automatic cleanup eligibility.
The captured test executable is a bounded regular single-link file, copied from
the same bytes used for its evidence digest. Source drift, skipped Go oracles and
unverified container cleanup fail the probe. These observations qualify the
retention component and synthetic package graph, not full product hooks or
runtime migration. DNF5 multi-name queries explicitly delimit each result.

APK checks the selected installed record, architecture and bounded world/database
snapshots. Coexisting product identities, missing or duplicated product roots,
and selected-product version pins, repository tags or conflict constraints are
refused. A bare product root or an exact `name><Q1...` root matching the installed
record checksum is accepted. The checksum must use the observed canonical APK v2
encoding; it is native identity evidence, not signature authority. A local-file
update rebinds this checksum to the new package. Other root forms are not
normalized or silently dropped. A local-file add could rewrite administrator
constraints or create an explicit root;
that is not authorized by a same-name update. Existing constrained dependency
roots remain unchanged, and only eligible unrooted historical dependencies are
added to the planned transaction. These snapshots do not lock the native database. Disposable Alpine 3.22 and 3.24
observations with inert nfpm-generated APK v2 files confirm checksum-root
rebinding and the need to refuse explicit pins and tags. They do not qualify
product scripts, native APK v3 formats or a full migration.

Offline prerequisite attestation uses the selected variant's exact profile. RPM
also requires the systemd runtime separately from its declared package metadata.
No optional module is installed or activated by this attestation. RPM channel
queries bind the selected name, epoch zero, standard release, exact running
version and x86_64; the separate package-owned RHEL channel stays refused.
Cancellation before or during a prerequisite or channel query cannot become
accepted evidence. Bounded dependency, payload, installation and activation
callbacks are also refused if they return success after their own deadline; a
late native result cannot authorize the next phase or a completion claim.

Historical compatibility APK v4 builds omitted the native revision and may
contain a normalized numeric minor, such as `4.3.2`. Installed attestation maps
that spelling to `v4.03.2`, while comparing raw CLI ownership text exactly first.
Only the compatibility v4 identity can use this historical interpretation. Base
and v5 installed packages require an explicit canonical revision. Ambiguous
revision syntax remains refused; parsing does not establish package trust.

Both production base-update gates remain closed. These components and their
injected-query regressions require native transaction, autoremove and recovery
qualification before base updates can be enabled.

## Downloaded native identity

Online and offline updaters inspect the already authenticated package descriptor
before handing it to a native installer. The selected package name, release
version and native architecture must match its actual header, not just its
filename or signed inventory entry. Both paths refuse a missing verifier,
malformed or ambiguous metadata, cancellation and an expired inspection deadline.
The offline path performs this check before extracting the candidate CLI.

The bounded readers support the current builder profiles: gzip control metadata
in DEB ar archives, V4 RPM typed headers and APK v2 gzip/tar streams. APK accepts
the optional signature stream but requires exactly one control metadata record
and one data stream. RPM requires the standard release `1` and absent or zero
epoch. New APKs require exactly revision `r0`. Local generation and unsigned v5
workflow generation set that revision explicitly and disable nfpm semantic
normalization, preserving `5.00.0-r0`. Historical hosted v4 generation continues
to omit the revision. Compatibility v4 candidate headers accept only the exact
canonical or historical numeric spelling derived from the selected authenticated
release, with no suffix or revision zero. A different revision, variant or
release is refused. A retained signed v4.10.4 APK and inert real nfpm builds
exercise these header forms; this does not re-establish their signature or
release acceptance. Unsupported framing or alternative profiles fail closed.

Inspection does not execute package tools, scripts or payloads. It preserves the
descriptor position and bounds metadata sizes and archive traversal. The signed
digest and private file identity are checked again after inspection and after the
last installed-package preflight. A mandatory execution guard repeats this check
after native dependency retention and APK argument preparation, using the actual
installation deadline, immediately before native handoff. Regression cases
refuse same-inode mutations and cancellation during these boundaries. Sparse tar
entries are refused before draining synthesized holes, so they cannot bypass
the expanded archive budget.
Pathname handoff is still not an atomic native transaction or a package database
lock. Header parsing does not replace native signatures, payload validation,
dependency retention or lifecycle qualification.

Inert packages built with dpkg-deb, rpmbuild and pinned nfpm exercise both native
names without installation. These format observations and component regressions
are intermediate evidence only; they do not establish product migration or
v5.00.0 IVVQ acceptance. Production base updates remain refused.

Production base updates remain explicitly refused. The new signed inventory
does not enable compatibility-package substitution, switch package identity,
relax native signature verification or bypass historical dependency retention.
Public workflows preserve the stable v4 three-artifact contract. Unsigned v5
generation does not open native signing, production updates or release acceptance.

## Payload handoff boundary

The selected design avoids ownership handoff during supported upgrades. Mutual
`Conflicts` expresses that the variants cannot coexist, but does not promise that
a package frontend will refuse every request to switch. A frontend can plan
removal of the installed variant to satisfy a request for the other one. Such
removal invokes the existing lifecycle and can lose the historical dependency
root. No untouched-state guarantee is made for an operator-authorized switch,
forced install or erasure transaction. Same-path collisions are not a substitute
for qualification of default APT, dpkg, DNF, RPM and APK entry points.

Do not treat `Conflicts`, `Breaks`, `Replaces`, `Obsoletes`, force-overwrite flags
or an incoming package script as proof of safe refusal. Native solvers and package
script failure semantics differ. In particular, an APK `preupgrade` error can be
followed by payload and registration changes. A hook installed by the incoming
package cannot guard that transaction's earlier planning boundary.

The existing laboratory characterizes an earlier compatibility-to-base graph.
Its fixtures have two distinct scopes:

1. A disjoint payload layout tests the package graph without overlapping runtime
   paths. The historical runtime belongs to the old package. After a successful
   compatibility upgrade, that path is absent and the new runtime is owned by the
   base package at a different path. No automatic runtime activation occurs.
2. Shared-path handoff and installation of the base onto an unprepared legacy
   system are characterization cases. The laboratory supplies no replacement or
   erasure overrides. It records registration, file content and native ownership,
   including partial outcomes after a nonzero transaction exit.

Success for the disjoint synthetic layout does not validate the selected full
package variants or transfer of current production paths. The selected variants
do not support coexistence, and the laboratory is not their acceptance matrix.

## Controlled APK launcher transition candidate

The current product payload and hooks do not implement this transition. Direct
APK installation and upgrade remain unqualified for administrator launcher
collisions, including same-identity upgrades of both package variants. An incoming
preinstall/preupgrade refusal cannot guarantee that APK leaves the filesystem
unchanged. Omitting a formerly owned alias from the new package alone is also
unsafe: the old package's cleanup can delete it.

The separate `scripts/ci/apk_protected_path_probe.py` characterizes a possible
pre-transaction bridge with inert APK v2 packages on apk-tools 2.14.12 and 3.0.8.
It uses existing cached Linux AMD64 images, no network or host mounts, verifies
actual container isolation before execution and verifies exact container cleanup.
Run it only with `--run-native`, an existing absolute `--nfpm` executable, an
exact cached `--image` ID and a new absolute `--output` directory. The independent
fixtures accept unsigned packages; the product verification contract does not.

Both identities run twelve scenarios with separately seeded native remove and
purge lifecycles, for 48 observations per image. The original cases change regular
file bytes or a symlink target relative to the old package. Additional cases keep
those bytes or targets and change only mode or timestamps. The probe separately
compares file/link identity, inert command output, native ownership and parent
metadata. A retained symlink does not prove that its target's behavior survives
replacement or removal. These consumers do not establish real SSH, firewall or
service preservation.

| Preparation and payload | Upgrade observation | Later removal observation |
| --- | --- | --- |
| Preexisting `+usr/local/bin` directory rule, changed bytes/targets still packaged | The changed launchers remain, but APK owns their paths. | Ordinary remove preserves them; purge deletes them. |
| Preexisting directory rule, changed bytes/targets omitted from new package | Their observed identity and effect remain; APK no longer owns them. | Separate remove and purge preserve both. |
| Preexisting directory rule, metadata-only regular files omitted | The old package cleanup deletes them despite the metadata change. | No preservation guarantee. |
| Exact-file protection rules | Replacement still occurs; omitted old aliases are deleted. | No preservation guarantee. |
| Rule shipped by the incoming package or written by its preupgrade script | Replacement still occurs in that transaction. | No preservation guarantee. |
| Exact-file stdin overlay, changed bytes/targets or metadata-only regular files omitted | Identity and inert behavior remain; aliases become unowned. | Separate remove and purge preserve both. |
| Metadata-only symlinks to the vendor payload, omitted with directory protection or stdin overlay | Link identity remains, but the updated target changes behavior. | The link remains unowned; its removed target no longer runs. |

The scoped overlay cases pass only these exact root-relative file names to
`apk --overlay-from-stdin` before database loading:

```text
usr/local/bin/syswarden
usr/local/bin/syswarden-tui
```

They use no shared-directory protection rule. All recorded parent metadata for
`/usr`, `/usr/local` and `/usr/local/bin` remains unchanged in these overlay
fixtures. The full matrix separately requires stable parent device, inode,
mode and ownership, while retaining size and timestamp observations. A native
ownership query that reports a symlink's target as owned is not alias ownership;
the parser keeps these outcomes separate.

These are controlled-transition candidates, not supported installation
procedures. The native [APK 2 database implementation](https://github.com/alpinelinux/apk-tools/blob/v2.14.12/src/database.c)
and [APK 3 database implementation](https://github.com/alpinelinux/apk-tools/blob/v3.0.8/src/database.c)
load overlay file entries before installed ownership. Incoming alias omission
is necessary to avoid reassignment to the new package. Directory protection
instead applies checksum-based old-payload cleanup and does not protect every
metadata-only change. Incoming package scripts cannot prepare either mechanism
before their own transaction has already loaded its state.

A production bridge still requires all of the following:

- A separate authenticated preparation step and explicit approval before native
  replacement, bound to the installed identity, exact old and new payloads,
  administrator inventory and selected transition. Incoming scripts, a package
  name, and a successful APK exit are not approval or ownership evidence.
- Bounded exact overlay input and native argument handling, with no arbitrary
  paths, directory entries or unreviewed stdin. A durable receipt must precede
  the transaction: a failed native operation can still change registration.
  Preserve candidate and recovery material, then inspect actual native state
  before any retry or finalization. These failure paths are not qualified by
  the successful overlay fixtures.
- If a protected-directory variant is used, protected policy-file creation and
  parent inspection, existing policy precedence and attributable cleanup remain
  mandatory. Do not overwrite administrator policy or remove shared rules.
- Inspection of all old and new payload paths and native removal effects,
  including parents, retired files, dependencies and recovery hooks. Unknown or
  changing ownership must refuse before the transaction. The two launcher
  fixtures do not prove this wider boundary or concurrent-writer safety.
- Coordinated APK alias omission, staging and payload attestations, hook checks,
  updater checks and removal inventories. Retained administrator aliases must
  remain unowned and must not be adopted into a product cleanup receipt. Product
  aliases created later need separate attributable ownership and removal rules.
- Verification of unchanged administrator behavior through failure, retry,
  maintenance, reload and reboot, with independent uninstall, native remove and
  native purge qualification. Backups alone do not prove uninterrupted behavior.

The compatibility identity must retain its historical dependency promises. The
base identity must retain every mandatory Alpine prerequisite. Fresh product
configuration must remain inactive with no selected list until explicit TOML
configuration and approved activation. This laboratory changes none of those
contracts, does not enable base updates and does not establish IVVQ acceptance.

## Inert native laboratory

`scripts/ci/native_dependency_split_probe.py` builds `sw-lab-*` packages with inert
text payloads and runs fresh disposable rootless containers. It reuses the
existing native transition probe's bounded process runner and inert local DNF
group metadata generator. It never pulls images, mounts host paths, uses network
access, installs host packages or starts product services. Each case is limited
to two CPUs, 512 MiB and a 90-second container lifetime. Native jobs run sequentially.

The synthetic fixtures alone permit unsigned packages. These flags are not a
production updater contract or an authorization to weaken product verification.
Every Podman invocation explicitly selects the local engine with `--remote=false`.
Each container has a new random name, a separate random ownership label and an
exact ID file. The name and ID file must be absent before launch. Image-declared
volumes are ignored, and the laboratory requests no host mounts or volumes.
Automatic removal is disabled to preserve the exact ID until cleanup. A container
is removed only after its exact name, label and any captured ID agree; removal
targets that full ID. Unknown or preexisting resources are never removed.
Unresolved ownership or cleanup fails qualification and stops subsequent cases.
This also applies after timeout or an interrupted launch.

The output directory is new and private, and records the exact image, probe and
nfpm identities, native versions, build output and per-case observations. A
separate per-case container record is written before launch and updated after
cleanup, including unsuccessful cleanup. Report schema v2 adds these ownership
and cleanup requirements; earlier v1 observations remain evidence of their
original source and do not acquire this stronger cleanup claim retroactively.

| Case | Required observation |
| --- | --- |
| `fresh-base` | Base registered; optional and compatibility packages absent; only the disjoint base runtime present. |
| `compatibility-upgrade` | Compatibility root upgraded; base owns the new disjoint runtime; old runtime absent; historical optional package and its native selection reason preserved after cleanup. |
| `compatibility-admin` | The same upgrade preserves an existing explicit administrator package selection. |
| `compatibility-held` | Debian preserves an existing hold and the original automatic/manual reason. |
| `compatibility-group` | DNF4/DNF5 preserve a native group reason. |
| `compatibility-pinned`, `compatibility-tagged` | APK preserves the exact existing world token. |
| `solver-refusal` | An unsatisfied dependency refuses before product replacement; old runtime bytes, inode, metadata, ownership and package identity remain; base registration and payload stay absent. |
| `shared-handoff` | Characterize transfer of the same path in a compatibility/base transaction without overwrite overrides. |
| `unprepared-shared-base` | Characterize direct base installation while the historical package still owns that path. |
| `script-refusal` | Characterize a failing incoming preinstall/preupgrade script without assuming rollback. |

The upgrade cases run APT or DNF autoremove. APK has no separate autoremove
command, so its case removes an unrelated fixture root and observes the solver
removing that root's otherwise unused dependency. Each case proves unrelated
automatic cleanup still works while the historical optional requirement survives.
The administrator sentinel is outside package ownership. Its bytes, permissions,
ownership, inode and effective value read by an inert consumer remain unchanged.
This sentinel is not a substitute for real SSH, firewall or optional-module tests.

The first native run can select only `--case compatibility-upgrade --format apk`.
Provide an existing absolute executable nfpm path, an existing exact 64-character
Linux AMD64 image ID, and a new absolute output directory. Omit `--case` to run
the full matrix for that format. RPM images require DNF4 or DNF5; legacy YUM is
not silently treated as qualified DNF. Raw dpkg and RPM entry points require
separate future scenarios and are not covered by frontend transactions.

The report distinguishes completed observations from successful synthetic
qualification. Characterization cases never set `synthetic_contract_passed`.
A subset cannot satisfy `synthetic_disjoint_contract_passed`. Every report keeps
`product_accepted` and `shared_payload_qualified` false. Missing markers, duplicate
observations, incomplete output, timeouts, invalid architectures or lost sentinels
cannot become a successful qualification result.

## Production work still required

Before publication, qualify fresh base installation, historical compatibility
upgrades, base-to-base upgrades and attempted conflicting installation on every
supported native platform. Test frontend and raw native entry points separately.
The selected design must preserve historical package reasons, holds, pins and
unrelated automatic cleanup without any ownership transfer. Cross-variant
transition remains unsupported and requires its own explicit design if requested.

Update artifact naming, signed manifest inventory, package ownership attestations,
dependency attestations, updater selection and legacy unsigned-era discovery
together. An old updater's refusal is not successful migration. The current
updater deliberately refuses `syswarden-base`; packaging metadata and ownership
guards alone cannot establish safe updates or complete removal.

Preserve administrator policy and runtime behavior through install, upgrade,
failure, retry, reload, reboot and maintenance. Qualify standalone uninstall,
native remove and native purge separately, accounting for both product package
identities and retained private recovery material. No cleanup may remove an
entire shared resource merely to retire a product-owned entry.
