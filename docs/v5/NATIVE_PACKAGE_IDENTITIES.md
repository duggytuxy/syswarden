# Native package identities and dependency retention

Development design for issue #422 and consolidated PR452. This document does not
establish production package support, migration readiness or v5.00.0 IVVQ
acceptance. Published v4 release package metadata and canonical signatures remain unchanged.
Local opt-in metadata generation and the v5 signed identity contract are
intermediate implementations.
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

The helper `scripts/ci/package_variant_metadata.sh` selects the local name,
dependencies and mutual conflict. It declares no provider alias, replacement,
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

Public workflow generation deliberately remains on the historical `syswarden`
contract. It does not publish `syswarden-base` or use this local metadata helper.
Public dual-identity generation, native payload qualification and
unsigned-era discovery still need coordinated qualification. Do not deploy the opt-in base artifacts as
supported packages until those paths and the native lifecycle are qualified.

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
epoch. APK requires revision `r0`. Alpine generation disables nfpm's semantic
version normalization so `5.00.0` remains `5.00.0-r0`, matching the release
contract. Unsupported framing or alternative package profiles fail closed.

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
Public workflows continue the stable v4 three-artifact contract until v5
production generation and the lifecycle matrix are completed together.

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
