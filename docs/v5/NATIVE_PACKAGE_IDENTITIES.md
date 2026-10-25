# Native package identities and dependency retention

Development design for issue #422 and consolidated PR452. This document does not
establish production package support, migration readiness or v5.00.0 IVVQ
acceptance. Production package metadata remains unchanged during this laboratory
stage. SysWarden supports Linux AMD64 only.

## Identity boundary

The intended fresh package identity is `syswarden-base`. Its native requirements
contain the independently verified base runtime and lifecycle prerequisites.
Optional VPN, Wazuh and hardening features require explicit configuration and
their separate prerequisite checks. Mandatory Alpine components, including
nftables, OpenRC, Cronie, `cronie-openrc`, process tools and account tools, remain
required.

Existing installations retain the `syswarden` identity as a compatibility root.
That root continues to require their historical optional dependencies and the
base runtime. Keeping the dependency graph rooted avoids converting every
installed optional package into a manual administrator selection. Existing
manual, group, hold, version-pin and repository-tag choices must survive.
Unrelated automatically installed packages must remain eligible for their normal
native cleanup.

The fresh installation command must explicitly select the new identity. Two
artifacts with the same native name but different dependency promises are not a
safe substitute. Removing the compatibility root is a separate prepared migration:
native dependency retention must succeed before its requirements disappear.
Keeping that root after a claimed complete product removal is not acceptable.

## Payload handoff boundary

Different package names do not solve shared-file ownership. The production design
must account for every executable, service, completion, configuration entry and
recovery artifact during ownership transfer. An automatically replaced legacy
package can lose the dependency root that makes preservation possible.

Do not treat `Conflicts`, `Breaks`, `Replaces`, `Obsoletes`, force-overwrite flags
or an incoming package script as proof of safe refusal. Native solvers and package
script failure semantics differ. In particular, an APK `preupgrade` error can be
followed by payload and registration changes. A hook installed by the incoming
package cannot guard that transaction's earlier planning boundary.

The initial laboratory therefore has two distinct scopes:

1. A disjoint payload layout tests the package graph without overlapping runtime
   paths. The historical runtime belongs to the old package. After a successful
   compatibility upgrade, that path is absent and the new runtime is owned by the
   base package at a different path. No automatic runtime activation occurs.
2. Shared-path handoff and installation of the base onto an unprepared legacy
   system are characterization cases. The laboratory supplies no replacement or
   erasure overrides. It records registration, file content and native ownership,
   including partial outcomes after a nonzero transaction exit.

Success for the disjoint synthetic layout does not validate transfer of the
current production paths. Coexistence also needs a runtime activation boundary
that preserves the existing daemon and administrator protections.

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

Before production metadata changes, qualify the ownership handoff and fresh
identity contract on every supported native platform. Update artifact naming,
signed manifest inventory, package ownership attestations, dependency attestations,
updater selection and legacy unsigned-era discovery together. An old updater's
refusal is not successful migration. Raw native callers need their own prepared
path and failure evidence.

Preserve administrator policy and runtime behavior through install, upgrade,
failure, retry, reload, reboot and maintenance. Qualify standalone uninstall,
native remove and native purge separately, accounting for both product package
identities and retained private recovery material. No cleanup may remove an
entire shared resource merely to retire a product-owned entry.
