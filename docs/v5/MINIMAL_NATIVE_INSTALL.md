# Minimal native installation and dependency preservation

Development contract for issue #422 and the v5.00.0 IVVQ campaign. This work
does not establish a migration-ready package or release acceptance.

## Installation boundary

A fresh Linux AMD64 native installation selects the standard list 1 profile.
VPN, Wazuh, SSH hardening, CIS Level 2, OS hardening and optional integrations
require explicit validated TOML choices and their activation checks. The base
profile must not implicitly enable them through environment variables or
package scripts.

Mandatory platform dependencies remain installed. On Alpine this includes the
requirements for nftables, OpenRC, feed scheduling and the native package and
service lifecycle. A smaller dependency list is not a security objective on its
own. Remove a requirement only after verifying its base runtime, update,
recovery and removal callers. Optional module prerequisites must be checked
before activation; missing prerequisites do not authorize adding repositories
or weakening native package verification.

Upgrades preserve administrator configuration, selected protection and existing
dependencies. A missing new TOML switch in a historical configuration is not
permission to disable its former behavior or remove a package.

## Native service activation choices

The standard native hooks distinguish fresh installation from upgrade using
their package-manager arguments. APK uses separate install and upgrade hooks;
it does not rely on inherited environment variables to identify the operation.
An unknown operation permits staging only.

Before the candidate install command loads configuration or recovers firewall
state, it observes `syswarden-core` and `syswarden-firewall` together. A fresh
operation can activate only an absent pair. An upgrade can refresh only an
already active, persistently enabled pair. A stopped, disabled, masked, missing
or transitional service defers the automatic host-activation pipeline. Core
depends on firewall, so an active core alone is insufficient authorization.
An unavailable or malformed observation refuses the operation instead of
assuming an inactive or fresh host.

For an eligible upgrade, service-definition publication leaves enablement
artifacts unchanged, including custom OpenRC runlevels. The installer rechecks
the pair before host mutation and before its conditional core restart. The
updater does not perform a second unconditional restart after package hooks.
Offline qualification activation explicitly retains upgrade semantics.

Package staging or a successful native transaction does not prove that the new
runtime is active. A deferred installation requires administrator review of
the configuration and both services before an explicit online `syswarden
install`. That explicit command can activate services; it is not a read-only
inspection. Preserve masks and existing protection until that decision is made.

These observations do not lock out concurrent administrator manager operations
and cannot undo actions already performed by historical outgoing hooks. An old
updater process may also restart services after the new package returns; this
candidate's updated finalizer does not retrofit that already-running caller.
Such historical entry points still require separate migration qualification.
Native
DEB/RPM/APK acceptance must still exercise fresh installation, active upgrades,
stopped/disabled/masked pairs, custom runlevels, offline staging, retries,
reload and reboot. The separate RHEL package-owned lifecycle remains unchanged.
This guard is not full migration or lifecycle acceptance.

## WireGuard credential output

Installation and reactivation never render a client configuration or its QR
code. Output identifies only the protected client file. This also applies when
an existing TOML configuration has explicitly enabled WireGuard and a native
package hook invokes the installer. Reusing attested state preserves its keys.
Reading or transferring the client file is a separate administrator operation;
its private key and preshared key must not be copied into package logs, support
reports or shared terminal recordings.

Removing automatic output does not invalidate older copies or rotate existing
keys. Previously disclosed credentials require a separate planned replacement
of the affected client key and preshared key. Do not erase diagnostic logs as a
substitute for revoking exposed credentials.

## WireGuard forwarding scope

Newly generated WireGuard policy uses a separately attested v2 rule shape.
Masquerading requires the tunnel ingress interface, configured IPv4 subnet and
selected egress interface together. Forwarding permits that outbound path and
established or related replies from the selected egress toward the tunnel.
Remaining forwarded traffic involving the tunnel is dropped, including new
connections from another local network. This does not add IPv6 tunnel routing.

The owned table leaves unrelated forwarding to administrator policy. It does
not change a shared chain's default policy or bypass another table's drops.
Explicit legacy migration uses equally scoped, token-bound permits when it
must preserve an existing shared forwarding chain. Runtime verification binds
rule content and order before cleanup; a matching name or comment alone does
not authorize deletion.

Historical v1 ownership remains readable for exact recovery and removal.
Existing v1 configurations are not silently rewritten, and an already sealed
v1 migration target remains recoverable. Their forwarding policy is not
upgraded merely by installing this candidate. Guarded v1-to-v2 policy migration,
encrypted client traffic, administrator routing preservation, reload and reboot
remain explicit native acceptance gates.

## Owned WireGuard policy assessment

`syswarden recover-wireguard --assess-owned-policy` inspects an already owned
policy without publishing a configuration, changing rules or starting/stopping
a service. It requires the complete manifest and exact companion files. The
result includes source identities, a scoped successor digest, preserved OpenRC
link ownership and an attested historical migration receipt when present. Keys
and configuration contents are never printed. A modified or partial ownership
set, pending transaction, changed predecessor or conflicting runtime is refused.

The candidate successor changes only the exact generated `PostUp` line. Client
configuration, private keys, PSK, peer settings, token, service choices and
forwarding persistence remain unchanged. Two matching observations detect drift;
they are not a lock, a write lease or proof that a service cannot start later.
On Alpine, service activity and enablement are explicitly unobserved until a
bounded OpenRC observer is available. The assessment never executes an init
status script to infer them, and records this limitation as a blocker.

This mode cannot be combined with `--apply`, `--plan-sha256` or historical
recovery modes. It prints no apply command and grants no migration authority.
Existing v1 policy still needs a recoverable server/manifest replacement, a
service-start fence, a successor record for any sealed predecessor, and exact
runtime retirement. Do not disable an access tunnel merely to clear a diagnostic
blocker. The activation and recovery workflow must be qualified first. The
assessment does not establish migration-ready packages or final IVVQ acceptance.
The `scoped-v2` state identifies the validated file policy only. It does not
establish complete runtime health, peer reachability or encrypted traffic flow.

## Dynamic observations and ban lifetime

Kernel packet-log observations retain their detection and threshold telemetry
without authority to ban a source address. A packet source alone does not prove
who sent it. This boundary keeps the configured kernel packet filtering and
existing policy entries; it does not remove existing bans. Post-threshold L3
events explicitly record an unverified packet source and no source ban.

Logging a successful dynamic ban does not append it to the permanent operator
blocklist. The runtime lifecycle and HA ownership paths retain responsibility
for its expiry. Explicit permanent policy writers remain separate. Historical
static entries are preserved until their ownership and recovery are established;
this change does not infer that any existing entry is disposable.

Original log-producer authentication, independent collector qualification and
historical policy migration remain required before full acceptance of enabled
detection paths. A root-owned file or authenticated relay is insufficient to
establish the original producer of every contained message.

## Consolidated implementation status

Source integration and native package acceptance are distinct. The current
consolidated implementation has the following boundaries:

| Area | Implemented source behavior | Remaining acceptance |
| --- | --- | --- |
| Fresh configuration | `standard-v1` templates select list 1, list-only policy and disabled optional modules. Environment variables cannot grant fresh-profile module consent. | Qualify the complete fresh native package on every supported platform after dependency metadata is reduced safely. |
| Installation and reload | Existing SSH, CIS and OS policy is preserved. Optional module prerequisites are checked without installing missing optional packages implicitly. | Complete the native lifecycle matrix and independent administrator-policy preservation checks. |
| Native dependencies | Managed updaters prepare historical dependency retention; v5 signed manifests require the new transition contract. Mandatory Alpine prerequisites remain required. | Direct native and unsigned-era updater transitions remain unqualified. Package metadata still declares historical optional tools and must not be reduced before that preservation path is accepted. |
| Dedicated SSH migration | Protected planning, publication, observation, original restoration and target-side access issuance exist. The activation/restoration binder refuses a different daemon mount view and binds explicit or verified compiled-default configuration selection. | Complete supported daemon-build qualification, guarded policy consumption, independent controller handoff, recovery acceptance and owned lifecycle before exposing forward migration. |

The source installer selecting minimal defaults does not mean the generated
DEB, RPM or APK is already a minimal, migration-ready package. In particular,
disabled VPN or CIS behavior does not remove their currently retained historical
package requirements. Keep issue #422 and consolidated PR452 open until both the
package dependency boundary and the runtime migration/lifecycle gates pass.
A green generic build or isolated SSH oracle does not replace those gates.

The selected package design separates a fresh `syswarden-base` identity from the
retained full `syswarden` compatibility package. Each owns the complete runtime
payload, conflicts with the other and supports same-identity upgrades only.
The local builder's opt-in `--minimal-package` generates base metadata without
changing the public release inventory. The [native identity design and
laboratory](NATIVE_PACKAGE_IDENTITIES.md) distinguish this intermediate generation
support from signed updater integration and native lifecycle acceptance. Public
package generation retains the historical dependency set at this stage.

## Incomplete configuration recovery

Installation and repair must not replace lost policy with the fresh standard
profile. When the published `config.toml` exists but a required module is missing,
the installer refuses before writing replacement templates, even when surviving
files look like defaults. This also applies to a missing `99-user.toml`: its former
operator choices cannot be inferred from the remaining files.

Without a master file, automatic completion is limited to an unfinished fresh
initialization whose surviving modules all match the exact current templates.
A custom user module or any additional TOML module makes an incomplete directory
ambiguous. Unsafe links are refused before defaults are created. A complete
administrator configuration is preserved byte for byte, including its permissions.

Restore the complete last-known configuration from the installation's retained
backup and validate it before retrying installation or reload. Do not delete
remaining configuration to make the installation appear fresh, and do not copy
new default files over a historical policy. For a genuinely new installation,
let the standard profile initialize completely before editing the optional TOML
selections. These refusals do not undo already active protection or establish that
an administrator's previous state has been recovered.

## Manual dependency resolution

The manual installer requests only the fixed base prerequisite set for the
selected package manager. Native package installation never invokes this manual
transaction. The separate read-only optional prerequisite checks remain in force
for both fresh selections and preserved historical modules. Missing optional
prerequisites are reported rather than installed implicitly.

The WAF log bridge publishes to the selected SysWarden WAAP engine. Therefore
`waap.log_bridge_enabled=true` requires an explicit `waap.enabled=true` selection.
The configuration readers reject an inconsistent producer/consumer choice before
publishing it or changing runtime state. They preserve the previous valid snapshot
and administrator TOML bytes. Selecting the pair grants no other module activation.

APT refresh failure stops the dependency stage. APT installation disables
recommended packages and refuses removals. DNF/YUM installation disables weak
dependencies, automatic dependency cleanup and obsolete-package substitution.
Alpine keeps OpenRC, Cronie, its OpenRC service definitions, process inspection
and account lifecycle prerequisites in the base plan. No branch adds optional
repositories, runs an autoremove command or disables package verification.

Manager lookup rejects unexpected paths and permission errors rather than
falling through to another manager. The executable and parent directories must
be protected. Dependency failures remain failures; an unsupported manager is not
a successful installation. Existing packages are never explicitly removed by
this resolver. Native package transactions still require separate platform and
upgrade qualification; command selection alone is not a rollback guarantee.
The manual command uses the system database, root working directory and a fixed
minimal environment. Explicit HTTP/HTTPS proxy settings are retained, while
ambient package-root/configuration and loader/interpreter overrides are excluded.
Cancellation is handled through the bounded native process-group runner.

Package metadata and the offline package dependency attestation retain their
historical inventory until the native transition strategy is qualified. These
intermediate resolver changes do not claim that minimal package publication or
direct native migration is complete.

## DEB and RPM update guards

The managed APT updater now disables recommendations and refuses transactions
that require removal, while retaining its bounded dpkg lock wait. DNF/YUM
updates disable weak dependencies, dependency cleanup and obsolete-package
substitution. The same RPM guards apply to the isolated offline qualification
command, which still disables plugins and repositories and requires native local
package signature verification. Offline Debian qualification continues to use
only `dpkg --install` on the verified package. Unexpected arguments, missing
guards, appended overrides and additional caller-supplied packages are rejected.

Command guards alone are not durable dependency retention. In the inert Debian
13 and AlmaLinux 10 fixtures, replacing a package with a version that no longer
requires a component left it eligible for later autoremove. Naming that component
in the same transaction changed the APT reason, but not the observed DNF reason.

The managed production and offline qualification update paths now prepare native
reasons before replacing a verified package. Scope is limited to a compiled list
of historical optional dependencies actually declared by installed SysWarden.
Two matching inventories must establish configured native package identities and
exact reasons. Missing, ambiguous, constrained or changed records stop replacement.
Only an automatic/dependency reason is promoted using `apt-mark manual`, DNF4's
`mark install` or DNF5's `mark user`. Already manual, user, external-user or group
selections remain unchanged. Holds,
versions, repository choices and unrelated packages are not modified by this step.

DNF's `repoquery --userinstalled` filter is insufficient to preserve group choices
on the tested platform. The implementation inspects exact installed reasons,
preserves administrator and group selections, and refuses unknown or incomplete results. The
post-operation inventory must confirm the intended reason and unchanged identities
and existing selections. A failed or cancelled preparation stops replacement;
partially retained reasons are never silently reversed. A retry is idempotent.

Native queries and replacement use the system package database and a fixed minimal
environment. Production replacement preserves explicit HTTP/HTTPS proxy settings,
but does not inherit alternate package database/configuration roots or interpreter
and loader overrides. Offline qualification keeps its distinct private marker and
repository restrictions. These controls do not weaken package signature checks.

Each operation uses the manager's own locks. Repeated inventories are observations,
not a lock covering all commands. Concurrent administrator package operations must
be coordinated. The tested native reason implementation uses Debian APT/dpkg and
AlmaLinux DNF4 and Fedora DNF5. The selected protected manager executable reports
its generation; the complete version observation is rechecked before every native
query or reason mutation. A provider change or unavailable command stops work.
DNF5 uses its own fixed reason vocabulary and newline-terminated query format;
unknown reasons are never inferred as dependencies. No direct native database
editing is performed.

The independent native probe is
`scripts/ci/native_dependency_transition_probe.py`. It requires `--run-native`,
an existing exact AMD64 image, a local nfpm executable, `--format deb` or `rpm`,
and a new output directory. It uses no network or host mounts and records native
versions and exact observations. RPM has no separate purge command, so the probe
does not relabel its erase operation as a purge acceptance. Fixture signatures
are deliberately absent; the RPM trust override exists only in this laboratory,
never in the product command contract. These tests do not establish signature
qualification, full product removal, policy preservation, or native SSH access.

With `--retention-test-binary`, the same DEB/RPM probe exercises the real retention
implementation against inert native metadata. It verifies retry mutation counts,
independently installed automatic packages, manual/group choices, Debian holds,
failed upgrades and separate model removal paths. A group-preservation case also
checks unchanged DNF4 history database bytes or DNF5 package/group state bytes
during preparation. The DNF5 group fixture is created through native commands
using a fixed empty local repository and group metadata. A weak-dependency case
also exercises DNF5's distinct reason. The container has no network access.
Missing, duplicate, skipped or failing oracle markers cannot pass. These are
component observations, not full SysWarden lifecycle or release acceptance.

The initial direct native transition and older updaters still need a prepared,
bounded retention path before historical dependency metadata can be reduced.
A package-manager zero exit and absence of immediate dependency removal are not
sufficient evidence of preservation across a later maintenance operation.

## Signed updater compatibility boundary

The manifest producer selects its contract from the target release version.
Targets before v5 keep `syswarden-update-manifest/v1` without a transition field.
Targets starting at v5 require `syswarden-update-manifest/v2` and the exact
`native_transition` value `syswarden-native-dependency-retention/v1`. Current
online and offline verifiers reject missing, unknown or version-inconsistent
contracts. This requirement cannot be disabled by an installer argument.

The discovery filenames remain `syswarden-update-manifest-v1.json` and its `.sig`
companion. Their names are stable locators; the authenticated document's `schema`
controls interpretation. Signature, trusted key, canonical encoding, target
version, complete AMD64 package inventory, size and checksum checks still apply.
Existing canonical v4 manifests and their signatures remain byte-compatible.

Historical signed updaters recognize only the original contract. They refuse the
new schema or field before requesting package bytes or invoking the installer.
This prevents that signed-update path from silently bypassing dependency retention.
The marker requires a capable updater; it is not evidence that retention ran or
succeeded. The current native preparation must still succeed before replacement,
including native signature verification and platform-specific restrictions.

This boundary does not cover unsigned-era updaters that never read a manifest,
direct APT/dpkg, DNF/RPM or APK transactions, or concurrent administrator package
operations. Do not bypass the refusal with an unprepared direct installation or
weaken signature checks. Those transitions still need an independently verified,
pre-transaction preservation path. A compatibility refusal is not a successful
migration, and it does not authorize reducing historical package dependencies or
publishing a migration-ready v5 package.

## APK update retention

The managed production and offline qualification updaters inspect protected
`/etc/apk/world` and `/lib/apk/db/installed` before an APK add transaction. The
reader bounds size, checks file and parent ownership, rejects linked or writable
inventory, and compares bytes and file identities after inspection.

Retention is limited to a fixed list of historical direct dependencies declared
by the installed SysWarden package. Missing, duplicated, constrained or broken
relevant package records require repair. Unrelated installed packages are not
promoted into explicit requirements. A modern minimal package with no historical
optional dependencies produces no extra requirement.

Already explicit administrator requirements, including version constraints and
repository tags, are left unchanged. Eligible installed dependencies that lack
an explicit requirement are passed as fixed bare names in the same native add
transaction. SysWarden does not edit `world` directly, pin their versions or run
an inner package transaction from a package script. Native signature verification,
script execution and commit hooks retain their existing command restrictions.

APK replacement, like DEB/RPM replacement, runs from `/` with a fixed minimal
environment. Explicit HTTP/HTTPS proxy settings are retained. Ambient package
configuration roots, loader paths and interpreter startup overrides cannot redirect
the replacement away from the system whose dependency inventory was inspected.
The production updater does not inherit the private offline qualification marker.

The inventory observation is not an APK lock lease. Coordination with concurrent
administrator package operations still needs qualification. An older updater or
an unprepared direct native upgrade does not acquire this new behavior. Package
dependency metadata must not be reduced until those transition entry points have
an accepted preservation strategy.

## Native characterization

`scripts/ci/apk_dependency_transition_probe.py` runs explicitly requested,
synthetic APK cases in disposable rootless Linux AMD64 containers. It requires
an existing exact image ID, never pulls images, and uses no network or host
mounts. The isolated fixture laboratory alone permits unsigned fixture packages;
the product updater does not accept that option.

The optional `--retention-test-binary` supplies a static Linux AMD64 system-package
test executable. The laboratory then checks the production protected-inventory
planner against APK-generated metadata. A missing or skipped planner result is
a failure. The fixtures contain inert payloads, not the product runtime.

The scenarios cover fresh installation without the optional fixture, successful
and failed upgrades, explicit dependency retention, administrator pins and
repository tags, solver conflicts, signature refusal, reinstall and synthetic
native removal. They also establish that a package script failure is not a
transaction rollback; a preexisting pre-commit refusal is a separate boundary.

These results do not validate the full SysWarden lifecycle. The consolidated
change still needs real fresh installation, update, reload, reboot and hourly
behavior, optional activation, complete SSH migration and recovery, and separate
standalone uninstall, native remove and native purge qualification. Required
platform dependencies and unrelated administrator protection must survive every
applicable path.

The full native removal laboratory seeds a complete historical modular policy
before its administrator sentinels. The historical `fresh` event labels in those
scenarios mean first package installation into that preconfigured fixture; they
do not prove the new standard-list-only defaults. A custom user module without
the other policy modules is an incomplete configuration and must be refused.

An APK removal script's nonzero exit is not a transaction veto. Native removal
can continue deleting the package payload after a preparation refusal. The
consolidated implementation must preserve an attributable recovery route for
that case and independently verify remaining protection, package registration,
payload and runtime state. A successful manager exit cannot establish successful
SysWarden removal. These paths remain acceptance blockers until qualified.

## Version-bound Alpine removal laboratory

The APK laboratory selects a separate reviewed-recovery profile for candidate
package versions starting at 5.00.0. Historical package contracts remain unchanged.
Both `apk del` and `apk del --purge` run in separate disposable containers with
real OpenRC. The fixture explicitly approves its exact legacy cron retirement,
private list/UI retention and administrator TOML preservation before removal.
This approval is part of the controlled test fixture, never automatic product
consent. The test rejects an unexpected retention inventory or ambiguous digest.

The current profile requires exact generated-completion cleanup, absence of all
package payloads and active product roots, and an exact inventory of the one
retained administrator TOML. Independent administrator files must retain their
bytes, modes and ownership. A separate OpenRC service maintains an unrelated
nftables rule in its own table. A dropped loopback probe must increment that
rule's counter before installation, after installation and removal, after its
own service reload, and after a real container restart with a different PID 1.
Product rule absence is checked before the restart as well, so a new network
namespace cannot hide incomplete runtime cleanup.

The restart must also preserve the private recovery data and administrator TOML,
leave the package unregistered, keep product services and rules absent, and
retain unrelated cron entries and a running rsyslog daemon. Evidence validation
requires every ordered check and both boot observations. A successful initial
removal cannot substitute for the restart or for the other native entry point.
The retained APK recovery tree must contain exactly the candidate-bound CLI,
core, TUI and signatures, with private parent permissions, exact file modes,
ownership and single links. Its CLI must still execute after removal and restart.

This profile exercises a preconfigured historical policy. It does not establish
clean standard-only installation, standalone `syswarden uninstall`, complete SSH
migration, another distribution's lifecycle, or final v5.00.0 IVVQ acceptance.

## APK recovery before native erasure

APK package removal scripts do not provide a reliable transaction veto. A refused
`pre-deinstall` can be followed by payload erasure. The v5 candidate therefore
ships an APK-owned `pre-commit` hook which preserves an exact private copy of the
installed CLI, core, TUI and signatures before any subsequent native transaction.
The copy is bound to the executing CLI and its compiled companion digests, uses
independent inodes, and is published only after content and metadata checks. An
existing copy must match exactly and is never overwritten. A failed copy refuses
the transaction at this earlier boundary. No configuration, service, policy or
package selection is changed by the copy operation.

The private archive under `/var/backups/syswarden-retired-v1/apk-payload-*` is
recovery evidence, not active configuration. It is not restored automatically or
pruned by removal. Unknown files beside the package payload are not copied or
adopted. An interrupted private staging directory is retained for diagnosis.
The native package owns the hook and removes it with its payload; the archive
does not install a persistent producer. A transaction explicitly bypassing APK
hooks or scripts is outside this recovery guarantee.

This copy alone does not establish complete removal or preserve dependencies
which the package manager independently removes. Subsequent recovery still
requires the existing ownership checks, required platform tools, and a separately
reviewed plan. The historical root-cron recovery recognizes the verified Alpine
Cronie/OpenRC provider and its `/etc/crontabs/root` spool, independently of the
Debian cron provider. Approval is bound to the selected spool and exact record
inventory. Unrelated records remain byte-for-byte unchanged, and the original
inode is retained privately. A custom provider or unresolved producer remains a
refusal. Full native uninstall, remove and purge qualification remains required.

Early complete native APK probes exposed a systemd-only nftables persistence
observer. The candidate now has a [bounded Alpine OpenRC observer](OPENRC_NFTABLES_OBSERVATION.md)
for reviewed distribution definitions, literal configuration, native runtime
state and active loader processes. It never executes an init script to obtain
status. Unknown or changing inputs remain a refusal, preserving existing
protection. Do not install systemd as a workaround, bypass the observer, stop the
shared nftables service or flush its rules. Component checks and recovery payload
retention do not establish complete native uninstall, remove or purge acceptance;
each complete path still requires its own qualification.

The lifecycle laboratory binds the additional APK hook to the v5 package
inventory, its exact source digest, a regular file, root ownership and mode
`0755`. Historical v4 inventories remain unchanged. Missing, duplicated,
modified or additional payload entries are rejected; successful native package
erasure does not override this inventory check.

The laboratory also validates the core's local native runtime snapshot when HA
is disabled. Local evidence cannot claim HA coordination or peer checkpoint
authority. Snapshot identity, model, counts, claims, canonical addresses and
nanosecond chronology must agree with the projected lifecycle fields. Complete
journal windows must account for every journal byte. Legacy telemetry and HA
retain their distinct contracts. The jq validator refuses sequence numbers above
its exact integer range, `2^53 - 1`, and noncanonical integer wire spellings
rather than rounding them into a passing observation.
