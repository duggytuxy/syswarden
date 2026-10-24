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

The current complete native APK probes still refuse firewall retirement: the
shared nftables persistence observer attests a systemd loader and does not yet
attest the Alpine OpenRC loader. The recovery copy and exact cron retirement do
not remove this blocker. Do not install systemd as a workaround, bypass the
observer, stop the shared nftables service or flush its rules. OpenRC loader
configuration and its effective entry points require their own bounded
observation before native removal can be qualified.
