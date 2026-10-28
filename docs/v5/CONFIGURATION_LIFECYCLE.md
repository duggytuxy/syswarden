# Configuration, activation and recovery

Development guide for issue #422 and Linux AMD64. This describes the current
CLI and the remaining configuration workflow, not a migration-ready release.

The required fresh-install outcome is no selected threat list and no implicit
module activation before an administrator makes explicit TOML choices through
`syswarden config`. Significant SSH and system changes require validation,
review of their effects and explicit approval. That complete configuration-led
activation flow is not implemented yet. Track fresh defaults and native
activation separately in [minimal native installation](MINIMAL_NATIVE_INSTALL.md).
Existing installations must retain their administrator-selected behavior.

## TOML organization

The normal root is `/etc/syswarden/config`. Keep each setting in its relevant
domain rather than copying a complete configuration into several files.

| File relative to the root | Purpose |
| --- | --- |
| `config.toml` | Master metadata, including the supported `schema_version = 1`. |
| `modules/00-core.toml` | Core profile, firewall backend and host settings. |
| `modules/05-ssh.toml` | Dedicated SSH selection with its separate ownership and approval rules. |
| `modules/10-network.toml` | Lists, address policies, WireGuard and network choices. |
| `modules/20-security.toml` | Detection, Layer 2 and compliance settings. |
| `modules/30-waap.toml` | WAAP and its optional log bridge. |
| `modules/40-integrations.toml` | HA, SIEM, Wazuh, reporting and BunkerWeb integration. |
| `modules/99-user.toml` | Deliberate administrator overrides permitted by each setting's contract. |

The loader reads the master first, then all `.toml` modules in lexical filename
order. Later values override earlier ones where the setting permits it. The
dedicated SSH and operator-policy declarations have stricter file-placement
rules; `99-user.toml` is not a way around them. Preserve protected file ownership
and permissions. See [explicit SSH selection](SSH_SELECTION.md) for the exact
`05-ssh.toml` requirements.

Use TOML tables, typed booleans and arrays instead of shell assignments. Network
prefixes use CIDR notation, for example `192.0.2.0/24`, with network host bits
clear; a dotted netmask is not the accepted prefix form. Examples are syntax,
not recommended trust grants. `network.whitelist_ips` accepts bounded addresses
or prefixes, while `network.lan_subnets` requires canonical prefixes. Persistent
block/allow/SSH-bypass lists reject IPv4 prefixes broader than `/24`, IPv6
prefixes broader than `/64`, and their prohibited special-use ranges.

Allow and block have opposite effects: product whitelist rules accept matching
incoming source addresses before product block rules. They do not override
independent firewall protection. LAN policy has a different validator and can
accept broader explicitly configured networks, including shared-address space
that persistent lists reject. An accepted LAN prefix is not evidence that its
members are trusted. Do not infer blanket trust from a private, shared or other
special-use classification, and do not treat the two validators as identical.

Country/ASN allow selections are restrictive policies. The application guard
requires nonempty merged allow populations for both IPv4 and IPv6 and identifies
the missing family on refusal. An incomplete selection cannot publish a new
policy; existing live and persistent policy stays unchanged by that refused
application. Recovery of an earlier transaction is a separate operation. This
check does not change rule ordering or the existing country/ASN union semantics.

## Commands available now

| Command | Current boundary |
| --- | --- |
| `syswarden config` | Provides private candidate editing, merged validation and explicit publication review for ordinary TOML modules, master metadata, the profile name and file import. It does not provide a review-and-activate transaction. |
| `syswarden config preview` | Validates the normal complete TOML snapshot and describes significant configured effects without host probes, writes or activation authority. |
| `syswarden config recover-edit` | Inspects an interrupted ordinary TOML publication and requires a fresh exact approval for a supported file recovery. It never activates policy. |
| `syswarden config validate --path /etc/syswarden/config` | Reads and validates the merged TOML, prints the selected module plan and reports unknown/deprecated keys without changing configuration or runtime. |
| `syswarden config-get KEY` | Reads one validated effective modular value. Some legacy-compatible settings can still reflect environment overrides, unlike file-only validation. |
| `syswarden config migrate --dry-run` | Validates historical flat-file migration without source or destination writes. `--source` and `--output` select its paths. |
| `syswarden config migrate` | Performs transactional configuration migration; normal preflight can recover pending firewall state. `syswarden migrate-config` is its compatibility alias. It does not activate the migrated choices. |
| `syswarden reload` | Requires exact approved TOML or an explicit current `--approve-plan` digest before reapplying policy, integrations and scheduling and normally restarting the core. |
| `syswarden config activate` / `syswarden install` | Reviews the complete TOML and live service, scheduling and interface observations; an exact `--approve-plan` digest is required for an explicit install. Native fresh staging remains inactive. |

Running the CLI without a subcommand, reading `syswarden manual`, using Cobra
help, or generating shell completion does not load or normalize host
configuration. These static information paths do not query recovery state or
prepare services. They remain available while configuration or removal needs
repair. Operational inspection commands such as `audit`, `alerts` and `list`
retain their own runtime requirements; they are not classified as static help.
`audit`, `alerts`, `check` and `list` load validated configuration without
persisting historical compatibility normalization. Eligible historical defaults
retain their safe in-memory interpretation, while original file bytes and
metadata remain unchanged. Invalid or ambiguous policy still refuses the
operation and preserves the last valid process snapshot. This configuration
boundary does not make every diagnostic host probe script-free; for example,
an OpenRC service status query can execute its administrator-controlled script.

The global `--config` option selects the legacy flat-file fallback; it does not
redirect the normal modular root or the protected SSH transaction inputs.

Opening `syswarden config` does not load or normalize configuration, recover
firewall state, create its state directory or acquire a transaction lock. It
refuses pending removal, WireGuard and firewall recovery state before presenting
the menu. The same read-only barriers protect `config preview`. Firewall journal absence is a point-in-time observation, not activation
authority or a lock against a later transaction. Invalid TOML can still be
opened for repair when the existing module directory is available.

All ordinary editor choices (1 through 6 and 9), profile-name changes (7) and
imports (8) capture the original configuration before editing or requesting
input. Editors receive a private working copy of their selected file rather
than its live path. Imports and profile-name changes target only the user
override file. The fixed target inventory excludes `05-ssh.toml`, arbitrary
filenames and path traversal; SSH still requires its protected workflow.

The merged candidate must pass validation before the menu displays the exact
target, module-selection summary, configured effects, warning counts and unique publication phrase.
Configuration values are not printed in that summary; review the edited or
imported TOML before approving. Empty or incorrect input cancels publication.
EOF, expired approval, changed TOML or a new recovery barrier refuses it. An
approval is limited to that exact target, original snapshot and candidate, and
cannot be reused. Publishing does not activate host policy or services.

Proposal capture and preview limit each TOML file to 256 KiB, the complete input inventory to 256 files, and directory enumeration to fewer than 272 entries. Oversized inventories are refused before unbounded enumeration or content capture. Candidate
merging retains lexical precedence, including when an explicitly selected
historical file is absent and would be created. A proposed file never counts
as an already complete fresh installation: a missing fresh module remains a
recovery barrier. The editor cannot silently recreate lost administrator state.
Existing runtime loading rules are unchanged by these proposal read limits.
The reviewed editor requires the effective operator to own its configuration
root, modules directory and inputs. Publication recovery records support regular
single-link TOML inputs with private mode 0600 or 0640. Foreign ownership,
unsupported modes and shared inodes cause refusal, never automatic ownership
or permission changes. Preserve those files for administrator review.

The private editor directory and initial working file use modes 0700 and 0600.
The selected editor retains the operator's privileges; this is not a sandbox.
Only the fixed working file and an empty directory are cleaned up. Unexpected
editor recovery files are retained for inspection, and publication is refused.
Private editor working files left before publication still require inspection.
The publication journal described below covers the recorded configuration pair;
it does not authorize deletion of arbitrary editor recovery files.

The Linux publisher exchanges an existing file atomically and uses a no-replace
operation for a new file. It rechecks the captured configuration before
publication, so readers do not encounter an intentionally missing live filename.
Unsupported atomic operations are refused. An in-process rollback restores the
original only when both file identities still match; a concurrent administrator
edit is preserved and the original private file is retained for inspection.
Reviewed menu publication records a private durable intent before exchanging
files and records its terminal state before deleting the retained file. Its
bounded canonical record binds the approved target, complete input inventory,
physical directory/file identities, metadata and SHA-256 digests. It contains no
TOML values. This remains a single-file boundary, not a transaction covering the
whole directory or a lock against arbitrary privileged writers.

An unresolved intent blocks normal editing, modular loading, default filling,
migration and affected mutating CLI preflight. The core configuration loader and
the TUI HA reader also refuse any intent object before and after reading their
candidate. Malformed records, terminal records awaiting cleanup, symlinks and
non-regular objects all require recovery. Refusal preserves the core's previously
loaded configuration and returns no TUI peers or credentials from the candidate;
it does not fall back to legacy HA credentials. These are point-in-time checks,
not a cross-process lock or a mechanism to revoke already running components.

Run `syswarden config recover-edit`
to inspect a supported recovery, then type its full `recover <approval-id>`
phrase only after reviewing the stated effect. Blank or wrong input cancels;
EOF, expired approval, changed evidence, a new administrator edit or a pending
lifecycle barrier refuses the attempt. Recovery approvals are single-use.

An unpublished candidate can be discarded. An exchanged but uncommitted file
can be restored only from its exact recorded original, including restoration
of original absence. A durably committed file can finish its recorded cleanup;
a rolled-back file can finish candidate cleanup. Other administrator changes
already present at recovery review are preserved. Committed cleanup revalidates
the current complete TOML and displays its module plan and warning counts before
approval; invalid current policy prevents cleanup. Missing, modified, unsafe or ambiguous
evidence is retained and is not treated as completed recovery. Do not delete
the intent to bypass the barrier. A completed file recovery still requires
configuration validation and does not reload services or establish host,
SSH-access, native migration or final IVVQ acceptance.

Use `syswarden config preview` to review the current merged file selections and
significant effects before activation. The publication prompt shows the same
effect categories for its private candidate, so an unpublished edit does not
replace the preview of current files. Both omit addresses, endpoints, arbitrary
values and credentials from their summaries. Review sensitive settings directly
in the protected TOML. The preview is a point-in-time file observation, not a
comparison with installed services or active kernel policy.

The review distinguishes host/list firewall policy, feed selection and refresh,
strict GeoIP/ASN allow requirements, access exceptions, VPN forwarding/NAT,
detection, log forwarding, external reports, independently installed Wazuh,
HA/BunkerWeb and separate SSH/system hardening. Disabled selections may still
cause owned-artifact or scheduling reconciliation during install/reload; they do
not mean that those commands are read-only or automatically undo prior policy.
Runtime ownership, available prerequisites, resolved feed populations, actual
access and recovery remain separate checks. The preview neither grants approval
nor runs a native package command, service action, firewall command or request
to an external endpoint.

After editing, run validation and review every reported selection and warning.
Unknown keys are reported but do not by themselves make validation fail. A
successful validation is neither approval to mutate the host nor proof of
effective kernel, service or access behavior. `config activate` and explicit
`install` now bind a command-specific plan to the complete captured TOML, local
source identities, predecessor approval and live service/scheduling/interface
observations. The first invocation prints that plan without activation. Repeat
it with the exact displayed `--approve-plan` digest after review. Source, host
observation, administrator connection context or predecessor drift refuses the
approval. Unknown or deprecated TOML entries must be resolved first.

Alpine activation review reads protected files and process evidence without
executing OpenRC scripts, APK or crontab commands. It requires a coherent live
OpenRC manager and known supported distribution service definitions. Root
crontab and owned schedule inspection creates no temporary files and refuses a
busy transaction lock immediately. Systemd observation uses fixed, validated
native executables for bounded read-only queries. Unknown or changed evidence
requires a new review; these observations do not authorize modifying independent
administrator services.

A newly approved command retains its original live-host and administrator
connection observation until the first possible host effect. It checks policy
authority after publishing approval, during consumption, and immediately before
firewall recovery. Recovery consumes that original observation because an
intentional host change would make it stale. The command then rechecks policy
authority before entering application. Failure or a repeated phase refuses
application within that command invocation and cannot publish successful
completion. Existing exact approval
used for an ordinary reload does not fabricate a new live-host review.

Successful-application publication revalidates the exact TOML and approval after
writing and synchronizing the completion record. Repeated completion requests
also revalidate the retained record. If source or approval identity changes
within that boundary, the command refuses success and preserves the private
record for inspection instead of silently declaring the new state approved.

Configuration activation and ordinary operational approval consumers refuse
retained Alpine transition hooks, gate-retirement quarantine and unresolved
launcher lineage. Removing a temporary hook is not a completion procedure. The
lineage reader requires the independent positive closure record after all
transaction resources have closed. Preserve incomplete records for bounded
native recovery; do not delete them to make activation proceed.

Approval publication also participates in an exclusion lock on the captured
configuration directory. The internal inactive-preservation observer can retain
exclusive custody while confirming absent approval state and unchanged TOML.
It creates no approval or application record. Existing state, even an empty
activation directory, is unresolved history for this observer. This observation
alone proves neither runtime inactivity nor permission to replace a package.
The complete inactive-update coordinator and signed native acceptance remain
required before that path can be exposed.

New native artifacts declare `syswarden-native-activation-v2` with the exact
`config-directory-flock-and-native-debt-v1` publication protocol. The historical
`activation-contract-v1.json` path is retained to preserve package layout.
Legacy v1 descriptors remain readable under their original contract and never
implicitly acquire the new capability. An internal read-only observer binds the
installed descriptor to the actual CLI/core bytes and detects later replacement.
Both source and candidate must support the protocol before an inactive update
can rely on it; declaring it alone proves neither inactivity nor update consent.

An independent terminal reader can reconstruct the original absence witness
while the coordinator retains its exclusive publication lease. Reading or
closing that observation neither takes nor releases the lease. The reader must
compare its digest with the original approved transaction record; newly observed
absence cannot replace that record. Appearance of activation state, changed TOML
or changed protected ancestry invalidates the observation. This read-only check
does not by itself authorize package execution or establish host inactivity.

The internal APK preparation and terminal record path distinguishes an explicit
`inactive-preservation-v1` policy mode from the historical applied-policy mode.
Inactive preparation and effect records use v2 schemas, retain the original
absence digest and carry no runtime approval. Missing approval in a v1 record
remains invalid. Mixed active/inactive evidence and schema substitution are
refused. The source publication descriptor must match the captured original
CLI/core pair; the authenticated candidate must also declare publication exclusion.
Reopening retained preparation and independent terminal verification preserve
these bindings without recapturing replacement bytes as source authority.

Component tests exercise this mode through retained preparation, execution
records and terminal cleanup using inert payloads and synthetic native hook
acknowledgments. They do not establish signed native migration.

The read-only Alpine admission observer separately binds stable OpenRC service
and runlevel inventories, complete supported cron inventories, product state
absence, exact installed product process checks, the boot and network namespace,
and the full nftables ruleset. It does not run init scripts, activate scheduling
providers, load kernel modules or change rules. A stopped product service, retained
history, unsupported legacy firewall state or possible product schedule/rule is
preserved and refused. Names are refusal signals, never ownership evidence.
Unrelated administrator schedules and rules remain intact. Ordinary nftables
packet/byte counters are normalized; other rule or dynamic-set changes require
another review. Alpine's exact packaged crontab alias is bound without following
arbitrary links, and its target inventory is checked independently.

The internal execution coordinator constructs its lifecycle boundary only after
reopening and verifying the original preparation under its exclusive lock.
Construction failure, cancellation or a missing boundary prevents native dispatch;
partially constructed resources close before the preparation lock is released.
This orders resource custody but does not supply production lifecycle authority.
The boundary closes before independent terminal verification, so the inactive
coordinator must retain publication exclusion separately across that verification.

Real isolated Alpine/OpenRC observation is intermediate evidence. It does not
qualify a signed package transaction, direct package-manager entry points,
repeated ownership transfers, reboot or removal. The coordinator still needs
proven original ownership, retained publication exclusion throughout replacement,
and independent terminal closure against the original observation. Production
terminal verification refuses the inactive path until these are integrated.
No installer or update command silently switches from missing activation approval
to inactive migration, and no activation is performed to satisfy an update gate.

Approval and successful application are separate root-private records. An
approved install permits its nested firewall reload and independent core start
before the parent can record success; a child reload cannot record completion
of the parent install. A later explicit install always needs a newly reviewed
plan. Boot and ordinary reload may reuse only the exact approved source scope.
`reload --no-restart` cannot create approval; it can only consume existing full
approval and suppresses the immediate core restart. Policy, integrations and
scheduling can still change. Ordinary scheduled and mutating CLI commands also
require exact existing approval before automatic recovery or configuration use.

The core independently checks protected authority and reads only the approved
bounded TOML bytes before publishing its runtime settings. Neither configuration
environment overrides, profile markers nor active services establish approval.
These controls are intermediate evidence. The plan is not a complete live
kernel-rule diff or an authenticated access proof. Native upgrade integration,
recovery and separate removal qualification remain open; in particular, a package
hook cannot mint new authority after replacing an unapproved older runtime.

## Optional external reporting

AbuseIPDB requires its explicit integration selection, a usable API key and
enterprise mode disabled. The core enforces enterprise mode itself before
retaining a reporting key. Missing or invalid selections and unusable keys
cannot enable reports. This selection is captured when the reporting component
initializes; changing TOML alone does not attest a running process or hot reload.

Install/reload validate the selected key without creating, replacing or deleting
`/etc/syswarden/secrets.env`. The core reads the TOML configuration directly;
it does not consume that historical duplicate. Existing copies remain unchanged
because their ownership and possible external consumers require separate review.
Their presence is not reporting authority, and this preservation is not a claim
of complete native removal or historical credential rotation. No credential is
printed by selection validation or the configured-effect preview.

Optional reports are best effort. The reporter keeps at most eight workers and
4,096 recent addresses, retaining the existing 15-minute per-address cooldown.
Saturation drops a report without queuing work or evicting an unexpired cooldown.
Expired entries are periodically pruned. Invalid addresses and private, loopback,
link-local, multicast or unspecified addresses are refused; accepted addresses
are canonicalized before suppression and export. Bounded ASCII rule identifiers select categories locally but are not
copied into public comments. Event text longer than 4 KiB is ignored for port
extraction. Raw event data is not retained by a reporting worker. Response bodies,
response headers and transport errors never enter reporting diagnostics; only a
fixed outcome and numeric HTTP status do.
Responses are drained by at most 4 KiB and closed under the existing ten-second
HTTP timeout. These bounds do not authenticate the original event producer or
prove that every report was delivered.

## Significant changes and missing activation steps

The configuration-led workflow still needs complete reviewable host effects,
explicit activation of the exact approved policy and complete native recovery qualification.
Ordinary TOML proposals retain the original configuration identities across
human review and recheck read-only WireGuard, removal and firewall barriers
around the journaled atomic publication primitive. Those
barriers are point-in-time checks, not cross-process locks or host activation
authority. Do not replace this original snapshot with a newly captured baseline
after approval, or write invalid live policy and then attempt a generic repair.
The dedicated SSH module needs its own protected publication boundary. There is currently no `config apply`
command; `config preview` grants no activation authority, the menu has no dedicated `05-ssh.toml` item, and editor exit is not
confirmation of a host change.

For SSH, `ssh-policy ports`, `plan` and `verify` expose bounded observation and
parser checks. Explicit TOML selection is separate from ownership, access
contexts and approval of an exact migration plan. Forward SSH application is
not available through the CLI, installer or generic reload. Existing SSH/CIS/OS
policy is preserved by install/reload; a changed selection does not undo it.
See [SSH selection](SSH_SELECTION.md) and [access commands](SSH_ACCESS_COMMANDS.md)
for the remaining independent access and policy-consumption boundaries.

## Upgrades, removal and restoration

Upgrades must preserve administrator TOML, existing protection, native package
identity, dependency choices and stopped/disabled/masked service state. Missing
historical modules do not authorize replacement with fresh defaults. Package
staging and a successful native transaction do not prove runtime activation.
The current identity guards, historical-caller limitations and remaining native
qualification are recorded in [package identities](NATIVE_PACKAGE_IDENTITIES.md)
and the [installation contract](MINIMAL_NATIVE_INSTALL.md).

Standalone `syswarden uninstall`, native package removal and native purge are
distinct entry points requiring separate verification. Standard registered
`syswarden` or `syswarden-base` installations use their owning package manager;
standalone uninstall refuses to erase their registered payload. Debian remove
and purge differ, Alpine has `del` and `del --purge`, and RPM erase has no
separate purge operation. None is a general rollback of prior host settings.

Complete removal means removing proven product-owned state while preserving
administrator configuration and unrelated protection. A refusal or retained
ambiguous artifact is incomplete removal. Keep its ownership records and
private recovery data. Review the relevant `recover-removal --help` inventory,
inspect it first, and apply only its exact plan with every required confirmation.
After bounded recovery, retry the original removal entry point so its native
registration and cleanup contract remain consistent.

Restoration requires attributable original state and a supported recovery path.
Do not overwrite a live configuration tree with an arbitrary backup or delete
journals to make a retry proceed. `recover-wireguard` offers specific inspected
recovery operations; it is not a whole-host restore. SSH
[`restore-original`](SSH_OPERATOR_RECOVERY.md) requires an existing owned
activation history and separately approved recovery digest. Its restored-access
exchange still reports `recovery_required=true`; restored files or a fresh login
alone do not establish consumed policy or completed recovery. Deliberately
retained private backups remain separate from active configuration.

## Source basis

The current behavior is implemented in the CLI
[`config`](../../src/core/syswarden-cli/cmd/config_cmd.go),
[`preflight`](../../src/core/syswarden-cli/cmd/root.go),
[`reload`](../../src/core/syswarden-cli/cmd/reload.go) and
[`removal recovery`](../../src/core/syswarden-cli/cmd/recover_removal.go) paths,
the [merged validator](../../src/core/syswarden-cli/config/validation_report.go),
the [validated publisher](../../src/core/syswarden-cli/config/user_module.go),
and the [network value boundaries](../../src/core/syswarden-cli/pkg/firewall/policy_values.go).
This guide does not replace their required native lifecycle and v5.00.0 IVVQ
acceptance.
