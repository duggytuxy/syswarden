# Bind an owned SSH publication to endpoint observations

Status: internal v5.00.0 integration component. Refs #235, #337 and #422.
The adapter joins [publication verification](SSH_OWNED_VERIFICATION.md) with
[endpoint correspondence](SSH_ENDPOINT_CORRESPONDENCE.md) while holding the
same journal lock and retaining the same protected ownership observation.

## One guarded observation

`ObserveOwnedSystemdEndpoints` requires root and the independently approved
original plan digest. It accepts no alternate root, parser, journal, endpoint
list or saved proof object. It opens the existing journal through its independent
receipt and holds its nonblocking exclusive lock until all observations finish.

Before inspecting the runtime, the adapter reconstructs the original plan and
verifies the complete publication history, live file identities, recovery inode,
installed parser and explicit TOML choice. The original, intermediate and final
graphs must retain unrelated settings and satisfy every declared direct,
ProxyJump and Ansible context. An occupied or matching generated filename cannot
replace this proof, and existing generated settings cannot supply consent.

The active standard SSH graph is then collected and compared with its sealed
parser image. Parsed addresses and ports must match the actual listener objects
inside the existing process, namespace and service-manager observation boundary.
The complete owned inventory and exact journal record identities remain guarded
around parsing and listener observation, including failed calls and the final
return. Replacing a record with identical bytes, changing a recovery inode or
revoking the TOML selection invalidates the entire composed result.

Both stages share one bounded context. A competing product operation cannot
acquire the journal lock between them. Failure, cancellation or a close error
produces no partial success summary. The adapter creates no files, writes no
phase record, repairs no durability state and changes no service.

## Evidence limits

The summary contains the publication and endpoint summaries together. It does
not expose configuration contents, raw endpoints, accounts or journal records.
It cannot be stored and replayed as authority for a later activation.

Agreement means that the verified published graph's parsed endpoints match the
observed sockets. A daemon could still use older authentication settings with
the same endpoints, or obtain configuration from different startup arguments.
Configuration consumption, activation and independent access therefore remain
unproven. The existing false runtime/access flags retain their meanings.
Repeated checks are not atomic snapshots and do not defend against a hostile
kernel or cooperating root administrator.

No CLI command or installation call is added. This is a prerequisite for the
activation and lifecycle integration, not a migration-ready package. Native
migration, administrator edits and separate uninstall/remove/purge outcomes,
including unrelated protections after reload and reboot, remain required for
the v5.00.0 IVVQ campaign.

Issue422 remains mandatory: standard-list-only fresh APK/DEB/RPM installation,
independent explicit TOML choices for SSH/CIS/OS and optional modules, and
preservation of administrator settings and existing protection during upgrade.
BunkerWeb's independent API, source ownership, expiry and HA are unchanged.
Linux AMD64 only.

## Validation

Tests exercise repeated observations without state changes, retention of the
journal lock, deadline propagation, invalid approval and changed selection
before runtime inspection. They reject file, parser, ownership and journal
drift during listener observation, including byte-identical record replacement,
late cancellation and an observer error after an otherwise valid sample.

The installed OpenSSH oracle publishes and restores forwarding, CIS and legacy
CIS fixtures with direct, ProxyJump and Ansible contexts. It compares the
published graph with real ephemeral loopback sockets. Its process/manager
summary is a test fixture; the oracle does not start SSH or prove actual login.
Existing process/socket tests cover the production descriptor boundary
separately. Together these are component evidence, not native acceptance.
