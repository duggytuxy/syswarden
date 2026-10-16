# HA state retention during removal

This development recovery path belongs to the v5.00.0 IVVQ scope. It does
not change the published v4.10.4 package or establish native acceptance.

After an HA-enabled installation, the default state directory can contain a
TLS identity, source-scoped ban history and replication/fence recovery files.
These older producers do not provide creation provenance that authorizes
automatic removal. A familiar path, matching certificate or valid JSON schema
does not prove exclusive ownership. Native package removal therefore preserves
the executable and removal barrier when this state remains.

## Bounded operator decision

`syswarden recover-removal --retain-ha-state` inspects only the fixed default
HA directory after the removal barrier exists, product services and mutators
are quiescent, and product kernel tables are independently confirmed absent.
It prints filenames, metadata and hashes, never key material or state contents.
It does not normalize configuration, restart services or change firewall rules.

The operator must confirm that every listed file is exclusively used by the
retired SysWarden instance, with no other consumer or producer. Only then may
the exact displayed plan be applied with `--apply`, `--plan-sha256` and the
separate `--confirm-exclusive-ha-state` flag. A changed inventory requires a
fresh inspection and decision. Do not confirm a shared TLS identity simply
because it resides beneath the default directory.

Application moves the original inode tree into a private, non-overwriting
backup below `/var/backups/syswarden-retired-v1/`. It preserves TLS keys, ban
history, fence evidence and any supported transaction records without replaying
them. It does not certify transaction completion or safe reuse of old identity.
All files and nested directory identities are checked before and after the
move; a mismatch stops completion and preserves the bytes. Completed operations
can be retried only when the retained backup still matches the reviewed plan.

Symlinks, hard links, mount boundaries, unsafe permissions, unknown names,
oversized files and concurrent changes are refused. Custom HA/TLS paths are
outside this recovery inventory. Unrelated administrator files are not adopted,
removed or silently exempted from the final removal check.

After successful archival, retry the original `uninstall`, native `remove` or
native `purge` operation. These remain separate lifecycle validation paths.
The backup is retained recovery material, not active product configuration.
A later installation must never restore its keys, bans or replication state
automatically. Protect and review backups under the operator's retention policy.

## Verification boundary

Component coverage checks complete inventory binding, secret-free plans,
original inode preservation, nested changes, substitution, unsafe metadata,
interrupted moves and exact resumption. Independent native lifecycle tests
must still demonstrate complete active-state removal, preservation of unrelated
services, reload/reboot behavior and reinstallation. This recovery mechanism
does not alter BunkerWeb authentication, source ownership, expiry or HA fencing.
