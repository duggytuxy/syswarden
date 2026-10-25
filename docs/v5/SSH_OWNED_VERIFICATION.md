# Verify an owned SSH publication

Status: read-only v5.00.0 development component. Refs #235, #337 and #422.
This extends the [shared SSH transaction](SSH_TRANSACTION.md) with fresh
verification of a configuration it already published. It does not complete
production integration or make a package ready for migration testing.

## Purpose and command

The initial planner refuses an occupied reserved drop-in because its name and
contents cannot establish ownership. After a completed internal transaction,
the original independent receipt and complete journal can instead establish
which configuration inodes were published and which original inode was retained.

```sh
sudo syswarden ssh-policy verify-owned --plan-sha256 ORIGINAL_APPROVED_PLAN_SHA256
```

Replace the placeholder with the original independently approved lowercase
SHA-256. The command does not accept an alternative root, journal, executable
or configuration path. The global `--config` option does not redirect its
authority. Root is required. It acquires the existing journal's nonblocking
exclusive lock, creates no lock file and refuses a competing product operation.

The JSON result contains digests, the transaction identity, selected profile
and verified context count. It contains no configuration text, accounts, peer
addresses, hostnames or parser output. On refusal it emits no partial result.
It bypasses automatic general configuration loading and firewall recovery.

## Verification boundary

Verification requires all of the following:

1. The independent ownership receipt still attests the original journal
   directory and marker. Permissions, attributes, identities and single-link
   custody must remain valid.
2. Exactly the preparation, marker and six publication phase records exist.
   Incomplete publication, rollback, abort, retained history and unexpected
   entries are refused.
3. Reconstructing the original plan from the first publication intent yields
   the supplied digest. The prepared file identities and every subsequent
   before/after transition must match that plan and each other.
4. The independently declared TOML SSH choice still authorizes the profile.
   The complete live input graph, metadata, directory entries, original
   recovery inode and generated policy must match the last completed phase.
5. The installed protected AMD64 parser matches the original parser digest.
   Syntax and effective values are checked for the original, intermediate
   and final sealed graphs, then compared with the live configuration.
   Global defaults and every declared direct, ProxyJump and Ansible context
   are checked; unrelated settings must remain unchanged.

The verifier pins every journal record's observed inode, bytes, metadata and
attributes for the duration of verification. It checks the history, live
configuration, parser identity and cancellation before and after each parser
invocation, including failed invocations. Replacing a record with identical
bytes during verification is refused. Administrator changes, a changed parser
or a changed TOML choice require a separate reviewed lifecycle transition.
They are not silently adopted.

## What a successful result establishes

`ownership_verified`, `publication_observed` and `parser_verified` are true
only after all checks finish. They describe the observed configuration.
`runtime_activated` and `access_verified` remain false. A running daemon may
still use an older configuration, and a parser cannot prove authentication
through a remote bastion or controller.

The command does not sync files, repair a failed durability operation, change
the journal, publish a policy, restart SSH or open a listener. It does not
authorize replaying `apply`, retire backups or accept an interrupted activation.
An occupied journal still prevents another publication attempt.

This observation is a prerequisite for future activation and already-owned
updates, not their implementation. Production callers must still share one
selected transaction, and native migration must demonstrate independent real
access and separate uninstall, package remove and package purge outcomes.

The minimal installation contract in
[#422](https://github.com/duggytuxy/syswarden/issues/422) remains mandatory:
fresh native packages must select no list and defer activation until explicit
configuration through `syswarden config`. SSH, CIS and OS hardening need explicit
independent TOML choices. This command neither changes package
defaults nor turns historical generated settings into consent.

The internal [owned endpoint adapter](SSH_OWNED_ENDPOINTS.md) retains this
verification's journal lock and ownership guards while comparing parsed
endpoints with observed listeners. It does not change this command or promote
matching endpoints into activation or authentication proof.

## Validation

Temporary-filesystem tests exercise repeated observations, unchanged inode and
record custody, incomplete phases, restored and retired histories, drift during
parser calls, changed authorization, unsafe metadata, cancellation and parser
failures. CLI tests verify required input, read-only root preparation, refusal
without partial JSON and explicit false runtime/access claims.

The installed OpenSSH oracle covers forwarding, CIS and attributed historical
CIS migration with direct, ProxyJump and Ansible declarations. It publishes
into an isolated fixture, reopens the journal, verifies ownership twice, then
restores the original configuration. It uses parser modes only. Component
success is neither native migration acceptance nor final v5.00.0 IVVQ acceptance.
