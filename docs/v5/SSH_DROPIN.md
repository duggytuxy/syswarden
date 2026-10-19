# Dedicated SSH hardening policy

Status: inactive SSH-01 preparation component for v5.00.0. Refs #235 and #337.
The current installer still uses its existing SSH configuration paths. This
component does not write a file, restart a service, migrate an installation or
change the published v4.10.4 behavior. Final v5.00.0 IVVQ remains open.

## Target and policy boundary

The intended publication target is
`/etc/ssh/sshd_config.d/00-syswarden-hardening.conf`. One shared implementation
will replace the standard forwarding writer and the separate CIS SSH writer.
The [preparation component](../../src/core/syswarden-cli/pkg/sshpolicy/policy.go)
already generates two fixed profiles:

| Profile | Directives |
| --- | --- |
| Forwarding | `AllowTcpForwarding no` |
| CIS | Forwarding plus `X11Forwarding no`, `MaxAuthTries 4`, `ClientAliveInterval 300`, `ClientAliveCountMax 3` |

Neither profile sets the port, listening addresses, root login policy,
authentication methods, passwords, keys, MFA or administrator access groups.
The dedicated file is intended to isolate product policy from administrator
configuration. Its filename and comments alone do not establish ownership.

These fixed profiles are not suitable for every SSH role. The
[environment compatibility contract](SSH_ENVIRONMENT_COMPATIBILITY.md)
distinguishes a target behind a bastion from a host providing the jump service,
and separates Ansible/external policy ownership from access role. A protected
role decision is required before runtime integration, even when no explicit
forwarding directive is found. The preparer cannot establish that intent.

OpenSSH generally uses the first obtained value for a keyword, with documented
exceptions. Included files are processed at the inclusion point and glob matches
in lexical order. Includes may also occur inside `Match`. A low-numbered filename
does not prove the resulting policy. See the official
[sshd_config manual](https://man.openbsd.org/sshd_config).

## Executable preparation boundary

`Prepare` consumes an inventory of configuration paths and bytes. The future
filesystem adapter must independently attest this inventory, including every
reachable file, directory membership and negative glob result. Supplying an
incomplete map can omit a conflict; this pure component cannot detect that. It
does not open a pathname, trust remote input, or attest file ownership/modes.

The inactive [protected Linux inventory reader](SSH_INVENTORY.md) supplies a
bounded descriptor-based collection and revalidation path for a restricted
Include layout. It does not yet provide role declarations, migration approval,
publication or lifecycle integration.

The [protected migration planner](SSH_MIGRATION_PLAN.md) now binds an explicit
administrator declaration and bounded legacy main-file edits to a complete
inventory. Its CLI is read-only; it does not yet approve or apply a migration.

Preparation requires the main file and an absent reserved destination. Even an
existing byte-identical drop-in is refused: an independent ownership receipt is
required before update or removal. The generated file must be included exactly
once, before any observed `Match`. A conditional inclusion, duplicate inclusion,
cycle or absent inclusion rejects the complete candidate. No fallback edits the
main file or ignores the failed plan.

The conservative scanner supports absolute includes, relative includes resolved
under `/etc/ssh`, simple tokens, complete double-quoted arguments, comments, and
`*`/`?` globs over canonical printable ASCII paths. Bracket expressions, escapes,
traversal and ambiguous forms refuse preparation. It does not try to replace the
complete OpenSSH parser. Once a `Match` has been observed, a later inclusion is
not treated as global, even after `Match all` or return from another include.
This deliberately refuses some valid layouts rather than guessing their scope.

Every controlled directive in a reachable file must already agree with the
requested value. Conflicting administrator directives are preserved and refused,
including conditional directives and later global directives that might currently
be shadowed. This is stricter than asking only for the default `sshd -T` output.
Legacy `SYSWARDEN OVERRIDE` and CIS block markers trigger separate migration
review; they are not permission to uncomment or delete administrator settings.

Limits are 128 input files, 1 MiB of combined input bytes, 1,024 bytes per path,
16 KiB per line, 16 nested include levels, 512 file visits, 512 include patterns
and 4 MiB of expanded configuration bytes. Any failure returns no partial
candidate. The result owns immutable bytes and a deterministic SHA-256 inventory
reference. This reference binds sorted path/content pairs with eight-byte
big-endian length prefixes under `SYSWARDEN-SSH-INVENTORY-V1` followed by LF.
It includes unmatched supplied files but does not authenticate a caller, attest
storage or authorize applying a plan.

`CheckEffective` checks one bounded OpenSSH `-T` result. Missing, duplicate,
malformed or mismatched controlled directives refuse it. Success is neither
runtime activation nor evidence for untested `Match` contexts. Real daemon
validation and explicit connection contexts remain mandatory. The official
[sshd manual](https://man.openbsd.org/sshd) describes `-t`, `-T` and `-C`.

## Required integration and lifecycle gates

These stages remain open and must be completed before replacing either writer.
The environment compatibility contract is an additional gate for each stage:

1. **SSH-02, protected inventory and migration.** Descriptor-based file and
   parent attestation, ownership/mode/link checks, bounded glob enumeration,
   stable inventory rechecks, exact plan approval for attributable historical
   edits and explicit handling of missing/conditional includes. Preserve
   ambiguous administrator changes. Do not infer origin from matching values,
   names or markers. Keep original recovery evidence private.
2. **SSH-03, one owned publication transaction.** Private durable ownership and
   before/after evidence; no-replace first publication; serialized update;
   crash recovery; syntax and effective-policy verification; port and access
   preservation; selected `Match` contexts; activation and checked rollback.
   Account for OpenRC, systemd aliases/sockets and offline package hooks. Both
   current writers must use this path, without competing edits to the main file.
3. **SSH-04, exact retirement and recovery.** Independently cover CLI
   `uninstall`, native `remove`, native `purge` and delayed purge. Remove only
   proven product contributions, validate the remaining SSH configuration and
   preserve administrator authentication/access behavior. Changed drop-ins or
   receipts retain evidence and require a bounded recovery plan. Test reload,
   reboot, interrupted publication/removal and restoration failures.
4. **SSH-05, native acceptance and documentation.** Exercise supported Linux
   AMD64 package profiles, ordinary-user tampering, legacy upgrades, custom
   ports and administrator drop-ins. Verify a second independent SSH connection
   before accepting activation. Update canonical operator documentation when
   behavior is integrated and verified. Do not change stable release references
   merely because a component PR passes.

The BunkerWeb API, source-specific ban lifetimes, withdrawal/cache handling and
HA contract remain independent. This component has no integration dependency.

## Evidence scope

Unit/race tests cover fixed profiles, unchanged source bytes, no output aliasing,
include ordering and recursion, unconditional inclusion, all controlled-key
conflicts, historical markers, malformed input, resource ceilings, complete
inventory hashing and effective-output rejection. Two bounded fuzz targets cover
preparation and effective-output validation. A golden digest is independently
reproduced outside Go.

The opt-in `TestOpenSSHOracle`, enabled with `SYSWARDEN_SSH_ORACLE_TEST=1`, uses
the installed `sshd` and a temporary generated host key. It invokes only `-t`
and `-T`, including `-C` contexts, and opens no listener or real configuration.
It checks both profiles, preserved port/authentication settings, earlier-main
precedence, a `Match` override invisible in the default view, and absent drop-in
behavior. Missing tools fail when the test is enabled. The default suite records
this oracle as skipped rather than claiming native coverage. This local parser
evidence is not distribution-level lifecycle acceptance or final IVVQ.
