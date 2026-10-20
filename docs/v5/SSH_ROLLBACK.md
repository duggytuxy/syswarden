# Verified SSH configuration rollback

Status: internal v5.00.0 development component. Refs #235 and #337.
The public SSH policy commands remain read-only. Installation, CIS hardening and
service activation do not invoke this helper yet. This is not a complete package
migration or final IVVQ acceptance.

## Recovery boundary

Rollback requires explicit approval of the original plan digest and the private,
independently owned transaction journal. It reconstructs that plan from the first
immutable publication inventory. The complete inventory, original configuration,
proposed main file and policy must agree with the prepared transaction. Current
files are never adopted because they have familiar names or matching contents.

All publication interruption positions are accounted for: an intent before its
operation, an observed operation whose completion is uncertain, or a completed
phase. There must be an exact, continuous history. An unrecorded administrator
change, replacement inode, changed permission, new Include member or conflicting
recovery name stops recovery and preserves the files for review.

Before reversal, the pinned installed OpenSSH parser verifies the sealed original,
intermediate and final configuration graphs for global defaults and every declared
connection context. No unreviewed setting may change. This check does not require
the currently published configuration to be accepted as the original baseline.

## Inverse operations

A private `rollback-start.json` records the exact observed publication position
and configuration inventory. Two ordered phases follow, with independent intent
and completion records:

1. If the main file was exchanged, exchange its exact original inode back from
   the nonincluded main stage. The candidate main inode remains at that stage.
2. If the policy was published, move its exact inode to a transaction-specific
   `.syswarden-ssh-drop-<transaction>` name in the same drop-in directory using
   a nonreplacing rename. The active reserved policy path becomes absent.

An operation that was never published has an explicit no-op inverse. The sequence
never unlinks configuration files. It retains candidate images with their attested permissions for
recovery; these are not active policy or completed product removal. Before
preparing any new publication, Include isolation now excludes both retention
names, including through nested, conditional or currently empty patterns.

Linux [rename semantics](https://man7.org/linux/man-pages/man2/rename.2.html)
provide the exchange and nonreplacement primitives. Parent directories and
transaction records are synced before using completion evidence. A process
resuming an uncertain operation explicitly repeats the required syncs rather
than treating a visible file as proof of durability.

The private product lock does not serialize external configuration managers. If
an administrator races an operation, an exchanged or renamed file remains
available. Reinspection refuses a successful result or automatic continuation.
This is not a defense against a hostile root administrator or kernel.

## Interruption and verification

A failed write or uncertain sync poisons the current journal handle. Recovery
must reopen and inspect it, then explicitly resume with the same approved plan.
Read-only inspection distinguishes a before-state, an observed after-state and
completed configuration phases. It validates both publication and rollback
history, including gaps, contradictory records and exact inventory continuity.

An after-state observation never claims that a failed sync succeeded. A completed
configuration position never claims that the parser, running daemon or a new
login has succeeded. A successful rollback operation separately reruns syntax
and effective-policy checks on the live restored graph. Its complete output
must match the sealed original for every declared context, including unrelated
access settings. Repeating a completed rollback reverifies the graph without
repeating configuration mutations.

Temporary filesystem tests cover all twelve publication failure positions,
rollback start/intent/mutation/sync/completion interruptions, explicit resumes,
malformed or contradictory records, concurrent administrator edits, reserved-name
collisions, cancellation and live parser failure after reversal. The installed
OpenSSH oracle exercises publication and restoration for forwarding, CIS and
historical CIS migration with direct, ProxyJump and Ansible context declarations.
It never opens a listener or authenticates a user.

## Remaining integration

The internal [shared transaction](SSH_TRANSACTION.md) now composes approval,
target-policy SELinux labeling, publication and explicit rollback. Production
install/CIS opt-in integration, owned updates, public recovery orchestration,
service activation, independent access testing and transaction retirement remain
required. Run separate native uninstall, package
remove and purge checks as soon as that coherent adapter is available. Preserve
later administrator changes and distinguish retained private evidence from
active product artifacts. BunkerWeb's independent API, temporary-ban ownership
and HA behavior remain unchanged.
