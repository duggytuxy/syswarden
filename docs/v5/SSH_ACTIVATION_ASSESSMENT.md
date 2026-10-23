# Read-only assessment after an SSH activation attempt

Status: development command for v5.00.0. Refs #235, #337 and #422.
It assesses an existing interrupted-activation history. It does not recover or
complete a migration, and a migration-ready package is not yet available.

## Operator boundary

The internal activation dispatcher persists an
[activation intent](SSH_ACTIVATION_BOUNDARY.md) before issuing a runtime request.
After an interruption, that intent alone cannot establish whether the request
was sent or whether the daemon loaded the intended policy. File-only recovery
must continue to refuse that history.

The development command provides a separate read-only assessment:

```sh
sudo syswarden ssh-policy assess-activation --plan-sha256 ORIGINAL_APPROVED_PLAN_SHA256
```

The original plan digest must come from the independently reviewed plan. The
command does not infer approval from the journal, current configuration or a
saved observation. It bypasses automatic configuration loading and firewall
recovery just like the other read-only SSH development commands.

There is no `--apply`, `--recover`, `--force` or retry option. The command writes
no configuration or journal records, performs no durability repair, signals no
process, and opens no authenticated connection. It retains the journal lock
through parsing and live observation. The complete observation has a bounded
two-minute lifetime.

## Evidence checked

1. Reopen the protected ownership receipt and journal at fixed live paths. A
   poisoned in-memory journal cannot be reused without reopening it.
2. Require exactly the eight original publication records and the activation
   intent. Incomplete, mixed, rollback and unknown histories are refused.
3. Read the bounded intent through its protected inode. Only the exact canonical
   encoding written by the dispatcher is accepted. Duplicate keys, unknown or
   case-folded fields, noncanonical JSON, unsafe file types, permissions and
   links fail without rewriting evidence.
4. Reconstruct the original plan from the publication history. Its independent
   approval, pinned installed parser, explicit TOML choice, original recovery
   inode and complete publication transitions must still agree.
5. Recompute every intent binding: transaction, preparation, plan, parser,
   published inventory and original record identities. The saved target digest
   is reported as historical evidence, not adopted as a current runtime target.
6. Revalidate the original, intermediate and final graphs with the installed
   parser, including all declared contexts. Compare the current effective
   configuration with the sealed approved candidate.
7. Observe the current qualified systemd process and listening endpoints with
   the existing protected read-only adapter. Recheck the intent inode, every
   original record and the configuration around parsing and observation.

The publication and activation-aware paths share only read-only history and
parser checks. Existing publication, rollback, retirement and repeated
activation retain their activation fences. Successful assessment does not make
any of those operations eligible.

## Result meaning

A successful JSON result has `intent_observed: true` and
`recovery_required: true`. It includes current publication/parser and endpoint
observations, plus hashes of the saved intent and historical target. Raw
configuration, account names, endpoint addresses and authentication material
are not included.

The result does not claim that the original write was durably acknowledged.
An intact record can be visible after a failed directory synchronization. Nor
does it claim that the current process is the original activation target:
observing a replacement process after a restart is current-state evidence only.
`runtime_activated`, `configuration_verified` for runtime observations and
`access_verified` remain false.

An inactive or unsupported service, mismatching endpoints, changed configuration,
replaced record, parser failure or cancellation produces an error with no
partial JSON summary. Such a failure is not permission to delete the activation
intent. Preserve all evidence and administrator changes for explicit recovery.

## Validation and remaining work

Isolated tests cover repeatable observation, a request that returned, an
unacknowledged directory sync, complete record and intent binding, malformed
records, link/type/mode attacks, replaced inodes, changing selection or policy,
parser and observer failures, cancellation, journal locking and replay refusal.
Command tests check mandatory approval, rejected mutation flags, no partial
output and avoidance of mutating root-command preparation.

Installed OpenSSH parser oracles exercise forwarding, CIS and attributed legacy
CIS graphs with direct, ProxyJump and Ansible context declarations. They use
real temporary TCP sockets for endpoint comparison and controlled process and
request fixtures. They do not authenticate those routes, reload the installed
SSH daemon, or establish native lifecycle acceptance.

Actual runtime-aware recovery, causal policy-consumption acknowledgement,
independent fresh authenticated access, already-owned updates and separate
native uninstall/remove/purge still require integration and validation.
Issue422 production minimal-profile wiring also remains open: fresh native
packages must use only the standard list, optional SSH/CIS/OS protection must
require explicit TOML choices, and upgrades must preserve administrator settings
and existing protection. BunkerWeb's independent contract is unchanged.
Linux AMD64 only; these checks are intermediate v5.00.0 IVVQ evidence.

## Private access-request continuation

A [private request preparer](SSH_PROTECTED_ACCESS_REQUEST.md) now runs inside the
same locked assessment and original inode guards. It derives all declared
contexts with explicitly supplied public key pins and performs a final guarded
recheck before returning canonical private bytes. The existing public
`assess-activation` command remains read-only and emits no request or credentials.
Independent controller execution and receipt acceptance do not follow
automatically from a successful assessment.
