# Isolated production SSH systemd oracle

Status: opt-in Linux AMD64 development validation for #235, #337 and #422.
This is component evidence for v5.00.0 IVVQ, not migration acceptance.

## Purpose and limits

The test uses the production systemd activation binder, protected process
descriptors, pidfd signal dispatch, listener-generation observer and prior
address-space retirement check. A disposable
Debian 13 container runs real systemd, D-Bus and OpenSSH. It generates its own
host and client keys, authenticates fresh connections with the host key pinned,
and probes TCP forwarding through loopback. No host SSH keys, services,
configuration or sockets are mounted.

The ordered checks require:

1. Fresh authentication and forwarding with the original fixture policy.
2. Continued forwarding after writing the dedicated drop-in without reloading.
3. Refusal of a no-op signal dispatch because no listener replacement occurs.
4. A real production reload, observed listener replacement and prior address-space
   retirement on the surviving process, followed by refusal of replay.
5. Fresh authentication with forwarding explicitly prohibited by the new policy.
6. Continued prohibition after restoring files without reloading.
7. A second production reload, fresh authentication and restored forwarding.
8. Unchanged original main configuration and removal of the exact test container.

The result proves these fixture transitions. It does not prove consumption of
every configured directive, independent controller enrollment, durable completion,
all daemon startup forms, native package migration or the complete recovery and
removal contracts. The controlled forwarding probe is not a production authority
for general policy-consumption acknowledgement. A successful fresh connection
alone cannot authorize migration completion.

## Integrated recovery scenarios

The same runner accepts `--scenario recovery-forwarding`, `recovery-cis`,
`recovery-legacy-cis` and `recovery-noop`. Each invocation requires a new output
folder and creates a new disposable container. The default `activation` scenario
retains the independent signal/listener negative controls described above.

The activation scenario also checks default main-file selection with the real
pinned parser. A private copy of the fixture ELF has only its unique, same-size
compiled configuration pathname replaced. Both files contain identical policy,
so their effective directives match, but implicit selection of the alternate
path must be refused. Explicit verified `-f` selection remains separate. The
copied executable runs only in parser test mode inside the disposable namespace;
it never replaces the installed daemon or starts a listener. The running process,
listener generation and original main-file bytes must remain unchanged across
these probes. This control qualifies selection evidence on the fixture build,
not arbitrary daemon provenance or completed policy consumption.

Recovery scenarios use the real pinned OpenSSH parser, transaction journal,
publication engine and production activation binder. They then call the actual
fixed-path `InspectSystemdRecovery`, `RestoreOriginalSystemd` and
`AssessSystemdRecovery` adapters. An independently disabled SSH TOML choice must
refuse publication before creating a journal or drop-in. The original migration
approval must not authorize the separate restoration. Repeated read-only
inspection must return the same recovery approval without changing history.

The forwarding and CIS cases verify unchanged running behavior after publication,
prohibited forwarding after activation, then restored forwarding after original
restoration. The legacy CIS case explicitly attributes exact historical main-file
lines and retains its original forwarding prohibition after restoration. A
separate administrator `Match` block is included in both parsed contexts.
Restoration must recover the original main inode, bytes, permissions, ownership,
attributes and modification time. The expected rename-related ctime change is
not confused with lost ownership. Candidate main and drop-in inodes remain
attributable recovery data outside active configuration. All original journal
records remain unchanged and exactly six inverse/reload records are added.

`recovery-noop` changes only the test lease's signal callback to a successful
no-op. The real listener observer must reject that request, while the original
files have already been restored. Fresh pinned authentication still succeeds,
but forwarding remains prohibited by the stale daemon policy. Read-only
assessment and repeated restoration cannot turn that uncertainty into acceptance
or replay the reload. Process and kernel listener identities must remain
unchanged across assessment and rejected replay. All scenarios keep `RecoveryRequired` true; none grants
production policy-consumption or independent access authority.

### Label preparation boundary

The recovery fixture prepares its candidate with an explicit test-only label
resolver. It observes the actual `security.selinux` attribute on a temporary
private file in the destination directory, clones only that attribute, rechecks
the original main label during publication and verifies the published drop-in's
attributes. Main-file attributes still pass through the real retained-inode
transaction and recovery checks. No label is stripped or concealed, no SELinux
filesystem is masked, and no host label or enforcement state is changed.

This prepares attributable recovery input; it does not qualify the production
label resolver or establish that the observed label is the policy-correct label
for the destination pathname. The unmodified production publication entry point
continues to refuse an unmounted SELinux state directory or visible labels with
unavailable policy. A Fedora-hosted container with either condition is therefore
not qualified for production publication by this fixture. SELinux enforcing
publication still requires its separate native qualification.

Synthetic journal records are exported as base64-encoded JSON in the private
runner log before container removal. A second bounded read is attempted even
when the main test watchdog bypasses Go cleanup. If the container or evidence
reader is unavailable, export can remain incomplete and the run cannot pass. The export
is bounded to the fixture journal and does not copy private keys or unrelated
files. Keep those logs private even though the fixture identities are generated.

## Runtime observations

An inactive vendor socket can be unloaded between independent manager queries.
Its configured target must resolve to the independently observed service;
conflicting reverse references and changing samples remain refused. Active
sockets still require a reciprocal relationship and remain outside the current
service-only reload binder.

An ordinary daemon reload can replace a PID file under the shared runtime
directory. Bus endpoint checks retain ancestor device/inode identity, type,
permissions, ownership and captured attributes, together with the full socket
identity. Unrelated sibling timestamps, size and directory link count do not
invalidate the endpoint. Descriptor traversal still checks safe ownership,
permissions, positive link count and replacement during capture. Configuration
inventories retain their stricter membership and timestamp comparison.
This boundary does not defend against compromised root or a malicious manager.

## Explicit local invocation

Use the repository's verified Go toolchain and existing shared build cache.
The rootless Podman host must support systemd containers, pidfds and cgroup
resource limits. Build the fixture image from
`scripts/ci/ssh_systemd_oracle.Containerfile`; record its immutable image ID.
Only image preparation needs package repository access. The test container has
no external network, host namespace, published port or writable host mount.

From the CLI module, build a standalone test executable with two CPU workers:

```sh
GOMAXPROCS=2 CGO_ENABLED=0 go test -p=2 -c \
  -o /absolute/private-output/sshpolicy.test ./pkg/sshpolicy
sha256sum /absolute/private-output/sshpolicy.test
```

Then, from the repository root, provide the verified executable digest and exact
prepared image ID. The output directory must be new, private and absolute:

```sh
python3 scripts/ci/ssh_systemd_oracle.py --run-native \
  --binary /absolute/private-output/sshpolicy.test \
  --binary-sha256 VERIFIED_BINARY_SHA256 \
  --image sha256:VERIFIED_PREPARED_IMAGE_ID \
  --output /absolute/private-output/new-native-run
```

The runner refuses root execution on the host. It checks the AMD64 binary,
image entry point and exact isolation settings before starting the container.
Binary stability checks bind identity, mode, ownership, size and nanosecond
mutation timestamps; the access-time change caused by reading is permitted.
Only the copied test binary and setup script are mounted read-only. Container
PID 1 receives namespace-local system administration capability for systemd;
setup and test execution drop that capability. The fixture retains namespace-local
process inspection capability for the protected process observer. It uses
private PID, IPC, UTS and cgroup namespaces, no-new-privileges, bounded temporary
filesystems, a 1 GiB memory limit, 256 tasks and two CPU workers.

The Go oracle independently refuses initial-namespace root, missing real systemd
PID 1, a missing exact fixture marker or a non-fixture main configuration.
These checks supplement isolation; the runner accepts only a trusted locally
built test executable and reviewed prepared image.

The runner removes only its generated container, including after an uncertain
create outcome. Cleanup failure is a failed result and identifies that container
for recovery. It never removes an image or touches other containers. Keep command
records and generated identity data private. A skipped test is not a passing
native result. The ordinary Python contract tests require no container access:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  scripts.ci.ssh_systemd_oracle_test
```

Fresh native packages still require standard-list-only defaults. SSH/CIS/OS and
other optional modules require independent explicit TOML choices. Administrator
upgrade state, mandatory Alpine prerequisites and BunkerWeb independence remain
part of the separate, incomplete #422 migration qualification.

## Fixed-path target access exchange

The `access-exchange` scenario extends the forwarding recovery case with a
single explicitly declared direct administrator context. It independently writes
a synthetic private controller enrollment before publication. It exercises the
internal coordinated first migration with the production opener and retained
systemd lease, then calls the actual root-only request, issuance and receipt
adapters after activation. Only label resolution uses the fixture label. Real OpenSSH
authentication produces a signed fixture receipt. Issuance and receipt replay
are refused. Revoking the enrollment blocks a new request, while the subsequent
original restoration must still succeed and retain both access records.

The fixture controller executes in the same disposable container and process,
using generated test credentials. This validates target composition and actual
transport, not independent-host controller trust, operational key provisioning
or full migration acceptance. Its private export accepts the resulting maximum
17-entry recovery history; no controller or SSH private key is exported.
