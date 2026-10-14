# Unprivileged local attack assurance

Status: incremental v5 implementation and acceptance plan, tracked in
[WP19](https://github.com/duggytuxy/syswarden/issues/337). A passed component
check is evidence for its declared boundary, not a guarantee that no vulnerability
exists. Preserve the distinction between security testing, independent review and
a professional penetration test. Do not describe automated checks as an external
pentest or as complete native acceptance.

## Threat model

The principal attacker is an ordinary local Linux account, distinct from every
SysWarden service identity, without sudo, capabilities, privileged supplementary
groups, inherited trusted descriptors or administrator-approved credentials. It
can run programs, create its own files, submit untrusted observations where
permitted and contact reachable interfaces. Add explicit cases for an unrelated
service account and an unintended group member when those boundaries exist.

An internal network, a local process, a claimed username or a path bearing the
product name does not confer authority. Separate observation from verified
provenance and authoritative decisions. A hash beside an attacker-controlled file
is not independent authentication. Keep root compromise, service-UID compromise,
kernel vulnerabilities, physical access and malicious administrators outside this
ordinary-user claim, with separate documented threat and recovery treatment.

## First mandatory component gate

`TestLocalUnprivilegedBoundary` runs against the real v5 journal storage and
`LocalAuthority` dispatcher with synthetic signed fixtures. The parent uses an
identity able to start a child as UID/GID 65534; this creates no system account.
Before probing, the child verifies its distinct identity, empty supplementary
groups, zero effective/permitted/inheritable/ambient capabilities, and
`no_new_privs` on its locked probe thread. Acquiring UID 0 must fail. A writable private canary proves the
child can perform ordinary I/O, rather than accepting a globally broken process
as proof of security.

The 132 mandatory cases cover:

- Protected launch configuration: 19 named cases (one group and 18 subcases)
  exercise valid root-owned input, unsafe descriptor/metadata/ACL/type/size, altered
  bytes, incorrect digests and service identity. These privileged fixture mutations
  test rejection; they do not assert that ordinary users can modify root-owned data.
- Reading, opening for overwrite/append/truncation, unlinking, replacement by
  rename, hard-linking, chmod and chown against policy, custody, anchor, segment
  and checkpoint files: 45 cases.
- File creation, symlink insertion and directory substitution against the four
  protected resource directories: 12 cases.
- Connection to a private test socket: one case.
- All six dispatcher routes with a real ungranted kernel peer, after deliberately
  making only the disposable test socket reachable: six cases. Claimed root and
  administrator labels are ignored; they are not authentication inputs. Policy
  administration has no configured identity provider and must deny.
- Mutation attempts against the actual listener endpoint: eight cases covering
  unlink, rename, hardlink, chmod, chown, entry creation, symlink insertion and
  directory substitution. The child belongs to the endpoint group but cannot write
  its directory or become its owner.
- Reads, overwrite/append/truncate opens, unlink, rename, hardlink, chmod and
  chown against the private endpoint ownership receipt: nine cases. Endpoint
  group membership cannot read or alter the service-owned `0600` receipt.
- Actual client/listener denial of all six framed operations for that ungranted group
  member, plus one connection refusal with a different primary group and no
  supplementary groups: seven cases. The socket remains `0660`, directory `0750`;
  no test-only public permission is needed for this listener.
- Wrong-UID listener rejected before any request bytes: one case. The privileged
  fixture parent deliberately deposits the child's listening socket into a protected
  directory with the expected metadata. Only kernel identity distinguishes it;
  the fixture does not assert that an ordinary user can change root-owned files.
- Per-UID concurrency isolation: one case. An ungranted account holds an
  incomplete connection; a second process with the same UID is refused before
  sending a request. A different authorized UID resumes while the first peer
  remains registered, then the first peer disconnects and releases its slot.
  This verifies the two-worker/one-peer-per-UID configuration, not flood resistance
  or guaranteed fairness. A test-only stop pipe carries one byte and no authority.
- Per-UID admission frequency: one case. After an admitted malformed request,
  the same ordinary UID reconnects without sending input and is refused despite
  available concurrent-peer capacity. A different authorized UID resumes and
  private storage stays unchanged. This proves spent quota survives disconnect;
  it does not establish flood resistance, fairness or durable admission history.
- Authorized client resume, commit and independently reopened resume after the
  attacks: one case.
- A separately executed non-root service, authorized client and ungranted peer,
  including protected storage and restart behavior: 18 cases, detailed below.
  Both private-storage probes also attempt pin read/write, unlink, rename, hardlink,
  symlink insertion and mode changes. All are denied; the pin inventory stays
  unchanged. This expands those cases without adding separate child processes.
- Deliberate process crash after the service reports readiness: one case. The
  exact private endpoint receipt and independent durable pin remain, and a fresh service process refuses
  startup without modifying it or deleting the stale socket. This is preservation
  and refusal evidence, not automatic crash recovery or physical power-loss IVV.
- Reviewed endpoint recovery after that crash: two cases. Another ordinary UID
  cannot inspect or apply recovery. A separately provisioned non-root service
  reads the creator-written pin from protected storage without a parent-supplied
  receipt digest, uses a synthetic review provider, retires the stale pair and pin, starts a new endpoint, serves verified
  resume and stops cleanly. Journal resources stay unchanged. See
  [Endpoint recovery](ENDPOINT_RECOVERY.md) for missing production providers and
  deliberately refused partial states.

The test exposes its harness ancestors so their permissions cannot accidentally
provide the protection attributed to product resource directories. Access probes
must fail with an actual permission error, not a missing file or unrelated error.
Protected bytes, inode identity, modes, owner/group, link counts, modification and
change times, and directory inventories are compared after each mutation attempt.
Access times are excluded because verification itself reads the files.

The existing required **Code Hygiene** job executes this dedicated gate, feeding
its result into **Security Audit**. The report verifier requires every named case
and package completion exactly once. Missing, skipped, duplicate, failed or
truncated evidence fails. Ordinary Go test runs explicitly skip this privileged
harness; that skip is not its mandatory CI result. A missing credential-changing
capability in the dedicated job is an error, never a green skip.

The CI parent runs on a disposable runner. Local verification can use the existing
rootless `podman unshare` namespace instead, with no new image or container cache.
Both modes test kernel identity separation. The actual
[listener](LOCAL_AUTHORITY_SERVER.md) and [client](LOCAL_AUTHORITY_CLIENT.md)
components use the production framing and
permission checks with synthetic authority resources. The earlier deliberately
reachable dispatcher probe remains a harness-only socket. Neither test establishes
deployed package ownership, SELinux/AppArmor policy, feed pipeline, process
isolation, boot behavior or distribution support. Production provisioning and
identity/approval providers remain separate work.

## Non-root service and requester processes

The same mandatory gate adds 18 `process-*` cases against an actual
`LocalAuthorityServer` child and `LocalAuthorityClient` children. It does not mock
peer credentials, file access or wire denials. The privileged fixture parent only
prepares synthetic signed policy/publication files, transfers ownership, starts
children and verifies before/after results. It never handles client operations on
behalf of the service. No system account, unit or host configuration is created.

The child now uses [protected-layout startup](PROVISIONED_AUTHORITY.md) with the
literal five-directory private layout and a separate endpoint. Existing private
storage cases also refuse listing or changing permissions on the state root and
verify its unchanged metadata. That root supplies an additional traversal boundary;
these process cases do not independently prove leaf permissions through an
accessible parent. The earlier direct storage probes still expose their ancestors
to test leaf protection separately. The [launch-record follow-up](AUTHORITY_LAUNCH.md) adds 19 in-process cases for a
132-case gate, with no new child process or timeout change. The service now receives
a root-owned read-only launch descriptor and independently supplied digest; clients
inherit neither it nor protected storage descriptors. Both client identities are
denied access to its private path and its complete inventory remains unchanged.

| Test identity | Provisioned access | Authority |
| --- | --- | --- |
| Service UID/GID 65533 | Private state root and resource directories `0700`, files `0600`; one supplementary endpoint group 65534. | Opens and owns the actual bounded server and existing authority stores. |
| Client UID/GID 65534 | Endpoint directory `0750` and socket `0660`; no supplementary groups or private resource descriptors. | Synthetic signed policy grants only resume and commit. |
| Unrelated UID 65532, GID 65534 | Same endpoint reachability; no supplementary groups or private resource descriptors. | No operation grant. |

The service's private storage group and endpoint access group deliberately differ.
This exercises provisioning where the service can bind and set the endpoint group
without root or active capabilities. The client independently checks the kernel
service UID/GID and endpoint metadata before sending.

Every child verifies real/effective IDs, its exact group list, zero effective,
permitted, inheritable and ambient capabilities, inability to acquire UID 0 and
ordinary read/write access to its own temporary canary. The locked probe/control
thread sets and verifies `no_new_privs`. It is not asserted for all pre-existing Go
runtime threads and does not establish a process sandbox. The
[kernel documentation](https://docs.kernel.org/userspace-api/no_new_privs.html)
describes its exec privilege boundary; it does not independently prevent every
privileged syscall. These checks are harness prerequisites, not product-provided
OS isolation.

Children receive synthetic test configuration through a bounded stdin pipe.
Only the service receives the two explicit readiness/stop pipes. Before opening
resources, children check that no private storage descriptor was inherited. The
paths and roots come from the test parent, not from a network request. This helper
is compiled only into tests; it is not a production configuration loader, service
launcher or identity/approval provider.

The cases require:

- Service startup, clean stop, a fresh service process over the same durable state
  and final clean stop, with exact owned socket removal after each stop.
- Authorized resume, commit and resume after service restart. A duplicate commit
  must be denied with unchanged protected state and an uncertain wire outcome,
  rather than automatically retried or described as a safe no-op.
- Read and append opens of all five protected files denied with `EACCES` to both
  the authorized client and unrelated account. API permission does not give direct
  custody, policy, anchor, segment or checkpoint access.
- All six operations denied to the reachable ungranted account. The authorized
  operational client also cannot inspect or apply policy administration when no
  independent administrator provider exists.
- A signal-zero permission probe from the client to the live service denied with
  `EPERM`, followed by successful authorized service work. As documented by
  [kill(2)](https://man7.org/linux/man-pages/man2/kill.2.html), signal zero checks
  permission without delivering a signal. This does not cover ptrace, every signal
  or the special same-session `SIGCONT` rule; those remain separate probes.

Private bytes, inode identity, mode, owner/group, link count, modification/change
times and directory inventories must remain identical across refused operations,
clean stops and restart reads. The approved commit must actually change protected
state; the subsequent independent process must return that exact new anchor.
Subprocess failures, absent assertion markers, startup/exit timeouts or missing
named results fail the dedicated gate. Cleanup is scoped to the test processes
and temporary fixtures. Race execution supplements the normal gate; existing CI
resource and timeout limits remain in place.

This establishes component behavior across non-root process identities and clean
restart. It does not establish systemd/OpenRC provisioning, SELinux/AppArmor
confinement, a complete capability-bounding policy, ptrace protection, authenticated
human administration, abrupt-crash or power-loss recovery, native package removal,
reboot acceptance or resistance to a compromised service UID. These remain explicit
work items. BunkerWeb and installed v4 services are unchanged.

## Remaining mandatory coverage

| Surface | Adversarial probes | Required evidence |
| --- | --- | --- |
| Installed code and services | Replace binaries, modules, helpers, units/drop-ins, scheduled jobs; PATH/environment or writable-parent substitution; unauthorized lifecycle commands. | Original content, metadata and effective service command preserved; legitimate health and lifecycle operations still work. |
| Configuration and ownership | Edit options, manifests, removal barriers and trust roots; symlink/hardlink/rename races; altered ACLs, group access or inherited descriptors. | Rejection before privileged mutation; independently trusted ownership retained; explicit diagnosis of unsafe provisioning. |
| Feed lists and update cache | Replace downloaded bytes, lists, signatures, sidecars, provenance, temporary files and cached results; replay stale valid data; exploit writable staging. | Only independently verified current data is promoted atomically; prior valid protection survives rejection; updater remains usable. |
| Results and evidence | Forge alerts, journal frames, checkpoints, counters, KPI inputs, health status and exports; spoof source or identity; terminal/control and CSV formula injection. | Untrusted observations never become verified origin, successful action or authoritative verdict; output remains inert and uncertainty visible. |
| Local and remote interfaces | Connect as wrong UID/group, reuse credentials or descriptors, inject ancillary data, attempt privilege escalation and cross-scope access. | Explicit authorization for each operation, independent approval for mutations, no confidential response on denial. |
| Availability | Bounded socket floods, slow peers, input/file growth, signal/ptrace attempts, lock contention and queue exhaustion. | Frozen CPU/RAM/disk/FD/time budgets, visible loss/refusal, no unlimited retries; authorized recovery and access remain possible. |
| Lifecycle and integrations | Repeat relevant attacks after installation, supported migration, restart, reload and reboot; test uninstall/remove/purge independently. | Active product ownership and unrelated administrator protection remain correct. BunkerWeb source-owned bans, TTL, retries and HA behavior remain independent of the dashboard and journal. |

Implement probes against the actual delivered path, not just a mock returning
permission denied. Include a positive control and an authorized recovery/health
check, retain failures, and bind results to the exact source and signed packages.
A failed prerequisite, timed-out child, unsupported probe or absent result is
incomplete evidence. It cannot count as a passing security assertion. Do not
relax SELinux, AppArmor, firewall ownership or host namespace restrictions to make
a product assertion pass.

## Native review matrix

These are the inherited v5 review targets from the
[scope contract](SCOPE_AND_AUTHORITY.md), not a newly declared support matrix.
Their unprivileged installed-product evidence remains pending.

| Target | Init/package boundary | Unprivileged native campaign |
| --- | --- | --- |
| Debian 13 | systemd / DEB | Pending |
| Ubuntu 24.04 and 26.04 | systemd / DEB, AppArmor profile recorded | Pending for each version |
| Fedora 44 | systemd / RPM, SELinux enforcing | Pending |
| AlmaLinux 9 and 10 | systemd / RPM, SELinux enforcing | Pending for each version |
| Alpine 3.22 and 3.24 | OpenRC / APK | Pending for each version |

Freeze the supported matrix through WP01 and bind its mandatory cases into the
v5 release verifier through WP14 before acceptance. This follow-up is not yet
implemented in the v5 publisher. A container using the host kernel is component
or userspace evidence, not a native reboot test. Existing v4 native evidence keeps
its original scope. Do not silently drop a target, accept an unrun profile, or
label a cross-UID test as coverage of every distribution.

Use existing hardware and simulated accounts/workloads. No paid test service,
additional infrastructure or new machine purchase is required by this plan.
If existing capacity prevents a required campaign, record the gap for review.
Never convert a resource limitation into a passed result.

## Reporting and completion

For every case record the attack identity and capabilities, protection under test,
expected refusal, observed status, before/after integrity, authorized postcondition,
candidate and environment, resources, timestamps and limitations. Keep operational
logs, identifying metadata and genuine secrets private. Public fixtures and CI
reports contain synthetic data only. Use the private vulnerability-reporting path
for a newly discovered exploitable issue; do not publish exploit details in an
ordinary tracking comment before coordinated handling.

This work complements the [validation plan](VALIDATION_PLAN.md), the file-integrity
work packages and the [BunkerWeb compatibility contract](BUNKERWEB_COMPATIBILITY.md).
Keep implementation, CI success, native acceptance and residual risk explicit.
An open coverage item stays open until the matching behavior and evidence exist.

The [process entry point](AUTHORITY_PROCESS.md) shares its startup/readiness/drain
runner with the existing non-root service fixture. The gate stays at 132 cases
with no additional child processes or timeout change. Standalone executable
installation and native service-manager signal handling remain outside this proof.

The [standalone executable assurance](AUTHORITY_EXECUTABLE_ASSURANCE.md) adds a
separate mandatory 53-case campaign against the actual built authority binary,
with exact-byte binding, kernel identity observations, separate client operations,
direct signal shutdown, crash preservation and stale restart refusal. The existing
132-case gate remains unchanged. This is component evidence, not installed-service
isolation or native acceptance. Stable remains v4.10.4 and BunkerWeb is independent.

The standalone command now rejects retained real/effective/saved privileges,
unexpected groups or capabilities and missing inherited no_new_privs before
private startup. It disables dumps, seals the four startup descriptors and sets
a restrictive umask. See the [startup contract](AUTHORITY_PROCESS.md). Four added
real-binary negative cases require unchanged private stores and no readiness.
A production launcher, complete OS confinement and native acceptance remain open.

The [sealed executable image](AUTHORITY_EXECUTABLE_IMAGE.md) now binds future launch
to an immutable copy of the approved bytes. The real-binary campaign executes that
image after replacing the source pathname. Native launch policy remains open.

The [non-root exec bootstrap](AUTHORITY_EXEC_BOOTSTRAP.md) now performs the actual
sealed-image transition, fixes the target environment and cwd, and isolates the
complete descriptor table before passing only the four startup handles. The
53-case executable campaign checks both real programs and post-exec inheritance.
Privileged provisioning, loader/MAC policy, supervision and native acceptance
remain separate work. No native package is activated.
