# Isolated production SSH systemd oracle

Status: opt-in Linux AMD64 development validation for #235, #337 and #422.
This is component evidence for v5.00.0 IVVQ, not migration acceptance.

## Purpose and limits

The test uses the production systemd activation binder, protected process
descriptors, pidfd signal dispatch and listener-generation observer. A disposable
Debian 13 container runs real systemd, D-Bus and OpenSSH. It generates its own
host and client keys, authenticates fresh connections with the host key pinned,
and probes TCP forwarding through loopback. No host SSH keys, services,
configuration or sockets are mounted.

The ordered checks require:

1. Fresh authentication and forwarding with the original fixture policy.
2. Continued forwarding after writing the dedicated drop-in without reloading.
3. Refusal of a no-op signal dispatch because no listener replacement occurs.
4. A real production reload, observed listener replacement and refusal of replay.
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
