# v4.10.0 performance evidence procedure

Status: measurement tooling and the generic native adapter implemented,
source-bound allocation producer and validator implemented, native campaigns
pending.

The release gate compares the exact v4.10.0 candidate with the immutable
v4.04.3 baseline commit. The prescribed producer does not synthesize
measurements: it derives them from actual commands, process counters and
captures, and fails when an observation is absent or ambiguous. The gate pins
the reviewed producer and configuration and detects substitutions or binding
drift. A malicious protected-runner operator remains outside this threat model;
without a TEE, repository tooling cannot prove that such an operator executed
the reviewed bytes. Each campaign must use the same host attestation, probe
bytes and number of samples for both sides of every metric. All campaigns must
use the same adapter, probe, environment attestation and baseline and candidate
artifact bytes. Campaign timestamps and baseline and candidate sample
documents must be distinct.

`idle_cpu_percent` and `loaded_cpu_percent` measure SysWarden process CPU
consumption over the reviewed observation window. Both are cost metrics, so a
lower value is better.

## Evidence flow

1. Restore or rebuild one attested native AMD64 host.
2. Record its immutable image, kernel, CPU, memory, service manager, package
   manager, provider firewall and snapshot identity in one JSON file.
3. Install the v4.04.3 baseline package by immutable GitHub asset ID and verify
   its published SHA-256 value.
4. Run `native_performance_probe.py` with a reviewed native adapter and store
   positive numeric samples for every metric that has an approved producer.
5. Restore the same host state, install the package built from the exact
   candidate commit and run the same probe.
6. Build one paired campaign with `performance_evidence.py campaign`.
7. Repeat this process for at least three campaigns. Event metrics need ten
   samples per campaign and at least 30 samples in total on each side.
8. Assemble the campaigns with `performance_evidence.py assemble` and validate
   the resulting document with `performance_gate.py`.

The campaign builder hashes the host attestation and probe itself. It rejects
symbolic links, multiply linked inputs, non-canonical identities, mismatched
units, unequal paired sample counts and an incomplete metric inventory.

## Native probe and adapter protocol

The repository probe is an evidence collector, not a benchmark simulator. It
executes one separately reviewed adapter directly with exec semantics. It does
not invoke a shell and does not interpolate adapter output into a command. The
adapter must be an owner-controlled, owner-executable regular file with one
link and no group or world write bits. Its expected SHA-256 is supplied on the
command line and verified before execution. Record that digest in the immutable
environment attestation used by the paired campaign.

For each iteration the probe invokes exactly:

```text
ADAPTER --candidate-commit CANDIDATE_SHA --campaign-id CAMPAIGN_ID \
  --recorded-at RECORDED_AT --subject-role ROLE \
  --subject-release RELEASE --iteration N --metrics CANONICAL_CSV
```

The adapter must emit one bounded JSON object and no additional standard
output. The exact keys are `schema_version`, `candidate_commit`, `campaign_id`,
`recorded_at`, `subject_role`, `subject_release`, `iteration` and `metrics`.
The first value is integer 2. Every binding must echo the request. `metrics`
must contain exactly the requested finite observations and no other key. CPU
and disk-I/O observations may be zero; every other metric must be positive.
The canonical CSV is sorted, contains no duplicate and changes by quota:
metrics requiring 30 aggregate samples are requested for all ten iterations;
`install_milliseconds` is requested only for iteration 1.

- `idle_cpu_percent`: SysWarden process CPU over the fixed idle window.
- `loaded_cpu_percent`: SysWarden process CPU over the fixed loaded window.
- `rss_bytes`: resident bytes at the defined sampling point.
- `startup_milliseconds`: service start request to ready-state transition.
- `install_milliseconds`: verified package-manager transaction duration.
- `event_to_rule_milliseconds`: source event timestamp to matched-rule timestamp.
- `waap_events_per_second`: admitted WAAP events divided by elapsed test time.
- `nft_transaction_milliseconds`: request to committed live nftables state.
- `disk_io_bytes_per_event`: process read and write byte delta divided by admitted events.

The repository adapter is `native_performance_adapter.py`. It performs the
measurement but deliberately does not guess distribution-specific package,
service, workload or nftables commands. One private, reviewed configuration
supplies the exact commands for the isolated host. Every command is an argument
vector, not a shell string, and binds an absolute executable path to its
SHA-256. The adapter opens and hashes that executable before each execution and
invokes the open descriptor. Interpolation is limited to documented values and
is never evaluated by a shell.

The configured commands must use real package-manager, service, event, HTTP
and nftables operations on the isolated host. The adapter aborts an iteration
if an event is rejected, a counter is ambiguous, cleanup fails or the installed
binary and package identity cannot be attested. The reviewed adapter,
configuration and workload inputs are retained with the private evidence. The
repository probe measures `binary_bytes` and `package_bytes` independently
from safe regular files after installation.

The probe requires exactly ten iterations per subject and campaign, bounds the
per-iteration timeout, rejects duplicate JSON keys, non-finite or invalidly negative values,
unknown or missing metrics, response identity mismatches and unsafe inputs. It
creates a new owner-only sample file and never overwrites an existing path.
Standard output and error are drained concurrently into fixed-size buffers.
Each adapter runs in a new process group; output overflow, timeout or a
persistent descendant terminates the complete group and rejects the iteration.
The quota is `ceil(minimum_samples / minimum_campaigns)`: ten samples for
metrics with a minimum of 30, and one sample for installation and artifact
sizes. Across three paired campaigns this means 60 runtime adapter invocations
and six real installations, while preserving all aggregate minima.

## Native adapter configuration

Install a reviewed copy of `native_performance_adapter.py` as an owner-only
mode `0700` file. Create one owner-only mode `0600` JSON configuration for the
complete paired campaign. Its SHA-256 is supplied separately to the probe,
verified through an inherited open descriptor, written into both sample
documents and propagated through the campaign and final gate. Baseline and
candidate runs, and all three campaigns, must use identical adapter and
configuration bytes.

The configuration has this exact top-level shape. The paths and hashes below
are placeholders, not runnable defaults:

```json
{
  "schema_version": 1,
  "candidate_commit": "FULL_CANDIDATE_SHA",
  "subjects": {
    "baseline": {
      "release": "v4.04.3",
      "artifact_commit": "381c1f8d91459a9b20605629c725900abd81dee8",
      "package_path": "/secure/packages/syswarden-v4.04.3.deb",
      "package_sha256": "BASELINE_PACKAGE_SHA256",
      "binary_path": "/opt/syswarden/bin/syswarden-core",
      "binary_sha256": "BASELINE_BINARY_SHA256",
      "identity_stdout": "EXPECTED_PACKAGE_MANAGER_OUTPUT\n"
    },
    "candidate": {
      "release": "v4.10.0",
      "artifact_commit": "FULL_CANDIDATE_SHA",
      "package_path": "/secure/packages/syswarden-v4.10.0.deb",
      "package_sha256": "CANDIDATE_PACKAGE_SHA256",
      "binary_path": "/opt/syswarden/bin/syswarden-core",
      "binary_sha256": "CANDIDATE_BINARY_SHA256",
      "identity_stdout": "EXPECTED_PACKAGE_MANAGER_OUTPUT\n"
    }
  },
  "captures": {
    "source_jsonl": "/secure/captures/source.jsonl",
    "rule_jsonl": "/secure/captures/rule.jsonl",
    "waap_jsonl": "/secure/captures/waap.jsonl"
  },
  "commands": {
    "install": {"path": "/usr/bin/dpkg", "sha256": "EXECUTABLE_SHA256", "arguments": ["--install", "{package}"]},
    "identity": {"path": "/usr/bin/dpkg-query", "sha256": "EXECUTABLE_SHA256", "arguments": ["--show", "syswarden"]},
    "stop": {"path": "/usr/bin/systemctl", "sha256": "EXECUTABLE_SHA256", "arguments": ["stop", "syswarden-core.service"]},
    "start": {"path": "/usr/bin/systemctl", "sha256": "EXECUTABLE_SHA256", "arguments": ["start", "syswarden-core.service"]},
    "ready": {"path": "/secure/workloads/syswarden-ready", "sha256": "EXECUTABLE_SHA256", "arguments": []},
    "pid": {"path": "/usr/bin/systemctl", "sha256": "EXECUTABLE_SHA256", "arguments": ["show", "--property=MainPID", "--value", "syswarden-core.service"]},
    "idle_prepare": {"path": "/secure/workloads/prepare-idle", "sha256": "EXECUTABLE_SHA256", "arguments": []},
    "loaded_workload": {"path": "/secure/workloads/waap-load", "sha256": "EXECUTABLE_SHA256", "arguments": ["--token", "{token}", "--events", "{events}"]},
    "loaded_cleanup": {"path": "/secure/workloads/waap-cleanup", "sha256": "EXECUTABLE_SHA256", "arguments": ["--token", "{token}"]},
    "event_emit": {"path": "/secure/workloads/emit-event", "sha256": "EXECUTABLE_SHA256", "arguments": ["--token", "{token}"]},
    "event_cleanup": {"path": "/secure/workloads/event-cleanup", "sha256": "EXECUTABLE_SHA256", "arguments": ["--token", "{token}"]},
    "nft_apply": {"path": "/secure/workloads/nft-apply", "sha256": "EXECUTABLE_SHA256", "arguments": ["--token", "{token}"]},
    "nft_verify": {"path": "/secure/workloads/nft-verify", "sha256": "EXECUTABLE_SHA256", "arguments": ["--token", "{token}"]},
    "nft_cleanup": {"path": "/secure/workloads/nft-cleanup", "sha256": "EXECUTABLE_SHA256", "arguments": ["--token", "{token}"]}
  },
  "limits": {
    "command_timeout_seconds": 60,
    "ready_timeout_milliseconds": 30000,
    "event_timeout_milliseconds": 30000,
    "nft_timeout_milliseconds": 30000,
    "poll_interval_milliseconds": 20,
    "idle_window_milliseconds": 30000,
    "waap_events": 1000
  }
}
```

Allowed argument placeholders are `{package}`, `{binary}`,
`{artifact_commit}`, `{candidate_commit}`, `{campaign_id}`, `{recorded_at}`,
`{subject_role}`, `{subject_release}`, `{iteration}`, `{token}` and `{events}`.
All paths are absolute and canonical. Packages, installed binaries,
executables and captures must be safe regular files; symbolic links,
multiple links and group- or world-writable files are rejected. Executables and
artifacts must be owned by root or the adapter UID. The adapter itself always
uses `shell=False` and passes an argv directly to the reviewed executable. This
does not prove that a configured helper is internally shell-free; helper bytes,
interpreter use and argument handling are part of the mandatory configuration
review, and every interpolated value must be treated as data.

The configuration is sealed into the release-evidence artifact and is currently
retained for three days. It and every literal argv value must contain no
password, token, private key or other credential; command lines are also visible
to other processes in the host security domain. Any credential needed by a real
operation must remain outside the evidence bundle and command line, in a
preprovisioned owner-only facility that the reviewed helper accesses without
printing it. The adapter supplies only its fixed sanitized environment.

`ready` returns zero only after the service is genuinely ready. `pid` queries
the service manager for the service's actual main PID and emits only its
canonical decimal value plus a newline; the adapter does not assume that
SysWarden creates a PID file. `identity`
queries the installed package database and its stdout must match the
subject-specific value byte for byte. `loaded_workload` submits exactly
`waap_events` real inputs. Cleanup commands remove only their iteration's
token-scoped state, verify its absence and return nonzero if anything remains.
The nft verification command returns zero only after the token-specific rule is
present in the live ruleset. The configuration is incomplete until these
commands have been reviewed against the selected immutable host image.

The three capture files are dedicated owner-controlled JSONL files. Each newly
admitted record has exactly this shape:

```json
{"token":"campaign-1.candidate.1","timestamp_ns":1789027200000000000}
```

The source and matched-rule writers use the same host clock and append the
timestamps observed at actual source admission and committed-rule transition.
The adapter requires exactly one source and one later rule record for the
iteration token. The WAAP capture must contain exactly the configured number of
newly admitted token records. Missing, duplicated, partial, replaced,
oversized or malformed captures fail the iteration; the adapter never
substitutes a duration or count. After the adapter reads a complete capture,
the cleanup command must archive it if retention is required and truncate the
dedicated active file in place. The adapter requires the same inode and an
empty file before continuing, which prevents ten iterations from accumulating
unbounded active captures.

Metrics are computed only from direct observations:

- CPU is the bound process's `/proc/PID/stat` CPU-tick delta divided by
  monotonic elapsed time.
- RSS is the resident-page count from `/proc/PID/stat` after the idle window.
- Disk I/O per event is the `/proc/PID/io` `read_bytes + write_bytes` delta
  divided by the exact admitted-event count.
- Startup, installation, loaded throughput and nftables transaction time use
  `CLOCK_MONOTONIC` around the actual commands and required verification. The
  loaded interval ends only after the exact admitted-event capture count is
  observed, and before cleanup starts.
- Event-to-rule latency is the positive difference between the two required
  capture timestamps.

The PID start time and executable SHA-256 must remain unchanged throughout an
iteration. A real zero CPU or disk-I/O delta is retained as zero; it is never
converted into a small positive number. Negative deltas, zero durations, zero
RSS and zero admitted-event throughput fail.
Configuration is limited to 128 KiB, each stdout and stderr stream to 64 KiB,
each active capture to 8 MiB, each newly read delta to 4 MiB, each JSONL record
to 512 bytes, command timeouts to 300 seconds and a loaded workload to 10,000
admitted events. Commands inherit the adapter process
group created by the probe and receive a sanitized environment; they may not
create a detached helper. Thus an outer timeout or cancellation kills the
adapter and its active command together. An internal command timeout kills the
direct command, makes the adapter fail, and lets the probe reject and terminate
any remaining member of the same group. The protected runner must additionally
place the complete probe in its recorded CPU, memory, PID and wall-time cgroup;
absence of that external containment is a native-lab stop condition.

Example candidate collection:

```sh
python3 scripts/ci/native_performance_probe.py \
  --candidate-commit CANDIDATE_SHA \
  --campaign-id campaign-1 \
  --recorded-at 2026-09-10T08:00:00Z \
  --subject-role candidate \
  --adapter /secure/evidence/reviewed-native-adapter \
  --adapter-sha256 ADAPTER_SHA256 \
  --adapter-config /secure/evidence/ADAPTER_CONFIG.json \
  --adapter-config-sha256 ADAPTER_CONFIG_SHA256 \
  --binary /opt/syswarden/bin/syswarden-core \
  --package /secure/packages/syswarden-candidate.pkg \
  --runs 10 \
  --timeout-seconds 300 \
  --output /secure/evidence/campaign-1-candidate.json
```

Run the same probe and exact adapter bytes against the restored baseline with
`--subject-role baseline`. The sample documents bind the expected release,
candidate SHA, adapter, adapter configuration, binary and package digests. The
campaign assembler rejects swapped roles or different adapter or configuration
bytes, verifies equal paired sample counts and binds the hash of
`native_performance_probe.py`. The final gate requires
`performance/ADAPTER_CONFIG.json`, checks that its digest matches every
campaign, checks its baseline and candidate commit bindings, and requires the
probe and adapter digests to match the checked-in repository files. The
gate also requires the passing native lifecycle verdict: its verified
DEB-U2604 baseline and candidate package digests must match the configuration
and campaign evidence. The current binary chain is the lifecycle-bound package
digest, a reviewed and hash-bound installation command, the fixed packaged
path `/opt/syswarden/bin/syswarden-core`, and the observed runtime binary hash.
The final evidence review must inspect the private configuration and its helper
hashes. The environment attestation binds the immutable host identity. No local
run is release proof until the native campaign documents and final gate pass.

## Sample file shape

Both the baseline and candidate sample files must contain the exact metric
inventory from `performance_contract_v4.10.0.json`:

```json
{
  "schema_version": 2,
  "schema_id": "syswarden-native-performance-samples/v2",
  "campaign_id": "campaign-1",
  "recorded_at": "2026-09-10T08:00:00Z",
  "subject_role": "candidate",
  "subject_release": "v4.10.0",
  "metrics": {
    "rss_bytes": {
      "unit": "bytes",
      "samples": [12345678, 12346000, 12347000]
    }
  }
}
```

The abbreviated example omits the release, candidate and digest bindings and
shows one metric only. A real input must contain every required top-level field
and every contract metric.

## Campaign command

```sh
python3 scripts/ci/performance_evidence.py campaign \
  --candidate-commit CANDIDATE_SHA \
  --id campaign-1 \
  --recorded-at 2026-09-10T08:00:00Z \
  --environment-id node02-ubuntu-26.04 \
  --environment-attestation /secure/evidence/node02-environment.json \
  --probe scripts/ci/native_performance_probe.py \
  --baseline-samples /secure/evidence/campaign-1-baseline.json \
  --candidate-samples /secure/evidence/campaign-1-candidate.json \
  --output /secure/evidence/campaign-1.json
```

The output path must be absolute, canonical and absent. The tool creates a new
owner-only file and never overwrites existing evidence.

## Assembly command

```sh
python3 scripts/ci/performance_evidence.py assemble \
  --candidate-commit CANDIDATE_SHA \
  --campaign /secure/evidence/campaign-1.json \
  --campaign /secure/evidence/campaign-2.json \
  --campaign /secure/evidence/campaign-3.json \
  --output /secure/evidence/performance-evidence.json \
  --report /secure/evidence/performance-report.json
```

A stable regression is a regression above 10 percent in the aggregate and in
at least half of the campaigns. Functional or security failures cannot be
waived. A performance-only waiver must be candidate-bound, current, justified
and linked to retained evidence.

## Independent source-bound allocation channel

The black-box native adapter does not report Go allocation counts from the
stripped production binary. It must not estimate them from RSS, `/proc`,
cgroups, `perf`, eBPF or `LD_PRELOAD`. The separate source-bound channel runs
the exact `engine.Engine.Scan` workload against both the immutable v4.04.3 tree
and the candidate tree. It records raw `Mallocs`, `TotalAlloc` and admitted
event counters with the pinned Go toolchain, fixture, catalog and build
bindings defined in `source_allocation_contract_v4.10.0.json`.

`source_allocation_gate.py` recomputes the exact rational allocations and
allocated bytes per admitted event from 60 fresh-process samples. It handles a
zero baseline without division by zero and allows no allocation waiver.
`performance_channel_aggregate.py` then recomputes both reports and passes only
when the installed-package native channel and the source-bound allocation
channel independently pass. The source-bound result is not a measurement of
the installed package process. The launcher-generated execution-control
attestation distinguishes the read-only repository source from
producer-writable temporary build checkouts. It records producer egress
denial, evidence-root-only persistent producer writes, probe egress denial and
a read-only probe-visible persistent filesystem. The producer validates and
retains these assertions but does not infer the controls from application
behavior.

Qualifying raw production must use `source_allocation_sandbox.sh`, not invoke
the Python producer directly. The launcher accepts only canonical
`/usr/bin/bwrap`, with root-owned non-writable parents and executable, and
binds its SHA-256 before and after production. It does not copy the executable,
so path-based AppArmor policy continues to identify `/usr/bin/bwrap`. The
launcher runs only under privileged-mode `/usr/bin/bash` and uses the real
target of `/usr/bin/python3` in isolated mode. It binds both interpreter
digests and identities before and after production. Its outer filesystem starts
empty and allowlists only the root-owned runtime directories, `os-release`,
the exact read-only inputs, and the new read-write evidence root. Host `/run`,
`/tmp`, and `/var/tmp` are not exposed. Repository and module-cache trees are
scanned before Git is invoked and fail on a special file, symlink, nested
filesystem, unsafe owner, or unsafe mode. An outer Unix-socket canary must be
unreachable before the attestation can claim egress denial. Temporary detached
build checkouts live inside the evidence workspace and remain writable by the
trusted producer; this is not represented as a read-only checkout guarantee.
Every candidate and baseline probe runs inside a second minimal bubblewrap
filesystem and separately unshared network. The producer runs a nested
Unix-socket canary before any measured probe. Nested sandboxes expose no
`/proc`: the outer procfs has protected submounts that prevent mounting another
procfs in a nested user namespace. The probe still has a separate PID namespace
and executes the verified probe bound read-only at a fixed entrypoint. The
probe requires that exact entrypoint, an absent procfs, isolated PID ancestry,
and a kernel-confirmed read-only mount before checking its own file metadata
and SHA-256. The producer retains and checks its original open descriptor
before and after execution. The canary checks the absent procfs and PID ancestry as
well as the hidden outer socket. The launcher fails if either
namespace or canary cannot be established, or if post-execution raw-bundle
validation fails.

```sh
scripts/ci/source_allocation_sandbox.sh \
  --repository /absolute/path/to/syswarden \
  --candidate-commit FULL_MERGED_MAIN_SHA \
  --toolchain-archive /secure/go1.26.6.linux-amd64.tar.gz \
  --module-cache /secure/read-only-go-module-cache \
  --output-root /secure/evidence/source-allocation
```

The Go archive must be owner-controlled mode `0600` and match the SHA-256 in
the allocation contract. The producer extracts a complete private toolchain
from the already verified archive bytes and uses only that extracted GOROOT.
It does not reopen or execute a separately supplied Go pathname. The module
cache is mounted read-only and all Go resolution runs with `GOPROXY=off`,
`GOSUMDB=off`, `GOWORK=off`, `GOFLAGS=-mod=readonly`, and
`GOTOOLCHAIN=local`. A local implementation test does not replace the required
native execution-control proof retained with the final qualification bundle.
The protected dedicated runner, its root account, kernel, service definition,
and sanitized job environment are trust anchors. The model excludes a hostile
caller environment and a hostile concurrent process running as the
qualification UID. Per-command timeouts and stdout/stderr capture bounds are
enforced by the producer. CPU, RSS, process-count, and filesystem-quota
containment remain external protected-runner availability controls; they must
be configured and recorded before qualification, and their absence is a stop
condition rather than an application-proven assertion. The current development
host exposes `/usr/bin/bwrap` as owned by `nobody` and also denies the required
NETLINK_ROUTE operation. Outer and nested namespace execution therefore
remains a native-lab requirement and is not claimed by the local test suite.
