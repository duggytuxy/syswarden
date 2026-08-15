# SysWarden Lot 1 Public Security Delivery Report

| Field | Value |
|---|---|
| Report status | Final technical evidence |
| Lot 1 source status | VALIDATED |
| Product release decision | NO-GO |
| Source candidate | v4.02.9 |
| Current official release | Historical v4.02.8, unchanged |
| Report date | 15 August 2026 |
| Distribution | Public |

## 1. Executive outcome

Lot 1 is technically validated as a source candidate for v4.02.9. It closes
the planned configuration, firewall, HA, BunkerWeb-side integration and signed
updater work without changing the historical v4.02.8 release or creating a new
tag or release.

The product release decision remains **NO-GO**. Source validation does not
replace the remaining package, FreeBSD, ARM64 and protected release
qualification work. This report therefore supports source review and a future
pull request; it does not authorize publication.

> Decision: Lot 1 may proceed to source review. No tag, release asset or public
> v4.02.9 release is authorized by this report.

## 2. Delivered controls

| Domain | Delivered result | Security boundary |
|---|---|---|
| Configuration | Atomic and retry-safe migration, strict validation, safe v4.02.8 first-hop compatibility, protected user overrides and fail-closed mutating commands | Invalid or concurrent configuration state cannot silently become active |
| Firewall | Transactional nftables reloads, shared locking, preserved dynamic bans and TTLs, verified PF state, idempotent fallback handling and corrected honeyport serialization | No success is reported before the effective kernel state is verified |
| HA | TLS 1.3 certificate verification, mandatory bearer authentication, bounded requests, strict CA bundles, durable ledgers and atomic blocklist updates | Peer IP or CIDR scope is defense in depth, not a replacement for the token |
| BunkerWeb integration | Opt-in TTL, source, reason and CIDR peer support, bounded batches and authenticated status access | Partner extensions require `integrations.bunkerweb.enabled = true`; durable node HA does not |
| Signed updates | Canonical manifest, detached Ed25519 signature, strict platform binding, secure staging and a second size and SHA-256 check immediately before installation | v4.02.9 and later refuse unsigned or mismatched update assets |
| Documentation and qualification | English operator guidance, public architecture diagram, machine-readable partner ownership matrix and positive firewall lab adapters | External partner scenarios are never reported as SysWarden PASS |

## 3. HA and BunkerWeb contract

Durable SysWarden node-to-node synchronization remains active whether the
BunkerWeb integration gate is `false` or `true`. Exact peers exchange operator
IP and CIDR entries and exact IPs persisted after local Layer 7 or WAAP
detections. The proof exercises both A-to-B and B-to-A add and delete paths.

When the BunkerWeb gate is enabled, the same durable exchange continues. The
partner scheduler sends each source-owned temporary ban directly to every
configured SysWarden peer. SysWarden does not relay temporary partner records
transitively. This preserves the original TTL and source and prevents
synchronization loops.

The following controls apply to all HA routes that expose or mutate host state:

- TLS 1.3 with normal X.509 hostname or IP verification;
- a strict explicit CA bundle or the system trust store, with malformed bundles
  rejected in full;
- mandatory constant-time bearer authentication;
- exact IP or canonical CIDR inbound peer authorization;
- bounded request bodies, batches, retries, timeouts and ledger sizes;
- atomic, locked and crash-durable state publication;
- duplicate JSON keys, invalid addresses and unknown fields rejected before
  mutation.

## 4. Firewall outcome

The `docker_protect` chain on the forward hook protects traffic addressed to
containerized services, not only traffic terminating on the host input path.
This is the relevant data-plane boundary for the BunkerWeb partnership.

The final nftables kernel laboratory passed all seven conditions. It preserved
the four stateful dynamic sets and their remaining TTLs, kept ports 23 and 6379
distinct, rejected the historical concatenated value 236379 before mutation,
used an isolated network namespace and left no ruleset residue after cleanup.

## 5. Verification evidence

| Control | Final evidence | Result |
|---|---|---|
| Python CI contracts | 310 tests | PASS |
| Go tests | 16 packages, 697 test events; normal and race matrices | PASS |
| Data-race detector | Full CLI, Core, TUI and versionctl matrix | PASS, 0 race |
| Go vet | Linux and FreeBSD, 4 modules each | PASS |
| FreeBSD cross-build | 16 test packages, amd64, CGO disabled | PASS |
| Gosec v2.28.0 | 8 Linux and FreeBSD matrices | PASS, 0 finding |
| Security and SARIF gates | 67 tests | PASS |
| Release and qualification contracts | 68 tests | PASS |
| `#nosec` policy | 332 total, 61 qualified, 271 legacy; baseline exactly 271 | PASS |
| Gitleaks v8.24.3 | Commit candidate and 1,269-commit history | PASS, 0 leak |
| Govulncheck v1.4.0 | CLI, Core, TUI and versionctl | PASS, 0 called or imported vulnerability |
| Workflow lint | 7 workflows with actionlint | PASS |
| Shell and YAML | 5 ShellCheck scripts; 11 YAML files with duplicate-key checks | PASS |
| Documentation truth gate | README, manual and 4 wiki pages; 310 Python tests | PASS |
| Real nftables laboratory | 7 of 7 kernel conditions | PASS |
| Version contract | 7 controlled targets and changelog validation | PASS, v4.02.9 |

Eighteen Go tests are intentionally skipped inside the restricted sandbox when
they require loopback sockets, a privileged nftables kernel or host ownership
semantics. Their HA and BunkerWeb loopback equivalents were executed separately
in the permitted environment and passed, including the two-node gate matrix for
both `false` and `true`.

## 6. Version and repository integrity

- The source candidate reports v4.02.9 across every controlled version target.
- The historical v4.02.8 release remains unchanged and no v4.02.9 tag exists.
- The changelog history from `# Release v4.02.8` onward is byte-identical to the
  repository baseline: 137,085 bytes, SHA-256
  `b6a7f32edb5c0e46ac270ea4c95faee11790bfde9585e5bbb9073f2e339eddf6`.
- `go.work.sum`, the compliance workflow and the existing policy configuration
  remain unchanged.
- The candidate contains no deletion. Local generated output is outside the
  commit scope.

## 7. Open release prerequisites

| Identifier or area | Remaining work | Release effect |
|---|---|---|
| SW-PKG-001 | Correct and requalify Alpine package execution on musl | Blocks release |
| SW-BSD-001 | Correct and requalify FreeBSD package, service and rollback behavior | Blocks release |
| ARM64 qualification | Provide a trustworthy binfmt or native runner and execute the full package lifecycle | Blocks formal qualification |
| Protected release environment | Provision and independently verify protected signing, release approvals and immutable tag policy | Blocks publication |
| Native package and VM evidence | Re-run the final candidate package lifecycle and FreeBSD VM qualification after Lot 2 | Blocks publication |
| Partner-owned scenarios | Execute BunkerWeb plugin UI, audit, cache, fail-open, latency and no-reload scenarios in the partner repository | Required for joint integration claims, not represented as SysWarden PASS |

The future Web-TUI configuration remains deliberately separate from the
BunkerWeb gate. Its dedicated contract must use `[webtui] enabled = false` by
default, port 62027, and conditional firewall exposure. It is not claimed as a
Lot 1 delivery.

## 8. Public decision

Lot 1 is complete as a validated source milestone. A Patch commit and pull
request may be reviewed. Product publication remains fail-closed until every
item in Section 7 has positive evidence and the protected release workflow
approves the exact candidate.
