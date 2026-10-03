# v4.10.3 historical WireGuard native rehearsal

Status: unsigned candidate rehearsal on hardened Debian 13. Protected native
signing and version-specific Patch IVV remain required before publication.
These observations do not establish recovery on a reporter's production host.

The tested implementation is commit
`8ac3376302949e2788f952444965f60d3eba92bc`, with candidate DEB SHA-256
`0533f6c65164f7a879acb5e86f87a651f675c6dce30df65d4c12a61255c44f6f`.
This digest identifies a private test input, not a public release download.
Raw logs, configuration identities, plans, keys and host details remain private.

## Genuine historical entry points

The official v4.02.8 package was installed through dpkg. Its installed CLI
matched SHA-256
`9348f68fb1fb3b73ec28f56f488853238e5eb60e8041f3524f3c6e65e152098a`.
The actual installed historical generator created the server, client and
forwarding files without an ownership manifest. A separate synthetic `wg0`
configuration used the exact supported older hook template. Its service was
failed and enabled while the generated `wg-syswarden` service was active and
enabled.

The unmodified installed v4.02.8 updater performed both first-hop attempts.
A process-local HTTPS fixture supplied only release discovery and the exact
checksum-verified target package. It used a private test CA and loopback proxy;
the system trust store and installed updater were unchanged. Other traffic
retained upstream certificate validation. No public v4.10.3 release was used.

## Observed results

| Case | Native observation |
| --- | --- |
| Direct old updater to v4.10.3 | Pre-install refusal occurred before payload replacement. Old dpkg version, executable digest, VPN file bytes and inodes, VPN service state and inspected nftables objects remained unchanged. |
| Active dual-generation recovery | The candidate recognized all three generated artifacts and reported five service/interface blockers without changing state. |
| Explicit retirement | After stopping the authorized test VPNs, the exact reviewed plan archived `wg0`, cleaned proven legacy rules and preserved all three generated files and their inodes. |
| Preserving migration | Separate reviewed migration retained VPN keys, addresses, port and exact client bytes, wrote private backups and published verified ownership. |
| Interrupted write and resume | A controlled backup-publication failure left a durable journal. Ordinary installation refused; a fresh reviewed plan resumed successfully with original files retained. |
| Old updater retry | After private preservation of its verified stale download, the unchanged historical updater completed native installation of v4.10.3. |
| Already half-configured v4.10.2 | A separate actual v4.02.8 update to the official v4.10.2 package reproduced `install ok half-configured 4.10.2` and its missing-manifest recovery refusal. The staged candidate retired and migrated the VPN; native installation then reached `install ok installed 4.10.3`. |
| Encrypted connectivity | The original client keys completed handshakes, bidirectional UDP transit and a public DNS query through VPN NAT before and after recovery. Only the test client's runtime endpoint was redirected to its local test underlay; its saved configuration stayed byte-identical. |
| Reboot recurrence | Both upgraded scenarios retained the client, activated the preserved VPN, left `wg0` inactive and disabled with its original path absent, restored the two owned shared-forward rules and had no failed units. Encrypted transit and NAT passed after both reboots. |
| Native removal | Direct CLI uninstall refused a registered package. Native purge removed owned state, including shared rules when the private table was already absent, while retaining operator policy and private backups. |
| Same-version reinstall | Native reinstall restored the complete executable payload and configured v4.10.3 with the explicit laboratory profile. Its final reboot retained the configured package, complete payload, SSH hardening and operator forward policy, with no failed units or stale WireGuard state. |

Negative cases rejected customized client text, a mismatched client key, a
missing generated file, a symlink, a hardlink, foreign nftables topology and a
duplicate legacy rule. Original file bytes and inodes were retained after each
fixture was restored. A stale plan and drifted ownership manifest also refused.
The existing shared forward-chain `drop` policy and unrelated operator rule
survived the relevant cleanup and migration checks.

## Scope and retained failures

The campaign used the explicit LAN laboratory profile to isolate WireGuard and
native package lifecycle behavior. A fresh-default reinstall encountered an
empty external OSINT intersection after restoring the executable payload. The
original failure was retained; configuration with the intended LAN profile and
a separate preseeded same-version reinstall succeeded. This campaign does not
qualify live external threat feeds.

The old v4.02.8 LAN-mode formatter also concatenates its two default honeyports
into an invalid port. The fixture selected one valid port, retained the initial
failure and reran the official native configuration without modifying a binary.

The old updater's retained `_apt`-owned `/tmp/syswarden.deb` caused a subsequent
retry to fail under temporary-file protection. The verified stale lab download
was archived privately before the unchanged updater retry. The recovery
[runbook](WIREGUARD_LEGACY_MIGRATION.md) explains resuming from a separately
verified native package without reducing temporary-directory protections.

Packet probes ran in dedicated test namespaces through an explicitly authorized
temporary root service. SSH hardening remained enabled. Initial harness errors
and their corrected assertions are retained alongside the successful receipts.
In particular, native installation may add its ownership-bound baseline comment
to the forwarding file after migration; client bytes remain the preservation
invariant across upgrade and reboot.

## Release boundary

These results support review of [PR #291](https://github.com/duggytuxy/syswarden/pull/291)
and the follow-up in [issue #283](https://github.com/duggytuxy/syswarden/issues/283).
They do not replace mandatory checks on the final reviewed commit, native
signatures, protected Patch IVV, the signed tag or publication approvals.
The stable version remains v4.10.2 until a verified release is published.
