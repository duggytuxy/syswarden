# Historical WireGuard migration without an ownership manifest

Status: v4.10.3 candidate implementation. The unsigned Debian 13 native
[rehearsal](WIREGUARD_LEGACY_NATIVE_V4.10.3.md) covers both historical upgrade
entry points. Protected signing and version-specific Patch IVV remain pending. This document does not authorize a tag
or publication. The public stable release remains v4.10.2 until verified
publication. Current public instructions belong at
[syswarden.io/docs](https://syswarden.io/docs/).

## Why the older upgrade fails

Historical releases, including v4.02.8, generated `wg-syswarden.conf`, the client
configuration and a forwarding sysctl file without an ownership manifest.
Their presence is not proof of a recent installation or corruption. When an
older `wg0` also claims the reserved nftables namespace, v4.10.2 refuses ordinary
installation. Its explicit retirement command also refuses these unmanifested
paths. An older updater can unpack v4.10.2 before that post-install refusal and
leave Debian package state `install ok half-configured`.

The v4.10.3 native pre-install screen rejects these known historical conditions
before its payload is unpacked. It does not execute the old installed CLI or
claim full ownership verification. Normal CLI preparation repeats the stronger
checks. Package managers can run hooks from the older package before or after
a failed pre-install script, so this boundary is not a claim that every older
package hook is free of side effects.

## Choose the operation before changing a VPN

Confirm the intended disposition of each VPN and an administration connection
that does not depend on it. Consent to retire a VPN on another installation is
not consent for this installation. The recovery commands never stop services.
Retiring `wg0` and preserving `wg-syswarden` are separate decisions and separate
plans. If `wg0` must remain operational, do not authorize its retirement.

Use a verified v4.10.3 candidate recovery executable extracted into a private
directory for an authorized test campaign. Do not replace the installed CLI or
force package configuration to make the command available. Follow the staged
extraction approach in the [recovery runbook](WIREGUARD_LEGACY_RECOVERY.md), but
use the independently verified candidate package, its own metadata and checksum.
The published v4.10.2 digest in that runbook cannot validate a v4.10.3 package.
No public v4.10.3 checksum is asserted here.

When a staged executable is required, substitute its absolute path for
`syswarden` in every command below, including printed apply suggestions.
Keep all plan output, configuration files, private backups and host diagnostics
private. Plans omit key bytes but contain operational metadata.

## Retire the old namespace claim

Inspect the explicit historical retirement plan:

```sh
sudo syswarden recover-wireguard --retire-legacy-wg0
```

The candidate recognizes a complete unmanifested generated `wg-syswarden`
installation only after verifying exact historical server and client templates,
the generated forwarding setting, matching public/private key relationships,
matching preshared keys, addresses, port and endpoint. It checks private file
permissions, ownership, link count, inode and content digests. Partial or
customized state remains untouched. Both generations must agree on the egress
interface before selecting their shared historical table.

After the operator has authorized retirement and confirmed independent access,
stop and disable only the affected services listed as blockers. Repeat the dry
run after stopping them. Historical PostDown can remove the NAT table and fail
to remove shared forward rules; both an absent table and exact residual rules
are supported. Do not manually delete nftables objects to work around refusal.

Authorize only the fresh digest printed by that same executable:

```sh
sudo syswarden recover-wireguard --retire-legacy-wg0 --apply --plan-sha256 REVIEWED_LOWERCASE_SHA256
```

This archives the exact historical `wg0` privately and removes only proven
historical runtime state. It leaves all three unmanifested `wg-syswarden` files
unchanged. Those files still need the separate migration below before ordinary
configuration or native removal can claim their ownership.

## Preserve and migrate the historical generated VPN

Once the historical `wg0` namespace claim is retired, inspect:

```sh
sudo syswarden recover-wireguard --migrate-legacy-wg-syswarden
```

The plan requires the generated VPN to be inactive and disabled, with its
interface absent. It rejects foreign or duplicate shared rules, unknown table
topology, another ownership/forwarding transaction, and any drift after review.
An unrelated administrator `wg0` is preserved and is not selected for migration.

The operation preserves the server private key, client keys, preshared key,
VPN addresses, listen port and the entire client file. It replaces only the
historical server hooks with current token-bound nftables hooks. The existing
forwarding file is retained; no historical runtime baseline is invented.

The migrated hook restores the two historical interface allowances in the
existing `inet filter forward` base chain, with exact ownership-token comments.
This preserves VPN transit under the operator's `drop` policy. The chain must
already exist as a filter/forward base chain at priority zero. Its policy and
foreign rules are preserved; the command does not create or replace it. Runtime
cleanup removes only the exact manifest-bound table and tokenized rule handles,
including residual shared rules when the private table is already absent.

Other administrator chains can still deny traffic. Check actual client transit
and the intended destinations; successful service activation alone is not a
connectivity test.

After reviewing the fresh plan, apply its exact digest:

```sh
sudo syswarden recover-wireguard --migrate-legacy-wg-syswarden --apply --plan-sha256 REVIEWED_LOWERCASE_SHA256
```

Before replacing the server configuration, the command creates a mode-0600
backup beside each original file, with a `.syswarden-legacy-v1` suffix and a
leading dot. It also retains the original server inode in a separate private
archive. Existing unjournaled backups are never overwritten. A durable journal
blocks ordinary installation and removal until migration completes. The final
manifest binds the exact resulting files; its private completion receipt and
backups remain available afterward.

If interrupted, retain every file and repeat the same migration dry run. Review
the new plan digest and apply it separately. The command verifies the recorded
phase, originals, backups and live files before continuing. It does not infer
ownership from path names or discard evidence to reset the operation.

## Resume the intended native package operation

The migration does not enable or start the VPN. Its owned shared-forwarding
hooks require v4.10.3. If v4.10.2 is half-configured, install the verified v4.10.3
package with the native package manager after migration; do not run v4.10.2's
configuration step against the migrated hooks. If v4.10.3 is already unpacked,
resume only its configuration with `sudo dpkg --configure syswarden`.

If pre-install screening preserved the older installed package instead, retry
the verified native upgrade. Check both the package-manager state and actual
VPN function afterward. A successful recovery plan does not establish client
reachability or host health.

When removal was the intended operation and a removal barrier remains, resume
native package removal after verified migration. Do not delete the barrier or
use direct CLI uninstall against a registered package. Keep private backups
until the operator verifies the intended outcome.

### A hardened temporary directory can block the old updater retry

The v4.02.8 updater downloads to the fixed path `/tmp/syswarden.deb` and changes
its owner to `_apt`. After a rejected upgrade, that file can remain present.
With `fs.protected_regular` enabled, a later invocation by root can fail before
package installation with `open /tmp/syswarden.deb: permission denied`.
This error does not invalidate a completed WireGuard migration. The old updater
also prints some failures while returning zero, so verify dpkg state and the
installed executable independently.

Keep the temporary-directory protections enabled. After the reviewed WireGuard
recovery, resume using the independently verified v4.10.3 package from its
separate staging path:

```sh
sudo apt-get install /absolute/path/to/verified/syswarden_4.10.3_amd64.deb
dpkg-query -W -f='${Status} ${Version}\n' syswarden
```

Replace the example path with the actual verified package. Retain the old
download as private evidence if needed; do not use broad temporary-file cleanup
or change the ownership of unrelated files. The first-hop laboratory rehearsal
also verifies an unchanged old updater retry after archiving only its exact,
checksum-verified stale download. That explicit laboratory step is not an
automatic cleanup performed by the recovery command.

## Required acceptance before publication

Fresh native tests must invoke the actual installed v4.02.8 updater, with its
binary digest recorded, and document any controlled candidate transport. Calling
the candidate updater instead does not satisfy this first-hop requirement.
Test refusal before payload replacement, already half-configured v4.10.2
recovery, both historical generations, preserved client connectivity,
interruption and retry, foreign state rejection, reboot recurrence prevention,
native removal and same-version reinstall. Complete the mandatory source,
package and security gates, protected signing and version-specific Patch IVV.
Prior v4.10.2 evidence remains historical evidence for its bounded scope.
