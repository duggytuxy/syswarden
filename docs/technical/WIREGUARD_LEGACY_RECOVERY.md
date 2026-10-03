# Historical WireGuard recovery and package removal

This runbook applies to the published v4.10.2 patch. Its targeted IVV scope and
verified artifacts are recorded in the [publication record](../releases/v4.10.2/README.md).
Current release instructions are maintained at
[syswarden.io/docs](https://syswarden.io/docs/).

For the newly reported v4.02.8 first-hop upgrade with historical generated files
without a manifest, see the [v4.10.3 candidate migration procedure](WIREGUARD_LEGACY_MIGRATION.md).
That extension is under validation. The published v4.10.2 procedure below does
not cover this unmanifested coexistence case.

## Identify the failure

Accumulated installations can leave an old `wg0` configuration alongside the
current manifest-owned `wg-syswarden` configuration. An old enabled service can
recreate the reserved `inet syswarden_wg` table without the current ownership
token. Ordinary recovery refuses to choose between two historical configurations.
An interrupted removal retains its durable barrier until verified cleanup succeeds.

Keep both configurations, the ownership manifest and any removal barrier in place
while investigating. Never delete them to bypass an ownership refusal. Do not
publish configuration contents, VPN keys, plan output or raw host diagnostics.
The plan omits key contents but still contains local operational metadata.

## Obtain the recovery command when an older removal is blocked

An existing removal barrier also blocks a normal package upgrade. On an older
DEB installation, do not remove that barrier or replace the installed CLI to
make the new command available. First obtain the official v4.10.2 amd64 DEB
and independently verify its release provenance, checksum and detached native
signature against the trusted release verification material. A checksum copied
from the same untrusted download is insufficient. Before publication, only the
protected qualification bundle is eligible for the authorized test campaign;
this runbook does not make an unpublished package a public release.

For that already verified package, extract its contents into a new private
directory. The command checks the copied package against the frozen v4.10.2
digest before extraction. This does not install the package or execute its
maintainer scripts.
Replace the final argument with the absolute path to the verified DEB:

```sh
sudo sh -eu -c 'umask 077; test -f "$1"; test ! -L "$1"; recovery_stage=$(mktemp -d /root/syswarden-recovery.XXXXXXXX); install -m 600 -- "$1" "$recovery_stage/package.deb"; printf "%s  %s\n" 0e71d9856e6838a3feeea369c514c6ed55676d249b1b3fe213b086cd942e5980 "$recovery_stage/package.deb" | sha256sum -c --status; test "$(dpkg-deb --field "$recovery_stage/package.deb" Package)" = syswarden; test "$(dpkg-deb --field "$recovery_stage/package.deb" Version)" = 4.10.2; test "$(dpkg-deb --field "$recovery_stage/package.deb" Architecture)" = amd64; mkdir -m 700 "$recovery_stage/root"; dpkg-deb --extract "$recovery_stage/package.deb" "$recovery_stage/root"; chmod 700 "$recovery_stage/root"; test -x "$recovery_stage/root/opt/syswarden/bin/syswarden-cli"; printf "Recovery executable: %s/root/opt/syswarden/bin/syswarden-cli\n" "$recovery_stage"' sh /absolute/path/to/verified/syswarden_4.10.2_amd64.deb
```

Use the printed executable path for every recovery inspection and application
below, including after stopping services. For example:

```sh
sudo /root/syswarden-recovery.REPLACE/root/opt/syswarden/bin/syswarden-cli recover-wireguard --retire-legacy-wg0
```

Replace `REPLACE` with the actual private directory suffix. The plan's printed
apply example uses `syswarden`; on this older installation, substitute the same
verified staged executable while retaining the exact fresh plan digest. Do not
accidentally invoke the older installed CLI for that step. All configuration,
ownership evidence and service checks still refer to the real host.

After verified retirement, resume removal through the native package manager as
described below. Install the verified current package only after removal has
completed and its barrier is absent. The temporary executable is recovery
tooling, not an installed product upgrade. Keep its provenance and the private
retirement archive until the operation and any required backup are verified.

## Inspect explicit historical retirement

The dedicated path retires the exact supported historical `wg0` configuration.
It is not an arbitrary WireGuard cleanup tool and does not select which VPN an
operator wants to keep.

```sh
sudo syswarden recover-wireguard --retire-legacy-wg0
```

This invocation is read-only. It binds the historical configuration, current
ownership evidence, both service states, interface presence, exact nftables
handles and a protected archive destination into a SHA-256 plan digest.

Retirement accepts an exactly recognized historical NAT table, an already absent
table, or an exact current manifest-owned table that will be preserved. Exact
historical shared forward rules can be removed. Unknown topology, duplicate
matching rules, unsupported configuration, missing current ownership evidence,
an ownership transaction in progress, or changed evidence causes refusal.

## Resolve runtime blockers

Before stopping a VPN, confirm that administration uses a separate working
connection or console and explicitly decide to retire the historical VPN.
For a pending retirement, both generations must be inactive and disabled, and
their interfaces must be absent. The recovery command never stops services.

On a systemd host, stop and disable only the affected services identified by the
plan, after confirming the access and retirement decisions:

```sh
sudo systemctl disable --now wg-quick@wg0.service
sudo systemctl disable --now wg-quick@wg-syswarden.service
```

Use the corresponding service-manager operations on an OpenRC host. Stopping an
old service may execute its historical PostDown hook and remove the NAT table.
That absence is supported. Do not perform additional manual nftables cleanup.
Repeat the dry run after any service or firewall change:

```sh
sudo syswarden recover-wireguard --retire-legacy-wg0
```

Review the new plan and its blockers. An earlier digest is no longer valid after
the observed state changes.

## Apply the reviewed plan

When the plan reports `safe_to_apply: true`, execute the exact command printed by
that dry run. Its form is:

```sh
sudo syswarden recover-wireguard --retire-legacy-wg0 --apply --plan-sha256 REPLACE_WITH_REVIEWED_DIGEST
```

The command rechecks the complete plan under the shared activation guard,
performs only the exact authorized nftables transaction, verifies its result,
and archives the old configuration without overwriting an existing file. The
archive directory is `/etc/wireguard/.syswarden-retired`, accessible only to root;
the preserved `wg0.conf` remains mode 0600. It contains secrets and must remain
private. The original active configuration path becomes absent. Current
manifest-owned files and unrelated administrator VPN configurations are retained.

If cleanup stops before archival, the active configuration remains as evidence.
Inspect again and authorize a fresh plan. If archival completed, a repeated dry
run verifies the retired state without repeating cleanup. Conflicting archives
are never overwritten. A newly recreated historical rule or configuration is an
error requiring inspection.

## Continue installation or removal

Choose the original operation after retirement. To keep SysWarden, reconcile its
current configuration through the supported installation procedure; restart the
current VPN only through that verified lifecycle. An existing removal barrier
must first complete its verified removal. Do not remove the barrier manually.

For a native package installation, use the package manager so package registration
and product files remain consistent:

| Package family | Removal command |
| --- | --- |
| DEB, retain package configuration | `sudo apt-get remove syswarden` |
| DEB, complete package removal | `sudo apt-get purge syswarden` |
| RPM | `sudo dnf remove syswarden` |
| APK | `sudo apk del syswarden` |

Package hooks perform their verified cleanup. Stop if they report an ownership
error and follow the retained evidence. `syswarden uninstall` is reserved for a
standalone installation and refuses native registration before deleting product
state, including incomplete package states. Setting a package-install environment
variable does not bypass that protection.

Removal is not a complete host rollback. Unproven legacy artifacts are preserved
for manual review rather than silently claimed or deleted.

## Repair an earlier missing DEB payload

Older direct CLI uninstall could delete the CLI while leaving dpkg registration.
An installation of the same version through APT may then skip unpacking and run
the package hook against the missing executable. Rebooting does not restore it.

Obtain the exact trusted package for the installed version and verify it using
that release's published verification procedure. For an already verified local
package, restore its payload before package-specific configuration:

```sh
sudo dpkg --unpack ./syswarden_VERSION_amd64.deb
sudo dpkg --configure syswarden
```

Replace `VERSION` with the verified package version. Run the configuration step
only after unpacking succeeds. Configuration applies the normal installation
pipeline and its host changes. If it fails, retain the complete local error and
ownership evidence. Do not copy individual binaries manually or remove package
database records.

Check package state and executable presence with these separate commands:

```sh
dpkg-query -W -f='${Status} ${Version}\n' syswarden
sudo test -x /opt/syswarden/bin/syswarden-cli && printf 'CLI executable present\n'
```

These two checks establish package registration and executable presence only.
Functional service, firewall, VPN, upgrade and reboot checks remain part of the
release's native lifecycle validation.
