# Historical WireGuard recovery and package removal

This runbook describes the v4.10.2 source candidate. It does not establish release
qualification or publication. Current release instructions are maintained at
[syswarden.io/docs](https://syswarden.io/docs/).

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
