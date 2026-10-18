# Bounded LXC service compatibility

Status: development correction for [issue #384](https://github.com/duggytuxy/syswarden/issues/384).
The published baseline remains v4.10.4. Component evidence does not establish
native LXC support or final v5.00.0 IVVQ acceptance.

## Why an active scheduler can be rejected

The cron scheduling preflight checks the loaded provider, its executable and
package attribution, its persistent enablement and service drop-ins. An active
`crond.service` alone does not establish that contract.

The [upstream distrobuilder generator](https://github.com/lxc/distrobuilder/blob/a81b4f5b59adcd5ca41265bbe2882df0254a124c/distrobuilder/lxc.generator)
creates `/run/systemd/system/service.d/zzz-lxc-service.conf`. Under
[systemd's drop-in rules](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html),
this runtime profile affects all services. The earlier enumerated attestor
rejects it even when Cronie is otherwise attributable and healthy.

## Reviewed boundary

The correction recognizes only the exact modern non-privileged generator
profile containing `ProcSubset=all`, `ProtectProc=default`,
`ProtectControlGroups=no`, `ProtectKernelTunables=no`, `NoNewPrivileges=no`,
empty `LoadCredential=`, `PrivateNetwork=no` and empty `ImportCredential=`.
Directive order, section, values and bytes are fixed. Older and privileged
variants, administrator additions and alternate paths remain unreviewed.

Acceptance requires the exact runtime path, a regular root-owned 0644 file with
one link, root-owned parents without group or other write permission, and
repeated successful
`systemd-detect-virt --container` observations identifying LXC. The detector
uses the existing trusted executable resolver. Content and inode identity are
rechecked across the observations; cron's repeated provider capture binds that
identity too. Stale or unknown `NeedDaemonReload` state is refused.

This proves conformity to a reviewed compatibility profile in an observed LXC
context. It does not prove which program originally created the file. Root and
the container host remain trusted. A matching filename, an active daemon or a
container label by itself never authorizes the exception.

Existing vendor and product drop-ins retain their independent checks. Unknown
or duplicate drop-ins, command or environment additions, credential inputs,
symlinks, hard links, writable files, changed evidence and non-LXC contexts
remain refusals. Cron executable and package checks are not bypassed.

## Isolation and lifecycle

The upstream profile relaxes several service-level restrictions to accommodate
the container runtime. SysWarden does not write, install, modify or delete this
shared file and does not claim host-equivalent service hardening. Container host
policy, network namespace isolation, netfilter capabilities, kernel support and
other product features require separate native assessment. Do not grant broad
host privileges simply to pass this preflight.

Normal service validation and removal use the same bounded compatibility
attestor. Package-owned service fragments retain their existing provenance
checks. Shared runtime files and unrelated cron jobs must survive product
retirement. The removal barrier and package scriptlets remain mandatory:
installation after an interrupted removal is a separate recovery problem.
Neither `rpm --noscripts` nor manual deletion of a removal marker is a supported
recovery procedure.

## Required evidence

### Profile attributes and kernel authority

The immutable-profile follow-up inspects the process UID map during both
package hooks and manual hardening. A remapped root receives verified private
profile modes, but no attempt to set or clear the immutable attribute. The
diagnostic explicitly reports that runtime restriction as not applicable;
it does not claim that the attribute is enforced.

The process capability mask is not sufficient evidence of authority over this
attribute. The [kernel inode flag check](https://github.com/torvalds/linux/blob/v6.12/fs/ioctl.c)
uses `capable(CAP_LINUX_IMMUTABLE)`, which checks the
[initial user namespace](https://github.com/torvalds/linux/blob/v6.12/kernel/capability.c).
A capability in a child user namespace cannot substitute for that authority.
Unknown or malformed UID maps fail closed. Host permission errors remain
errors, with the existing profile rollback and identity checks preserved.

Tests cover remapped-root execution with and without an active service manager,
manual execution, malformed namespace evidence, mode attestation, host attribute
updates, rollback failures and concurrent pathname replacement. HA ownership
validation is unchanged: test runners must provide trusted mapped directory
ancestors and the required loopback operations. An overflow UID does not grant
ownership and must not be added to the trusted-owner set to make a test pass.

### Native acceptance still required

Component tests cover the exact Debian cron and RPM Cronie provider paths,
unsafe or changing profiles, context errors, composition with verified package
drop-ins, stale manager metadata and service removal preparation without
changing the shared file. These checks do not run a real scheduler or kernel.

Before closing the issue, record a controlled LXC campaign with the exact guest
OS, runtime, privilege model and product/package identities. Verify installation,
a real scheduled job, reload, reboot and each independent native removal path.
Preserve unrelated cron jobs and administrator configuration after removal and
reboot. Keep capability refusals visible and retain private evidence. Native
container validation remains open; no stable package or release claim changes.
