# Removal after an interrupted historical upgrade

Status: implementation and unsigned native rehearsal. Fresh signed packages
and protected v4.10.3 IVV are required before release acceptance. Operator
instructions belong in [the canonical documentation](https://syswarden.io/docs/).

## Reproduced failure

An official v4.02.8 installation can retain its generated systemd units when
the v4.10.2 post-install script stops before service migration. The package is
then half-configured. Native removal publishes its durable barrier but rejects
the old units as modified, even when they match the official historical bytes.
The barrier correctly prevents the failed-removal post-install fallback from
activating the incomplete installation.

The old core unit is 712 bytes with SHA-256
`0079096c0a92f17e3aafb6c76ad89a0fdac03c2977732a15776be01220d81768`.
The old firewall unit is 307 bytes with SHA-256
`bc730793c007273a380261155b7602571c42efd93972f45ad2dd440f98251724`.
Neither filename nor service inactivity alone proves ownership.

## Bounded correction

Removal recognizes the frozen v4.02.8 core and firewall templates and the
v4.04.3 core template, at the supported historical modes. It retains root
ownership, single-link, parent-directory, stable-content, loaded-command,
drop-in, process and exact-deletion checks. Customized units remain refused.
This selection does not authorize service activation or template rewriting.

A staged recovery CLI can attest the two exact product-owned systemd drop-ins
from the half-configured v4.10.2 amd64 package. This exception requires the
verified removal barrier and the exact package status, architecture, version,
file inventory and expected drop-in bytes. Package state and content are
rechecked. Normal activation retains its same-release rule. Unknown versions,
package states and architectures remain refused; RPM authority is unchanged.

The official v4.02.8 WAF rsyslog bridge is also recognized for removal. Its
frozen template is reconstructed from the retained configuration without
expanding historical globs or opening log inputs. Unsafe strings, changed
configuration, extra directives, links and ambiguous metadata remain refused.
The existing quarantine, rollback and verified rsyslog restart must complete
before removing the socket or SELinux policy. The historical bridge is never
published or activated by this compatibility path.

The staged preparation removes verified runtime state and retains the installed
package payload and removal barrier. The original native removal command then
finishes the package transaction. No force option, manual barrier deletion,
package-database edit or standalone CLI uninstall bypass is introduced.

## Required regression coverage

- Reproduce the actual v4.02.8 updater reaching half-configured official v4.10.2.
- Resolve the recognized historical WireGuard state with separate reviewed
  plans, preserving private originals.
- Reproduce the official v4.10.2 removal refusal with the historical unit hashes.
- Refuse and preserve customized service and rsyslog fixtures.
- Complete staged preparation and resume the original native removal command.
- Preserve unrelated firewall rules, the operator's forward policy and private
  VPN originals; let the native lifecycle remove the durable barrier.
- Reinstall the complete native package and verify executable payload, package
  status and reboot behavior.
- Retain failed attempts separately and repeat the required observations with
  the final signed product. Earlier signed-product results cannot be relabeled.

This scope covers recognized historical generators. Unknown customizations
remain preserved for inspection. No production-host recovery outcome is inferred
from a laboratory rehearsal.
