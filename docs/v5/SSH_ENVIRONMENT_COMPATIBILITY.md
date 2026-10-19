# SSH environment compatibility contract

Status: required v5.00.0 integration and IVVQ criteria, not implemented runtime
autodetection or a new configuration interface. Refs #235 and #337. The inactive
[SSH preparer](SSH_DROPIN.md) checks two fixed policies; it does not yet select
deployment roles, manage a bastion or replace either existing installer writer.

## Objective and evidence boundary

Adapt to a declared, verified environment while preserving administrator access
and existing management tools. Compatibility must be recorded for tested
combinations and versions, with explicit unsupported or unverified cases.
Neither a successful parser check nor detection of an installed package proves
end-to-end interoperability. Unknown environments must not trigger broader
permissions, destructive fallback or a claim of successful hardening.

Separate observed capabilities from administrator intent:

- Observe the installed daemon's supported syntax, complete configuration graph,
  effective connection contexts, service manager and activation mechanism.
- Obtain the machine's SSH role, required access routes and policy ownership
  from protected administrator configuration. A host can have several roles.
- Treat `SSH_CONNECTION`, process names, package presence, configuration comments
  and network addresses as observations, never authorization to enable
  forwarding, change authentication or adopt another tool's files. A target
  cannot reliably infer a controller's ProxyJump chain from its immediate peer.
- Refuse the proposed SSH mutation if intent, ownership or effective behavior
  cannot be established. Preserve the working configuration and explain the
  unresolved prerequisite. Do not silently retry through the old main-file
  writer or mark a skipped SSH control as enforced.

## Access roles and policy ownership

These are design categories, not released setting names or command flags.
Access role and policy owner are separate dimensions: an Ansible-managed host
can also be a target or a bastion.

| Environment | Required behavior | Boundary before activation |
| --- | --- | --- |
| Directly administered target | Preserve declared port, identities, authentication and access groups | Verify an independent connection using the intended administrator route |
| Target reached through one or more SSH jump hosts | Preserve the controller's route and target authentication | Do not enable target forwarding merely because a bastion is used |
| Host acting as a bastion | Preserve explicitly approved forwarding users/groups and destinations | The fixed no-forwarding profiles are not a bastion policy; reject them where they conflict |
| Ansible-managed target | Preserve remote commands, configured transfer method, session multiplexing and privilege escalation | Validate the actual controller workflow; do not disable SFTP or weaken host-key verification as a workaround |
| SSH policy owned by an external manager | Support explicit validation-only ownership, or a reviewed division of independently owned files | No concurrent writers, adoption based on comments, or automatic override of an external policy |
| Mixed, unknown or unsupported role | Report the unresolved role or capability | No SSH mutation until a bounded supported plan is available |

OpenSSH's [ProxyJump contract](https://man.openbsd.org/ssh_config#ProxyJump)
places the TCP forwarding on the jump host. The destination's ordinary incoming
SSH session does not by itself require forwarding there. Standard ProxyJump
does not require delegating an authentication agent to the jump host; see the
[OpenSSH client guidance](https://man.openbsd.org/ssh#A).

For an explicitly managed bastion, the future policy must scope local TCP
forwarding to approved accounts and exact destinations, rather than enable it
globally. Check `Match`, `PermitOpen`, `DisableForwarding`, per-key/certificate
restrictions and remote forwarding together. Preserve existing restrictions;
never infer approval for `any`, wildcard destinations or agent forwarding.
Shell access and other forwarding channels need their own controls: limiting
TCP forwarding alone does not establish a complete bastion security boundary.
The [daemon manual](https://man.openbsd.org/sshd_config) defines these semantics.

## Coexistence with Ansible and dev-sec

The original [ansible-ssh-hardening repository](https://github.com/dev-sec/ansible-ssh-hardening)
is archived and directs users to the hardening collection. Use the
[current dev-sec SSH role](https://github.com/dev-sec/ansible-collection-hardening/tree/master/roles/ssh_hardening)
as an interoperability reference, not an automatically installed dependency or
a policy to copy wholesale. It provides explicit settings for the server
configuration path, forwarding and SFTP; old standalone-role defaults differ.

The [Ansible SSH connection plugin](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/ssh_connection.html)
allows controller SSH arguments and transfer-method selection. Preserve the
selected method and validate it from that controller. A plain remote command
can succeed while an upload, a multiplexed connection or a `become` task fails.
Do not force an old SCP fallback, disable certificate checks, lower crypto
policy, remove an MFA step or change sudo policy merely to make a test pass.

External management is an explicit ownership choice, not detection from an
`Ansible managed` comment. Before enabling it on an existing installation,
account for every already-owned SysWarden contribution and any legacy main-file
edits. Report controls supplied externally separately from controls enforced by
SysWarden. If an external manager rewrites an owned file or changes the Include
graph, stop reconciliation with a precise conflict and retain recovery evidence.
Repeated runs must not oscillate between two policies or restart SSH endlessly.

## Required integration checks

The SSH-02 through SSH-05 gates in [SSH_DROPIN.md](SSH_DROPIN.md) must include:

1. A protected role/ownership decision and inventory bound to the reviewed plan.
   Recheck the daemon capabilities, files and graph immediately before commit.
   No positive role inference from a private address, a running process or
   attacker-controlled environment text. An undeclared bastion using daemon
   forwarding defaults must not silently receive the fixed target profile.
2. Before/after effective configuration for all declared administrator,
   automation and jump-user contexts. Preserve authentication, certificate/MFA
   requirements, listening ports, SFTP, commands, multiplexing, restrictions and
   distribution crypto policy. A stricter external setting must not be relaxed.
3. Syntax and effective checks using the installed daemon, followed by a new
   independent session over each required route. Disable connection reuse for
   this access check: an old authenticated session or ControlMaster is not proof
   that a new login succeeds. Existing sessions alone cannot authorize success.
4. Positive and negative bastion tests: approved destinations work, unapproved
   destinations and non-authorized users remain denied, and no implicit remote
   or agent forwarding is introduced. Include multi-hop access where declared.
5. Ansible command, upload/download, multiplexing, approved `become` and repeat
   run from the controller. Verify external-policy convergence before and after
   SysWarden reconciliation, with no file churn or restart loop.
6. Uninstall, native remove and native purge as separate paths, plus delayed
   purge, reload, reboot and interrupted migration/rollback. Preserve external
   files and effective access, retire only attested product contributions, and
   test the resulting administrator and automation connections again.

The validation record must distinguish parser evidence, complete connection
tests, controller interoperability and native lifecycle evidence. Record exact
versions, role combinations and untested dimensions privately. Publish only the
supported matrix and non-sensitive results. Use existing AMD64 laboratories and
synthetic fixtures; this contract authorizes no extra infrastructure spending.

## Current executable coverage and remaining work

`TestPrepareEnvironmentBoundaries` verifies unchanged administrator input,
preservation of unrelated automation/authentication directives and refusal of
conflicting external or bastion forwarding policies. It also checks that
environment hints and management comments cannot grant a forwarding exception.

`TestOpenSSHOracle` additionally checks effective SFTP/session settings and a
scoped bastion policy using temporary files and the local daemon parser only.
It opens no listener and executes no Ansible tasks. These checks do not prove
a login, a ProxyJump connection, a file transfer or privilege escalation.

Protected role selection, external-management mode, scoped bastion publication,
controller tests and lifecycle integration remain open. Do not activate the
fixed preparer for arbitrary machines before those prerequisites are met.
The broader v5 compatibility work for firewalld/NetworkManager, containers and
[BunkerWeb](BUNKERWEB_COMPATIBILITY.md) retains its independent evidence gates;
SSH compatibility does not establish those other integrations or require the
optional dashboard. Kubernetes remains scoped separately to v5.01.0.
