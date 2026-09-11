# Custom log source ownership and permissions

The `waap.modsec_logs` setting supplies custom inputs to the rsyslog bridge and
the direct WAAP log collector. Both paths require a real regular file owned by
the service's effective user, which is root for the native installation. Group
and other write permissions are refused. Read permissions for a monitoring
group are allowed; for example, root-owned mode 0640 is eligible.

Before publishing a custom rsyslog input, the CLI checks the matching file's
owner, permissions and type. It opens the final component without following
links or blocking on a special file, then rechecks the opened descriptor and
the path identity. A symlink, special file, different owner, writable file or
identity change stops configuration generation before that custom input is
published. The operator must correct the source; SysWarden does not change its
ownership or permissions automatically.

These checks align the custom bridge inputs with the existing direct collector
ownership policy. The direct collector also rechecks its held file and handles
rotation. The rsyslog check is a configuration-time check, so source directories
must remain under trusted administrative control while rsyslog runs. Native
qualification must exercise the installed package and retain its actual refusal
records; local regression tests alone do not qualify a release.

## Native authentication writer and socket access

Native authentication logs retain the supported rsyslog writer: root by
default, or the `syslog` account selected by `$PrivDropToUser syslog` in the
root-owned `/etc/rsyslog.conf` without group or other write access. Hardening
uses mode 0640 and preserves that writer in logrotate rules, including rules already using 0600
or 0640. An existing `syslog` membership in `adm` is retained for the configured
writer. Unknown or ambiguous privilege-drop declarations stop hardening before
authentication log ownership changes. Other privilege-drop configuration
formats must be reviewed and expressed in this supported form first.

The SSH authentication rule accepts records from `sshd` and `sshd-session`
without a syslog envelope, with the traditional month/day timestamp, or with an
ISO timestamp using `Z` or a numeric timezone offset and optional fractional
seconds. The process identity remains anchored after the timestamp and host.
Successful logins and connection-close records do not count as failed attempts.

On Linux the datagram socket grants write access to root and the private
`syslog` group when its account and primary group agree. Every datagram must
also carry kernel-generated sender credentials for root or that exact syslog
UID. Membership in the group alone does not authorize injection; missing,
truncated, or unauthorized credentials are refused before rule evaluation.
Package removal accepts that exact root-owned logging socket with mode 0660
after resolving the same canonical syslog account and private group. The parent
directory and command socket retain their root:root ownership requirements.
Legacy root:root sockets and already-absent sockets need no syslog lookup;
unexpected identities and changes during removal are refused.

When the syslog account is absent, only root is authorized. A service running
as a non-root user accepts only its own UID. Platforms without the Linux
credential mechanism cannot start this receiver.

Custom inputs still require root ownership for a native root service. Operators
using an unprivileged rsyslog producer must additionally provide read and
directory traversal access, for example a root-owned 0640 log readable by the
logging group. The local audit reports permissions and configuration; it does
not claim that configuration inspection proves successful event delivery.
