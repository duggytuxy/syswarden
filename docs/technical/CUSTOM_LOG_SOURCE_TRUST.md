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
