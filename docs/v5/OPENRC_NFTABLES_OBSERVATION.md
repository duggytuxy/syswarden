# Alpine nftables loader observation

Status: candidate implementation for issue #422 in PR #452. Native lifecycle
qualification and final v5.00.0 IVVQ acceptance remain required.

Alpine uses OpenRC service definitions. The nftables persistence observer selects
the Alpine adapter when `/etc/alpine-release` exists; it does not attempt a
`systemctl` query on that platform. The adapter reads files and native state
markers without executing `nft`, an init script, or a shell. Loading an init
script merely to request status is unsafe because its top-level code and sourced
configuration can perform mutations.

The initially reviewed Linux x86_64 profiles are:

| Alpine series | OpenRC package | nftables-openrc package |
| --- | --- | --- |
| 3.22 | 0.62.6-r0 | 1.1.3-r0 |
| 3.24 | 0.63.2-r0 | 1.1.6-r1 |

Exact distribution hashes bind `openrc-run`, its shell support files and the
nftables init script. They identify reviewed loader behavior, not ownership of
administrator firewall policy. Changed definitions require separate review and
are preserved. The nft executable, configuration sources, metadata and source
identities are also captured and rechecked before subsequent operations.

The bounded configuration reader accepts literal settings in `/etc/rc.conf`,
ordinary `/etc/rc.conf.d/*.conf` files and `/etc/conf.d/nftables`, in that order.
It resolves `rules_file`, the legacy `NFTABLES_SAVE` alias, or the distribution
default `/etc/nftables.nft`. Spaces in values require quotes. It refuses shell
evaluation, unknown settings, namespace overrides, forwarding changes and
save-on-stop. Optional legacy/environment imports, plugins, hidden global
configuration, runlevel-specific service configuration, cached or runtime
framework overrides, and executable shadowing
are refused rather than silently ignored. This is deliberately not a general
shell interpreter.

Observation requires a coherent OpenRC runtime and PID 1, stable runlevel state,
and no pending or failed nftables transition. A separate bounded procfs
inspection rejects active loader processes, including reloads that do not set
OpenRC transition markers. Unreadable or changing observations refuse recovery. Persistent runlevel links are
observed separately; unresolved stacked runlevels are refused. An operator boot-loader proof additionally requires a
started nftables service and its enablement in `boot` or `default`; an idle
unstarted loader alone does not establish that proof. Runtime observation does
not establish rule ownership or current kernel enforcement.

The existing systemd observation and retirement digest format remain unchanged.
Unknown or changing inputs preserve the existing firewall and prevent unsafe
retirement. The observer never stops the shared service or flushes its rules.

## Native command execution boundary

The separate CLI manager preflight runner still executes trusted manager commands;
it must not be confused with the script-free nftables observer above. In
particular, requesting an OpenRC service's `status` executes its init script.
A bounded process runner does not make that operation read-only or authorize
activation before administrator review.

Manager preflight captures at most 64 KiB across stdout and stderr and stops on
output overflow, with a 15-second maximum observation deadline. Successful
stdout stays separate from stderr warnings; rejected-command evidence retains
both bounded streams. The child starts in a private process group. Linux
`waitid` observes its exit without reaping it, and group cleanup occurs while
the original leader identity is still retained. This avoids signaling a recycled
process group after an early leader exit. Inherited pipes, closed output streams
and a successful leader with lingering descendants are covered separately.

These bounds do not control an external daemon, an intentionally escaped process
group or a kernel execution stall. They do not establish native service health,
configuration consumption, an activation approval or complete lifecycle recovery.

Upstream references:

- [Alpine nftables configuration](https://wiki.alpinelinux.org/wiki/Nftables)
- [Alpine nftables package definitions](https://gitlab.alpinelinux.org/alpine/aports/-/tree/master/main/nftables)
- [OpenRC 0.63.2 service loading](https://github.com/OpenRC/openrc/blob/0.63.2/sh/openrc-run.sh.in)
- [OpenRC environment filtering](https://github.com/OpenRC/openrc/blob/0.63.2/src/shared/misc.c)
- [OpenRC configuration imports](https://github.com/OpenRC/openrc/blob/0.63.2/src/librc/librc-misc.c)
