# Bounded authority startup observation

Status: inactive Linux v5 supervisor component. Refs #224, #225 and #337, all
partial. Stable remains v4.10.4. No package, service or server is changed.

## One channel for one launch

`NewAuthorityReadinessChannel` creates an unnamed pipe with both nonblocking and
close-on-exec flags applied atomically by `pipe2`. Failure returns no channel;
there is no named pipe, blocking fallback, subprocess or persistent file. The
caller owns two descriptors and must close the channel even if launching fails.
Only the trusted supervisor and the intended child may receive its handles.

`Writer` lends the write end for the child's inherited readiness descriptor 6.
The supervisor must finish process creation before calling `CloseWriter` or `Wait`.
It must not write, change flags, or close the borrowed pointer directly. The child
receives its own inherited descriptor; releasing the parent's writer cannot close
that copy. A failed close stays recorded and prevents a later successful wait.
The reader is private. `Close` attempts both closes even after an error; it never
signals a child or edits private storage. Methods require serialized ownership,
not concurrent calls or copied channel values. Context cancellation is concurrent.

## Bounded observation

`Wait` accepts an explicit context and consumes the attempt once, even on failure.
It releases the local writer and caps observation at 30 seconds, or the caller's
earlier deadline or cancellation. Each read holds the Go descriptor lifetime and
checks read-only access, nonblocking mode, FIFO type and close-on-exec protection.
Unsafe or closed descriptors fail without changing their flags. No caller-provided
blocking I/O or named path is accepted through this channel's public API.

A fixed two-byte read accepts exactly one ASCII `R`. EOF before notification, a
wrong byte, already queued extra bytes, I/O failure or uncertain partial I/O is
failure. Empty nonblocking reads and interrupted syscalls are paced at 25 ms;
there is no busy loop or detached cancellation goroutine. The Go runtime may
schedule execution later than a deadline; the ceiling is a logical wait bound,
not a real-time scheduling guarantee. The API keeps the reader until `Close`.

Cancellation is checked before and after reads and wins when observed. Concurrent
cancellation can still happen just after success. Readiness is a startup snapshot,
not continuous health, a durable event, authenticated human approval or an operation
grant. A child can exit immediately after writing `R`; later bytes cannot be
predicted by a completed read. The supervisor must separately observe process exit,
signals and clean drain. On timeout it must preserve uncertain evidence and apply
an explicitly reviewed shutdown policy. This helper never kills, retries, repairs
or claims clean removal. Arbitrary holders of the writer can spoof the notification;
trusted descriptor delivery and child-image identity remain necessary.

Pipe creation and EOF semantics follow the Linux documentation for
[pipe2](https://man7.org/linux/man-pages/man2/pipe.2.html) and
[pipe lifetimes](https://man7.org/linux/man-pages/man7/pipe.7.html).

## Verification and remaining integration

The actual root launcher and independent bootstrap now use this production channel
and receiver in their real lifecycle tests. Existing readiness, client operations,
signals, crash preservation and restart assertions remain. Two new child-process
cases prove that a disconnected or full supervisor channel fails startup, preserves
private state and removes only exact startup-owned endpoint artifacts.

The mandatory actual-program campaign requires 276 named cases normally and with
the race detector. Its new monitor cases exercise valid data and EOF, malformed
bytes, cancellation, deadlines, unavailable or unsafe descriptors, repeated use and
sticky close failures. Unit fault injection checks syscall failure without fallback,
interrupted/empty-read pacing, cancellation during reads and both-handle cleanup.
All 132 independent cross-UID cases remain mandatory. No acceptance claim relies
on skipped privileged tests in an ordinary unprivileged test invocation.

Installed process creation and supervision, trust provisioning, dynamic dependency
approval, native sandbox/cgroup policy, identity providers, durable decision audit
and complete native IVV remain open. The new component does not activate the v5
authority. BunkerWeb retains its independent authenticated API, source-owned
transient bans, expiry, retries and HA, without a journal or dashboard dependency.
