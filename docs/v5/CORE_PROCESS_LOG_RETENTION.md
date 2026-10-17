# Bounded core process logs

Status: development correction for [issue #391](https://github.com/duggytuxy/syswarden/issues/391).
The published baseline remains v4.10.4. Local component results do not establish
native lifecycle or final v5.00.0 IVVQ acceptance.

## Retention contract

The core process writes to the system journal and a bounded private file sink.
The managed sink keeps at most 16 MiB in `core.log` and one previous generation,
`core.log.1`, also at most 16 MiB. Rotation happens before the next write would
exceed the bound. Concurrent writes are serialized and another managed writer
cannot acquire the same directory lease.

The writer opens a new active inode after renaming the previous generation. It
does not use `copytruncate`, signal another process, invoke `systemctl`, reload
the firewall or restart the core. Existing `waf.json` telemetry retention remains
independent. System journal retention remains the operating system's policy;
these limits do not cap journald or unrelated application logs.

An oversized creation-attested generation from an older installation is reduced
to its most recent complete newline-delimited records on startup. The reader
loads at most 16 MiB, writes one private `.core.log.tail` staging inode, synchronizes
it and atomically replaces the proven source. Temporary extra storage is at most
16 MiB; the original oversized source still occupies its existing space until
publication. A crash before publication can leave a proven redundant staging
file, which the next startup retires only when its recorded source inode,
creation marker and modification metadata still match. Missing or changed source
evidence preserves the staging file and disables the file sink for review. A crash after active-to-retained rename
leaves the complete previous generation and permits a fresh active file.

This is a bounded rolling operational log, not permanent evidence retention or
a lossless archival service. Export required evidence separately under an
administrator-controlled retention policy before it ages out.

## Ownership and failure behavior

Every parent is opened without following symlinks. The final directory must be
service-owned with mode 0700 or 0750. Active, retained and staging files must be
regular 0600 inodes with one link and the service's UID/GID. The writer rechecks
the pinned directory, opened inode, pathname, permissions and creation marker.
An ordinary local user cannot supply a replacement file or copied marker to
authorize rotation. A marker binds the inode and creation time, not its name.

Only creation-attested product logs may be compacted, replaced or automatically
retired. Existing unmarked active logs can receive bounded appends but cannot be
adopted or rotated. Oversized unmarked logs, unknown retained files, malformed
markers, links and changed evidence stop file logging and remain untouched.
A newly created inode whose provenance cannot be recorded is also preserved.
The diagnostic requests explicit recovery rather than inventing ownership.

A file error, oversized single record or uncertain filesystem transition disables
that file sink until reopen. The independent system journal write continues and
a direct diagnostic reports degradation once, without recursively logging the
error. Startup refusal is visible in the journal too. No successful file-retention
claim applies to preserved unknown legacy data. Administrators must review and
privately archive such data before retrying, without deleting ownership evidence.

Do not combine external rotation with this managed sink. A renamed or replaced
active path is detected and refused; the process does not keep silently appending
to the externally renamed generation. An existing administrator logrotate policy
is not deleted or rewritten by this correction and must be reviewed separately.

## Removal and evidence

The CLI independently recognizes exactly `core.log`, `core.log.1` and
`.core.log.tail` as possible core-log entries alongside the two telemetry names.
Names alone confer no removal authority. Every entry must pass its own private
metadata, inode, birth-time and creation-marker checks. Proven logs follow the
existing private recovery-backup retirement path. Unknown or modified data keeps
the removal barrier in place. Explicit, digest-approved legacy retention may
preserve the same bounded inventory without assigning product ownership. Its
existing per-file size ceiling remains unchanged; larger unmarked archives need
separate administrator review. Do not truncate unknown data to force acceptance.

Component coverage includes limits, concurrent writes, fresh-open recovery,
owned oversized and sparse multi-gigabyte migration, unmarked data preservation,
wrong-kind/copied markers, links, special files, replaced parents, competing
writers, journal continuity and the independent CLI retirement inventory.
Actual service operation, scheduled host maintenance, reboot, and separate
`uninstall`, native `remove` and native `purge` paths remain required native
validation. Keep issue #391 open until the relevant acceptance evidence exists.
