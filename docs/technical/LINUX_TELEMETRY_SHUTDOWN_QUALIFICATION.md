# Linux telemetry shutdown qualification

Applies to the v4.10.0 candidate. This note does not qualify a release.

## Observed failure and fix

Native APK-324 execution on candidate
`2e81ce3579937a6c03d84ef65933cc9646b689c4` retained two failed shutdown
observations: the standard OpenRC stop exhausted its five-second TERM window,
and a separate identity-bound SIGTERM observation still had not exited after
30 seconds. Final logger drop/coalescing counters were absent. Both original
captures and the local regression against the unchanged candidate are retained
in private qualification evidence. The laboratory was restored and verified.

The Linux telemetry workers read a Bash command's stdout to EOF before calling
`Wait`. Default `CommandContext` cancellation kills Bash alone. Its tail or
journalctl descendants can keep stdout open, blocking the workers and preventing
the core from reaching logger shutdown.

Each telemetry command now starts a separate process group. Cancellation kills
that owned group, including its readers, while excluding the core and unrelated
processes. The constant scripts, collector paths, parsing rules, provenance
checks, logger budgets and native service stop limits remain unchanged. This
fix covers graceful cancellation; it does not establish crash recovery.

Regression tests exercise the actual commands with inert reader executables:
allowed-event collection with and without journalctl, plus kernel collection
through journalctl, OpenRC files and dmesg. Each reader must produce output
before cancellation, then close its inherited pipe and terminate. An unrelated
process using the same executable must survive. An already-cancelled command
must not start. Tests wait for EOF before `Wait`, matching the production worker.

## Candidate and evidence impact

This changes executable Linux core behavior. The earlier catalogue-only
comparison is not a continuity admission for this fix. The signature catalogue,
CLI and TUI source, package policy, frozen contracts, updater protocol and HA
protocol are unchanged, but each rebuilt artifact needs its own exact identity.

Before native use, build all four package variants from the reviewed merged
commit, obtain fresh protected signatures, independently verify their complete
inventories, and build and verify the protected candidate update bundle. Bind
each campaign to those exact commits, catalogues, package hashes and artifact
IDs. Local builds are supplemental and do not replace protected artifacts.

Replay policy:

| Evidence | Treatment |
| --- | --- |
| Failed APK-324 attempts on 2e81ce35 | Retain unchanged; never promote or relabel them as PASS. |
| APK-324 | Replay the complete frozen capability campaign, including default OpenRC stop, final queue counters and verified restoration. |
| Linux stop, restart, upgrade, downgrade and removal | Invalidate affected runtime observations for each package/init profile; replay shutdown and cleanup with the new signed core. |
| Logger and Linux runtime/performance observations | Reassess and replay affected measurements against the changed executable; do not claim binary-equivalent continuity. |
| Two native HA campaigns | Still outstanding; run each full 30-minute campaign on the new exact candidate, including crash/recovery and rolling transitions. |
| Global protected acceptance | Still outstanding; requires all constituent evidence to be bound or explicitly admitted to the new candidate. |
| Unchanged catalogues, contracts and unrelated historical results | Preserve original hashes and candidate bindings. Retention is not admission to the new candidate. |

No historical runtime PASS may move between commits by editing a manifest.
Selective reuse requires a separately reviewed, protected continuity decision
that names every eligible control, original observation, new artifact and
reason for equivalence. The existing PR257 continuity policy is restricted to
its own candidate pair and must not be reused here. Until a new decision is
accepted, affected current-candidate gates remain pending; if a frozen gate
cannot accept selective evidence, replay its complete profile.

Preparation, container exercises and local concurrency tests do not replace
native campaigns. Preserve the final node restoration receipts. No tag or
release publication is authorized by these activities.
