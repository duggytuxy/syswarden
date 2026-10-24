# Prepared Alpine standalone removal

`scripts/ci/alpine_standalone_removal.py` is an explicit, separate v5 native
scenario for the real `syswarden uninstall` command. It does not change the
historical package lifecycle scenarios or their evidence contracts.

The candidate APK is only a verified payload source. The runner never installs
or removes SysWarden through APK and never changes its native registration.
It requires absent SysWarden registration and unchanged bytes and metadata for
the APK installed database and world file before initialization, after
initialization, after uninstall, after the unrelated firewall reload, and after
a real container restart.

## Inputs and execution

Run as an unprivileged user on Linux AMD64 with rootless Podman. Supply:

- A locally built v5 APK and its independently recorded SHA-256. The CLI must
  contain the exact core, TUI and signatures bindings produced by the repository
  package builders. Selected regular files, modes, ownership, launchers,
  architecture and companion bindings are checked before staging. Archive
  paths are never extracted to the host filesystem.
- An existing exact `sha256:` image ID for Alpine 3.22 or 3.24, prepared using the
  corresponding `package_lifecycle_lab.build_containerfile` contract. This
  includes real `/sbin/openrc-init` as the image command, the version-bound
  OpenRC configuration and hostname adjustments, installed lifecycle tools,
  enabled cronie and rsyslog, and the laboratory network and rsyslog-readiness
  providers. A stock Alpine image is insufficient. The runtime namespace,
  manager, cron and rsyslog attestations remain mandatory.
- A new absolute output directory whose parent already exists. Existing output
  directories are refused. Input and output parents must not contain symlinks.

```sh
python3 scripts/ci/alpine_standalone_removal.py \
  --run-native \
  --candidate /absolute/path/syswarden_5.00.0_x86_64.apk \
  --candidate-sha256 CANDIDATE_SHA256 \
  --image sha256:PREPARED_IMAGE_SHA256 \
  --alpine-version 3.22 \
  --output /absolute/path/new-standalone-result \
  --timeout 600
```

Replace both digest placeholders with exact lowercase hexadecimal values.
The runner never builds or pulls images. The container has no external network,
private namespaces, bounded memory/process counts and a two-CPU limit. Only
frozen selected payloads, helper scripts and the new result directory are
mounted. The compatibility `/previous` mount is empty. The container is removed
after execution; its absence is required. The supplied image is preserved.

## What this scenario establishes

The fixture explicitly selects the networkless historical policy, preserves
administrator TOML, independent configuration/data/certificate sentinels and
unrelated cron entries, and creates an independent OpenRC nftables protection.
Its dropped loopback probe must increment the independent rule's counter before
activation, afterward, after uninstall, after its own reload and after restart.

Fixture initialization invokes the real candidate `install` command with the
existing `SYSWARDEN_PKG_INSTALL=1` and
`SYSWARDEN_OFFLINE_QUALIFICATION=activate` opt-ins. These suppress dependency
acquisition and feed downloads while generating product runtime through real
code. They do not create native registration. The real uninstall runs in a clean
environment without either opt-in. Explicit fixture recovery approvals cover
only the exact synthetic cron, lists, UI and administrator TOML inventories.

Every ordered check is mandatory. Product services, rules, launchers, completion
and generated artifacts must be absent after uninstall, after unrelated reload
and after restart. Exact private recovery data must survive. The standalone
payload backup requires four candidate-bound files, exact modes, ownership,
single links, no extra entries, its content/device/inode-derived name and an
executable retained CLI. The restart must replace PID 1; a successful initial
command or a new network namespace alone cannot pass.

The private output contains `report.json`, the exact executed script, source and
candidate digests, `commands.jsonl` with command arguments/exit codes/output,
and detailed fixture results. Keep raw execution output local. Missing checks,
failed commands, missing restart evidence or failed cleanup produce failure.

This is prepared standalone-removal evidence. It does not establish standalone
installation, minimal fresh native installation, native remove/purge, dependency
retention through old/direct upgrades, SSH migration or final v5 IVVQ acceptance.
