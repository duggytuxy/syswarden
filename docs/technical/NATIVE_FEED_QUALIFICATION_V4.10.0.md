# Native feed qualification for v4.10.0

Status: implemented evidence gate, not qualified.

The v4.10.0 release requires one candidate-bound native feed campaign on
NODE02, the disposable Ubuntu 26.04 AMD64 DEB qualification host.
Deterministic tests remain development evidence, but they do not satisfy this
native release gate.

The machine-readable contract is
`scripts/ci/native_feed_contract_v4.10.0.json`. The protected producer accepts
one exact raw bundle, recomputes `EVIDENCE.json` and `VERDICT.json`, and compares
both files byte for byte with the NODE02 outputs before sealing the native
release evidence bundle. The qualification workflow and both release manager
stages repeat the same computation.

## Required inputs

Use only the checked-out scripts from the exact candidate commit. The lab
requires canonical absolute paths to:

- the signed `syswarden_4.10.0_amd64.deb` and its detached `.asc` signature;
- the exact signed package inventory produced by the native signing workflow;
- `scripts/ci/native_package_signature_policy_v4100.json`;
- a temporary fixture certificate, private key and CA;
- a new evidence directory under the candidate SHA.

The fixture private key must be owned by root, have mode `0600`, and be stored
in a root-owned directory with mode `0700`. It is never copied into evidence.
The candidate package must already be installed on NODE02. The lab independently
verifies its OpenPGP signature, package bytes, DEB payload, installed CLI hash,
dpkg identity, ownership and `dpkg --verify` result before executing the CLI.

Example invocation:

```console
sudo bash /ABSOLUTE/CANDIDATE/scripts/ci/osint_tls_qualification_lab.sh \
  --mode-file /var/lib/syswarden-osint-fixture/mode \
  --evidence-dir /var/lib/syswarden/native-release-evidence/FULL_40_CHARACTER_SHA/native-feed \
  --candidate-sha FULL_40_CHARACTER_SHA \
  --deb-package /ABSOLUTE/SIGNED/syswarden_4.10.0_amd64.deb \
  --deb-signature /ABSOLUTE/SIGNED/syswarden_4.10.0_amd64.deb.asc \
  --signature-policy /ABSOLUTE/CANDIDATE/scripts/ci/native_package_signature_policy_v4100.json \
  --signature-inventory /ABSOLUTE/SIGNED/signed-inventory.json \
  --deb-key-id QUALIFIED_DEB_KEY_ID \
  --deb-signature-date YYYY-MM-DD \
  --fixture-cert /ROOT-PRIVATE/FIXTURE/server.crt \
  --fixture-key /ROOT-PRIVATE/FIXTURE/server.key \
  --fixture-ca /ROOT-PRIVATE/FIXTURE/ca.crt \
  --node02-ssh-host-key-sha256 SHA256:PINNED_NODE02_HOST_KEY \
  --campaign-id native-feed-node02-01
```

The CLI and list root are deliberately fixed to
`/opt/syswarden/bin/syswarden-cli` and `/etc/syswarden/lists`. They cannot be
overridden.

## Native scenarios

The lab owns the temporary `/etc/hosts` mapping, Ubuntu CA installation and TLS
1.3 fixture lifecycle. Proxy and alternate trust environment variables are
removed from every child process. The real installed `syswarden update-feeds`
command runs in this order:

1. `success` publishes the current validated feed while filtering the fixture
   6to4 entry.
2. `malformed` rejects a syntactically invalid source entry.
3. `below-minimum` rejects a syntactically valid source whose public entry count
   is below the product minimum.

The raw fixture journal binds each product request to its TLS version, host,
path, User-Agent, response and scenario time window. The accepted feed must
equal the deterministic union expected from the fixture. Both refusals must
preserve the accepted IPv4 and IPv6 feed bytes, hidden last-known-good snapshot,
provenance digest, and exact nftables set semantics.

## Exclusive-writer quarantine

NODE02 is a disposable qualification clone. Before the first product mutation,
the lab:

1. atomically creates and attests a root-private campaign lock directory under
   `/run/lock` without following or truncating an existing pathname;
2. rejects any unexpected `update-feeds` schedule or writer;
3. installs systemd condition drop-ins for `cron.service`,
   `syswarden-core.service` and `syswarden-firewall.service`;
4. durably synchronizes each new drop-in directory, reloads systemd and verifies
   all three drop-ins;
5. creates `/var/lib/syswarden/.native-feed-snapshot-restore-required` last;
6. locks the firewall path before the lists path, suspends the existing cron and
   core main processes, verifies their identity and stopped state, then releases
   both locks.

After the scenarios, the lab stops the fixture and restores `/etc/hosts` and the
Ubuntu CA store byte for byte. It intentionally does not restore the synthetic
feed or nftables state and never resumes cron or SysWarden. The same process
identities must remain stopped and the three systemd units must remain blocked
by the durable marker.

Export the completed evidence while SSH remains available, then restore the
clean Linode snapshot before any other use of NODE02. Only that snapshot restore
requalifies the node. If emergency access requires manually continuing a stopped
process, the campaign is invalid and the snapshot restore remains mandatory.

## Evidence staging

A successful lab creates this exact shape:

```text
/var/lib/syswarden/native-release-evidence/FULL_40_CHARACTER_SHA/
  native-feed/EVIDENCE.json
  native-feed/VERDICT.json
  native-feed/raw/SHA256SUMS
  native-feed/raw/<exact contract inventory>
```

Directories must be private and files must be singly linked, regular and
owner-controlled. Empty raw files are allowed only where the validator's fixed
allowlist requires an empty observation. `raw/SHA256SUMS` covers the exact raw
inventory, including final line endings and order.

The evidence binds the candidate SHA, NODE02 host identity and profile, signed
DEB identity, installed CLI, fixture transport, scheduler quarantine, all three
feed scenarios, provenance, last-known-good bytes, and both nftables address
sets. A passing verdict is one required v4.10.0 input. It does not authorize a
tag or public release by itself.
