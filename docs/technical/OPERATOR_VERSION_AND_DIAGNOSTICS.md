# Version-aware operator guidance

Applies to: stable v4.04.3 and the v4.10.0 source candidate, as distinguished
below. Candidate behavior and regression tests do not establish native release
qualification.

This reference complements the [deployment tutorial](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial).
It incorporates independent Debian 13 and AlmaLinux feedback from
[Stephane Robert's installation guide](https://blog.stephane-robert.info/docs/securiser/reseaux/syswarden/).
Always identify the installed version before following documentation from main.

## Stable and candidate boundaries

| Area | Stable v4.04.3 | v4.10.0 source candidate |
| --- | --- | --- |
| HA | Legacy TLS and bearer-token synchronization | Optional HA v2 with explicit writer/standby roles, mTLS, pins and epoch controls |
| SSH authentication signature | Traditional syslog timestamp and `sshd` process | Also accepts ISO timestamps and `sshd-session` |
| Default WAAP log discovery | Can propose missing paths from another distribution | Discovers existing distro and BunkerWeb paths; explicit configured paths remain subject to validation |
| Native runtime history | Do not apply the candidate lifecycle contract | Separate verified lifecycle history described in the candidate reference |

Do not copy `v2_enabled`, `peer_cert_sha256` or `v2_secret_file` into a v4.04.3
installation. Use the [stable configuration procedure](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial#7-configuration-layout)
and the installed configuration schema. The
[HA v2 prerequisites](HA_V2_OPERATOR_PREREQUISITES.md) and
[native runtime lifecycle](NATIVE_RUNTIME_LIFECYCLE.md) describe the candidate.

## Diagnose SSH authentication events in order

1. Confirm that the SSH server generated an authentication failure. Inspect the
   effective `sshd` configuration and the actual authentication log or journal.
   When password authentication is disabled, a password test may produce only
   `Connection closed ... [preauth]` rather than `Failed password`. Image and
   local policy settings vary; do not infer a distribution-wide default or
   weaken production SSH authentication to generate a test.
2. Verify the configured WAAP inputs, their ownership and permissions, and
   delivery to the running core. An `[ALLOWED] ... SERVICE: sshd` event comes
   from a separate successful-login observer. It does not prove that the attack
   collector received or recognized the failure. For candidate input rules,
   see [custom log source trust](CUSTOM_LOG_SOURCE_TRUST.md). For explicit
   BunkerWeb paths, see the [configuration example](../../examples/bunkerweb/README.md).
3. Check the exact timestamp and process name against the installed signature.
   The v4.04.3 signature does not recognize the combination commonly observed
   in the reported Debian 13 lab: an ISO timestamp and `sshd-session`.
   [PR176](https://github.com/duggytuxy/syswarden/pull/176) and
   [PR185](https://github.com/duggytuxy/syswarden/pull/185) address the process
   name and timestamp respectively in the v4.10.0 candidate. Both are needed.
4. Check the threshold and time window. A recognized tracked event below the
   threshold can produce `SHADOW-ALERT`. That is evidence of recognition, not
   proof of a ban. Successful logins and connection-close records deliberately
   do not count as failed authentication. `Invalid user` is a separate
   recognized failure pattern; disabling passwords does not imply that every
   SSH detection path is inactive.
5. Check whether the source is an eligible firewall target. Loopback, private
   and special-use addresses are protected independently of `lan_subnets`.
   Removing `10.0.0.0/8` from that setting does not make RFC1918 sources eligible
   for dynamic enforcement. Recognized protected sources can still produce
   `SHADOW-ALERT`; the public-address restriction concerns enforcement, not all
   parsing or detection.
6. Check the enforcement mode and the result. Audit mode does not install a
   ban. In enforcing mode, correlate the source and rule with the ban outcome,
   persistent state and actual kernel enforcement. A shadow event alone is not
   sufficient. For an end-to-end test, use an authorized public source under
   your control, outside allowlists, with verified console recovery available.
   Retain existing protection until that chain is validated.

The independent v4.04.3 lab reported this recognition matrix:

| Timestamp | Process | Recognized failure reaching enforcement |
| --- | --- | --- |
| ISO | `sshd-session` | No |
| ISO | `sshd` | No |
| Traditional syslog | `sshd-session` | No |
| Traditional syslog | `sshd` | Yes, with an eligible source and threshold reached |

The candidate's existing
[SSH regression matrix](../../src/core/syswarden-core/engine/ssh_session_catalog_test.go)
crosses both process names, IPv4/IPv6, six timestamp envelopes and four failure
patterns. Negative cases cover successful logins, connection-close records,
forged process identities and malformed timestamps. These are parsing and
threshold tests, not a substitute for a real SSH-to-kernel qualification test.
Use your own controlled public source in a native lab, not documentation-range
addresses copied from unit tests.

## CLI location and configuration on a stable installation

Some RHEL-family sudo configurations omit `/usr/local/bin` from `secure_path`.
The package CLI link is `/usr/local/bin/syswarden`. If `sudo syswarden` reports
`command not found`, use its absolute path, for example:

```console
sudo /usr/local/bin/syswarden --help
```

This avoids changing the global sudo search path or adding an unmanaged binary
link. Use the same absolute path for the documented administrative commands.

The `--config` help default `/opt/syswarden/syswarden-auto.conf` is the legacy
configuration path retained for compatibility. A fresh modular installation
uses `/etc/syswarden/config/config.toml` and
`/etc/syswarden/config/modules/*.toml`. When the modules directory exists,
the CLI selects that modular root ahead of the legacy flag path. The absence
of the historical file alone does not indicate a broken installation. Follow the
[configuration layout](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial#7-configuration-layout)
and use `syswarden config validate --path /etc/syswarden/config` to inspect the
modular configuration. Do not create a legacy file simply to match the help
text. This documentation does not change configuration precedence or defaults.

## Legacy HA trust without changing system roots

Both v4.04.3 and the candidate CLI support the dedicated
`/etc/syswarden/ha-ca.pem` trust bundle for legacy `ha-sync`. When present and
valid, it supplies the CLI's HA trust roots instead of the system pool. When
absent, the CLI uses system trust. An invalid or unsafe bundle fails closed;
it is not ignored in favor of a permissive fallback.

Provision only independently authenticated public CA certificates, keep the
bundle and its directory protected, and retain certificate name/IP validation.
The file must be regular, not a symlink, owned by root or the effective CLI
user, and not writable by group or others. This does not require installing a
CA into the system-wide trust store and does not replace the HA bearer token.
See the [HA deployment procedure](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial)
for provisioning and [BunkerWeb integration](https://github.com/duggytuxy/syswarden/wiki/BunkerWeb-Integration)
for its separate client configuration. HA v2 has additional mutual-TLS and
identity requirements; the legacy bundle alone does not satisfy them.

Legacy HA rejects protected addresses before applying the submitted batch.
An HTTP 400 is not permission to bypass target validation or to silently skip
entries. The existing generic error may require reviewing the submitted list
locally to locate the invalid source.

## Authenticate a manual package download

For stable v4.04.3, `SHA256SUMS.txt` checks that downloaded packages agree with
the downloaded inventory. That alone does not authenticate the publisher:
replacing a package and its checksum would still pass that check.

The existing Ed25519 verifier checks the signed manifest against the repository's
trusted release keys, the expected version, and all three package sizes and
hashes. It needs a trusted source checkout and Go, and must run without sudo.
Before using it, authenticate that checkout and the release signing public key
through your established maintainer trust process. A key downloaded beside an
untrusted package does not establish independent trust. Do not edit the trusted
key inventory to make a failed verification pass.

For this pinned stable example, place the following regular files downloaded
from the [v4.04.3 release](https://github.com/duggytuxy/syswarden/releases/tag/v4.04.3)
in one directory, without subdirectories or symlinks:

- `syswarden_4.04.3_amd64.deb`
- `syswarden-4.04.3-1.x86_64.rpm`
- `syswarden_4.04.3_x86_64.apk`
- `SHA256SUMS.txt`
- `syswarden-update-manifest-v1.json`
- `syswarden-update-manifest-v1.json.sig`

From the root of the independently trusted source checkout, with the Go
toolchain required by that checkout available, run the existing verifier.
Replace the directory below with the absolute path to those downloaded files:

```sh
release_assets='/absolute/path/to/v4.04.3-assets'
GOFLAGS=-mod=readonly go run ./scripts/ci/update_manifest.go verify \
  --repository "$PWD" \
  --tag v4.04.3 \
  --packages "$release_assets" \
  --manifest "$release_assets/syswarden-update-manifest-v1.json" \
  --signature "$release_assets/syswarden-update-manifest-v1.json.sig"
```

Stop on any nonzero result. The tool verifies the complete three-package
inventory even when only one package will be installed. After successful
authentication, install only the package appropriate for the host using the
[installation procedure](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial#4-verify-and-install-one-package).
Do not run a newly downloaded CLI as the bootstrap verifier for itself.
An already trusted installation uses its embedded release keys during the
normal signed update flow.

The signed update manifest authenticates package metadata; it does not sign
every auxiliary release asset. The SPDX SBOM is an inventory for dependency
review. Do not infer SBOM authentication from a successful package-manifest
check. Native package signatures and complete release evidence have separate
checks; candidate documentation is not proof that a release has passed them.
