# BunkerWeb withdrawal and applied-state regression contract

Status: mandatory v5.00.0 IVVQ coverage. Component tests are executable;
real scheduler delivery, worker application and HTTP acceptance remain open.
This is a general integration contract, not a diagnosis of a deployment.

## Separate decisions and evidence

The SysWarden API publishes a list snapshot. BunkerWeb's SysWarden plugin
downloads lists into its own cache and builds local worker matchers. Removing
a local SysWarden entry does not prove that every configured peer, BunkerWeb
cache or worker has removed the corresponding restriction. The plugin reason
`syswarden` identifies the decision source, not a live query of the host kernel.
Historical request reports are not the current ban inventory.

For the separately pinned plugin 1.13 fixture, the download job runs hourly;
`SYSWARDEN_BLOCKLIST_INTERVAL` selects `hour` or `day`, with `hour` as default.
A fresh cache can postpone a read. A failed or incomplete collection preserves
the previous list. Therefore an hour is not a maximum convergence guarantee
during failure. A successful job exit requesting reload is not proof that the
scheduler delivered the new bytes or that every serving worker applied them.

Reference source:
[download job](https://github.com/bunkerity/bunkerweb-plugins/blob/45c1f989ca558f47a49046098de5586b06fd9ba7/syswarden/jobs/syswarden-blocklist-download.py)
and [worker matchers](https://github.com/bunkerity/bunkerweb-plugins/blob/45c1f989ca558f47a49046098de5586b06fd9ba7/syswarden/syswarden.lua).
The existing plugin 1.11 API baseline remains frozen. Neither fixture claims
acceptance for every later partner release.

`syswarden check` inspects local exact records and local nftables output. It
does not query partner caches, other peers or every covering CIDR policy.
An absent exact record cannot establish a global allow decision.

## Executable component checks

The regular core Go tests include
[published withdrawal snapshots](../../src/core/syswarden-core/network/bunkerweb_withdrawal_contract_test.go).
They exercise the actual authenticated API and durable ledger with a test
firewall dependency: IPv4 and IPv6, separate source scopes, deletion, expiry,
another retained claim, persistent administrator protection, the final empty
`{"ips":null}` response, idempotent withdrawal and reopening durable state.
Existing native-expiry, HA writer/fence and retry suites remain required.

The existing security-gate unittest discovery also runs the
[offline partner job regression](../../scripts/ci/bunkerweb_cache_regression_test.py).
It verifies pinned public source digests, runs the exact download job and
selected pure helpers with in-memory cache and HTTP substitutes, and checks:

- Fresh cached lists can outlive removal at the source until a refresh.
- Successful empty snapshots clear the final entry and request reload.
- Another configured peer retaining an entry prevents global withdrawal.
- Failed, malformed or invalid-address responses preserve previous lists.
- Cache-write failure does not claim successful delivery.
- Partial cache writes retain a pending-delivery marker and request another
  delivery even when the newly written cache is already fresh.
- Disabled integration performs no peer request.
- Successful empty reverse ban inventory differs from failed or incomplete
  inventory. It must not authorize withdrawal of other producers' claims.

The fake cache does not model worker acknowledgement. A pending marker cleared
by a reload request does not itself establish downstream success. The harness
does not execute TLS, own-claim exclusion, Redis, the real scheduler or Nginx.
It reads no deployment credentials and downloads no moving code during CI.

## Required native evidence before acceptance

Use the existing authorized AMD64 laboratory and exact candidate packages.
Record SysWarden, BunkerWeb and plugin identities separately, the peer set,
enabled list directions and actual scheduling settings. Keep operational
evidence private. Do not infer installed versions from a release page.

For each case, correlate the source/API snapshot, cache digest, delivery result,
serving worker generation and a new HTTP request with an independent request
identifier. Verify both the intended withdrawal and retained unrelated bans.
Use a controlled backend and expected application response; absence of a
`syswarden` reason alone is not proof that the request reached that backend.

| Case | Required outcome |
| --- | --- |
| Explicit withdrawal | The caller's eligible ban disappears from the API; after verified delivery and worker application, a new request has the expected application result if no other protection applies. |
| Final entry | A complete empty snapshot clears the old matcher; repeated empty refreshes do not resurrect it. Cover the deployed null-list wire shape. |
| Expiry | TTL is not renewed by polling, retry or restart; the published and applied states converge without removing other live claims. |
| Multiple owners and peers | Another source, peer, persistent entry, covering CIDR or native BunkerWeb ban remains effective; local withdrawal is not advertised as global unban. |
| Delayed polling | Previous enforcement and freshness are reported honestly before refresh; no instantaneous-success claim. |
| Failed collection or cache write | Previous known lists remain; failure is visible; successful retry converges without global cache flushing. |
| Delivery or worker reload failure | Failed delivery, one stale worker or an unavailable instance cannot be called applied. Verify subsequent recovery on all serving instances. |
| Restart and upgrade | Durable withdrawal remains withdrawn; worker/cache reconstruction agrees with current authorized sources. Record rollback behavior separately. |
| Scope and protocol variants | Exercise IPv4, IPv6, covering CIDRs, multisite, configured peer topology and supported TLS modes without widening allowlists. |
| Integration independence | The same sequence works without the dashboard; log-only or disabled synchronization creates no unexpected peer traffic or reload. |

A missing or skipped native case remains open. Source fixtures do not provide
native HTTP, all-worker or final IVVQ acceptance. Do not flush shared Redis or
nftables state, delete ownership records, or add blanket allowlist entries to
make a test pass.

## Dashboard interpretation

The BunkerWeb tab must distinguish local SysWarden state, last successful list
exchange, cache/delivery state when observed, and partner applied state when
independently verified. Use `unknown`, `stale` or `pending verification` when
evidence is missing. API success, a ping or a reload request is not an applied
acknowledgement. Preserve historical request events separately from active
claims. This contract adds no dashboard requirement to the integration API.
