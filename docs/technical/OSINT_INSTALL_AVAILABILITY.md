# OSINT supplement availability during installation

The built-in OSINT supplement accepts only public host addresses present in
both configured HTTPS sources. Its minimum intersection remains four entries.
Both responses must independently pass the existing transport, size, format,
address and source-origin checks before an intersection can be considered.

Two valid lists can contain fewer than four common addresses. This condition
previously stopped package configuration even after the separate Data-Shield
feed had passed its origin quorum. It can affect a fresh installation or a
reinstallation independently of WireGuard and historical service ownership.

## Lifecycle behavior

During installation, an insufficient intersection of otherwise valid sources
now omits the optional OSINT supplement with an explicit warning. That step
publishes no addresses and leaves existing feed snapshots and provenance
unchanged. The normal installer still reconciles selected feed provenance and
runs the independent Data-Shield validation before reaching this step.

Explicit and hourly feed refreshes still return the intersection error. The
hourly updater can retry when the upstream lists change. The correction does
not make an unavailable supplement appear current or fully populated.

The following failures remain blocking during installation:

- A malformed, empty or individually undersized source.
- Invalid transport, a rejected redirect or an unacceptable response type.
- Invalid or repeated source origins.
- A cancelled or expired operation.
- A feed publication or filesystem-integrity error.

No single-origin union is introduced. The minimum intersection, public-address
validation, provenance checks and existing firewall policy are unchanged.

## Verification scope

Regression tests cover empty and undersized intersections, new and existing
feed directories, successful corroborated publication, explicit refresh errors,
invalid sources, cancellation and duplicate origins. An omitted supplement
must preserve the complete existing directory inventory, file contents,
provenance and modification times.

The final signed v4.10.3 package passed installation and reinstallation checks
using independent valid HTTPS fixtures with no common addresses. Configuration
completed while retaining the validated primary snapshot, reporting the omitted
supplement and preserving unrelated firewall state. Explicit refresh and
malformed-source refusal were also checked. The
[publication record](../releases/v4.10.3/README.md) records protected Patch IVV
acceptance. Fixture results do not establish live upstream availability.

The upstream lists represent distinct observation sources. See the
[CINS Army description](https://cinsscore.com/) and the
[Blocklist.de export documentation](https://www.blocklist.de/en/export.html).
