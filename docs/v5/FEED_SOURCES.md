# Managed feed sources for v5

Development contract, pending the v5.00.0 IVVQ acceptance campaign.

Fresh native installation selects no list and defers activation until explicit
configuration through `syswarden config`. When selected, list 1 (standard) and
list 2 (critical) use only their selected Data-Shield IPv4 feed. SysWarden no
longer downloads or merges the former CINS and blocklist.de supplement in these
modes. The existing independent mirror quorum, canonical
address validation, provenance and protected publication checks remain required.
No replacement provider or single-origin exception is introduced.

The historical `network.blocklists.osint_enabled` TOML field remains readable
for compatibility. Either value has no effect on managed source selection.
Existing administrator configuration is not rewritten. Neither a reload nor
an hourly update can reactivate the retired providers through this field.
An old combined snapshot cannot be relabeled as Data-Shield-only: its provenance
is rejected, and normal reconciliation requires a fresh verified Data-Shield
snapshot. A supplemental IPv6 snapshot is no longer selected. No address is
removed by guessing its original provider, and user-managed lists are not edited.

An offline upgrade cannot manufacture matching source evidence. A historical
combined snapshot requires an online verified refresh before offline acceptance.
If rebuilding fails, the operation reports failure; it must not attest the old
combined snapshot as compliant with the new selection. Unrelated firewall policy,
local custom lists and independent BunkerWeb decisions retain their own contracts.

Pinned custom feeds in choice 3, no-feed choice 4, LAN mode, embedded GeoIP and
separately selected ASN features keep their existing boundaries. This change
concerns SysWarden's direct supplement and provenance. It does not claim to audit
or change the upstream composition of the maintainer-curated Data-Shield lists.

Historical v4 fixtures and sealed evidence keep their original provider bytes.
They are not v5 source-selection acceptance. Candidate regression tests cover
both managed lists, historical TOML values, rejected combined provenance, stale
IPv6 retirement and preservation of matching Data-Shield snapshots.
