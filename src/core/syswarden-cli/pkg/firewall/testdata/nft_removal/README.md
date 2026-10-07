# Synthetic nftables removal template fixtures

`arp_templates.json` contains outputs of the complete official Go ARP renderer
from the two commits recorded in its provenance metadata. The source bytes
were independently compared with the renderer statements in both commits.
Only documentation addresses are used. The JSON observations were obtained
from nftables in a disposable single-user network namespace.

These fixtures are product-source tests, not operational evidence. Full source
and kernel shape equivalence is only one part of removal authorization. The
source file identity, configuration lineage, producer quiescence, persistent
dependencies and live kernel generation still require independent attestation.
A matching table name or logging prefix is never sufficient.

`netdev_templates.json` contains sixteen independently compiled variants of
both the v4.02.8 and current Go ingress renderer, with Geo/ASN enabled or
disabled and one or two synthetic interfaces. The production profile catalogue
records the exact official source commits and hashes, literal renderer output
and a kernel template for each generation. Interfaces are fixture names only.

Ingress topology recognition requires a terse table observation with no set
elements. It does not attest the origin of populated sets. Independent source,
population and producer evidence is required before whole-table retirement.

`inet_sources.json` contains seventy-two synthetic source variants from the
historical and current Go renderer statements. The original product code was
parsed as source and was not executed. The cases were independently composed
and compiled by nftables in a disposable network namespace. They cover
Geo/ASN, strict allow mode, WireGuard, honeyports, empty or singleton port
lists, IPv6 LAN presence, and the historical duplicate-LAN behavior.

The source recognizer uses fixed compiled renderer statements and explicitly
validated input bindings. Historical Web-TUI permission and honeyport spacing
remain generation-specific. It does not inspect the live inet table or attest
where those inputs originated. Kernel topology, population ownership, source
lineage and producer evidence remain separate requirements.

`inet_kernel.json` contains the matching independent kernel observations for
those seventy-two cases. `nft_removal_inet_semantics.json` binds the original
renderer statements and line offsets to exact kernel declarations and rule
expressions. The source catalogue records both official commits and hashes.
The topology inspector compares all declarations and each chain's rule order.
It normalizes only validated handles, anonymous counter progress and the exact
typed operands bound to configuration inputs. Port and address operands use
bounded closed-interval equivalence, including singleton and merged sets.

An additional administrator rule, comment, object or unknown field is refused.
The live fixture repeats all cases in an isolated network namespace, preserves
an added administrator rule and demonstrates that terse topology recognition
cannot establish ownership of set populations. These tests do not authorize
whole-table removal or replace input lineage, producer and persistence checks.

`shell_templates.json` covers forty variants of the last official shell
renderer before v2, whose commit and complete source hash are recorded in
`nft_removal_shell_profile.json`. Literal heredocs and echo output were
extracted without executing the historical installer. Cases cover WireGuard,
IPv4 and IPv6 whitelist entries, duplicate historical entries, empty or varied
active-port lists, and conditional QUIC permission.

The historical comparator covers the complete `inet syswarden_table` block
and both chains, including ordered whitelist rules. It does not attest other
historical tables or included files. The live fixture removes only its own
synthetic tables through the generation fence and preserves a concurrent
administrator addition. Parameter provenance and persistent dependencies
remain separate prerequisites for production retirement.

`shell_serialized.json` records the actual `nft list table` output of those
forty cases. The historical installer persisted this representation rather
than its original heredoc text. `nft_removal_shell_serialization.json` binds
its fixed printer output to the same source statements and typed inputs.
The live persistence fixture also covers duplicate and singleton port sets,
port ordering and host prefixes, then reloads each exact printed table.

The persistence inspector accepts one complete historical inet table block.
It refuses appended statements, includes, custom rules and any mismatch with
live topology. It does not authorize retirement of an entire containing file;
file identity, additional tables, include dependencies and producer ownership
must be independently established before any file edit or removal.

The ingress fixtures also include eight variants of the pre-v2 shell renderer,
covering Geo/ASN branches and two synthetic interface choices. The profile
binds its set-name defaults to the exact official `src/core/00-config.sh`
source hash. Modified names, additional objects and population claims remain
outside this topology proof. The original installer is never executed by
these tests or by the compiled recognizer.

`netdev_persistence.json` contains sixteen independently captured historical
netdev dumps with empty or populated sets. The input populations are recorded
separately from kernel output and include adjacent prefixes, host addresses
and IPv4/IPv6 ranges. The persistence comparator requires equality between
those supplied populations, the persistent elements and the live elements.
Only interval-union equivalence and validated anonymous counter progress are
normalized. Added addresses, element metadata or custom rules are refused.

Agreeing persistent and live snapshots alone never prove population ownership.
The source of the supplied population inputs and every containing file,
dependency and producer still need independent attestation. The inspector is
read-only and does not authorize retirement by itself.

`historical_files.json` captures forty complete historical files by combining
the exact two original `nft list table` outputs. Both table generators share
the independently recorded whitelist input. Complete-file checks also cover
the forty inet-only forms left when the optional ingress dump was unavailable.
Extra blocks, includes, directives, comments and inconsistent whitelist inputs
are refused. This source-only evidence remains separate from live topology
evidence, allowing a later recovery planner to inspect old persistence after
an upgrade replaced its runtime. It does not establish input provenance, file
ownership, dependency ownership or permission to remove a file.

`current_files.json` contains eight complete current persistent files and their
independently captured kernel observations. They cover empty and populated
IPv4/IPv6 sets, address and port concatenations, ingress mirrors, Geo/ASN and
optional ARP protection. The fixed population writer order and chunk boundary
are compared against independently supplied inputs. All set values and complete
table topology must agree; element metadata and additional administrator
addresses are refused. Dynamic populations require separate runtime ownership
evidence. The current source binding also survives include-graph retirement
and recovery from its private journal. These checks do not establish input
origin, producer authority or native package removal qualification.
