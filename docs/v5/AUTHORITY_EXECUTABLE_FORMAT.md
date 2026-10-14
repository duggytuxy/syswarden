# Bounded native authority executable layout

Status: inactive Linux v5 launch control. Refs #224, #225 and #337, all partial.
Stable remains v4.10.4. No package, installed service or account is changed.

## Authentication before interpretation

`InspectAuthorityExecutableImage` first verifies the root-owned sealed image and
its independently supplied SHA-256 using the existing image contract. Only then
may it inspect the fixed ELF and program headers. Both the non-root bootstrap and
the root-to-service launcher require this inspection before their exec transition.
A correctly hashed script, foreign architecture or unsupported layout is refused.
Errors expose no partial profile and produce the existing fixed startup failure.
The snapshot API remains an opaque byte-preservation primitive; snapshot success
alone does not establish a valid executable layout.

The returned `AuthorityExecutableFormat` records the native architecture, ELF
position-independent type, dynamic-loading presence and declared interpreter.
The interpreter string is descriptive data. It is neither a trusted path nor an
approval to load dependencies. The inspector never opens it, resolves libraries,
spawns a command or changes the held image's offset.

## Deliberately bounded profile

The profile accepts little-endian ELF32 for `386` and ELF64 for `amd64` or `arm64`,
matching the actual launcher's compiled architecture. Other architectures fail.
This is parser coverage, not a new published platform-support claim. Identification
and object versions, ABI fields, machine identity, zero platform flags, exact header
sizes and executable object type must match the supported profile.

After the existing bounded 64 MiB authentication pass, format inspection makes at
most three exact positional reads: a 64-byte header, up to 64 program headers of
at most 56 bytes each, and at most 256 interpreter bytes. Fixed arrays bound memory.
Offsets and lengths are checked before conversion or reading. Short reads, I/O
errors, integer overflow and extended or excessive program-header counts fail.
No section, symbol, relocation or compressed debug table is parsed. The code does
not invoke the general-purpose `debug/elf` parser, whose documentation explicitly
excludes adversarial-input hardening from its security contract.

Load segments must be readable, ordered and nonoverlapping, with consistent
alignment and file/memory extents. Aggregate declared load memory and its virtual
span are each limited to 1 GiB; load alignment cannot exceed that bound. This is a header admission bound, not a runtime
RSS limit or an execution quota. The entry point must lie in file-backed executable
load bytes. Writable executable segments and an executable or absent GNU stack
declaration are rejected. These are declared segment checks; they do not establish
page-level W^X across every kernel, loader or later application mapping.

The supported forms are a static `ET_EXEC`, or an `ET_EXEC`/`ET_DYN` with a single
interpreter and matching dynamic segment. Self-relocating static PIE is outside
this initial profile and fails explicitly. A dynamic segment must describe a
bounded, consistently mapped part of a load segment. The interpreter must precede
loads, fit the fixed bound, contain one final NUL and name a canonical absolute
ASCII path without control characters. Duplicate declarations and unknown program
header types are rejected. The inspector accepts only the documented standard
headers and GNU stack, unwind, RELRO and property metadata used by the toolchain.
It does not evaluate the contents of dynamic tags, relocations or GNU properties.

The field relationships follow the [ELF header specification](https://gabi.xinuos.com/elf/02-eheader.html)
and [program-loading specification](https://gabi.xinuos.com/elf/07-pheader.html).
The parser choice follows the [Go debug/elf security notice](https://pkg.go.dev/debug/elf#hdr-Security).
This is a deliberately narrower product profile, not a universal ELF verifier or
a replacement for the kernel loader. A later kernel execution denial still fails
without a disk, shell or policy-bypass fallback.

## Evidence and remaining trust boundary

The required actual-executable campaign now contains 124 cases. It inspects all
three independently authenticated product images, observes whether their layouts
are static or dynamic, and verifies unchanged offsets. Eight additional startup
refusals inject correctly hashed sealed scripts or malformed architecture, load,
stack, table, entry-point and interpreter data. They exercise the real root launcher
and independent non-root bootstrap and require unchanged private inventories,
no readiness and the fixed failure status. Existing lifecycle and cross-UID cases
remain mandatory. Missing evidence cannot be treated as a passing result.

Unit cases exercise all three supported parser architectures, static and dynamic
profiles, field mutations, resource bounds and short/error reads. Fuzz input may
never escape the read/count/allocation bounds or expose a partial result. Normal
and race campaigns remain separate, including the actual cgo-linked race programs.

A pinned image does not pin its interpreter, shared libraries, loader cache,
configuration or kernel. Dynamic dependency provenance, freshness, path custody,
search paths and recursive closure still require a separately reviewed deployment
policy. Static code can also perform later dynamic loading; this header profile
cannot prove otherwise. No native package is activated while trusted provisioning,
loader/MAC/seccomp policy, installed lifecycle and human approval/audit remain open.
BunkerWeb retains its independent authenticated API, source-owned temporary bans,
expiry, retries and HA, without a new journal, dashboard or identity dependency.
