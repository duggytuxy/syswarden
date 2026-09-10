# Explicit approval of existing ASN policy snapshots

Some historical ASN files contain legitimate public routes wider than the
generic IPv4 /24 and IPv6 /64 firewall-list limits. For example, an existing
AS16276 selection can include IPv4 /15 and IPv6 /32 routes. An upgrade must
not silently drop these routes or treat newly downloaded WHOIS data as trusted.

An operator can approve the exact bytes of an existing IPv4/IPv6 pair using a
private policy pin. This approval is local configuration authority. It is not
a publisher signature, a proof of ASN membership, or authorization to download
and accept a new snapshot. SysWarden never creates these pins automatically.

## Review and pin an exact pair

1. Export and preserve the installed configuration, both list files, and the
   active firewall policy. Verify a recovery point before changing the host.
2. Review the actual routes and their intended role. Confirm that the approved
   pair represents the existing operator-selected ASN policy. Record the
   independent SHA-256 digest of each reviewed file.
3. Prepare the following ASCII file using those already reviewed digests. Do
   not calculate and approve arbitrary current file contents in one unattended
   command. Substitute the exact selected ASN in the name and `list_base`.

```text
SYSWARDEN_ASN_POLICY_V1
list_base=allowed_AS16276
ipv4_sha256=<reviewed lowercase SHA-256 of allowed_AS16276.ipv4>
ipv6_sha256=<reviewed lowercase SHA-256 of allowed_AS16276.ipv6>
```

The final newline is required. The example placeholders must be replaced;
they are not accepted as digests. The filename for this example is
`/etc/syswarden/lists/allowed_AS16276.policy-pin`. A deny selection uses
`AS16276.policy-pin` and `list_base=AS16276` instead. Approval of an allow pair
cannot be reused as approval of a deny pair or another ASN.

4. Install the reviewed pin as a root-owned regular file with mode 0600 and
   one hard link. Both list files must also be root-owned regular files with
   mode 0600 and one hard link. Preserve their exact approved bytes. The list
   directory must be a real owner-controlled directory, with no writable group
   or other permissions. Coordinate writes using an exclusive lock on that
   directory; SysWarden holds its shared snapshot lock while preparing policy.
5. Run the normal installation or reload only after preserving operator SSH
   and the verified recovery path. Check the native exit status, package
   database, product services and actual firewall sets after the operation.

## Validation and failure behavior

Only configured ASN sources can use a policy pin. The complete pair must match
both approved digests before either source is accepted. The actual bytes are
checked again when the firewall parses them. A missing member, changed digest,
malformed pin, wrong purpose, symlink, additional hard link, unsafe permissions,
special file, or oversized file rejects the candidate policy.

Each file is limited to 8 MiB and 100,000 route records. Approved routes must be
canonical CIDRs of the correct address family. Default routes, private space,
special-purpose space, mapped addresses and noncanonical host bits remain
invalid. Overlapping approved routes are normalized without expanding their
combined address coverage. Host addresses must use explicit /32 or /128 CIDRs.

Without a pin, configured ASN files retain the generic /24 and /64 limits.
Generic allow lists, block lists, SSH exceptions, SaaS monitors and downloaded
threat feeds do not inherit this exception. Unsigned RADB refreshes remain
non-authoritative and cannot update an approved pair. A later change requires
a new explicit review of both files and replacement of the matching pin.

## Qualification boundary

Local regression tests and exact address-union comparisons do not qualify an
installed package. Candidate packages must be rebuilt, signed and tested on
the supported native hosts. This mechanism does not repair an immutable older
release or change the frozen NODE01 migration contract. Any replacement for
that historical migration route requires its own reviewed contract and fresh
native evidence before a release verdict can pass.
