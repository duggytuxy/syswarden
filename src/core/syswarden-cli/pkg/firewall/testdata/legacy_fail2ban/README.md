# Historical Fail2ban template fixtures

These fixtures come from official repository source, not operational feedback.
They are inert data for exact template recognition tests. Never execute the
historical generators as a cleanup procedure.

- `syswarden-*.conf`: literal action heredocs and the portscan filter in
  `src/functions/configure_fail2ban.sh` and `src/jails/29-portscan.sh` at
  `b1f909c8d774b679f46156443020fa5af45eea33`. The filter includes the required
  final empty `ignoreregex` line appended after its heredoc.
- `portscan-v1013*.conf`: jail output from `src/jails/29-portscan.sh` at
  `d1b9f5dac86c41dd9b5d4cc3d4cfc175ce1a8ead` using the nftables backend.
- `portscan-pre_v2*.conf`: the corresponding jail at
  `b1f909c8d774b679f46156443020fa5af45eea33` using the nftables backend.
- `*-aligned.conf`: output after the official final logpath indentation pass.

Dynamic fixture choices are `/var/log/kern.log` and the `systemd` backend.
A template match alone does not authorize file deletion or a runtime command.
Tests must also reject customized files and incomplete template prefixes.

`literal_filters.json` records 49 additional complete, quoted filter heredocs
at the same pre-v2 revision. Each entry binds the exact destination path,
generator source hash and output hash. The JSON strings preserve original
newlines and trailing spaces without normalizing the historical output.
The only appended prefixed filter at this revision is portscan, which remains
covered by its separate complete-output matcher. The final indentation pass
targets jail files, not filter files. Generic distribution filters and the
dynamic HTTP flood filter are not in this catalogue. Matching an unused
definition still requires complete inventory, installed-parser and runtime
preservation checks before private retirement.

The `effective-*.txt` files are successful `fail2ban-client -d` output from
Debian 13 Fail2ban 1.1.0-8 in disposable network namespaces with two synthetic
jails. Temporary test directory paths were normalized to
`/run/fail2ban-fixture/`; original private test receipts are unchanged.
`upstream` uses the packaged nftables-allports action. `historical` uses the
exact historical syswarden-nft action with another synthetic jail sharing it.
Before and after configuration validation succeeded. These fixtures test
command-stream preservation, not host ownership or complete removal.
