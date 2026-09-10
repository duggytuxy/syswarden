# Native transport rule JSON

The adjacent `operator-policy-transport-native-nft*.json` files retain actual `nft -j list`
output captured on 2026-09-10 in disposable network namespaces. The four rules
have no hook and use documentation address ranges. Host firewall tables were
verified unchanged before and after each capture.

The 1.0.9 capture came from AlmaLinux 9.8, the 1.1.3 capture from Debian 13.6,
and the 1.1.5 capture from AlmaLinux 10.2. Ubuntu 26.04 and Alpine 3.24 both
produced the identical 1.1.6 capture. SHA256 digests:

- 1.0.9: `039d67f2def2a09853f675dbd18cd8750d5529e230dfb13ecd1ea1c29d672476`
- 1.1.3: `63ca633943c9cc2253bed2dc393082286a0a8a4672f695c5edca3ccb3ff16dce`
- 1.1.5: `7088d2bf2b1d17e5d2f67739c63e7724040d6217f25fed7ceaf5ce4f65a777d5`
- 1.1.6: `e83c7b96a83736adcb105324cf2714d937b7743e61a31177814d7bdb779f4d34`

Each submitted rule explicitly contained `meta l4proto tcp` or
`meta l4proto udp` before the matching transport destination-port expression.
The native JSON omits this redundant expression. The typed TCP or UDP payload
expression remains, as do the source match, counter and accept verdict.
The regression test reads these independent native captures instead of
constructing its successful input from the expected-expression builder.

The namespace received the following ruleset before
`nft -j list table inet sw4100_transport_probe`:

```nft
table inet sw4100_transport_probe {
 chain operator-policy {
  ip saddr 198.51.100.42/32 meta l4proto tcp tcp dport 80 counter accept comment "native-tcp-v4"
  ip6 saddr 2001:db8::42/128 meta l4proto tcp tcp dport 62028 counter accept comment "native-tcp-v6"
  ip saddr 198.51.100.0/24 meta l4proto udp udp dport 62028 counter accept comment "native-udp-v4"
  ip6 saddr 2001:db8:1::/64 meta l4proto udp udp dport 62028 counter accept comment "native-udp-v6"
 }
}
```
