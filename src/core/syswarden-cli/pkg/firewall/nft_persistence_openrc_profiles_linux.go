//go:build linux

package firewall

// Reviewed Alpine x86_64 nftables/OpenRC definitions. Hashes describe the
// distribution files, not ownership of firewall policy. Unknown revisions
// require review instead of evaluating arbitrary shell. Sources and versions
// are documented in docs/v5/OPENRC_NFTABLES_OBSERVATION.md.
func nftOpenRCProfiles() []map[string]string {
	return []map[string]string{
		{
			"/etc/init.d/nftables":                    "ffc3bba3fc17d93c251711529331321d53e2e67c52485afbf00911468aad86c2",
			"/sbin/openrc-run":                        "db2b75c083044393ab33fb9487107e7c92b1eb699b158e70493406822b8a100b",
			"/usr/libexec/rc/sh/openrc-run.sh":        "157ff55414d1d46ca5b83b4a15ffa781edfa60358961137baf6e288ad19eb393",
			"/usr/libexec/rc/sh/functions.sh":         "f136318dbfcf2a8bddccf48d3abcd05933e78c5b846bb25c9309fdf3268fe9dd",
			"/usr/libexec/rc/sh/rc-functions.sh":      "4ad2ebc7e5bdb7e3f8579cec1ca9abf4aba73286400d49dddf03d37840fd0041",
			"/usr/libexec/rc/sh/rc-cgroup.sh":         "43a4ac4974d25318a2379ffb79ade920791e03a06364e045e857c9298aaa2688",
			"/usr/libexec/rc/sh/runit.sh":             "8a625897484921d9fe44b91cd376d09679d1e20722c340c6e3e06291b3b59306",
			"/usr/libexec/rc/sh/s6.sh":                "cefca95504bdb97d804ffac2ed63f3209a6927d23c1147dcb8d342fc2c8317fe",
			"/usr/libexec/rc/sh/start-stop-daemon.sh": "2a35e632b84b463c86f428def1abb5342d53574f4f4e22d36b9330b55c66c922",
			"/usr/libexec/rc/sh/supervise-daemon.sh":  "f4a14ec76e68b465a221f1040facc4a9fb3c90cb6ec5eee6314c55a777c41935",
		},
		{
			"/etc/init.d/nftables":                    "ffc3bba3fc17d93c251711529331321d53e2e67c52485afbf00911468aad86c2",
			"/sbin/openrc-run":                        "9b1f2b4869daf94ba8d0e9eee45ac512b9c573caa04fa9bf29c43bed315ff4f6",
			"/usr/libexec/rc/sh/openrc-run.sh":        "6eeba8ef81e707b8da81d6277d7f9a2057b3ca935eacaad32712f7d443fb98dc",
			"/usr/libexec/rc/sh/functions.sh":         "42c03e4b0fc6e5e1c8ab5734a4856b3248410a022e28280126e46d938fb9e959",
			"/usr/libexec/rc/sh/rc-functions.sh":      "92fa74c60bbbb3e6ab15ef0a9f46b321097edce487218e2204f4f80c2d07d611",
			"/usr/libexec/rc/sh/rc-cgroup.sh":         "43a4ac4974d25318a2379ffb79ade920791e03a06364e045e857c9298aaa2688",
			"/usr/libexec/rc/sh/runit.sh":             "8a625897484921d9fe44b91cd376d09679d1e20722c340c6e3e06291b3b59306",
			"/usr/libexec/rc/sh/s6.sh":                "4882180cd01906c99d080305d821ea040b219e36b5b5e6c3a83066488ba3ff5a",
			"/usr/libexec/rc/sh/start-stop-daemon.sh": "2a35e632b84b463c86f428def1abb5342d53574f4f4e22d36b9330b55c66c922",
			"/usr/libexec/rc/sh/supervise-daemon.sh":  "f4a14ec76e68b465a221f1040facc4a9fb3c90cb6ec5eee6314c55a777c41935",
		},
	}
}
