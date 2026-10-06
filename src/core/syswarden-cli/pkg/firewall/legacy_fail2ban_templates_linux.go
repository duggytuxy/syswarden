//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
)

const (
	legacyFail2banTemplateRevision     = "b1f909c8d774b679f46156443020fa5af45eea33"
	legacyFail2banNFTAllPortsRevision  = "d1b9f5dac86c41dd9b5d4cc3d4cfc175ce1a8ead"
	maximumLegacyFail2banTemplateBytes = 64 << 10
)

// A match establishes source-template equivalence only. It does not attest
// filesystem metadata, effective Fail2ban settings, live action commands or
// other consumers of the file. Those dependencies must be checked separately
// before retiring a file or asking Fail2ban to stop a jail.
type legacyFail2banTemplateMatch struct {
	path             string
	sha256           [sha256.Size]byte
	kind             string
	jail             string
	banaction        string
	templateRevision string
	templateSource   string
}

// matchLegacyFail2banTemplate recognizes complete generated files from the
// official pre-v2 sources. Prefixes, filenames and partial heredocs alone are
// insufficient. No shell or configuration fragment is evaluated here.
func matchLegacyFail2banTemplate(path string, content []byte) (legacyFail2banTemplateMatch, bool) {
	if len(content) == 0 || len(content) > maximumLegacyFail2banTemplateBytes {
		return legacyFail2banTemplateMatch{}, false
	}
	match := legacyFail2banTemplateMatch{
		path: path, sha256: sha256.Sum256(content),
		templateRevision: legacyFail2banTemplateRevision,
		templateSource:   "src/functions/configure_fail2ban.sh",
	}
	if literal, found := legacyFail2banLiteralFilters[path]; found {
		if fmt.Sprintf("%x", match.sha256) != literal.sha256 {
			return legacyFail2banTemplateMatch{}, false
		}
		match.kind, match.templateSource = "filter", literal.source
		return match, true
	}
	var digest string
	switch path {
	case "/etc/fail2ban/action.d/syswarden-nft.conf":
		digest = "a5386f5d303ee719d7ab5e15f3243226f8301aaceae2a6ba816e5ca926b1171b"
	case "/etc/fail2ban/action.d/syswarden-webhook.conf":
		digest = "b6465036ab590957dbb10afd53a8c630782b4d132f20cf8e9c8c59fd04bc1919"
	case "/etc/fail2ban/action.d/syswarden-persistence.conf":
		digest = "b877eaa369698cc863cc41dd225bf9b8e84f058ca86914be61a9c0a827b8e9d1"
	case "/etc/fail2ban/jail.d/syswarden-portscan.conf":
		for _, log := range []string{"kern-firewall.log", "kern.log", "messages", "syslog"} {
			for _, backend := range []string{"auto", "systemd"} {
				for _, action := range []string{"iptables-allports", "nftables-allports", "syswarden-nft", "firewallcmd-allports", "ufw"} {
					for _, logSeparator := range []string{"   = ", "   =\n          "} {
						// The historical final alignment pass rewrote the space
						// before /var/log into an indented continuation line.
						expected := "[syswarden-portscan]\nenabled   = true\nport      = 0:65535\nfilter    = syswarden-portscan\nlogpath" + logSeparator + "/var/log/" + log +
							"\nbackend   = " + backend + "\nbanaction = " + action + "\nmaxretry  = 10\nfindtime  = 10m\nbantime   = 24h\n"
						if string(content) != expected {
							continue
						}
						match.kind, match.jail, match.banaction = "jail", "syswarden-portscan", action
						match.templateSource = "src/jails/29-portscan.sh"
						if action == "nftables-allports" {
							match.templateRevision = legacyFail2banNFTAllPortsRevision
						}
						return match, true
					}
				}
			}
		}
		return legacyFail2banTemplateMatch{}, false
	case "/etc/fail2ban/filter.d/syswarden-portscan.conf":
		// The literal heredoc is only a prefix. The generator always appends
		// an ignoreregex line, possibly containing escaped address literals.
		prefixEnd := bytes.Index(content, []byte("ignoreregex ="))
		if prefixEnd < 0 || fmt.Sprintf("%x", sha256.Sum256(content[:prefixEnd])) != "aa930dbb8740883a04b5a5e857b9c39911a88ed21bae30736194e14cc98d4c3c" {
			return legacyFail2banTemplateMatch{}, false
		}
		if !matchLegacyFail2banIgnoreLine(string(content[prefixEnd:])) {
			return legacyFail2banTemplateMatch{}, false
		}
		match.kind = "filter"
		match.templateSource = "src/jails/29-portscan.sh"
		return match, true
	default:
		return legacyFail2banTemplateMatch{}, false
	}
	if fmt.Sprintf("%x", match.sha256) != digest {
		return legacyFail2banTemplateMatch{}, false
	}
	match.kind = "action"
	return match, true
}

func matchLegacyFail2banIgnoreLine(line string) bool {
	if line == "ignoreregex =\n" {
		return true
	}
	const prefix, suffix = "ignoreregex = SRC=(", ") \n"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) {
		return false
	}
	entries := strings.Split(line[len(prefix):len(line)-len(suffix)], "|")
	for _, entry := range entries {
		literal := strings.ReplaceAll(entry, `\.`, ".")
		if strings.ReplaceAll(literal, ".", `\.`) != entry {
			return false
		}
		if _, err := netip.ParseAddr(literal); err != nil {
			if _, err := netip.ParsePrefix(literal); err != nil {
				return false
			}
		}
		// Scoped IPv6 addresses are not historical literal whitelist input.
		if strings.Contains(literal, "%") {
			return false
		}
	}
	return true
}
