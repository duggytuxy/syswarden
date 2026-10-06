//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixtureLegacyFail2banNFTClaimPlan(t *testing.T, upstream bool) (string, nftPersistenceFilesystem, legacyFail2banRetirementPlan, legacyFail2banConfigurationView) {
	t.Helper()
	root, host := fixtureLegacyFail2banInstalledParser(t)
	packaged, err := os.OpenRoot(os.Getenv("SYSWARDEN_TEST_FAIL2BAN_CONFIG_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = packaged.Close() }()
	for _, path := range []string{"action.d/nftables.conf", "action.d/nftables-allports.conf", "filter.d/common.conf"} {
		content, err := packaged.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		writeNFTPersistenceFixture(t, root, "/etc/fail2ban/"+path, string(content))
	}
	defaults, err := host.root.ReadFile("etc/fail2ban/jail.conf")
	if err != nil {
		t.Fatal(err)
	}
	defaults = bytes.Replace(defaults, []byte("action = noop\n"), []byte("banaction = noop\naction = %(banaction)s[name=%(__name__)s, port=\"%(port)s\", protocol=\"tcp\"]\n"), 1)
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.conf", string(defaults))
	jail := "portscan-pre_v2.conf"
	if upstream {
		jail = "portscan-v1013.conf"
	}
	writeNFTPersistenceFixture(t, root, legacyPlanTarget, string(readLegacyFail2banFixture(t, jail)))
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/filter.d/syswarden-portscan.conf", string(readLegacyFail2banFixture(t, "syswarden-portscan-filter.conf")))
	probe, err := newLegacyFail2banConfigurationProbe(host)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareLegacyFail2banRetirement(host, []string{legacyPlanTarget}, probe)
	if err != nil {
		t.Fatal(err)
	}
	view, err := probe(plan.baseline, nil)
	if err != nil {
		t.Fatal(err)
	}
	return root, host, plan, view
}

func fixtureLegacyFail2banClaimRuntime(t *testing.T, view legacyFail2banConfigurationView) legacyFail2banRuntimeSnapshot {
	t.Helper()
	actions, err := decodeLegacyFail2banConfiguredActions(view.actionsEnabled)
	if err != nil {
		t.Fatal(err)
	}
	live := legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail)}
	for name, values := range actions {
		live.jails[name] = legacyFail2banRuntimeJail{actions: values}
	}
	target := live.jails["syswarden-portscan"]
	target.bans = []string{"127.0.0.2 \tfixture expiration"}
	live.jails["syswarden-portscan"] = target
	return live
}

func TestLegacyFail2banNFTClaimsJoinOfficialSourcesAndInstalledParser(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		_, host, plan, view := fixtureLegacyFail2banNFTClaimPlan(t, upstream)
		live := fixtureLegacyFail2banClaimRuntime(t, view)
		claims, err := bindLegacyFail2banNFTClaims(host, plan, view.parserSHA256, view.actionsEnabled, live)
		if err != nil {
			t.Fatal(err)
		}
		count := 1
		if upstream {
			count = 2
		}
		if len(claims) != count || claims[0].jail != "syswarden-portscan" || claims[0].filePlan != plan.sha256 ||
			claims[0].actionsSHA256 == "" || !reflect.DeepEqual(claims[0].bans, []string{"127.0.0.2"}) {
			t.Fatal("kernel claims lost their source or ban binding")
		}
		if upstream && (claims[1].addressFamily != "ip6" || len(claims[1].bans) != 0) {
			t.Fatal("uninstantiated IPv6 action profile was lost")
		}
		observation, _ := fixtureLegacyFail2banNFT(t, upstream)
		if _, err := prepareLegacyFail2banNFTTransition(observation, claims); err != nil {
			t.Fatal("source-bound claim failed exact kernel planning", err)
		}
	}
}

func TestLegacyFail2banNFTActionProfilesRejectChangedHooksAndParameters(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		_, _, _, view := fixtureLegacyFail2banNFTClaimPlan(t, upstream)
		profile := "syswarden-nft"
		if upstream {
			profile = "nftables-allports"
		}
		for _, change := range []string{"none", "timeout", "port", "stop", "start", "name", "set", "conditional", "extra", "missing", "executable-timeout", "known-chain", "custom-chain", "known-chain-changed-hook"} {
			live := fixtureLegacyFail2banClaimRuntime(t, view)
			properties := live.jails["syswarden-portscan"].actions[profile]
			switch change {
			case "timeout":
				properties["timeout"] = legacyFail2banValue{kind: 'i', number: 120}
			case "port":
				properties["port"] = fixtureLegacyFail2banRuntimeString("80,443")
			case "stop", "start":
				properties["action"+change] = fixtureLegacyFail2banRuntimeString("nft flush ruleset")
			case "name":
				properties["name"] = fixtureLegacyFail2banRuntimeString("administrator")
			case "set":
				properties["addr_set"] = fixtureLegacyFail2banRuntimeString("administrator-ban")
			case "conditional":
				properties["actionstop?family=inet6"] = fixtureLegacyFail2banRuntimeString("different")
			case "extra":
				properties["custom"] = fixtureLegacyFail2banRuntimeString("unreviewed")
			case "missing":
				delete(properties, "actioncheck")
			case "known-chain", "known-chain-changed-hook":
				properties["chain"] = fixtureLegacyFail2banRuntimeString("<known/chain>")
				if change == "known-chain-changed-hook" {
					properties["actionstart"] = fixtureLegacyFail2banRuntimeString("nft flush ruleset")
				}
			case "custom-chain":
				properties["chain"] = fixtureLegacyFail2banRuntimeString("administrator-chain")
			case "executable-timeout":
				properties["timeout"] = fixtureLegacyFail2banRuntimeString("unsafe")
			}
			err := verifyLegacyFail2banNFTActionProfile("syswarden-portscan", profile, properties)
			if (err == nil) != (change == "none" || change == "timeout" || change == "port" || change == "known-chain" || !upstream && change == "custom-chain") {
				t.Fatal("unexpected profile decision", profile, change, err)
			}
		}
	}
}

func TestLegacyFail2banNFTClaimsRefuseUnboundOrChangedEvidence(t *testing.T) {
	_, host, plan, view := fixtureLegacyFail2banNFTClaimPlan(t, false)
	for _, change := range []string{"parser", "plan", "live-hook", "other-jail", "missing-jail", "prefix-ban", "duplicate-ban", "ipv6-ban", "absent-time", "additional-action"} {
		live := fixtureLegacyFail2banClaimRuntime(t, view)
		copyPlan, parser := plan, view.parserSHA256
		target := live.jails["syswarden-portscan"]
		switch change {
		case "parser":
			parser = sha256.Sum256([]byte("different parser"))
		case "plan":
			copyPlan.sha256 = strings.Repeat("0", 64)
		case "live-hook":
			target.actions["syswarden-nft"]["actionstop"] = fixtureLegacyFail2banRuntimeString("")
		case "other-jail":
			live.jails["administrator-added"] = legacyFail2banRuntimeJail{}
		case "missing-jail":
			delete(live.jails, "syswarden-portscan")
		case "prefix-ban":
			target.bans = []string{"127.0.0.0/8\ttiming"}
		case "duplicate-ban":
			target.bans = append(target.bans, target.bans[0])
		case "ipv6-ban":
			target.bans = []string{"2001:db8::1\ttiming"}
		case "absent-time":
			target.bans = []string{"127.0.0.2"}
		case "additional-action":
			target.actions["custom"] = nil
		}
		if change != "missing-jail" {
			live.jails["syswarden-portscan"] = target
		}
		claims, err := bindLegacyFail2banNFTClaims(host, copyPlan, parser, view.actionsEnabled, live)
		if err == nil || claims != nil {
			t.Fatal("unbound kernel evidence returned a claim", change)
		}
	}
}

func TestLegacyFail2banNFTClaimsRefuseChangedOwnedSource(t *testing.T) {
	root, host, plan, view := fixtureLegacyFail2banNFTClaimPlan(t, false)
	content := readLegacyFail2banFixture(t, "portscan-pre_v2.conf")
	writeNFTPersistenceFixture(t, root, legacyPlanTarget, string(content)+"# administrator override\n")
	if claims, err := bindLegacyFail2banNFTClaims(host, plan, view.parserSHA256, view.actionsEnabled, fixtureLegacyFail2banClaimRuntime(t, view)); err == nil || claims != nil {
		t.Fatal("modified owned source authorized kernel cleanup")
	}
}
