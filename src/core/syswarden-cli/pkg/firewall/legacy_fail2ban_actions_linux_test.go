//go:build linux

package firewall

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const legacyFail2banActionFixture = `[["administrator-web",[["nft",[["actionstop",["s","nft delete set inet fixture owned"]],["banEpoch",["i",0]],["timeout",["i",60]],["ESCAPE_CRE",["r","ESCAPE_CRE"]]]]]]]`

func TestLegacyFail2banConfiguredActionsRejectAmbiguousData(t *testing.T) {
	valid := []byte(legacyFail2banActionFixture)
	if _, err := decodeLegacyFail2banConfiguredActions(valid); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		nil, []byte("null"), []byte("{}"), append(bytes.Clone(valid), []byte("[]")...),
		[]byte(`[["j",[]],["j",[]]]`), []byte(`[["j",[["a",[]],["a",[]]]]]`),
		[]byte(`[["j",[["a",[["name",["s","one"]],["name",["s","two"]]]]]]]`),
		bytes.Replace(valid, []byte(`["i",60]`), []byte(`["i",null]`), 1),
		bytes.Replace(valid, []byte(`["i",60]`), []byte(`["i",1.5]`), 1),
		bytes.Replace(valid, []byte(`["i",60]`), []byte(`["i",9223372036854775808]`), 1),
		bytes.Replace(valid, []byte(`["r","ESCAPE_CRE"]`), []byte(`["s","ESCAPE_CRE"]`), 1),
		bytes.Replace(valid, []byte(`["r","ESCAPE_CRE"]`), []byte(`["r","ESCAPE_VN_CRE"]`), 1),
		bytes.Replace(valid, []byte(`"actionstop"`), []byte(`"__class__"`), 1),
		bytes.Repeat([]byte("x"), (8<<20)+1),
	} {
		if result, err := decodeLegacyFail2banConfiguredActions(input); err == nil || result != nil {
			t.Fatal("ambiguous or partial configured actions accepted")
		}
	}
}

func TestLegacyFail2banConfiguredRuntimeRejectsChangedHooks(t *testing.T) {
	for _, change := range []string{"none", "epoch", "negative-epoch", "stop-hook", "missing-property", "extra-property", "missing-action", "extra-action", "missing-jail", "extra-jail"} {
		t.Run(change, func(t *testing.T) {
			expected, err := decodeLegacyFail2banConfiguredActions([]byte(legacyFail2banActionFixture))
			if err != nil {
				t.Fatal(err)
			}
			copy, err := decodeLegacyFail2banConfiguredActions([]byte(legacyFail2banActionFixture))
			if err != nil {
				t.Fatal(err)
			}
			live := legacyFail2banRuntimeSnapshot{jails: map[string]legacyFail2banRuntimeJail{
				"administrator-web": {actions: copy["administrator-web"]},
			}}
			actions := live.jails["administrator-web"].actions
			switch change {
			case "epoch":
				actions["nft"]["banEpoch"] = legacyFail2banValue{kind: 'i', number: 3}
			case "negative-epoch":
				actions["nft"]["banEpoch"] = legacyFail2banValue{kind: 'i', number: -1}
			case "stop-hook":
				actions["nft"]["actionstop"] = fixtureLegacyFail2banRuntimeString("nft flush ruleset")
			case "missing-property":
				delete(actions["nft"], "timeout")
			case "extra-property":
				actions["nft"]["custom"] = fixtureLegacyFail2banRuntimeString("changed")
			case "missing-action":
				delete(actions, "nft")
			case "extra-action":
				actions["custom"] = nil
			case "missing-jail":
				delete(live.jails, "administrator-web")
			case "extra-jail":
				live.jails["other"] = legacyFail2banRuntimeJail{}
			}
			err = verifyLegacyFail2banConfiguredRuntime(expected, live)
			if (err == nil) != (change == "none" || change == "epoch") {
				t.Fatal("unexpected configured/live action comparison", change, err)
			}
		})
	}
}

func TestLegacyFail2banProbeResolvesActionsWithoutExecutingHooks(t *testing.T) {
	root, host := fixtureLegacyFail2banInstalledParser(t)
	marker := filepath.Join(root, "must-not-exist")
	hook := "printf unsafe > " + marker
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/action.d/noop.local", "[Definition]\nactionstop = "+hook+"\n[Init]\ntimeout = 2m\n")
	probe, err := newLegacyFail2banConfigurationProbe(host)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal(err)
	}
	view, err := probe(inventory, nil)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := decodeLegacyFail2banConfiguredActions(view.actionsEnabled)
	if err != nil {
		t.Fatal(err)
	}
	values := actions["administrator-active"]["noop"]
	if values["actionstop"].text != hook || values["timeout"].kind != 'i' || values["timeout"].number != 120 {
		t.Fatal("installed action conversion or local override was lost")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("configuration inspection executed an action")
	}
	if !strings.Contains(values["actionban"].text, "/etc/fail2ban") {
		t.Fatal("original configuration root interpolation changed")
	}
	// Configuration cannot ask the inspection to invoke an action method.
	writeNFTPersistenceFixture(t, root, "/etc/fail2ban/action.d/noop.local", "[Init]\nstop = {}\n")
	inventory, err = inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe(inventory, nil); err == nil {
		t.Fatal("callable action property accepted")
	}
}
