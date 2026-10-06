//go:build linux

package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNFTOperatorReceiverObserverNeverGrantsMutationAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nft-observer")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\"\n"), 0700); err != nil {
		t.Fatal(err)
	} // #nosec G306 -- Private inert observer fixture records arguments only.
	fixtureLegacyFail2banNFTExecutable(t, path)
	runner, err := newExecNFTCommandRunner()
	if err != nil {
		t.Fatal(err)
	}
	valid := "operator_preserved_0123456789abcdef0123"
	output, err := runner.Run(context.Background(), nil, "-j", "list", "table", "inet", valid)
	if err != nil || string(output) != "-j list table inet "+valid+"\n" {
		t.Fatal("exact read-only receiver inspection failed", err)
	}
	for _, args := range [][]string{
		{"delete", "table", "inet", valid},
		{"-j", "delete", "table", "inet", valid},
		{"-j", "list", "table", "ip", valid},
		{"-j", "list", "table", "inet", valid, "extra"},
		{"-j", "list", "table", "inet", strings.ToUpper(valid)},
		{"-j", "list", "table", "inet", valid + "0"},
		{"-j", "list", "table", "inet", valid[:len(valid)-1]},
		{"-j", "list", "table", "inet", "operator_preserved_0123456789abcdef012; delete table inet x"},
		{"-j", "list", "table", "inet", "operator_preserved_0123456789abcdef012g"},
	} {
		if _, err := runner.Run(context.Background(), nil, args...); err == nil {
			t.Fatal("receiver observer authorized an unsupported action", args)
		}
	}
	if isSyswardenNFTTable(nftTableTarget{family: "inet", name: valid}) || isReservedNFTTableForUninstall(nftTableTarget{family: "inet", name: valid}) {
		t.Fatal("receiver namespace entered product deletion targets")
	}
}
