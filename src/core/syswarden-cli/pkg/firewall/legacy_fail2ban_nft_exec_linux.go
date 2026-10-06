//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"time"
)

type legacyFail2banNFTRunner struct {
	executable execNFTCommandRunner
	plan       legacyFail2banNFTTransition
}

func newLegacyFail2banNFTRunner(plan legacyFail2banNFTTransition) (nftCommandRunner, error) {
	if !validLegacyRetirementDigest(plan.sha256) || plan.sha256 != plan.digest() {
		return nil, fmt.Errorf("Fail2ban nftables executable requires an exact bound plan")
	}
	runner, err := newExecNFTCommandRunner()
	if err != nil {
		return nil, err
	}
	executable, valid := runner.(execNFTCommandRunner)
	if !valid {
		return nil, fmt.Errorf("Fail2ban nftables executable is not pinned")
	}
	return bindLegacyFail2banNFTRunner(plan, executable)
}

func bindLegacyFail2banNFTRunner(plan legacyFail2banNFTTransition, executable execNFTCommandRunner) (nftCommandRunner, error) {
	if !validLegacyRetirementDigest(plan.sha256) || plan.sha256 != plan.digest() {
		return nil, fmt.Errorf("Fail2ban nftables executable requires an exact bound plan")
	}
	plan.before, plan.after, plan.claims, plan.transaction = bytes.Clone(plan.before), bytes.Clone(plan.after), bytes.Clone(plan.claims), bytes.Clone(plan.transaction)
	return legacyFail2banNFTRunner{executable: executable, plan: plan}, nil
}

// Keep this adapter separate from general firewall application. The only
// accepted write is this exact previously bound retirement transaction.
func (runner legacyFail2banNFTRunner) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	if runner.plan.sha256 != runner.plan.digest() {
		return nil, fmt.Errorf("Fail2ban nftables executable plan changed")
	}
	if reflect.DeepEqual(args, []string{"-j", "list", "table", runner.plan.family, runner.plan.table}) && input == nil {
		return observeLegacyFail2banNFT(ctx, runner.executable, runner.plan.table)
	}
	if !reflect.DeepEqual(args, []string{"-j", "-f", "-"}) || !bytes.Equal(input, runner.plan.transaction) {
		return nil, fmt.Errorf("Fail2ban nftables executable refuses an unbound command")
	}
	return runLegacyFail2banNFT(ctx, runner.executable, runner.plan.table, input)
}

// Absence comes from a successful complete table listing, never from an
// execution error or a missing-table diagnostic. A racing creation is caught
// by the next bound observation; it is never included in an old transaction.
func observeLegacyFail2banNFT(ctx context.Context, executable execNFTCommandRunner, table string) ([]byte, error) {
	if table != "syswarden_f2b" && table != "f2b-table" {
		return nil, fmt.Errorf("unsupported Fail2ban nftables observation target")
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	listing, err := executable.Run(child, nil, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("cannot establish the Fail2ban nftables table inventory")
	}
	present, err := legacyFail2banNFTTablePresence(listing, table)
	if err != nil {
		return nil, err
	}
	if !present {
		return []byte(`{"nftables":[]}`), nil
	}
	return runLegacyFail2banNFT(child, executable, table, nil)
}

func legacyFail2banNFTTablePresence(content []byte, table string) (bool, error) {
	document, err := decodeLegacyFail2banNFTJSON(content)
	if err != nil {
		return false, err
	}
	entries, valid := document["nftables"].([]any)
	if !valid || len(entries) > 16384 {
		return false, fmt.Errorf("invalid bounded nftables table inventory")
	}
	present, metadata := false, false
	seen := make(map[string]bool)
	for _, entry := range entries {
		object, valid := entry.(map[string]any)
		if !valid || len(object) != 1 {
			return false, fmt.Errorf("ambiguous nftables table inventory entry")
		}
		for kind, data := range object {
			value, valid := data.(map[string]any)
			if !valid {
				return false, fmt.Errorf("invalid nftables table inventory body")
			}
			if kind == "metainfo" && !metadata {
				if value["json_schema_version"] != json.Number("1") {
					return false, fmt.Errorf("unsupported nftables table inventory schema")
				}
				metadata = true
				continue
			}
			family, familyOK := value["family"].(string)
			name, nameOK := value["name"].(string)
			if kind != "table" || !familyOK || !nameOK || family == "" || name == "" || !legacyFail2banNFTHandle(value) || seen[family+":"+name] {
				return false, fmt.Errorf("nftables table inventory is incomplete or ambiguous")
			}
			seen[family+":"+name] = true
			present = present || family == "inet" && name == table
		}
	}
	return present, nil
}

func runLegacyFail2banNFT(ctx context.Context, executable execNFTCommandRunner, table string, transaction []byte) ([]byte, error) {
	if table != "syswarden_f2b" && table != "f2b-table" || len(transaction) > 1<<20 {
		return nil, fmt.Errorf("unsupported Fail2ban nftables execution target")
	}
	file, identity, err := pinNFTExecutable(executable.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if identity != executable.identity {
		return nil, fmt.Errorf("Fail2ban nftables executable changed identity")
	}
	child, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var command *exec.Cmd
	if transaction != nil {
		command = exec.CommandContext(child, "/proc/self/fd/3", "-j", "-f", "-")
		command.Stdin = bytes.NewReader(transaction)
	} else if table == "syswarden_f2b" {
		command = exec.CommandContext(child, "/proc/self/fd/3", "-j", "list", "table", "inet", "syswarden_f2b")
	} else {
		command = exec.CommandContext(child, "/proc/self/fd/3", "-j", "list", "table", "inet", "f2b-table")
	}
	command.ExtraFiles = []*os.File{file}
	command.Env = fixedLinuxWrapperCommandEnvironment()
	command.Dir = "/"
	command.WaitDelay = nftCommandProcessWait
	stdout, stderr := &boundedNFTCommandOutput{limit: 8 << 20}, &boundedNFTCommandOutput{limit: 65536}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || child.Err() != nil || stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("bound Fail2ban nftables command was not confirmed; details are withheld")
	}
	return bytes.Clone(stdout.content.Bytes()), nil
}
