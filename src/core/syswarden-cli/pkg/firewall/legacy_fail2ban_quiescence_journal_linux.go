//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"sort"
	"syscall"
)

const legacyFail2banQuiescenceSchema = "syswarden-legacy-fail2ban-quiescence-v1"

type legacyFail2banQuiescenceRecord struct {
	Schema      string     `json:"schema"`
	FilePlan    string     `json:"file_plan_sha256"`
	Actions     string     `json:"configured_actions_sha256"`
	Invocation  string     `json:"service_invocation"`
	PID         int32      `json:"process_id"`
	StartTicks  uint64     `json:"process_start_ticks"`
	Targets     []string   `json:"target_jails"`
	Transitions [][]string `json:"transitions"`
}

func encodeLegacyFail2banQuiescenceRecord(record legacyFail2banQuiescenceRecord) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", fmt.Errorf("invalid bounded Fail2ban quiescence intent")
	}
	invocation, err := hex.DecodeString(record.Invocation)
	if record.Schema != legacyFail2banQuiescenceSchema || !validLegacyRetirementDigest(record.FilePlan) || !validLegacyRetirementDigest(record.Actions) ||
		err != nil || len(invocation) != 16 || hex.EncodeToString(invocation) != record.Invocation || bytes.Equal(invocation, make([]byte, 16)) ||
		record.PID <= 1 || record.StartTicks == 0 || len(record.Targets) == 0 || len(record.Targets) > 128 || len(record.Transitions) > 4096 {
		return invalid()
	}
	targets := make(map[string]bool)
	for i, name := range record.Targets {
		if !validLegacyFail2banJailName(name) || name[0] == '-' || i > 0 && record.Targets[i-1] >= name {
			return invalid()
		}
		targets[name] = true
	}
	seen := make(map[string]bool)
	phase := 0
	idled, stopped := make(map[string]bool), make(map[string]bool)
	for _, command := range record.Transitions {
		encoded, err := encodeLegacyFail2banRetirementCommand(command)
		if err != nil || !targets[command[1]] || seen[string(encoded)] {
			return invalid()
		}
		seen[string(encoded)] = true
		if command[0] == "stop" {
			if !idled[command[1]] || stopped[command[1]] {
				return invalid()
			}
			phase = 2
			stopped[command[1]] = true
		} else if command[2] == "idle" {
			if phase != 0 || idled[command[1]] {
				return invalid()
			}
			idled[command[1]] = true
		} else {
			if phase > 1 || !idled[command[1]] {
				return invalid()
			}
			phase = 1
		}
	}
	if !reflect.DeepEqual(idled, stopped) {
		return invalid()
	}
	content, err := json.Marshal(record)
	if err != nil || len(content) > 1<<20 {
		return invalid()
	}
	return content, fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

// Jail selection comes from the complete official files already bound into
// the file plan. Neither a caller-supplied jail name nor a socket name is an
// ownership claim. The intent is recreated independently for each verified
// service invocation; old private records are retained after a reboot.
func makeLegacyFail2banQuiescenceRecord(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, inspection *legacyFail2banServiceInspection) (legacyFail2banQuiescenceRecord, error) {
	var empty legacyFail2banQuiescenceRecord
	if inspection == nil || inspection.process == nil || inspection.parser.digest != plan.binding.ParserSHA256 {
		return empty, fmt.Errorf("Fail2ban quiescence requires the file plan's inspected service and parser")
	}
	jails, _, err := legacyFail2banOwnedJails(host, plan)
	if err != nil {
		return empty, err
	}
	targets := make(map[string]bool)
	for name := range jails {
		targets[name] = true
	}
	expected, err := decodeLegacyFail2banConfiguredActions(inspection.actionsSource)
	if err != nil || !reflect.DeepEqual(expected, inspection.actions) {
		return empty, fmt.Errorf("Fail2ban configured action evidence changed")
	}
	stateFromConfiguration := legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail)}
	for name, actions := range expected {
		stateFromConfiguration.jails[name] = legacyFail2banRuntimeJail{actions: actions}
	}
	commands, err := planLegacyFail2banQuiescence(stateFromConfiguration, targets)
	if err != nil {
		return empty, err
	}
	var names []string
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	record := legacyFail2banQuiescenceRecord{
		Schema: legacyFail2banQuiescenceSchema, FilePlan: plan.sha256, Actions: fmt.Sprintf("%x", sha256.Sum256(inspection.actionsSource)),
		Invocation: inspection.status.values["InvocationID"], PID: inspection.status.peer.Pid, StartTicks: inspection.process.start,
		Targets: names, Transitions: commands,
	}
	_, _, err = encodeLegacyFail2banQuiescenceRecord(record)
	if err != nil {
		return empty, err
	}
	return record, nil
}

type legacyFail2banQuiescenceJournal struct {
	host    nftPersistenceFilesystem
	record  legacyFail2banQuiescenceRecord
	content []byte
	path    string
	file    nftPersistenceRead
	guard   func(context.Context) error
}

// The guard verifies the service, complete configuration, removal barrier,
// held locks and shared-kernel dependency proof. Publishing changes only a
// private recovery directory. It cannot stop a jail or edit active files.
func publishLegacyFail2banQuiescenceIntent(ctx context.Context, host nftPersistenceFilesystem, record legacyFail2banQuiescenceRecord, guard func(context.Context) error, ops legacyRetirementFileOps) (*legacyFail2banQuiescenceJournal, error) {
	if guard == nil || !validLegacyRetirementOperations(func() error { return guard(ctx) }, ops) {
		return nil, fmt.Errorf("Fail2ban quiescence requires complete intent guards")
	}
	content, digest, err := encodeLegacyFail2banQuiescenceRecord(record)
	if err != nil {
		return nil, err
	}
	if _, err := readLegacyFail2banPlan(host, record.FilePlan); err != nil {
		return nil, err
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	path := legacyFail2banPlanPath(record.FilePlan) + "/runtime/" + digest
	if err := ensureLegacyRetirementPrivateDirectory(host, path, ops); err != nil {
		return nil, err
	}
	directory, err := host.openDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	descriptor, err := directory.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = descriptor.Close() }()
	before, err := host.snapshot(path + "/intent.json")
	if errors.Is(err, fs.ErrNotExist) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		if err := publishLegacyRetirementJSON(directory, descriptor, "intent", content, ops); err != nil {
			return nil, err
		}
		before, err = host.snapshot(path + "/intent.json")
	}
	if err != nil || before.identity == nil || before.identity.Mode().Perm() != 0600 || !bytes.Equal(before.content, content) {
		return nil, fmt.Errorf("Fail2ban quiescence intent differs from its exact private record")
	}
	file, err := directory.OpenFile("intent.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	identity, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(before.identity, identity) {
		return nil, fmt.Errorf("Fail2ban quiescence intent changed before synchronization")
	}
	if err := errors.Join(ops.sync(file), ops.sync(descriptor)); err != nil {
		return nil, err
	}
	var bound legacyFail2banQuiescenceRecord
	if err := json.Unmarshal(content, &bound); err != nil {
		return nil, err
	}
	journal := &legacyFail2banQuiescenceJournal{host: host, record: bound, content: bytes.Clone(content), path: path, file: before, guard: guard}
	if err := journal.verify(ctx); err != nil {
		return nil, err
	}
	if err := ops.checkpoint("quiescence-intent-durable"); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *legacyFail2banQuiescenceJournal) verify(ctx context.Context) error {
	if journal == nil || journal.guard == nil {
		return fmt.Errorf("Fail2ban quiescence journal is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := journal.guard(ctx); err != nil {
		return err
	}
	if _, err := readLegacyFail2banPlan(journal.host, journal.record.FilePlan); err != nil {
		return err
	}
	directory, err := journal.host.openDirectory(journal.path)
	if err != nil {
		return err
	}
	info, err := directory.Stat(".")
	_ = directory.Close()
	if err != nil || info.Mode().Perm() != 0700 {
		return fmt.Errorf("Fail2ban quiescence journal directory is not private")
	}
	current, err := journal.host.snapshot(journal.path + "/intent.json")
	if err != nil || !sameLegacyFail2banSource(journal.file, current) || !bytes.Equal(current.content, journal.content) {
		return fmt.Errorf("Fail2ban quiescence journal changed")
	}
	return nil
}

// This proves durable membership only. A coordinator must additionally verify
// the phase and empty live hooks before an allowed stop can be authorized.
func (journal *legacyFail2banQuiescenceJournal) verifyTransition(ctx context.Context, command []string) error {
	if err := journal.verify(ctx); err != nil {
		return err
	}
	content, _, err := encodeLegacyFail2banQuiescenceRecord(journal.record)
	if err != nil || !bytes.Equal(content, journal.content) {
		return fmt.Errorf("Fail2ban quiescence intent changed in memory")
	}
	for _, allowed := range journal.record.Transitions {
		if reflect.DeepEqual(command, allowed) {
			return nil
		}
	}
	return fmt.Errorf("Fail2ban transition is not part of the durable quiescence intent")
}
