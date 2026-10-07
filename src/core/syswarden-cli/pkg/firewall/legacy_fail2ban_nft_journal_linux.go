//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"syscall"
)

func encodeLegacyFail2banNFTClaims(claims []legacyFail2banNFTClaim) ([]byte, error) {
	if len(claims) == 0 || len(claims) > 256 {
		return nil, fmt.Errorf("invalid bounded Fail2ban kernel claims")
	}
	var evidence [][]any
	for _, claim := range claims {
		evidence = append(evidence, []any{claim.jail, claim.profile, claim.addressFamily, claim.filePlan, claim.actionsSHA256, claim.bans})
	}
	content, err := json.Marshal(evidence)
	if err != nil || len(content) > 8<<20 {
		return nil, fmt.Errorf("Fail2ban kernel claims exceed their byte limit")
	}
	return content, nil
}

func decodeLegacyFail2banNFTClaims(content []byte) ([]legacyFail2banNFTClaim, error) {
	var records [][]json.RawMessage
	if len(content) == 0 || len(content) > 8<<20 || json.Unmarshal(content, &records) != nil || len(records) == 0 || len(records) > 256 {
		return nil, fmt.Errorf("invalid bounded Fail2ban kernel claim evidence")
	}
	var claims []legacyFail2banNFTClaim
	for _, record := range records {
		if len(record) != 6 {
			return nil, fmt.Errorf("incomplete Fail2ban kernel claim record")
		}
		var values [5]string
		for index := range values {
			if json.Unmarshal(record[index], &values[index]) != nil || bytes.Equal(record[index], []byte("null")) {
				return nil, fmt.Errorf("invalid Fail2ban kernel claim field")
			}
		}
		var bans []string
		if json.Unmarshal(record[5], &bans) != nil || len(bans) > 65536 {
			return nil, fmt.Errorf("invalid Fail2ban kernel claim ban list")
		}
		claims = append(claims, legacyFail2banNFTClaim{values[0], values[1], values[2], values[3], values[4], bans})
	}
	canonical, err := encodeLegacyFail2banNFTClaims(claims)
	if err != nil || !bytes.Equal(canonical, content) {
		return nil, fmt.Errorf("Fail2ban kernel claims are not canonical")
	}
	return claims, nil
}

const legacyFail2banNFTJournalSchema = "syswarden-legacy-fail2ban-kernel-v1"

type legacyFail2banNFTPlanRecord struct {
	Family      string `json:"family"`
	Table       string `json:"table"`
	Before      string `json:"before"`
	After       string `json:"after"`
	Claims      string `json:"claims"`
	Transaction string `json:"transaction"`
	Digest      string `json:"sha256"`
}

type legacyFail2banNFTJournalRecord struct {
	Schema     string                         `json:"schema"`
	Quiescence legacyFail2banQuiescenceRecord `json:"quiescence"`
	Plans      []legacyFail2banNFTPlanRecord  `json:"plans"`
}

func makeLegacyFail2banNFTJournalRecord(quiescence legacyFail2banQuiescenceRecord, plans []legacyFail2banNFTTransition) legacyFail2banNFTJournalRecord {
	record := legacyFail2banNFTJournalRecord{Schema: legacyFail2banNFTJournalSchema, Quiescence: quiescence}
	for _, plan := range plans {
		record.Plans = append(record.Plans, legacyFail2banNFTPlanRecord{plan.family, plan.table, string(plan.before), string(plan.after), string(plan.claims), string(plan.transaction), plan.sha256})
	}
	return record
}

// Rebuild every transaction from the original structured observation and
// source claims. A digest alone never authorizes a command loaded from disk.
func encodeLegacyFail2banNFTJournalRecord(record legacyFail2banNFTJournalRecord) ([]byte, string, []legacyFail2banNFTTransition, error) {
	invalid := func() ([]byte, string, []legacyFail2banNFTTransition, error) {
		return nil, "", nil, fmt.Errorf("invalid or inconsistent Fail2ban kernel retirement intent")
	}
	_, quiescenceDigest, err := encodeLegacyFail2banQuiescenceRecord(record.Quiescence)
	if err != nil || (record.Schema != legacyFail2banNFTJournalSchema && record.Schema != legacyFail2banCompleteNFTJournalSchema) || len(record.Plans) == 0 || len(record.Plans) > 2 {
		return invalid()
	}
	targets := make(map[string]bool)
	for _, name := range record.Quiescence.Targets {
		targets[name] = true
	}
	profiles := make(map[string]string)
	families := make(map[string]map[string]bool)
	var plans []legacyFail2banNFTTransition
	for index, entry := range record.Plans {
		if entry.Family != "inet" || index > 0 && record.Plans[index-1].Table >= entry.Table || len(entry.Before) > 8<<20 || len(entry.After) > 8<<20 || len(entry.Transaction) > 1<<20 {
			return invalid()
		}
		claims, err := decodeLegacyFail2banNFTClaims([]byte(entry.Claims))
		if err != nil {
			return invalid()
		}
		for index, claim := range claims {
			if !targets[claim.jail] || claim.filePlan != record.Quiescence.FilePlan || claim.actionsSHA256 != record.Quiescence.Actions ||
				index > 0 && (claims[index-1].jail > claim.jail || claims[index-1].jail == claim.jail && claims[index-1].addressFamily >= claim.addressFamily) {
				return invalid()
			}
			if profile, found := profiles[claim.jail]; found && profile != claim.profile {
				return invalid()
			}
			profiles[claim.jail] = claim.profile
			if families[claim.jail] == nil {
				families[claim.jail] = make(map[string]bool)
			}
			if families[claim.jail][claim.addressFamily] {
				return invalid()
			}
			families[claim.jail][claim.addressFamily] = true
		}
		observation := append(append([]byte(`{"nftables":`), []byte(entry.Before)...), '}')
		planner := prepareLegacyFail2banNFTTransition
		if record.Schema == legacyFail2banCompleteNFTJournalSchema {
			planner = prepareLegacyFail2banCompleteNFTTransition
		}
		plan, err := planner(observation, claims)
		if err != nil || plan.family != entry.Family || plan.table != entry.Table || plan.sha256 != entry.Digest ||
			string(plan.before) != entry.Before || string(plan.after) != entry.After || string(plan.claims) != entry.Claims || string(plan.transaction) != entry.Transaction {
			return invalid()
		}
		plans = append(plans, plan)
	}
	for name := range targets {
		if !families[name]["ip"] || profiles[name] == "nftables-allports" && !families[name]["ip6"] {
			return invalid()
		}
	}
	content, err := json.Marshal(record)
	if err != nil || len(content) > maximumNFTPersistenceBytes {
		return invalid()
	}
	return content, quiescenceDigest, plans, nil
}

type legacyFail2banNFTJournal struct {
	host           nftPersistenceFilesystem
	record         legacyFail2banNFTJournalRecord
	plans          []legacyFail2banNFTTransition
	content        []byte
	path           string
	quiescencePath string
	file           nftPersistenceRead
	guard          func(context.Context) error
}

func publishLegacyFail2banNFTIntent(ctx context.Context, host nftPersistenceFilesystem, record legacyFail2banNFTJournalRecord, guard func(context.Context) error, ops legacyRetirementFileOps) (*legacyFail2banNFTJournal, error) {
	if guard == nil || !validLegacyRetirementOperations(func() error { return guard(ctx) }, ops) {
		return nil, fmt.Errorf("Fail2ban kernel intent requires complete production guards")
	}
	content, quiescenceDigest, _, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil {
		return nil, err
	}
	if _, err := readLegacyFail2banPlan(host, record.Quiescence.FilePlan); err != nil {
		return nil, err
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	kernelDigest := fmt.Sprintf("%x", sha256.Sum256(content))
	path := legacyFail2banPlanPath(record.Quiescence.FilePlan) + "/runtime/" + quiescenceDigest + "/kernel/" + kernelDigest
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
	existing, err := host.snapshot(path + "/kernel.json")
	if errors.Is(err, fs.ErrNotExist) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		if err := publishLegacyRetirementJSON(directory, descriptor, "kernel", content, ops); err != nil {
			return nil, err
		}
		existing, err = host.snapshot(path + "/kernel.json")
	}
	if err != nil || existing.identity.Mode().Perm() != 0600 || !bytes.Equal(existing.content, content) {
		return nil, fmt.Errorf("Fail2ban kernel intent differs from its existing private evidence")
	}
	file, err := directory.OpenFile("kernel.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	identity, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(existing.identity, identity) {
		return nil, fmt.Errorf("Fail2ban kernel intent changed before synchronization")
	}
	if err := errors.Join(ops.sync(file), ops.sync(descriptor)); err != nil {
		return nil, err
	}
	journal, err := readLegacyFail2banNFTIntent(ctx, host, record.Quiescence, kernelDigest, guard)
	if err != nil {
		return nil, err
	}
	if err := ops.checkpoint("kernel-intent-durable"); err != nil {
		return nil, err
	}
	return journal, nil
}

// Recovery selects an exact reviewed digest. A changed administrator ban can
// produce a separately reviewed plan without replacing any earlier evidence.
// Never choose a record by timestamp or treat the newest file as authority.
func readLegacyFail2banNFTIntent(ctx context.Context, host nftPersistenceFilesystem, quiescence legacyFail2banQuiescenceRecord, kernelDigest string, guard func(context.Context) error) (*legacyFail2banNFTJournal, error) {
	_, digest, err := encodeLegacyFail2banQuiescenceRecord(quiescence)
	if err != nil || guard == nil || !validLegacyRetirementDigest(kernelDigest) {
		return nil, fmt.Errorf("Fail2ban kernel recovery requires exact guarded quiescence evidence")
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	quiescencePath := legacyFail2banPlanPath(quiescence.FilePlan) + "/runtime/" + digest
	path := quiescencePath + "/kernel/" + kernelDigest
	file, err := host.snapshot(path + "/kernel.json")
	if err != nil {
		return nil, err
	}
	var record legacyFail2banNFTJournalRecord
	if json.Unmarshal(file.content, &record) != nil || !reflect.DeepEqual(record.Quiescence, quiescence) {
		return nil, fmt.Errorf("Fail2ban kernel recovery evidence does not match this service invocation")
	}
	content, rebound, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil || rebound != digest || !bytes.Equal(content, file.content) || fmt.Sprintf("%x", sha256.Sum256(content)) != kernelDigest {
		return nil, fmt.Errorf("Fail2ban kernel recovery evidence is noncanonical or inconsistent")
	}
	journal := &legacyFail2banNFTJournal{host: host, record: record, plans: plans, content: content, path: path, quiescencePath: quiescencePath, file: file, guard: guard}
	// A preceding process can have stopped after rename and before directory
	// synchronization. Reading a visible intent is not proof of durability.
	if err := syncLegacyFail2banNFTIntent(host, path, file); err != nil {
		return nil, err
	}
	if err := journal.verify(ctx); err != nil {
		return nil, err
	}
	return journal, nil
}

func syncLegacyFail2banNFTIntent(host nftPersistenceFilesystem, path string, expected nftPersistenceRead) error {
	directory, err := host.openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	descriptor, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = descriptor.Close() }()
	file, err := directory.OpenFile("kernel.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	identity, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(expected.identity, identity) {
		return fmt.Errorf("Fail2ban kernel recovery intent changed before resynchronization")
	}
	return errors.Join(file.Sync(), descriptor.Sync())
}

func (journal *legacyFail2banNFTJournal) verify(ctx context.Context) error {
	if journal == nil || journal.guard == nil {
		return fmt.Errorf("Fail2ban kernel retirement journal is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := journal.guard(ctx); err != nil {
		return err
	}
	if _, err := readLegacyFail2banPlan(journal.host, journal.record.Quiescence.FilePlan); err != nil {
		return err
	}
	directory, err := journal.host.openDirectory(journal.path)
	if err != nil {
		return err
	}
	info, err := directory.Stat(".")
	_ = directory.Close()
	if err != nil || info.Mode().Perm() != 0700 {
		return fmt.Errorf("Fail2ban kernel retirement directory is not private")
	}
	current, err := journal.host.snapshot(journal.path + "/kernel.json")
	if err != nil || current.identity.Mode().Perm() != 0600 || !sameLegacyFail2banSource(journal.file, current) || !bytes.Equal(current.content, journal.content) {
		return fmt.Errorf("Fail2ban kernel retirement evidence changed")
	}
	return nil
}

// Durable membership is necessary but not sufficient: the caller's guard
// must independently prove target quiescence and all persistent dependencies.
func (journal *legacyFail2banNFTJournal) verifyTransition(ctx context.Context, digest string) error {
	if err := journal.verify(ctx); err != nil {
		return err
	}
	content, _, plans, err := encodeLegacyFail2banNFTJournalRecord(journal.record)
	if err != nil || !bytes.Equal(content, journal.content) {
		return fmt.Errorf("Fail2ban kernel intent changed in memory")
	}
	quiescence, err := journal.host.snapshot(journal.quiescencePath + "/intent.json")
	expected, _, encodeErr := encodeLegacyFail2banQuiescenceRecord(journal.record.Quiescence)
	if err != nil || encodeErr != nil || quiescence.identity.Mode().Perm() != 0600 || !bytes.Equal(quiescence.content, expected) {
		return fmt.Errorf("Fail2ban kernel cleanup lacks its exact durable quiescence intent")
	}
	for _, plan := range plans {
		if plan.sha256 == digest && plan.digest() == digest {
			return nil
		}
	}
	return fmt.Errorf("nftables transition is not part of the durable Fail2ban kernel intent")
}

func (journal *legacyFail2banNFTJournal) evidenceSHA256() string {
	return fmt.Sprintf("%x", sha256.Sum256(journal.content))
}
