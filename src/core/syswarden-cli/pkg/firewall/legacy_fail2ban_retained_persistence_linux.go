//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"
)

// A historical table name can remain as an administrator container after its
// exact product entries were retired. This is permission to preserve one
// declaration, never permission to delete a table or ignore other references.
func unresolvedNFTPersistentProductReference(host nftPersistenceFilesystem, path string, content []byte) bool {
	return unresolvedNFTPersistentProductReferenceUsing(host, path, content, verifyRetainedLegacyFail2banKernel)
}

func unresolvedNFTPersistentProductReferenceUsing(host nftPersistenceFilesystem, path string, content []byte, observe func(legacyFail2banNFTTransition) error) bool {
	tokens, err := scanNFTPersistence(content)
	if err != nil {
		return true
	}
	var references []int
	for index, token := range tokens {
		if (token.kind == 'w' || token.kind == 'q') && strings.Contains(strings.ToLower(string(content[token.start:token.end])), "syswarden") {
			references = append(references, index)
		}
	}
	if len(references) == 0 {
		return false
	}
	if len(references) != 1 || observe == nil {
		return true
	}
	index := references[0]
	if index < 2 || nftPersistenceWord(content, tokens[index]) != "syswarden_f2b" || nftPersistenceWord(content, tokens[index-1]) != "inet" || nftPersistenceWord(content, tokens[index-2]) != "table" {
		return true
	}
	document, err := inspectNFTPersistence(content)
	if err != nil {
		return true
	}
	var declaration []byte
	for _, table := range document.tables {
		if table.family == "inet" && table.name == "syswarden_f2b" && table.start == tokens[index-2].start {
			declaration = content[table.start:table.end]
		}
	}
	if len(declaration) == 0 {
		return true
	}
	names, err := legacyFail2banPrivateReviewNames(host, legacyRetirementBackupRoot, 128)
	if err != nil {
		return true
	}
	matches, inspected := 0, 0
	for _, filePlan := range names {
		if !validLegacyRetirementDigest(filePlan) {
			continue
		}
		reviews, err := legacyFail2banPrivateReviewNames(host, legacyFail2banPlanPath(filePlan)+"/persistence", 64)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || inspected+len(reviews) > 256 {
			return true
		}
		inspected += len(reviews)
		for _, review := range reviews {
			if !validLegacyRetirementDigest(review) {
				return true
			}
			record, err := readLegacyFail2banPersistence(host, filePlan, review)
			if err != nil {
				return true
			}
			if verifyRetainedLegacyFail2banSource(host, path, declaration, record, review, observe) == nil {
				matches++
			}
		}
	}
	return matches != 1
}

func legacyFail2banPrivateReviewNames(host nftPersistenceFilesystem, path string, limit int) ([]string, error) {
	root, err := host.openDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	names, readErr := file.Readdirnames(limit + 1)
	closeErr := file.Close()
	if statErr != nil || info.Mode().Perm() != 0700 || readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) > limit {
		return nil, fmt.Errorf("retained persistence review inventory is not private and bounded")
	}
	sort.Strings(names)
	return names, nil
}

func verifyRetainedLegacyFail2banSource(host nftPersistenceFilesystem, path string, declaration []byte, record legacyFail2banPersistenceRecord, review string, observe func(legacyFail2banNFTTransition) error) error {
	_, reviewed, err := encodeLegacyFail2banPersistence(record, host)
	if err != nil || reviewed != review {
		return fmt.Errorf("retained source lacks its exact complete review")
	}
	_, digest, plans, err := encodeLegacyFail2banNFTJournalRecord(record.Kernel)
	if err != nil || digest == "" || observe == nil {
		return fmt.Errorf("retained table lacks independently bound historical targets")
	}
	var selected *legacyFail2banNFTTransition
	for index := range plans {
		if plans[index].family == "inet" && plans[index].table == "syswarden_f2b" {
			selected = &plans[index]
		}
	}
	if selected == nil {
		return fmt.Errorf("retained table is outside the reviewed historical action")
	}
	remainder, err := legacyFail2banNFTEntries(append(append([]byte(`{"nftables":`), selected.after...), '}'), selected.family, selected.table)
	if err != nil || len(remainder) < 2 {
		return fmt.Errorf("an empty historical table requires separate ownership review")
	}
	files, err := readLegacyFail2banPlan(host, record.FilePlan)
	if err != nil {
		return err
	}
	check := func() error {
		if _, err := readLegacyFail2banPersistence(host, record.FilePlan, review); err != nil {
			return err
		}
		state, err := inspectLegacyFail2banPlanState(host, files)
		if err != nil || len(state.retired) != len(files.Targets) {
			return fmt.Errorf("retained table still has incomplete historical configuration retirement")
		}
		for _, source := range record.Sources {
			if source.Artifact.Path != path || source.Artifact.SHA256 == source.EditedSHA256 {
				continue
			}
			shared, err := readNFTPersistenceSharedRecord(host, path, review)
			if err != nil || shared.Original != nftPersistenceGraphFileRecord(source, review) || shared.Xattrs != source.Xattrs || shared.Replacement.Source.SHA256 != source.EditedSHA256 {
				return fmt.Errorf("retained shared source differs from its reviewed edit")
			}
			state, err := inspectNFTPersistenceSharedStateUsing(host, shared, func(content []byte) (nftPersistenceEdit, error) {
				return planLegacyFail2banPersistence(content, record.Kernel)
			})
			if err != nil || state.phase != 2 {
				return fmt.Errorf("retained shared source has no complete exact original backup")
			}
			document, err := inspectNFTPersistence(state.replacement.content)
			if err != nil {
				return err
			}
			for _, table := range document.tables {
				if table.family == "inet" && table.name == "syswarden_f2b" && bytes.Equal(state.replacement.content[table.start:table.end], declaration) {
					return nil
				}
			}
		}
		return fmt.Errorf("retained declaration differs from the proven administrator remainder")
	}
	if err := check(); err != nil {
		return err
	}
	if err := observe(*selected); err != nil {
		return err
	}
	return check()
}

func verifyRetainedLegacyFail2banKernel(plan legacyFail2banNFTTransition) error {
	runner, err := newLegacyFail2banNFTRunner(plan)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	content, err := runner.Run(ctx, nil, "-j", "list", "table", plan.family, plan.table)
	if err != nil {
		return err
	}
	return matchRetainedLegacyFail2banKernel(content, plan)
}

// Handles may change on a reboot. Everything else, including rule order and
// administrator expressions, must still match the separately reviewed result.
// No write command is ever issued by this completion check.
func matchRetainedLegacyFail2banKernel(content []byte, plan legacyFail2banNFTTransition) error {
	canonical := func(wire []byte) ([]byte, error) {
		entries, err := legacyFail2banNFTEntries(wire, plan.family, plan.table)
		if err != nil {
			return nil, err
		}
		for _, raw := range entries {
			for _, value := range raw.(map[string]any) {
				delete(value.(map[string]any), "handle")
			}
		}
		return json.Marshal(entries)
	}
	expected, err := canonical(append(append([]byte(`{"nftables":`), plan.after...), '}'))
	if err != nil {
		return err
	}
	actual, err := canonical(content)
	if err != nil || !bytes.Equal(actual, expected) {
		return fmt.Errorf("retained historical table differs from the exact reviewed administrator remainder")
	}
	return nil
}
