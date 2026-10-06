//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	nftPolicyOwnershipName         = ".firewall-policy-ownership-v1.json"
	nftPolicyOwnershipSchema       = "syswarden-generated-policy-v1"
	maximumNFTPolicyOwnershipBytes = 128 << 10
)

// Generation inputs are captured by the policy writer, before its transaction.
// They are never inferred from an existing table or an unmarked source file.
type nftPolicyGeneration struct {
	Base          nftV4028PersistenceInputs `json:"base"`
	OperatorChain string                    `json:"operator_chain"`
}

type nftPolicyOwnership struct {
	Schema       string              `json:"schema"`
	Transaction  string              `json:"transaction_id"`
	SourceSHA256 string              `json:"source_sha256"`
	Generation   nftPolicyGeneration `json:"generation"`
}

func decodeNFTPolicyOwnership(content []byte) (nftPolicyOwnership, error) {
	var record nftPolicyOwnership
	if len(content) == 0 || len(content) > maximumNFTPolicyOwnershipBytes || json.Unmarshal(content, &record) != nil {
		return record, fmt.Errorf("generated policy ownership is not a bounded record")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(append(canonical, '\n'), content) || record.Schema != nftPolicyOwnershipSchema ||
		!nftTransactionIDPattern.MatchString(record.Transaction) || validateNFTPersistentDigest(record.SourceSHA256) != nil ||
		len(record.Generation.OperatorChain) == 0 || len(record.Generation.OperatorChain) > maximumCompiledOperatorPolicyBytes {
		return record, fmt.Errorf("generated policy ownership has noncanonical or inconsistent fields")
	}
	return record, nil
}

func prepareNFTPolicyOwnership(source []byte, generation *nftPolicyGeneration, transaction string) ([]byte, error) {
	if generation == nil {
		return nil, nil
	}
	if len(source) == 0 || len(source) > maximumNFTJournalFieldBytes || !nftTransactionIDPattern.MatchString(transaction) {
		return nil, fmt.Errorf("generated policy ownership lacks bounded transaction input")
	}
	baseEnd := bytes.Index(source, []byte("add element "))
	if baseEnd < 0 {
		baseEnd = len(source)
	}
	// The operator chain remains explicitly separate from product ownership.
	// Capture every writer input without imposing retirement profile limits on
	// normal policy application. Retirement separately checks the full model.
	base := source[:baseEnd]
	if generation.OperatorChain == "" || bytes.Count(base, []byte(generation.OperatorChain)) != 1 {
		return nil, fmt.Errorf("generated policy ownership does not match its operator chain")
	}
	record := nftPolicyOwnership{nftPolicyOwnershipSchema, transaction, nftSHA256Hex(source), *generation}
	content, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	content = append(content, '\n')
	if _, err := decodeNFTPolicyOwnership(content); err != nil {
		return nil, err
	}
	return content, nil
}

// Reconstruct populations only after their exact source hash is authorized by
// a private writer receipt. The independent full renderer check still runs.
func currentNFTInputsFromOwnership(source, ownership []byte) (nftCurrentPersistenceInputs, error) {
	var empty nftCurrentPersistenceInputs
	record, err := decodeNFTPolicyOwnership(ownership)
	if err != nil || record.SourceSHA256 != nftSHA256Hex(source) {
		return empty, fmt.Errorf("persistent policy differs from its writer ownership receipt")
	}
	operator, err := compileOperatorPolicy(nil)
	if err != nil || record.Generation.OperatorChain != operator.chain {
		return empty, fmt.Errorf("operator policy requires separate preservation before product retirement")
	}
	input := nftCurrentPersistenceInputs{Base: record.Generation.Base}
	remaining := ""
	if offset := bytes.Index(source, []byte("add element ")); offset >= 0 {
		remaining = string(source[offset:])
	}
	count := 0
	for _, spec := range nftCurrentPopulationSpecs(input.Base.Inet.Geo, input.Base.Inet.ASN) {
		population := nftCurrentPopulation{Name: spec.name}
		first := "add element netdev syswarden_hw_drop " + spec.name + " { "
		inet := "add element inet syswarden " + spec.name + " { "
		if spec.inetOnly {
			first = inet
		}
		for strings.HasPrefix(remaining, first) {
			line, tail, found := strings.Cut(remaining, "\n")
			if !found || !strings.HasSuffix(line, " }") {
				return empty, fmt.Errorf("owned persistent population has an incomplete command")
			}
			payload := strings.TrimSuffix(strings.TrimPrefix(line, first), " }")
			entries := strings.Split(payload, ", ")
			count += len(entries)
			if payload == "" || len(entries) > 4096 || count > maximumNFTRetirementPopulationEntries {
				return empty, fmt.Errorf("owned persistent population exceeds its bounded writer contract")
			}
			population.Entries = append(population.Entries, entries...)
			remaining = tail
			if !spec.inetOnly {
				paired := inet + payload + " }\n"
				if !strings.HasPrefix(remaining, paired) {
					return empty, fmt.Errorf("owned persistent population has inconsistent table copies")
				}
				remaining = strings.TrimPrefix(remaining, paired)
			}
		}
		input.Populations = append(input.Populations, population)
	}
	if remaining != "" {
		return empty, fmt.Errorf("owned persistent policy has unrecognized population commands")
	}
	if _, err := inspectNFTCurrentPersistentFile(source, input); err != nil {
		return empty, err
	}
	return input, nil
}

func readOptionalNFTPolicyOwnership(path string) ([]byte, error) {
	content, err := readPrivateRootedNFTFile(path, maximumNFTPolicyOwnershipBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := decodeNFTPolicyOwnership(content); err != nil {
		return nil, err
	}
	return content, nil
}

func validateNFTJournalOwnership(journal *nftTransactionJournal) error {
	if len(journal.CandidateOwnership) == 0 {
		if len(journal.PreviousOwnership) != 0 {
			return fmt.Errorf("firewall journal has previous ownership without a candidate")
		}
		return nil
	}
	candidate, err := decodeNFTPolicyOwnership(journal.CandidateOwnership)
	if err != nil || candidate.Transaction != journal.TransactionID || candidate.SourceSHA256 != journal.CandidatePersistentSHA256 {
		return fmt.Errorf("firewall journal candidate ownership is inconsistent")
	}
	if len(journal.PreviousOwnership) > 0 {
		previous, err := decodeNFTPolicyOwnership(journal.PreviousOwnership)
		if err != nil || !journal.PreviousPersistentExists || previous.SourceSHA256 != journal.PreviousPersistentSHA256 {
			return fmt.Errorf("firewall journal previous ownership is inconsistent")
		}
	}
	return nil
}

func commitNFTPolicyOwnership(stateDirectory string, journal *nftTransactionJournal) error {
	return commitNFTPolicyOwnershipUsing(stateDirectory, journal, defaultLegacyRetirementFileOps())
}

// Ownership is published only after the durable persisted phase. The journal
// binds both receipts before kernel mutation. Exchange preserves an unexpected
// concurrent file; retries reconcile an interrupted exchange without adoption.
func commitNFTPolicyOwnershipUsing(stateDirectory string, journal *nftTransactionJournal, ops legacyRetirementFileOps) error {
	if err := validateNFTTransactionJournal(journal); err != nil {
		return err
	}
	if len(journal.CandidateOwnership) == 0 {
		return nil
	}
	if journal.Phase != nftTransactionPersisted || !validLegacyRetirementOperations(func() error { return nil }, ops) {
		return fmt.Errorf("ownership publication requires a persisted transaction and complete filesystem operations")
	}
	if err := verifyNFTPersistentPolicy(filepath.Join(stateDirectory, filepath.Base(nftStateFile)), true, journal.CandidatePersistentSHA256); err != nil {
		return err
	}
	directory, err := os.OpenRoot(stateDirectory)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	fd, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()
	identity, err := fd.Stat()
	if err != nil {
		return err
	}
	stage := ".firewall-ownership-" + journal.TransactionID + ".pending"
	targetPath, stagePath := filepath.Join(stateDirectory, nftPolicyOwnershipName), filepath.Join(stateDirectory, stage)
	check := func() ([]byte, []byte, error) {
		if err := attestNFTStateDirectory(stateDirectory); err != nil {
			return nil, nil, err
		}
		current, err := os.Lstat(stateDirectory)
		if err != nil || !os.SameFile(identity, current) || identity.Mode() != current.Mode() {
			return nil, nil, fmt.Errorf("ownership publication directory changed")
		}
		durable, err := readNFTTransactionJournal(stateDirectory)
		if err != nil || !reflect.DeepEqual(durable, journal) {
			return nil, nil, fmt.Errorf("ownership publication differs from the durable transaction")
		}
		if err := verifyNFTPersistentPolicy(filepath.Join(stateDirectory, filepath.Base(nftStateFile)), true, journal.CandidatePersistentSHA256); err != nil {
			return nil, nil, err
		}
		target, err := readOptionalNFTPolicyOwnership(targetPath)
		if err != nil {
			return nil, nil, err
		}
		staged, err := readOptionalNFTPolicyOwnership(stagePath)
		return target, staged, err
	}
	target, staged, err := check()
	if err != nil {
		return err
	}
	if !bytes.Equal(target, journal.CandidateOwnership) {
		if !bytes.Equal(target, journal.PreviousOwnership) {
			return fmt.Errorf("ownership receipt changed before committed publication; preserve the journal")
		}
		if len(staged) == 0 {
			file, err := directory.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
			if err != nil {
				return err
			}
			if err := file.Chmod(0600); err != nil {
				return errors.Join(err, file.Close())
			}
			written, writeErr := file.Write(journal.CandidateOwnership)
			if written != len(journal.CandidateOwnership) {
				writeErr = errors.Join(writeErr, io.ErrShortWrite)
			}
			err = errors.Join(writeErr, ops.sync(file), file.Close(), ops.sync(fd))
			if err != nil {
				return err
			}
			if err := ops.checkpoint("policy-ownership-staged"); err != nil {
				return err
			}
		}
		target, staged, err = check()
		if err != nil || !bytes.Equal(target, journal.PreviousOwnership) || !bytes.Equal(staged, journal.CandidateOwnership) {
			return errors.Join(fmt.Errorf("ownership publication changed before its atomic commit"), err)
		}
		flag := uint(unix.RENAME_NOREPLACE)
		if len(journal.PreviousOwnership) > 0 {
			flag = unix.RENAME_EXCHANGE
		}
		if err := ops.rename(int(fd.Fd()), stage, int(fd.Fd()), nftPolicyOwnershipName, flag); err != nil {
			return err
		}
		if err := ops.checkpoint("policy-ownership-published"); err != nil {
			return err
		}
	}
	target, staged, err = check()
	if err != nil || !bytes.Equal(target, journal.CandidateOwnership) || len(staged) > 0 && !bytes.Equal(staged, journal.PreviousOwnership) {
		// Restore a concurrent replacement only if our exact candidate still
		// occupies the active path. Never unlink the displaced unknown file.
		if len(journal.PreviousOwnership) > 0 && bytes.Equal(target, journal.CandidateOwnership) {
			restoreErr := ops.rename(int(fd.Fd()), stage, int(fd.Fd()), nftPolicyOwnershipName, unix.RENAME_EXCHANGE)
			return errors.Join(fmt.Errorf("ownership exchange found a concurrent replacement"), err, restoreErr, ops.sync(fd))
		}
		return errors.Join(fmt.Errorf("ownership publication is ambiguous; preserve every receipt and the journal"), err)
	}
	if len(staged) > 0 {
		if err := directory.Remove(stage); err != nil {
			return err
		}
	}
	file, err := directory.OpenFile(nftPolicyOwnershipName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	if err := errors.Join(ops.sync(file), file.Close(), ops.sync(fd)); err != nil {
		return err
	}
	target, staged, err = check()
	if err != nil || !bytes.Equal(target, journal.CandidateOwnership) || len(staged) != 0 {
		return errors.Join(fmt.Errorf("ownership receipt is not exactly durable"), err)
	}
	return ops.checkpoint("policy-ownership-durable")
}
