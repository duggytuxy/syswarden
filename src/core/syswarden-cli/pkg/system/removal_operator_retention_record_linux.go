//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"syscall"
)

const operatorRetentionAuthority = "explicit-operator-retention-at-original-paths"

// The same bounded, canonical text is reviewed, hashed and read by the native
// post-removal script after the CLI no longer exists. Never evaluate this text
// as shell commands. Its only authority is preserving the listed paths.
func encodeOperatorConfigurationRetention(plan OperatorConfigurationRetentionPlan) ([]byte, error) {
	if plan.Schema != operatorRetentionSchema || plan.Authority != operatorRetentionAuthority || len(plan.Files) == 0 || len(plan.Files) > 128 {
		return nil, fmt.Errorf("invalid operator configuration retention inventory")
	}
	var wire strings.Builder
	wire.WriteString(operatorRetentionSchema + "\n" + operatorRetentionAuthority + "\n")
	for index, file := range plan.Files {
		id := file.Identity
		if !operatorRetentionPath(file.Path) || index > 0 && plan.Files[index-1].Path >= file.Path || file.CreationProvenance ||
			id.Inode == 0 || id.Mode != syscall.S_IFREG|0600 && id.Mode != syscall.S_IFREG|0640 ||
			file.Size < 0 || file.Size > 256<<10 || file.Modified.Sec < 0 || file.Changed.Sec < 0 ||
			file.Modified.Nsec < 0 || file.Modified.Nsec >= 1e9 || file.Changed.Nsec < 0 || file.Changed.Nsec >= 1e9 {
			return nil, fmt.Errorf("invalid operator configuration retention entry")
		}
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != file.SHA256 {
			return nil, fmt.Errorf("invalid operator configuration content fingerprint")
		}
		fmt.Fprintf(&wire, "file\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", file.Path,
			id.Device, id.Inode, id.Mode, id.UID, id.GID, file.Size, file.Modified.Sec, file.Modified.Nsec, file.Changed.Sec, file.Changed.Nsec, file.SHA256)
	}
	if wire.Len() > 64<<10 {
		return nil, fmt.Errorf("operator configuration retention record exceeds its byte bound")
	}
	return []byte(wire.String()), nil
}

func OperatorConfigurationRetentionPlanSHA256(plan OperatorConfigurationRetentionPlan) (string, error) {
	wire, err := encodeOperatorConfigurationRetention(plan)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

func decodeOperatorConfigurationRetention(content []byte) (OperatorConfigurationRetentionPlan, error) {
	plan := OperatorConfigurationRetentionPlan{Schema: operatorRetentionSchema, Authority: operatorRetentionAuthority}
	if len(content) > 64<<10 || !bytes.HasSuffix(content, []byte("\n")) {
		return plan, fmt.Errorf("operator configuration retention record is not bounded canonical text")
	}
	lines := strings.Split(string(content[:len(content)-1]), "\n")
	if len(lines) < 3 || len(lines) > 130 || lines[0] != plan.Schema || lines[1] != plan.Authority {
		return plan, fmt.Errorf("operator configuration retention record has an invalid header or inventory")
	}
	for _, line := range lines[2:] {
		file, err := decodeOperatorRetentionEntry(line)
		if err != nil {
			return plan, err
		}
		plan.Files = append(plan.Files, file)
	}
	canonical, err := encodeOperatorConfigurationRetention(plan)
	if err != nil || !bytes.Equal(canonical, content) {
		return plan, fmt.Errorf("operator configuration retention record is inconsistent or noncanonical")
	}
	return plan, nil
}

func decodeOperatorRetentionEntry(line string) (LegacyLogRetentionFile, error) {
	file := LegacyLogRetentionFile{}
	fields := strings.Split(line, "\t")
	if len(fields) != 13 || fields[0] != "file" {
		return file, fmt.Errorf("invalid operator configuration retention record fields")
	}
	var numbers [10]uint64
	for index, field := range fields[2:12] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return file, fmt.Errorf("invalid operator configuration retention metadata")
		}
		numbers[index] = value
	}
	var ownership [3]uint32
	for index, value := range numbers[2:5] {
		if value > math.MaxUint32 {
			return file, fmt.Errorf("operator configuration retention ownership exceeds its bounds")
		}
		ownership[index] = uint32(value)
	}
	var metadata [5]int64
	for index, value := range numbers[5:] {
		if value > math.MaxInt64 {
			return file, fmt.Errorf("operator configuration retention metadata exceeds its integer bounds")
		}
		metadata[index] = int64(value)
	}
	if metadata[0] > 256<<10 || metadata[2] >= 1e9 || metadata[4] >= 1e9 {
		return file, fmt.Errorf("operator configuration retention metadata exceeds its bounds")
	}
	file.Path, file.SHA256 = fields[1], fields[12]
	file.Identity = LegacyLogRetentionIdentity{Device: numbers[0], Inode: numbers[1], Mode: ownership[0], UID: ownership[1], GID: ownership[2]}
	file.Size = metadata[0]
	file.Modified, file.Changed = syscall.Timespec{Sec: metadata[1], Nsec: metadata[2]}, syscall.Timespec{Sec: metadata[3], Nsec: metadata[4]}
	return file, nil
}
