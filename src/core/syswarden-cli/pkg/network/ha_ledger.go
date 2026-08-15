package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	DefaultHABanLedgerFile = "/var/lib/syswarden/ha/bans.json"
	maxCLIHALedgerBytes    = 16 * 1024 * 1024
	maxCLIHALedgerRecords  = 16_384
	cliHALedgerVersion     = 1
	maxCLIHASourceBytes    = 64
	maxCLIHAReasonBytes    = 512
)

type ActiveHABan struct {
	IP           string
	Source       string
	Reason       string
	PeerScope    string
	OriginPeerIP string
	ExpiresAt    time.Time
}

type cliHABanLedger struct {
	Version int                    `json:"version"`
	Bans    []cliHABanLedgerRecord `json:"bans"`
}

type cliHABanLedgerRecord struct {
	IP           string `json:"ip"`
	Source       string `json:"source"`
	Reason       string `json:"reason"`
	PeerScope    string `json:"peer_scope"`
	OriginPeerIP string `json:"origin_peer_ip"`
	ExpiresAt    string `json:"expires_at"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	State        string `json:"state"`
}

func ReadActiveHABans(path string, now time.Time) ([]ActiveHABan, error) {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || cleanPath != path {
		return nil, fmt.Errorf("HA ledger path must be absolute and canonical")
	}
	path = cleanPath
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect HA ledger parent: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA ledger parent must be a real directory")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open HA ledger parent: %w", err)
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		return nil, fmt.Errorf("HA ledger parent changed while opening")
	}
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect HA ledger: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("HA ledger must be a regular 0600 file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open HA ledger: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened HA ledger: %w", err)
	}
	current, err := root.Lstat(name)
	if err != nil || !opened.Mode().IsRegular() || !current.Mode().IsRegular() || opened.Mode().Perm() != 0600 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("HA ledger changed while opening")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxCLIHALedgerBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HA ledger: %w", err)
	}
	if len(wire) > maxCLIHALedgerBytes {
		return nil, fmt.Errorf("HA ledger exceeds %d bytes", maxCLIHALedgerBytes)
	}
	if err := rejectCLIHALedgerDuplicateKeys(wire); err != nil {
		return nil, fmt.Errorf("decode HA ledger: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var ledger cliHABanLedger
	if err := decoder.Decode(&ledger); err != nil {
		return nil, fmt.Errorf("decode HA ledger: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decode HA ledger: trailing JSON")
	}
	if ledger.Version != cliHALedgerVersion || len(ledger.Bans) > maxCLIHALedgerRecords {
		return nil, fmt.Errorf("unsupported or oversized HA ledger")
	}
	now = now.UTC()
	active := make([]ActiveHABan, 0, len(ledger.Bans))
	seen := make(map[string]struct{}, len(ledger.Bans))
	for index, record := range ledger.Bans {
		expires, err := validateCLIHALedgerRecord(record)
		if err != nil {
			return nil, fmt.Errorf("invalid HA ledger record %d: %w", index, err)
		}
		key := record.IP + "\x00" + record.Source + "\x00" + record.PeerScope
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate HA ledger record %d", index)
		}
		seen[key] = struct{}{}
		if record.State == "active" && expires.After(now) {
			active = append(active, ActiveHABan{
				IP: record.IP, Source: record.Source, Reason: record.Reason, PeerScope: record.PeerScope,
				OriginPeerIP: record.OriginPeerIP, ExpiresAt: expires,
			})
		}
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].IP != active[j].IP {
			return active[i].IP < active[j].IP
		}
		if active[i].Source != active[j].Source {
			return active[i].Source < active[j].Source
		}
		if active[i].PeerScope != active[j].PeerScope {
			return active[i].PeerScope < active[j].PeerScope
		}
		if active[i].OriginPeerIP != active[j].OriginPeerIP {
			return active[i].OriginPeerIP < active[j].OriginPeerIP
		}
		return active[i].ExpiresAt.Before(active[j].ExpiresAt)
	})
	return active, nil
}

func rejectCLIHALedgerDuplicateKeys(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	if err := scanCLIHALedgerJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanCLIHALedgerJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanCLIHALedgerJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanCLIHALedgerJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
}

func validateCLIHALedgerRecord(record cliHABanLedgerRecord) (time.Time, error) {
	canonical, err := canonicalHAAddress(record.IP)
	if err != nil || canonical != record.IP || !validCLIHAIdentifier(record.Source) || !validCLIHAReason(record.Reason) {
		return time.Time{}, fmt.Errorf("invalid address, source, or reason")
	}
	scope, err := netip.ParsePrefix(record.PeerScope)
	if err != nil || !scope.IsValid() || scope.Addr().Is4In6() || scope.Addr().Zone() != "" || scope != scope.Masked() {
		return time.Time{}, fmt.Errorf("invalid peer scope")
	}
	origin, err := netip.ParseAddr(record.OriginPeerIP)
	if err != nil || origin.Is4In6() || origin.Zone() != "" || !scope.Contains(origin) {
		return time.Time{}, fmt.Errorf("invalid observed origin")
	}
	created, createdErr := parseCLIHAUTC(record.CreatedAt)
	updated, updatedErr := parseCLIHAUTC(record.UpdatedAt)
	expires, expiresErr := parseCLIHAUTC(record.ExpiresAt)
	if createdErr != nil || updatedErr != nil || expiresErr != nil || updated.Before(created) || !expires.After(created) {
		return time.Time{}, fmt.Errorf("invalid timestamps")
	}
	if record.State != "pending_apply" && record.State != "active" && record.State != "pending_delete" {
		return time.Time{}, fmt.Errorf("invalid state")
	}
	return expires, nil
}

func parseCLIHAUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("timestamp is not canonical UTC RFC3339")
	}
	return parsed.UTC(), nil
}

func validCLIHAIdentifier(value string) bool {
	if len(value) < 1 || len(value) > maxCLIHASourceBytes {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("._:/-", character) {
			return false
		}
	}
	return true
}

func validCLIHAReason(value string) bool {
	if len(value) < 1 || len(value) > maxCLIHAReasonBytes || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func RenderActiveHABans(writer io.Writer, bans []ActiveHABan) error {
	if len(bans) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(writer, "[ HA Temporary Bans ]"); err != nil {
		return err
	}
	for _, ban := range bans {
		if _, err := fmt.Fprintf(writer, "  -> %s | claimed_source=%s | observed_origin=%s | peer_scope=%s | reason=%s | expires_at=%s\n",
			ban.IP, ban.Source, ban.OriginPeerIP, ban.PeerScope, ban.Reason, ban.ExpiresAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}
