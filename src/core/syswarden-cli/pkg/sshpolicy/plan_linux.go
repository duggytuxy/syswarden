//go:build linux

package sshpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syswarden-cli/pkg/sshselection"
)

// PlanSummary contains no configuration contents, account names, addresses or
// hostnames. Its digest identifies an inspection, not an apply authorization.
type PlanSummary struct {
	Schema               int    `json:"schema"`
	Operation            string `json:"operation"`
	Role                 string `json:"role"`
	Owner                string `json:"owner"`
	Profile              string `json:"profile"`
	ContextCount         int    `json:"context_count"`
	LegacyEditCount      int    `json:"legacy_edit_count"`
	MainBeforeSHA256     string `json:"main_before_sha256"`
	MainAfterSHA256      string `json:"main_after_sha256"`
	DropInSHA256         string `json:"drop_in_sha256,omitempty"`
	PlanSHA256           string `json:"plan_sha256"`
	SSHHardening         string `json:"ssh_hardening"`
	SSHSelectionDeclared bool   `json:"ssh_selection_declared"`
	ApplyAvailable       bool   `json:"apply_available"`
}

type migrationPlan struct {
	selection sshselection.Config
	intent    intent
	inventory inventorySnapshot
	main      []byte
	candidate Candidate
	summary   PlanSummary
}

// InspectPlan performs a root-only, read-only inspection of fixed production
// paths. It neither loads general SysWarden configuration nor creates a lock,
// backup, receipt, directory or configuration file. No daemon is executed.
func InspectPlan() (PlanSummary, error) {
	if os.Geteuid() != 0 {
		return PlanSummary{}, fmt.Errorf("SSH policy inspection requires root")
	}
	root, err := os.Open("/")
	if err != nil {
		return PlanSummary{}, err
	}
	defer root.Close()
	plan, err := inspectPlan(root, 0)
	return plan.summary, err
}

func inspectPlan(root *os.File, uid int) (migrationPlan, error) {
	if root == nil {
		return migrationPlan{}, ErrInventoryUnsafe
	}
	snapshot, err := collectPlanInventory(root, uid)
	if err != nil {
		return migrationPlan{}, err
	}
	declaration, err := parseIntent(snapshot.files[IntentPath])
	if err != nil {
		return migrationPlan{}, err
	}
	plan, err := preparePlan(snapshot, declaration)
	if err != nil {
		return migrationPlan{}, err
	}
	current, err := collectPlanInventory(root, uid)
	if err != nil || !reflect.DeepEqual(current, snapshot) {
		return migrationPlan{}, fmt.Errorf("SSH policy inputs changed during planning: %w", ErrInventoryChanged)
	}
	return plan, nil
}

func collectPlanInventory(root *os.File, uid int) (inventorySnapshot, error) {
	if err := sshselection.RejectEnvironment(); err != nil {
		return inventorySnapshot{}, err
	}
	reader := inventoryReader{root: root, uid: uid,
		state: inventorySnapshot{files: make(map[string][]byte), nodes: make(map[string]inventoryStamp),
			entries: make(map[string][]string), links: make(map[string]string)},
		active: make(map[string]bool), walked: make(map[string]bool)}
	content, exists, err := reader.readFile(IntentPath)
	if err != nil {
		return inventorySnapshot{}, fmt.Errorf("inspect protected SSH administrator intent: %w", err)
	}
	if !exists {
		return inventorySnapshot{}, fmt.Errorf("explicit SSH role and ownership are required in %s; no default role is inferred", IntentPath)
	}
	metadata := reader.state.nodes[IntentPath]
	if metadata.mode&07777 != 0600 || int64(metadata.gid) != int64(uid) || len(content) > MaxIntentBytes {
		return inventorySnapshot{}, fmt.Errorf("SSH intent must be a private root-owned 0600 file within size bounds")
	}
	selection, selected, err := reader.readFile(sshselection.Path)
	if err != nil {
		return inventorySnapshot{}, err
	}
	if selected {
		metadata := reader.state.nodes[sshselection.Path]
		if metadata.mode&07777 != 0600 || int64(metadata.gid) != int64(uid) || len(selection) > sshselection.MaxBytes {
			return inventorySnapshot{}, fmt.Errorf("SSH selection must be a private root-owned 0600 file within size bounds")
		}
	}
	if _, _, err := reader.readFile(DropInPath); err != nil {
		return inventorySnapshot{}, err
	}
	if err := reader.walk(MainPath, 0, true); err != nil {
		return inventorySnapshot{}, err
	}
	return reader.state, nil
}

func preparePlan(snapshot inventorySnapshot, declaration intent) (migrationPlan, error) {
	if _, exists := snapshot.files[DropInPath]; exists {
		return migrationPlan{}, fmt.Errorf("reserved SSH drop-in already exists; verified lifecycle ownership is required")
	}
	selection, err := sshselection.ParseModule(snapshot.files[sshselection.Path])
	if err != nil {
		return migrationPlan{}, err
	}
	main := snapshot.files[MainPath]
	plan := migrationPlan{selection: selection, intent: declaration, inventory: snapshot,
		summary: PlanSummary{Schema: 1, Operation: "publish", Role: declaration.Role, Owner: declaration.Owner,
			Profile: declaration.Profile, ContextCount: len(declaration.Contexts), MainBeforeSHA256: digestBytes(main)}}
	plan.summary.SSHHardening = selection.Hardening
	plan.summary.SSHSelectionDeclared = selection.Hardening != ""
	if plan.summary.SSHHardening == "" {
		plan.summary.SSHHardening = "disabled"
	}
	plan.main, err = migrateMain(main, declaration.Legacy)
	if err != nil {
		return migrationPlan{}, err
	}
	plan.summary.MainAfterSHA256 = digestBytes(plan.main)
	if declaration.Legacy != nil {
		plan.summary.Operation = "migrate"
		plan.summary.LegacyEditCount = len(declaration.Legacy.Edits)
	}
	files := make(map[string][]byte, len(snapshot.files))
	for name, content := range snapshot.files {
		if isSSHConfiguration(name) {
			files[name] = content
		}
	}
	files[MainPath] = plan.main
	if declaration.Owner == "external" {
		for _, content := range files {
			if strings.Contains(string(content), "SYSWARDEN OVERRIDE:") || strings.Contains(string(content), "SYSWARDEN CIS SSH HARDENING") {
				return migrationPlan{}, fmt.Errorf("external SSH observation cannot retire unresolved legacy SysWarden edits")
			}
		}
		plan.summary.Operation = "observe"
	} else {
		if err := checkSSHStateIsolation(snapshot); err != nil {
			return migrationPlan{}, err
		}
		profile := Forwarding
		if declaration.Profile == "cis" {
			profile = CIS
		}
		plan.candidate, err = Prepare(profile, files)
		if err != nil {
			return migrationPlan{}, err
		}
		plan.summary.DropInSHA256 = digestBytes(plan.candidate.Bytes())
	}
	plan.summary.PlanSHA256 = planDigest(plan)
	return plan, nil
}

func isSSHConfiguration(name string) bool {
	return name != IntentPath && name != sshselection.Path
}

func digestBytes(content []byte) string { return fmt.Sprintf("%x", sha256.Sum256(content)) }

func hashPart(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

// Bind file bytes, complete metadata observations, negative lookups, directory
// membership and vendor alias text. A SourceDigest alone omits these facts.
// Both capture and any eventual apply must freshly attest the same inputs.
func planDigest(plan migrationPlan) string {
	h := sha256.New()
	hashPart(h, []byte("SYSWARDEN-SSH-MIGRATION-PLAN-V3"))
	hashPart(h, []byte(plan.summary.Operation))
	hashPart(h, plan.main)
	hashPart(h, plan.candidate.Bytes())
	for _, name := range sortedKeys(plan.inventory.files) {
		hashPart(h, []byte("file"))
		hashPart(h, []byte(name))
		hashPart(h, plan.inventory.files[name])
	}
	for _, name := range sortedKeys(plan.inventory.nodes) {
		node := plan.inventory.nodes[name]
		hashPart(h, []byte("node"))
		hashPart(h, []byte(name))
		exists := uint64(0)
		if node.exists {
			exists = 1
		}
		values := []uint64{exists, node.dev, node.ino, node.links, uint64(node.mode), uint64(node.uid), uint64(node.gid)}
		for _, value := range values {
			var raw [8]byte
			binary.BigEndian.PutUint64(raw[:], value)
			hashPart(h, raw[:])
		}
		for _, value := range []int64{node.size, node.modified.Sec, node.modified.Nsec, node.changed.Sec, node.changed.Nsec} {
			hashPart(h, []byte(strconv.FormatInt(value, 10)))
		}
	}
	for _, name := range sortedKeys(plan.inventory.entries) {
		hashPart(h, []byte("directory"))
		hashPart(h, []byte(name))
		for _, entry := range plan.inventory.entries[name] {
			hashPart(h, []byte(entry))
		}
		hashPart(h, nil)
	}
	for _, name := range sortedKeys(plan.inventory.links) {
		hashPart(h, []byte("alias"))
		hashPart(h, []byte(name))
		hashPart(h, []byte(plan.inventory.links[name]))
	}
	for _, name := range sortedKeys(plan.inventory.attributes) {
		hashPart(h, []byte("attributes"))
		hashPart(h, []byte(name))
		for _, key := range sortedKeys(plan.inventory.attributes[name]) {
			hashPart(h, []byte(key))
			hashPart(h, plan.inventory.attributes[name][key])
		}
		hashPart(h, nil)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
