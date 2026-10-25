//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

// These are historical direct requirements absent from the proposed base
// profile. Never infer product ownership from all installed/automatic packages.
var debRetentionNames = [...]string{"apt-listchanges", "e2fsprogs", "ipset", "qrencode", "rsyslog", "unattended-upgrades", "wireguard-tools"}
var rpmRetentionNames = [...]string{"checkpolicy", "dnf-automatic", "e2fsprogs", "ipset", "policycoreutils-python-utils", "rsyslog", "wireguard-tools"}

const debRetentionQuery = "--showformat=${Package}\t${db:Status-Abbrev}\t${Version}\t${Architecture}\t${Depends}\n"
const rpmRetentionQuery = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n"

var retentionDependencyToken = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9+.-]*`)

type nativeRetentionRunner func(context.Context, string, string, []string) ([]byte, error)

type nativeRetentionSnapshot struct {
	owner, dependencies string
	identities          map[string]string
	reasons             map[string]string
}

func retentionEligible(manager string) []string {
	switch manager {
	case "/usr/bin/apt-get", "/usr/bin/dpkg":
		return slices.Clone(debRetentionNames[:])
	case "/usr/bin/dnf", "/usr/bin/yum":
		return slices.Clone(rpmRetentionNames[:])
	}
	return nil
}

// Retention uses only native reason APIs. It never installs a prerequisite,
// edits native databases, changes holds/pins, or runs inside a package script.
func nativeRetentionCommand(manager, operation string, names []string) (string, []string, error) {
	return nativeRetentionCommandVariant(manager, operation, names, 4)
}

func nativeRetentionCommandVariant(manager, operation string, names []string, generation int) (string, []string, error) {
	if generation != 4 && generation != 5 {
		return "", nil, errors.New("unqualified native package manager generation")
	}
	// Select an executable from constants instead of forwarding a caller's path.
	var rpmManager string
	switch manager {
	case "/usr/bin/dnf":
		rpmManager = "/usr/bin/dnf"
	case "/usr/bin/yum":
		rpmManager = "/usr/bin/yum"
	}
	if operation == "provider" && (manager == "/usr/bin/dnf" || manager == "/usr/bin/yum") && len(names) == 0 {
		return rpmManager, []string{"--noplugins", "--version"}, nil
	}
	if operation == "product-requires" && len(names) == 1 {
		return retentionProductRequiresCommandForName(manager, names[0])
	}
	eligible := retentionEligible(manager)
	if len(eligible) == 0 || len(names) == 0 || len(names) > len(eligible) {
		return "", nil, errors.New("invalid dependency retention command scope")
	}
	seen := make(map[string]bool)
	selected := make([]string, 0, len(names))
	for _, name := range names {
		if seen[name] || (!slices.Contains(eligible, name) && !(operation == "identity" && validNativeProductPackageName(name))) {
			return "", nil, errors.New("unapproved dependency retention package")
		}
		seen[name] = true
		// Return only compiled-in names. Caller text is a selector, never an
		// argument to the native process even after successful validation.
		for _, candidate := range append(slices.Clone(eligible), nativeProductPackageNames[:]...) {
			if name == candidate {
				selected = append(selected, candidate)
				break
			}
		}
	}
	names = selected
	deb := manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg"
	switch operation {
	case "identity":
		if len(names) == 1 {
			if deb {
				return "/usr/bin/dpkg-query", []string{"--show", debRetentionQuery, names[0]}, nil
			}
			return "/usr/bin/rpm", []string{"--query", "--queryformat", rpmRetentionQuery, names[0]}, nil
		}
	case "requires":
		// No arbitrary package requires query is exposed to the runner.
		return "", nil, errors.New("requires uses the dedicated product operation")
	case "reasons", "retain":
		if deb {
			action := "showauto"
			if operation == "retain" {
				action = "manual"
			}
			return "/usr/bin/apt-mark", append([]string{action}, names...), nil
		}
		if generation == 5 {
			args := []string{"--no-plugins", "--cacheonly", "--disable-repo=*", "-q"}
			if operation == "retain" {
				return rpmManager, append(append(args, "--assumeyes", "mark", "user"), names...), nil
			}
			return rpmManager, append(append(args, "repoquery", "--installed", "--queryformat", "%{name}\t%{reason}\n"), names...), nil
		}
		args := []string{"--noplugins", "--cacheonly", "--disablerepo=*", "-q"}
		if operation == "retain" {
			return rpmManager, append(append(args, "mark", "install"), names...), nil
		}
		return rpmManager, append(append(args, "repoquery", "--installed", "--qf", "%{name}\t%{reason}"), names...), nil
	}
	return "", nil, errors.New("unapproved dependency retention operation")
}

func retentionProductRequiresCommand(manager string) (string, []string, error) {
	return retentionProductRequiresCommandForName(manager, compatibilityNativePackageName)
}

func retentionProductRequiresCommandForName(manager, packageName string) (string, []string, error) {
	if !validNativeProductPackageName(packageName) {
		return "", nil, errors.New("RPM dependency query requires an exact product identity")
	}
	if manager != "/usr/bin/dnf" && manager != "/usr/bin/yum" {
		return "", nil, errors.New("RPM dependency query requires the RPM manager")
	}
	switch packageName {
	case compatibilityNativePackageName:
		return "/usr/bin/rpm", []string{"--query", "--requires", compatibilityNativePackageName}, nil
	case baseNativePackageName:
		return "/usr/bin/rpm", []string{"--query", "--requires", baseNativePackageName}, nil
	default:
		return "", nil, errors.New("RPM dependency query requires an exact product identity")
	}
}

func runNativeRetentionCommandVariant(ctx context.Context, manager, operation string, names []string, generation int) ([]byte, error) {
	var path string
	var args []string
	var err error
	if operation == "product-requires" && len(names) == 0 {
		path, args, err = retentionProductRequiresCommand(manager)
	} else {
		path, args, err = nativeRetentionCommandVariant(manager, operation, names, generation)
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateOfflineQualificationDependency(path, 0); err != nil {
		return nil, fmt.Errorf("untrusted native retention executable: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if err := attestCronProviderDirectoryChain(filepath.Dir(canonical)); err != nil {
		return nil, err
	}
	command := exec.Command(path, args...) // #nosec G204 -- fixed operations and compiled package names validated above
	command.Env = nativeRetentionEnvironment()
	command.Dir = "/"
	stdout := qualificationBoundedBuffer{limit: 64 << 10}
	stderr := qualificationBoundedBuffer{limit: 4 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	err = runQualificationProcessGroup(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("native dependency retention %s failed: %w", operation, err)
	}
	if stdout.overflow || stderr.overflow || len(stderr.Bytes()) != 0 {
		return nil, errors.New("native dependency retention output is oversized or has diagnostics")
	}
	if generation == 5 && operation == "reasons" {
		return normalizeDNF5RetentionReasons(stdout.Bytes())
	}
	return stdout.Bytes(), nil
}

func retentionRecord(manager, name string, data []byte) (string, string, error) {
	if len(retentionEligible(manager)) == 0 || (!validNativeProductPackageName(name) && !slices.Contains(retentionEligible(manager), name)) {
		return "", "", errors.New("native package identity is outside the retention scope")
	}
	text := string(data)
	if len(text) == 0 || len(text) > 64<<10 || strings.Count(text, "\n") != 1 || !strings.HasSuffix(text, "\n") || strings.ContainsAny(text, "\x00\r") {
		return "", "", errors.New("native package identity is empty, oversized or ambiguous")
	}
	fields := strings.Split(strings.TrimSuffix(text, "\n"), "\t")
	deb := manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg"
	if deb {
		if len(fields) != 5 || fields[0] != name || (fields[1] != "ii " && fields[1] != "hi ") ||
			!retentionVersion(fields[2]) || (fields[3] != "amd64" && (validNativeProductPackageName(name) || fields[3] != "all")) {
			return "", "", errors.New("DEB retention requires one configured native package identity")
		}
		return strings.Join(fields[:4], "\t"), fields[4], nil
	}
	if len(retentionEligible(manager)) == 0 || len(fields) != 3 || fields[0] != name || !retentionVersion(fields[1]) ||
		(fields[2] != "x86_64" && (validNativeProductPackageName(name) || fields[2] != "noarch")) {
		return "", "", errors.New("RPM retention requires one native package identity")
	}
	return strings.TrimSuffix(text, "\n"), "", nil
}

func retentionVersion(version string) bool {
	if version == "" || len(version) > 512 {
		return false
	}
	for _, c := range version {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+:~_-", c) {
			return false
		}
	}
	return true
}

func retentionDeclared(manager, text string) ([]string, error) {
	eligible := retentionEligible(manager)
	if len(eligible) == 0 || len(text) > 64<<10 || strings.ContainsAny(text, "\x00\r\t") {
		return nil, errors.New("invalid native dependency declaration")
	}
	separator := "\n"
	if manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg" {
		separator = ","
		if strings.Contains(text, "\n") {
			return nil, errors.New("multiline DEB dependency declaration")
		}
	}
	found := make(map[string]bool)
	for _, part := range strings.Split(text, separator) {
		for _, token := range retentionDependencyToken.FindAllString(part, -1) {
			if slices.Contains(eligible, token) {
				if strings.TrimSpace(part) != token || found[token] {
					return nil, errors.New("historical native dependency is constrained, alternative or duplicated")
				}
				found[token] = true
			}
		}
	}
	var names []string
	for _, name := range eligible {
		if found[name] {
			names = append(names, name)
		}
	}
	return names, nil
}

// DNF's userinstalled filter can omit group reasons. Read each exact reason,
// preserve user/group choices, and refuse unknown or incomplete observations.
func retentionReasons(manager string, names []string, data []byte) (map[string]string, error) {
	if len(data) > 64<<10 || strings.ContainsAny(string(data), "\x00\r ") || (len(data) != 0 && data[len(data)-1] != '\n') {
		return nil, errors.New("ambiguous native dependency reasons")
	}
	deb := manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg"
	result := make(map[string]string)
	if deb {
		for _, name := range names {
			result[name] = "manual"
		}
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" && len(data) == 0 {
			continue
		}
		name, reason := line, "auto"
		if !deb {
			fields := strings.Split(line, "\t")
			if len(fields) != 2 || !slices.Contains([]string{"user", "group", "external-user", "dependency", "weak-dependency"}, fields[1]) {
				return nil, errors.New("unknown or ambiguous RPM dependency reason")
			}
			name, reason = fields[0], fields[1]
		}
		if !slices.Contains(names, name) || seen[name] {
			return nil, errors.New("unexpected or duplicate native dependency reason")
		}
		seen[name], result[name] = true, reason
	}
	if len(result) != len(names) {
		return nil, errors.New("incomplete native dependency reasons")
	}
	return result, nil
}

func retentionProtected(reason string) bool {
	return reason == "manual" || reason == "user" || reason == "group" || reason == "external-user"
}

func inspectNativeRetention(ctx context.Context, manager string, run nativeRetentionRunner) (nativeRetentionSnapshot, error) {
	return inspectNativeRetentionForName(ctx, manager, compatibilityNativePackageName, run)
}

func inspectNativeRetentionForName(ctx context.Context, manager, packageName string, run nativeRetentionRunner) (nativeRetentionSnapshot, error) {
	snapshot := nativeRetentionSnapshot{identities: make(map[string]string), reasons: make(map[string]string)}
	if ctx == nil || run == nil || !validNativeProductPackageName(packageName) || len(retentionEligible(manager)) == 0 {
		return snapshot, errors.New("native dependency retention requires an exact product identity and available runner")
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	data, err := run(ctx, manager, "identity", []string{packageName})
	if err != nil {
		return snapshot, err
	}
	snapshot.owner, snapshot.dependencies, err = retentionRecord(manager, packageName, data)
	if err != nil {
		return snapshot, err
	}
	if manager == "/usr/bin/dnf" || manager == "/usr/bin/yum" {
		data, err = run(ctx, manager, "product-requires", []string{packageName})
		if err != nil {
			return snapshot, err
		}
		snapshot.dependencies = string(data)
	}
	names, err := retentionDeclared(manager, snapshot.dependencies)
	if err != nil || len(names) == 0 {
		return snapshot, errors.Join(err, ctx.Err())
	}
	for _, name := range names {
		data, err = run(ctx, manager, "identity", []string{name})
		if err != nil {
			return snapshot, err
		}
		id, _, recordErr := retentionRecord(manager, name, data)
		if recordErr != nil {
			return snapshot, recordErr
		}
		snapshot.identities[name] = id
	}
	data, err = run(ctx, manager, "reasons", names)
	if err != nil {
		return snapshot, err
	}
	snapshot.reasons, err = retentionReasons(manager, names, data)
	return snapshot, errors.Join(err, ctx.Err())
}

func preserveNativeDependencyReasonsForName(ctx context.Context, manager, packageName string) error {
	if ctx == nil || !validNativeProductPackageName(packageName) || len(retentionEligible(manager)) == 0 {
		return errors.New("native dependency retention requires an exact product identity and supported manager")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	run, err := bindNativeRetentionRunner(ctx, manager, runNativeRetentionCommandVariant)
	if err != nil {
		return err
	}
	return preserveNativeDependencyReasonsForNameWith(ctx, manager, packageName, run)
}

// Every native operation has its own native locking. Repeated inventory checks
// detect observed drift; they are not a package-manager lock spanning commands.
// Concurrent administrator package changes require coordination. A failed reason
// operation may already retain a subset; never undo those protections on retry.
func preserveNativeDependencyReasonsForNameWith(ctx context.Context, manager, packageName string, run nativeRetentionRunner) error {
	if ctx == nil || !validNativeProductPackageName(packageName) || len(retentionEligible(manager)) == 0 || run == nil {
		return errors.New("native dependency retention is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := inspectNativeRetentionForName(ctx, manager, packageName, run)
	if err != nil {
		return fmt.Errorf("inspect historical dependencies before replacement: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := inspectNativeRetentionForName(ctx, manager, packageName, run)
	if err != nil || !reflect.DeepEqual(before, current) {
		return errors.New("native dependency inventory changed or became unavailable before preparation")
	}
	var names []string
	for _, name := range retentionEligible(manager) {
		if _, exists := current.identities[name]; exists && !retentionProtected(current.reasons[name]) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := run(ctx, manager, "retain", names); err != nil {
		return fmt.Errorf("native reason preparation incomplete; do not replace the package, retained reasons are not reverted: %w", err)
	}
	after, err := inspectNativeRetentionForName(ctx, manager, packageName, run)
	for _, name := range names {
		current.reasons[name] = "user"
		if manager == "/usr/bin/apt-get" || manager == "/usr/bin/dpkg" {
			current.reasons[name] = "manual"
		}
	}
	if err != nil || !reflect.DeepEqual(current, after) {
		return errors.New("native reason preparation is not verified; package replacement must remain stopped")
	}
	return ctx.Err()
}

// Keep retention after the exact authenticated-package command boundary and
// before replacement. Both callers use the same preparation, while offline
// qualification retains its independent repository/signature restrictions.
func runWithNativeDependencyRetention(ctx context.Context, name string, args []string, offline bool,
	prepare func(context.Context, string) error, execute commandRunner) error {
	validate := validateExternalCommand
	if offline {
		validate = validateQualificationExternalCommand
	}
	if err := validate(name, args); err != nil {
		return err
	}
	if prepare == nil || execute == nil {
		return errors.New("native update execution boundary is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(retentionEligible(name)) != 0 {
		if err := prepare(ctx, name); err != nil {
			return fmt.Errorf("preserve historical native dependencies before replacement: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return execute(ctx, name, args...)
}

// Queries and package replacement must resolve the same system database. Do not
// inherit alternate database/configuration roots or loader/interpreter settings.
// Production network transport may retain proxy choices; package signatures and
// authenticated candidate selection remain mandatory.
func nativeRetentionEnvironment() []string {
	return []string{"DEBIAN_FRONTEND=noninteractive", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
}

func productionNativeCommandEnvironment() []string {
	environment := nativeRetentionEnvironment()
	for _, key := range []string{"http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} {
		if value, ok := os.LookupEnv(key); ok {
			environment = append(environment, key+"="+value)
		}
	}
	return environment
}
