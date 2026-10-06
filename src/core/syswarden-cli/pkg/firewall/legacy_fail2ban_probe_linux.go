//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

//go:embed legacy_fail2ban_probe.py
var legacyFail2banProbeHelper string

const legacyFail2banLibrary = "/usr/lib/python3/dist-packages/fail2ban"

type legacyFail2banPythonModule struct {
	Path    string `json:"path"`
	Package bool   `json:"package"`
	Content []byte `json:"content"`
}

type legacyFail2banProbeRequest struct {
	Files       map[string][]byte                     `json:"files"`
	Directories []string                              `json:"directories"`
	Modules     map[string]legacyFail2banPythonModule `json:"modules"`
}

type legacyFail2banParserSnapshot struct {
	executable  string
	binary      nftPersistenceRead
	modules     map[string]legacyFail2banPythonModule
	sources     map[string]nftPersistenceRead
	directories map[string]os.FileInfo
	digest      [sha256.Size]byte
}

// captureLegacyFail2banParser supports the Debian packaged Python layout.
// Unknown layouts are preserved for reviewed recovery. Fail2ban is never
// installed or started to make a retirement plan possible.
func captureLegacyFail2banParser(host nftPersistenceFilesystem) (legacyFail2banParserSnapshot, error) {
	parser := legacyFail2banParserSnapshot{
		modules:     make(map[string]legacyFail2banPythonModule),
		sources:     make(map[string]nftPersistenceRead),
		directories: make(map[string]os.FileInfo),
	}
	path := "/usr/bin/python3"
	for depth := 0; ; depth++ {
		if depth > 8 || !canonicalNFTPersistencePath(path, false) || filepath.Dir(path) != "/usr/bin" {
			return parser, fmt.Errorf("Python interpreter link leaves the trusted executable directory")
		}
		parent, err := host.openDirectory("/usr/bin")
		if err != nil {
			return parser, err
		}
		info, err := parent.Lstat(filepath.Base(path))
		if err != nil {
			_ = parent.Close()
			return parser, err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			_ = parent.Close()
			parser.binary, err = host.snapshot(path)
			if err != nil {
				return parser, err
			}
			if info.Mode().Perm()&0111 == 0 || !sameNFTPersistenceIdentity(info, parser.binary.identity) {
				return parser, fmt.Errorf("Python interpreter is not a stable trusted executable")
			}
			parser.executable = path
			break
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != host.expectedUID || stat.Gid != host.expectedGID {
			_ = parent.Close()
			return parser, fmt.Errorf("Python interpreter link is not trusted")
		}
		target, err := parent.Readlink(filepath.Base(path))
		after, statErr := parent.Lstat(filepath.Base(path))
		_ = parent.Close()
		if err != nil || statErr != nil || !sameNFTPersistenceIdentity(info, after) {
			return parser, fmt.Errorf("Python interpreter link changed during inspection")
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join("/usr/bin", target)
		}
		path = filepath.Clean(target)
	}
	total := 0
	// The configuration reader uses these three packages only. Other modules,
	// site customizations and configuration Python actions are never loaded.
	for _, dir := range []string{legacyFail2banLibrary, legacyFail2banLibrary + "/client", legacyFail2banLibrary + "/server"} {
		directory, err := host.openDirectory(dir)
		if err != nil {
			return parser, fmt.Errorf("inspect installed Fail2ban parser: %w", err)
		}
		before, err := directory.Stat(".")
		if err != nil {
			_ = directory.Close()
			return parser, err
		}
		file, err := directory.Open(".")
		if err != nil {
			_ = directory.Close()
			return parser, err
		}
		entries, readErr := file.ReadDir(513)
		_ = file.Close()
		_ = directory.Close()
		if readErr != nil && readErr != io.EOF || len(entries) > 512 {
			return parser, fmt.Errorf("installed Fail2ban parser exceeds its entry limit")
		}
		parser.directories[dir] = before
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".py") {
				continue
			}
			path := filepath.Join(dir, name)
			source, err := host.snapshot(path)
			if err != nil {
				return parser, err
			}
			total += len(source.content)
			if len(parser.modules) >= 512 || total > 8<<20 {
				return parser, fmt.Errorf("installed Fail2ban parser exceeds its source limit")
			}
			relative := strings.TrimPrefix(strings.TrimSuffix(path, ".py"), legacyFail2banLibrary)
			module := "fail2ban" + strings.ReplaceAll(relative, "/", ".")
			isPackage := name == "__init__.py"
			if isPackage {
				module = strings.TrimSuffix(module, ".__init__")
			}
			for _, part := range strings.Split(module, ".") {
				if !validLegacyPythonIdentifier(part) {
					return parser, fmt.Errorf("installed Fail2ban parser has an unsupported module name")
				}
			}
			parser.modules[module] = legacyFail2banPythonModule{path, isPackage, bytes.Clone(source.content)}
			parser.sources[path] = source
		}
	}
	for _, required := range []string{"fail2ban", "fail2ban.client", "fail2ban.server", "fail2ban.client.configurator", "fail2ban.version"} {
		if _, found := parser.modules[required]; !found {
			return parser, fmt.Errorf("installed Fail2ban parser is incomplete")
		}
	}
	encoded, err := json.Marshal(struct {
		Helper           string                                `json:"helper"`
		ExecutableSHA256 [sha256.Size]byte                     `json:"executable_sha256"`
		Modules          map[string]legacyFail2banPythonModule `json:"modules"`
	}{legacyFail2banProbeHelper, sha256.Sum256(parser.binary.content), parser.modules})
	if err != nil {
		return parser, err
	}
	parser.digest = sha256.Sum256(encoded)
	if err := parser.reattest(host); err != nil {
		return parser, err
	}
	return parser, nil
}

func validLegacyPythonIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, c := range value {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (parser legacyFail2banParserSnapshot) reattest(host nftPersistenceFilesystem) error {
	current, err := host.snapshot(parser.executable)
	if err != nil || !sameLegacyFail2banSource(parser.binary, current) {
		return fmt.Errorf("Python interpreter changed during Fail2ban inspection")
	}
	for path, source := range parser.sources {
		current, err := host.snapshot(path)
		if err != nil || !sameLegacyFail2banSource(source, current) {
			return fmt.Errorf("installed Fail2ban parser changed during inspection")
		}
	}
	for path, identity := range parser.directories {
		if err := attestLegacyRetirementDirectory(host, path, identity); err != nil {
			return fmt.Errorf("installed Fail2ban parser directory changed during inspection")
		}
	}
	return nil
}

func makeLegacyFail2banProbeRequest(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource, modules map[string]legacyFail2banPythonModule) ([]byte, error) {
	if _, err := inspectLegacyFail2banDependencies(inventory); err != nil {
		return nil, err
	}
	request := legacyFail2banProbeRequest{Files: make(map[string][]byte), Modules: modules}
	omit := make(map[string][sha256.Size]byte)
	for _, target := range retiring {
		if _, exists := omit[target.path]; exists {
			return nil, fmt.Errorf("duplicate staged Fail2ban omission")
		}
		omit[target.path] = target.sha256
	}
	for _, dir := range inventory.directories {
		request.Directories = append(request.Directories, dir.path)
	}
	for _, source := range inventory.sources {
		if digest, remove := omit[source.path]; remove {
			if digest != source.sha256 {
				return nil, fmt.Errorf("staged Fail2ban omission is not bound to inspected bytes")
			}
			delete(omit, source.path)
			continue
		}
		request.Files[source.path] = source.snapshot.content
	}
	if len(omit) != 0 {
		return nil, fmt.Errorf("staged Fail2ban omission is absent from the inventory")
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > 64<<20 {
		return nil, fmt.Errorf("Fail2ban snapshot request cannot be encoded within its limit")
	}
	return encoded, nil
}

// newLegacyFail2banConfigurationProbe supplies immutable configuration and
// parser source snapshots over a private pipe. It creates no staging files or caches,
// executes no action and never opens the server socket. A production removal
// coordinator must separately attest service entry points and live actions.
func newLegacyFail2banConfigurationProbe(host nftPersistenceFilesystem) (legacyFail2banConfigurationProbe, error) {
	parser, err := captureLegacyFail2banParser(host)
	if err != nil {
		return nil, err
	}
	return legacyFail2banConfigurationProbeUsingParser(host, parser), nil
}

func legacyFail2banConfigurationProbeUsingParser(host nftPersistenceFilesystem, parser legacyFail2banParserSnapshot) legacyFail2banConfigurationProbe {
	return func(inventory legacyFail2banInventory, retiring []nftPersistenceRetiredSource) (legacyFail2banConfigurationView, error) {
		var empty legacyFail2banConfigurationView
		if err := parser.reattest(host); err != nil {
			return empty, err
		}
		request, err := makeLegacyFail2banProbeRequest(inventory, retiring, parser.modules)
		if err != nil {
			return empty, err
		}
		parent, err := host.openDirectory(filepath.Dir(parser.executable))
		if err != nil {
			return empty, err
		}
		defer func() { _ = parent.Close() }()
		binary, err := parent.OpenFile(filepath.Base(parser.executable), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return empty, err
		}
		defer func() { _ = binary.Close() }()
		info, err := binary.Stat()
		if err != nil || !sameNFTPersistenceIdentity(parser.binary.identity, info) {
			return empty, fmt.Errorf("Python interpreter changed before execution")
		}
		view, err := runLegacyFail2banProbe(binary, request, 20*time.Second)
		if err != nil {
			return empty, err
		}
		if err := parser.reattest(host); err != nil {
			return empty, err
		}
		view.parserSHA256 = parser.digest
		return view, nil
	}
}

func runLegacyFail2banProbe(binary *os.File, input []byte, timeout time.Duration) (legacyFail2banConfigurationView, error) {
	var empty legacyFail2banConfigurationView
	if binary == nil || len(input) == 0 || len(input) > 64<<20 || timeout <= 0 || timeout > 20*time.Second {
		return empty, fmt.Errorf("Fail2ban snapshot runner has invalid bounded inputs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// All command arguments are fixed. Embedded product code uses stdin;
	// configuration data has a separate read-only descriptor in the child.
	reader, writer, err := os.Pipe()
	if err != nil {
		return empty, fmt.Errorf("create private Fail2ban snapshot pipe")
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	written := make(chan error, 1)
	go func() {
		_, err := writer.Write(input)
		closeErr := writer.Close()
		if err == nil {
			err = closeErr
		}
		written <- err
	}()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", "-I", "-S", "-B", "-")
	command.ExtraFiles = []*os.File{binary, reader}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
	command.Dir = "/"
	command.Stdin = strings.NewReader(legacyFail2banProbeHelper)
	command.WaitDelay = time.Second
	stdout := &boundedNFTCommandOutput{limit: 36 << 20}
	stderr := &boundedNFTCommandOutput{limit: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	runErr := command.Run()
	_ = reader.Close()
	_ = writer.Close()
	inputErr := <-written
	if runErr != nil || inputErr != nil || stdout.exceeded || stderr.exceeded || ctx.Err() != nil {
		return empty, fmt.Errorf("Fail2ban snapshot evaluation failed or exceeded its limit; configuration and parser diagnostics are withheld")
	}
	return decodeLegacyFail2banProbe(stdout.content.Bytes())
}

func decodeLegacyFail2banProbe(output []byte) (legacyFail2banConfigurationView, error) {
	var empty legacyFail2banConfigurationView
	invalid := func() (legacyFail2banConfigurationView, error) {
		return empty, fmt.Errorf("Fail2ban snapshot evaluator returned an unsupported response")
	}
	if len(output) == 0 || len(output) > 36<<20 {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return invalid()
	}
	result := make(map[string]string)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return invalid()
		}
		name, ok := key.(string)
		if !ok || name != "enabled" && name != "all" && name != "version" && name != "socket" && name != "pidfile" && name != "actionsEnabled" && name != "actionsAll" {
			return invalid()
		}
		if _, duplicate := result[name]; duplicate {
			return invalid()
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return invalid()
		}
		result[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(result) != 7 || result["version"] != "1.1.0" {
		return invalid()
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return empty, fmt.Errorf("Fail2ban snapshot evaluator returned trailing data")
	}
	for _, content := range []string{result["enabled"], result["all"]} {
		if _, err := retainedLegacyFail2banCommands([]byte(content), nil, false); err != nil {
			return empty, err
		}
	}
	if !canonicalNFTPersistencePath(result["socket"], false) || !canonicalNFTPersistencePath(result["pidfile"], false) || result["socket"] == result["pidfile"] {
		return invalid()
	}
	for _, key := range []string{"actionsEnabled", "actionsAll"} {
		if _, err := decodeLegacyFail2banConfiguredActions([]byte(result[key])); err != nil {
			return empty, err
		}
	}
	return legacyFail2banConfigurationView{enabled: []byte(result["enabled"]), allJails: []byte(result["all"]), socket: result["socket"], pidfile: result["pidfile"], actionsEnabled: []byte(result["actionsEnabled"]), actionsAll: []byte(result["actionsAll"])}, nil
}
