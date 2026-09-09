//go:build linux

// Command source_allocation_probe measures one bounded SysWarden Engine.Scan
// allocation sample. It deliberately performs no native package, service,
// firewall, logging, webhook, feed, SSH, or network operation.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"

	"syswarden-core/engine"
)

const (
	workloadID       = "syswarden-waap-engine-scan-allocation-workload/v1"
	rawSchemaID      = "syswarden-allocation-raw-sample/v1"
	repositoryID     = "duggytuxy/syswarden"
	targetRelease    = "v4.10.0"
	baselineRelease  = "v4.04.3"
	baselineCommit   = "381c1f8d91459a9b20605629c725900abd81dee8"
	toolchainVersion = "go1.26.6"
	toolchainArchive = "708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89"
	warmupEvents     = 256
	measuredEvents   = 2048
	expectedThreads  = 2
	maxRequestBytes  = 64 * 1024
	maxFixtureBytes  = 64 * 1024
	maxCatalogBytes  = 1024 * 1024
	sandboxProbePath = "/syswarden-allocation-probe"
)

var (
	shaPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	noncePattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	campaignPattern = regexp.MustCompile(`^allocation-campaign-0[1-3]$`)
	sampleIDPattern = regexp.MustCompile(`^allocation-campaign-0[1-3]-(?:baseline|candidate)-(?:0[1-9]|10)$`)
)

type probeRequest struct {
	SchemaVersion          int    `json:"schema_version"`
	Repository             string `json:"repository"`
	TargetRelease          string `json:"target_release"`
	CandidateCommit        string `json:"candidate_commit"`
	BaselineRelease        string `json:"baseline_release"`
	BaselineCommit         string `json:"baseline_commit"`
	CampaignID             string `json:"campaign_id"`
	CampaignRecordedAt     string `json:"campaign_recorded_at"`
	SampleIndex            int    `json:"sample_index"`
	InvocationIndex        int    `json:"invocation_index"`
	SampleID               string `json:"sample_id"`
	ProcessNonce           string `json:"process_nonce"`
	SubjectRole            string `json:"subject_role"`
	SubjectRelease         string `json:"subject_release"`
	SubjectCommit          string `json:"subject_commit"`
	SubjectTree            string `json:"subject_tree"`
	ProbeBinarySHA256      string `json:"probe_binary_sha256"`
	ModuleGraphSHA256      string `json:"module_graph_sha256"`
	EnvironmentSHA256      string `json:"environment_sha256"`
	BuildAttestationSHA256 string `json:"build_attestation_sha256"`
	BenchmarkSourceSHA256  string `json:"benchmark_source_sha256"`
	FixturePath            string `json:"fixture_path"`
	FixtureSHA256          string `json:"fixture_sha256"`
	SignatureCatalogPath   string `json:"signature_catalog_path"`
	SignatureCatalogSHA256 string `json:"signature_catalog_sha256"`
	ToolchainVersion       string `json:"toolchain_version"`
	ToolchainArchiveSHA256 string `json:"toolchain_archive_sha256"`
	WorkloadID             string `json:"workload_id"`
}

type fixtureExpected struct {
	RuleID         string `json:"rule_id"`
	Service        string `json:"service"`
	RiskCategory   string `json:"risk_category"`
	Action         string `json:"action"`
	Threshold      int    `json:"threshold"`
	Window         int    `json:"window"`
	SourceIP       string `json:"source_ip"`
	MetricEligible bool   `json:"metric_eligible"`
}

type fixtureDocument struct {
	SchemaVersion int             `json:"schema_version"`
	WorkloadID    string          `json:"workload_id"`
	Record        string          `json:"record"`
	Expected      fixtureExpected `json:"expected"`
}

type rawSubject struct {
	Role              string `json:"role"`
	Release           string `json:"release"`
	Commit            string `json:"commit"`
	Tree              string `json:"tree"`
	ProbeBinarySHA256 string `json:"probe_binary_sha256"`
	ModuleGraphSHA256 string `json:"module_graph_sha256"`
}

type rawBindings struct {
	Architecture           string `json:"architecture"`
	KernelMachine          string `json:"kernel_machine"`
	EnvironmentSHA256      string `json:"environment_sha256"`
	BuildAttestationSHA256 string `json:"build_attestation_sha256"`
	BenchmarkSourceSHA256  string `json:"benchmark_source_sha256"`
	FixtureSHA256          string `json:"fixture_sha256"`
	SignatureCatalogSHA256 string `json:"signature_catalog_sha256"`
	ToolchainVersion       string `json:"toolchain_version"`
	ToolchainArchiveSHA256 string `json:"toolchain_archive_sha256"`
	WorkloadID             string `json:"workload_id"`
}

type rawWorkload struct {
	WarmupEvents                       int  `json:"warmup_events"`
	RequestedEvents                    int  `json:"requested_events"`
	AdmittedEvents                     int  `json:"admitted_events"`
	RejectedEvents                     int  `json:"rejected_events"`
	DuplicateEvents                    int  `json:"duplicate_events"`
	DegradedEvents                     int  `json:"degraded_events"`
	GOMAXPROCS                         int  `json:"gomaxprocs"`
	GoroutinesBefore                   int  `json:"goroutines_before"`
	GoroutinesAfter                    int  `json:"goroutines_after"`
	GarbageCollectionDuringMeasurement bool `json:"garbage_collection_during_measurement"`
}

type rawCounters struct {
	MallocsBefore         string `json:"mallocs_before"`
	MallocsAfter          string `json:"mallocs_after"`
	TotalAllocBytesBefore string `json:"total_alloc_bytes_before"`
	TotalAllocBytesAfter  string `json:"total_alloc_bytes_after"`
	GCCyclesBefore        string `json:"gc_cycles_before"`
	GCCyclesAfter         string `json:"gc_cycles_after"`
}

type rawSample struct {
	SchemaVersion      int         `json:"schema_version"`
	SchemaID           string      `json:"schema_id"`
	Repository         string      `json:"repository"`
	TargetRelease      string      `json:"target_release"`
	CandidateCommit    string      `json:"candidate_commit"`
	BaselineRelease    string      `json:"baseline_release"`
	BaselineCommit     string      `json:"baseline_commit"`
	CampaignID         string      `json:"campaign_id"`
	CampaignRecordedAt string      `json:"campaign_recorded_at"`
	SampleStartedAt    string      `json:"sample_started_at"`
	SampleCompletedAt  string      `json:"sample_completed_at"`
	SampleIndex        int         `json:"sample_index"`
	InvocationIndex    int         `json:"invocation_index"`
	SampleID           string      `json:"sample_id"`
	ProcessNonce       string      `json:"process_nonce"`
	Subject            rawSubject  `json:"subject"`
	Bindings           rawBindings `json:"bindings"`
	Workload           rawWorkload `json:"workload"`
	Counters           rawCounters `json:"counters"`
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, tokenErr := decoder.Token()
			if tokenErr != nil {
				return tokenErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is incomplete")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func strictDecode(raw []byte, destination any) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON input is not valid UTF-8")
	}
	keyDecoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(keyDecoder); err != nil {
		return err
	}
	if _, err := keyDecoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	return nil
}

func readBounded(path string, maximum int64, requiredMode os.FileMode) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("input is not a regular non-symlink file")
	}
	if before.Mode().Perm() != requiredMode {
		return nil, fmt.Errorf("input mode is %04o, expected %04o", before.Mode().Perm(), requiredMode)
	}
	statBefore, ok := before.Sys().(*syscall.Stat_t)
	if !ok || statBefore.Nlink != 1 || int(statBefore.Uid) != os.Geteuid() {
		return nil, errors.New("input owner or link count is unsafe")
	}
	if before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("input size is outside the accepted bound")
	}
	file, err := os.Open(path) // #nosec G304 -- exact attested path is supplied by the producer.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("input identity changed before open")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("input read failed or exceeded its bound")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || opened.ModTime() != after.ModTime() {
		return nil, errors.New("input changed while it was read")
	}
	return raw, nil
}

func probeExecutable() (string, error) {
	path, err := os.Executable()
	if err == nil {
		return path, nil
	}
	// The trusted nested launcher exposes no procfs. It executes this exact
	// read-only bind mount, whose bytes are independently checked below and
	// whose source descriptor remains checked by the producer before and after.
	if !errors.Is(err, os.ErrNotExist) || len(os.Args) != 1 || os.Args[0] != sandboxProbePath ||
		os.Getpid() != 2 || os.Getppid() != 1 {
		return "", errors.New("probe executable is not the fixed isolated entrypoint")
	}
	if _, procErr := os.Lstat("/proc"); !errors.Is(procErr, os.ErrNotExist) {
		return "", errors.New("isolated probe unexpectedly exposes procfs")
	}
	info, err := os.Lstat(sandboxProbePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("isolated probe entrypoint is not a regular file")
	}
	var filesystem syscall.Statfs_t
	// Linux statfs ST_RDONLY is bit zero; require the actual mount flag.
	if err := syscall.Statfs(sandboxProbePath, &filesystem); err != nil || filesystem.Flags&1 == 0 {
		return "", errors.New("isolated probe entrypoint is not mounted read-only")
	}
	return sandboxProbePath, nil
}

func readExecutable(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- opened executable identity is verified by fstat and SHA-256.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o700 || before.Size() <= 0 || before.Size() > maximum {
		return nil, errors.New("probe executable metadata is unsafe")
	}
	statBefore, ok := before.Sys().(*syscall.Stat_t)
	if !ok || statBefore.Nlink != 1 || int(statBefore.Uid) != os.Geteuid() {
		return nil, errors.New("probe executable owner or link count is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("probe executable read failed or exceeded its bound")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, errors.New("probe executable changed while it was read")
	}
	return raw, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func canonicalTimestamp(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	return err == nil && parsed.UTC().Format("2006-01-02T15:04:05Z") == value
}

func expectedInvocation(role string, sampleIndex int) int {
	firstRole := "baseline"
	if sampleIndex%2 == 0 {
		firstRole = "candidate"
	}
	if role == firstRole {
		return 2*sampleIndex - 1
	}
	return 2 * sampleIndex
}

func validateRequest(request probeRequest) error {
	if request.SchemaVersion != 1 || request.Repository != repositoryID || request.TargetRelease != targetRelease ||
		request.BaselineRelease != baselineRelease || request.BaselineCommit != baselineCommit {
		return errors.New("request release or repository binding is invalid")
	}
	if !shaPattern.MatchString(request.CandidateCommit) || !campaignPattern.MatchString(request.CampaignID) ||
		!canonicalTimestamp(request.CampaignRecordedAt) || request.SampleIndex < 1 || request.SampleIndex > 10 ||
		!sampleIDPattern.MatchString(request.SampleID) || !noncePattern.MatchString(request.ProcessNonce) {
		return errors.New("request campaign or sample identity is invalid")
	}
	if request.SubjectRole != "baseline" && request.SubjectRole != "candidate" {
		return errors.New("subject role is invalid")
	}
	wantID := fmt.Sprintf("%s-%s-%02d", request.CampaignID, request.SubjectRole, request.SampleIndex)
	if request.SampleID != wantID || request.InvocationIndex != expectedInvocation(request.SubjectRole, request.SampleIndex) {
		return errors.New("sample ID or invocation order is invalid")
	}
	wantRelease, wantCommit := targetRelease, request.CandidateCommit
	if request.SubjectRole == "baseline" {
		wantRelease, wantCommit = baselineRelease, baselineCommit
	}
	if request.SubjectRelease != wantRelease || request.SubjectCommit != wantCommit || !shaPattern.MatchString(request.SubjectTree) {
		return errors.New("subject source binding is invalid")
	}
	for _, value := range []string{
		request.ProbeBinarySHA256, request.ModuleGraphSHA256, request.EnvironmentSHA256,
		request.BuildAttestationSHA256, request.BenchmarkSourceSHA256, request.FixtureSHA256,
		request.SignatureCatalogSHA256,
	} {
		if !sha256Pattern.MatchString(value) {
			return errors.New("request contains a noncanonical SHA-256 binding")
		}
	}
	if request.ToolchainVersion != toolchainVersion || request.ToolchainArchiveSHA256 != toolchainArchive || request.WorkloadID != workloadID {
		return errors.New("request toolchain or workload binding is invalid")
	}
	if request.FixturePath == "" || request.SignatureCatalogPath == "" {
		return errors.New("fixture and catalog paths are required")
	}
	return nil
}

func machineName() (string, error) {
	var name syscall.Utsname
	if err := syscall.Uname(&name); err != nil {
		return "", err
	}
	raw := make([]byte, 0, len(name.Machine))
	for _, value := range name.Machine {
		if value == 0 {
			break
		}
		raw = append(raw, byte(value))
	}
	return string(raw), nil
}

func validateMatch(match *engine.Match, fixture fixtureDocument, source netip.Addr) bool {
	return match != nil && match.RuleID == fixture.Expected.RuleID && match.Service == fixture.Expected.Service &&
		match.RiskCategory == fixture.Expected.RiskCategory && match.Action == fixture.Expected.Action &&
		match.Threshold == fixture.Expected.Threshold && match.Window == fixture.Expected.Window &&
		match.Host == source && match.Payload == fixture.Record && match.MetricEligible == fixture.Expected.MetricEligible
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "this probe accepts one JSON request on standard input and no arguments")
		os.Exit(2)
	}
	requestRaw, err := io.ReadAll(io.LimitReader(os.Stdin, maxRequestBytes+1))
	if err != nil || len(requestRaw) == 0 || len(requestRaw) > maxRequestBytes {
		fmt.Fprintln(os.Stderr, "read bounded probe request failed")
		os.Exit(1)
	}
	var request probeRequest
	if err := strictDecode(requestRaw, &request); err != nil {
		fmt.Fprintln(os.Stderr, "decode probe request:", err)
		os.Exit(1)
	}
	if err := validateRequest(request); err != nil {
		fmt.Fprintln(os.Stderr, "validate probe request:", err)
		os.Exit(1)
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "probe runtime architecture is not linux/amd64")
		os.Exit(1)
	}
	machine, err := machineName()
	if err != nil || machine != "x86_64" {
		fmt.Fprintln(os.Stderr, "probe kernel architecture is not x86_64")
		os.Exit(1)
	}
	executable, err := probeExecutable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve probe executable:", err)
		os.Exit(1)
	}
	executableRaw, err := readExecutable(executable, 64*1024*1024)
	if err != nil || digest(executableRaw) != request.ProbeBinarySHA256 {
		fmt.Fprintln(os.Stderr, "probe executable identity mismatch")
		os.Exit(1)
	}
	fixtureRaw, err := readBounded(request.FixturePath, maxFixtureBytes, 0o600)
	if err != nil || digest(fixtureRaw) != request.FixtureSHA256 {
		fmt.Fprintln(os.Stderr, "fixture identity mismatch")
		os.Exit(1)
	}
	var fixture fixtureDocument
	if err := strictDecode(fixtureRaw, &fixture); err != nil || fixture.SchemaVersion != 1 || fixture.WorkloadID != workloadID || fixture.Record == "" {
		fmt.Fprintln(os.Stderr, "fixture contract is invalid")
		os.Exit(1)
	}
	source, err := netip.ParseAddr(fixture.Expected.SourceIP)
	if err != nil || !source.IsValid() || source.IsUnspecified() || source.IsLoopback() {
		fmt.Fprintln(os.Stderr, "fixture source address is invalid")
		os.Exit(1)
	}
	catalogRaw, err := readBounded(request.SignatureCatalogPath, maxCatalogBytes, 0o600)
	if err != nil || digest(catalogRaw) != request.SignatureCatalogSHA256 {
		fmt.Fprintln(os.Stderr, "signature catalog identity mismatch")
		os.Exit(1)
	}
	if err := scanJSONDocument(catalogRaw); err != nil {
		fmt.Fprintln(os.Stderr, "signature catalog JSON is invalid:", err)
		os.Exit(1)
	}

	runtime.GOMAXPROCS(1)
	detector, err := engine.NewEngine(request.SignatureCatalogPath, 5, 60)
	if err != nil {
		fmt.Fprintln(os.Stderr, "construct detection engine:", err)
		os.Exit(1)
	}
	startedAt := time.Now().UTC().Truncate(time.Second)
	for index := 0; index < warmupEvents; index++ {
		if !validateMatch(detector.Scan(fixture.Record), fixture, source) {
			fmt.Fprintln(os.Stderr, "warm-up event did not produce the exact expected match")
			os.Exit(1)
		}
	}

	runtime.GC()
	previousGCPercent := debug.SetGCPercent(-1)
	previousMemoryLimit := debug.SetMemoryLimit(1<<63 - 1)
	var before runtime.MemStats
	var after runtime.MemStats
	runtime.ReadMemStats(&before)
	goroutinesBefore := runtime.NumGoroutine()
	admitted := 0
	rejected := 0
	for index := 0; index < measuredEvents; index++ {
		match := detector.Scan(fixture.Record)
		if !validateMatch(match, fixture, source) {
			rejected++
			continue
		}
		admitted++
	}
	goroutinesAfter := runtime.NumGoroutine()
	runtime.ReadMemStats(&after)
	debug.SetMemoryLimit(previousMemoryLimit)
	debug.SetGCPercent(previousGCPercent)
	completedAt := time.Now().UTC().Truncate(time.Second)

	if admitted != measuredEvents || rejected != 0 || goroutinesBefore != expectedThreads || goroutinesAfter != expectedThreads ||
		runtime.GOMAXPROCS(0) != 1 || before.NumGC != after.NumGC || after.Mallocs < before.Mallocs || after.TotalAlloc < before.TotalAlloc {
		fmt.Fprintln(os.Stderr, "measured workload invariant failed")
		os.Exit(1)
	}
	objectDelta := after.Mallocs - before.Mallocs
	byteDelta := after.TotalAlloc - before.TotalAlloc
	if (objectDelta == 0) != (byteDelta == 0) {
		fmt.Fprintln(os.Stderr, "allocation counter zero-state mismatch")
		os.Exit(1)
	}

	output := rawSample{
		SchemaVersion: 1, SchemaID: rawSchemaID, Repository: repositoryID,
		TargetRelease: targetRelease, CandidateCommit: request.CandidateCommit,
		BaselineRelease: baselineRelease, BaselineCommit: baselineCommit,
		CampaignID: request.CampaignID, CampaignRecordedAt: request.CampaignRecordedAt,
		SampleStartedAt:   startedAt.Format("2006-01-02T15:04:05Z"),
		SampleCompletedAt: completedAt.Format("2006-01-02T15:04:05Z"),
		SampleIndex:       request.SampleIndex, InvocationIndex: request.InvocationIndex,
		SampleID: request.SampleID, ProcessNonce: request.ProcessNonce,
		Subject: rawSubject{Role: request.SubjectRole, Release: request.SubjectRelease, Commit: request.SubjectCommit,
			Tree: request.SubjectTree, ProbeBinarySHA256: request.ProbeBinarySHA256, ModuleGraphSHA256: request.ModuleGraphSHA256},
		Bindings: rawBindings{Architecture: "linux/amd64", KernelMachine: machine,
			EnvironmentSHA256: request.EnvironmentSHA256, BuildAttestationSHA256: request.BuildAttestationSHA256,
			BenchmarkSourceSHA256: request.BenchmarkSourceSHA256, FixtureSHA256: request.FixtureSHA256,
			SignatureCatalogSHA256: request.SignatureCatalogSHA256, ToolchainVersion: toolchainVersion,
			ToolchainArchiveSHA256: toolchainArchive, WorkloadID: workloadID},
		Workload: rawWorkload{WarmupEvents: warmupEvents, RequestedEvents: measuredEvents,
			AdmittedEvents: admitted, RejectedEvents: rejected, DuplicateEvents: 0, DegradedEvents: 0,
			GOMAXPROCS: 1, GoroutinesBefore: goroutinesBefore, GoroutinesAfter: goroutinesAfter,
			GarbageCollectionDuringMeasurement: false},
		Counters: rawCounters{MallocsBefore: strconv.FormatUint(before.Mallocs, 10), MallocsAfter: strconv.FormatUint(after.Mallocs, 10),
			TotalAllocBytesBefore: strconv.FormatUint(before.TotalAlloc, 10), TotalAllocBytesAfter: strconv.FormatUint(after.TotalAlloc, 10),
			GCCyclesBefore: strconv.FormatUint(uint64(before.NumGC), 10), GCCyclesAfter: strconv.FormatUint(uint64(after.NumGC), 10)},
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, "encode raw sample:", err)
		os.Exit(1)
	}
}

func scanJSONDocument(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON input is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	return nil
}
