package network

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"syswarden-core/logger"

	"github.com/spf13/viper"
)

const (
	defaultSaaSIPv4Path  = "/etc/syswarden/lists/syswarden_saas_monitors.ipv4"
	defaultSaaSIPv6Path  = "/etc/syswarden/lists/syswarden_saas_monitors.ipv6"
	maximumSaaSBodySize  = 1 << 20
	maximumSaaSLineSize  = 1024
	maximumSaaSLines     = 20000
	maximumSaaSEntries   = 10000
	saasPairManifestName = "syswarden_saas_monitors.pair"
	saasPairManifestV1   = "syswarden-saas-pair-v1"
)

type saasFeed struct {
	url      string
	required bool
}

// SaasMonitorDownloader periodically publishes validated SaaS monitor networks.
type SaasMonitorDownloader struct {
	logger     *logger.Logger
	client     *http.Client
	feeds      []saasFeed
	targetIPv4 string
	targetIPv6 string
}

func NewSaasMonitorDownloader(l *logger.Logger) *SaasMonitorDownloader {
	return &SaasMonitorDownloader{
		logger: l,
		client: newBoundedSaaSHTTPClient(),
		feeds: []saasFeed{
			{url: "https://uptime.betterstack.com/ips.txt", required: true},
		},
		targetIPv4: defaultSaaSIPv4Path,
		targetIPv6: defaultSaaSIPv6Path,
	}
}

func newBoundedSaaSHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("SaaS feed redirects are disabled")
		},
	}
}

func (s *SaasMonitorDownloader) Start() {
	if !s.isSaasAllowed() {
		s.logInfo("SaaS monitor auto-whitelist is disabled. Skipping downloader.")
		return
	}

	s.logInfo("Starting the SaaS monitor downloader (Better Stack) in the background.")
	if err := s.fetchMonitors(); err != nil {
		s.logError("Failed to refresh SaaS monitor lists", err)
	}

	ticker := time.NewTicker(time.Hour)
	go func() {
		for range ticker.C {
			if err := s.fetchMonitors(); err != nil {
				s.logError("Failed to refresh SaaS monitor lists", err)
			}
		}
	}()
}

func (s *SaasMonitorDownloader) logInfo(message string) {
	if s.logger != nil {
		s.logger.Info(message)
	}
}

func (s *SaasMonitorDownloader) logError(message string, err error) {
	if s.logger != nil {
		s.logger.Error(message, err)
	}
}

func resolveSaaSAllowance(configuration *viper.Viper) bool {
	if configuration.IsSet("network.saas.allow_monitors") {
		return configuration.GetBool("network.saas.allow_monitors")
	}
	if configuration.IsSet("integrations.saas.enabled") {
		return configuration.GetBool("integrations.saas.enabled")
	}
	return false
}

func (s *SaasMonitorDownloader) isSaasAllowed() bool {
	return resolveSaaSAllowance(viper.GetViper())
}

func (s *SaasMonitorDownloader) fetchMonitors() error {
	if s.client == nil {
		return errors.New("SaaS feed HTTP client is not configured")
	}
	if len(s.feeds) == 0 {
		return errors.New("no SaaS monitor feed is configured")
	}

	allEntries := make([]string, 0)
	for _, feed := range s.feeds {
		entries, err := s.downloadList(feed.url)
		if err != nil {
			if feed.required {
				return fmt.Errorf("required SaaS feed %s: %w", feed.url, err)
			}
			s.logError("Optional SaaS feed was rejected: "+feed.url, err)
			continue
		}
		allEntries = append(allEntries, entries...)
	}

	ipv4, ipv6, err := canonicalSaaSEntries(allEntries)
	if err != nil {
		return err
	}
	if len(ipv4)+len(ipv6) == 0 {
		return errors.New("SaaS feeds contain no usable IP address or CIDR")
	}
	return publishSaaSListPair(s.targetIPv4, s.targetIPv6, renderSaaSList(ipv4), renderSaaSList(ipv6))
}

func (s *SaasMonitorDownloader) downloadList(rawURL string) ([]string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("SaaS feed URL must be an absolute HTTPS URL without credentials or a fragment")
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create SaaS feed request: %w", err)
	}
	request.Header.Set("Accept", "text/plain")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download SaaS feed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SaaS feed returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maximumSaaSBodySize {
		return nil, fmt.Errorf("SaaS feed exceeds %d bytes", maximumSaaSBodySize)
	}

	limited := io.LimitReader(response.Body, maximumSaaSBodySize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read SaaS feed: %w", err)
	}
	if len(body) > maximumSaaSBodySize {
		return nil, fmt.Errorf("SaaS feed exceeds %d bytes", maximumSaaSBodySize)
	}

	entries := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 1024), maximumSaaSLineSize)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > maximumSaaSLines {
			return nil, fmt.Errorf("SaaS feed exceeds %d lines", maximumSaaSLines)
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		canonical, _, parseErr := canonicalSaaSEntry(line)
		if parseErr != nil {
			return nil, fmt.Errorf("SaaS feed line %d: %w", lineCount, parseErr)
		}
		entries = append(entries, canonical)
		if len(entries) > maximumSaaSEntries {
			return nil, fmt.Errorf("SaaS feed exceeds %d entries", maximumSaaSEntries)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan SaaS feed: %w", err)
	}
	return entries, nil
}

func canonicalSaaSEntry(value string) (string, bool, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" || address.Is4In6() {
			return "", false, fmt.Errorf("unsupported IP address %q", value)
		}
		return address.String(), address.Is4(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return "", false, fmt.Errorf("invalid IP address or CIDR %q", value)
	}
	prefix = prefix.Masked()
	return prefix.String(), prefix.Addr().Is4(), nil
}

func canonicalSaaSEntries(entries []string) ([]string, []string, error) {
	ipv4Set := make(map[string]struct{})
	ipv6Set := make(map[string]struct{})
	for _, entry := range entries {
		canonical, isIPv4, err := canonicalSaaSEntry(strings.TrimSpace(entry))
		if err != nil {
			return nil, nil, err
		}
		if isIPv4 {
			ipv4Set[canonical] = struct{}{}
		} else {
			ipv6Set[canonical] = struct{}{}
		}
	}
	ipv4 := make([]string, 0, len(ipv4Set))
	for entry := range ipv4Set {
		ipv4 = append(ipv4, entry)
	}
	ipv6 := make([]string, 0, len(ipv6Set))
	for entry := range ipv6Set {
		ipv6 = append(ipv6, entry)
	}
	sort.Strings(ipv4)
	sort.Strings(ipv6)
	return ipv4, ipv6, nil
}

func renderSaaSList(entries []string) []byte {
	if len(entries) == 0 {
		return nil
	}
	return []byte(strings.Join(entries, "\n") + "\n")
}

func publishSaaSListPair(ipv4Path, ipv6Path string, ipv4Content, ipv6Content []byte) error {
	cleanIPv4 := filepath.Clean(ipv4Path)
	cleanIPv6 := filepath.Clean(ipv6Path)
	if !filepath.IsAbs(cleanIPv4) || cleanIPv4 != ipv4Path || !filepath.IsAbs(cleanIPv6) || cleanIPv6 != ipv6Path {
		return errors.New("SaaS list paths must be absolute and canonical")
	}
	if filepath.Dir(cleanIPv4) != filepath.Dir(cleanIPv6) || filepath.Base(cleanIPv4) == filepath.Base(cleanIPv6) {
		return errors.New("SaaS list paths must be distinct files in one directory")
	}
	directoryPath := filepath.Dir(cleanIPv4)
	directory, err := openSaaSListDirectory(directoryPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	lockFile, err := directory.Open(".")
	if err != nil {
		return fmt.Errorf("open SaaS list directory lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return fmt.Errorf("lock SaaS list directory: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}()

	ipv4Name := filepath.Base(cleanIPv4)
	ipv6Name := filepath.Base(cleanIPv6)
	oldIPv4, oldIPv4Exists, err := readExistingSaaSList(directory, ipv4Name)
	if err != nil {
		return err
	}
	oldIPv6, oldIPv6Exists, err := readExistingSaaSList(directory, ipv6Name)
	if err != nil {
		return err
	}
	oldManifest, oldManifestExists, err := readExistingSaaSList(directory, saasPairManifestName)
	if err != nil {
		return err
	}
	ipv4Stage, err := stageSaaSList(directory, ipv4Name, ipv4Content)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Remove(ipv4Stage) }()
	ipv6Stage, err := stageSaaSList(directory, ipv6Name, ipv6Content)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Remove(ipv6Stage) }()
	manifestStage, err := stageSaaSList(directory, saasPairManifestName, renderSaaSPairManifest(ipv4Content, ipv6Content))
	if err != nil {
		return err
	}
	defer func() { _ = directory.Remove(manifestStage) }()
	if err := directory.Rename(ipv4Stage, ipv4Name); err != nil {
		return fmt.Errorf("publish IPv4 SaaS list: %w", err)
	}
	if err := directory.Rename(ipv6Stage, ipv6Name); err != nil {
		restoreErr := restoreSaaSList(directory, ipv4Name, oldIPv4, oldIPv4Exists)
		return errors.Join(fmt.Errorf("publish IPv6 SaaS list: %w", err), restoreErr)
	}
	if err := directory.Rename(manifestStage, saasPairManifestName); err != nil {
		restoreIPv4Err := restoreSaaSList(directory, ipv4Name, oldIPv4, oldIPv4Exists)
		restoreIPv6Err := restoreSaaSList(directory, ipv6Name, oldIPv6, oldIPv6Exists)
		return errors.Join(fmt.Errorf("commit SaaS list pair: %w", err), restoreIPv4Err, restoreIPv6Err)
	}
	if err := syncSaaSDirectory(directory); err != nil {
		restoreIPv4Err := restoreSaaSList(directory, ipv4Name, oldIPv4, oldIPv4Exists)
		restoreIPv6Err := restoreSaaSList(directory, ipv6Name, oldIPv6, oldIPv6Exists)
		restoreManifestErr := restoreSaaSList(directory, saasPairManifestName, oldManifest, oldManifestExists)
		return errors.Join(fmt.Errorf("sync SaaS list publication: %w", err), restoreIPv4Err, restoreIPv6Err, restoreManifestErr)
	}
	return nil
}

func renderSaaSPairManifest(ipv4Content, ipv6Content []byte) []byte {
	ipv4Digest := sha256.Sum256(ipv4Content)
	ipv6Digest := sha256.Sum256(ipv6Content)
	return []byte(fmt.Sprintf(
		"%s\nipv4_sha256=%x\nipv6_sha256=%x\n",
		saasPairManifestV1,
		ipv4Digest,
		ipv6Digest,
	))
}

func openSaaSListDirectory(path string) (*os.Root, error) {
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for SaaS lists: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.ToSlash(path), "/"), "/") {
		if component == "" {
			continue
		}
		info, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect SaaS list parent component %q: %w", component, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, fmt.Errorf("SaaS list parent component %q must be a real directory", component)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open SaaS list parent component %q: %w", component, err)
		}
		openedInfo, err := next.Stat(".")
		if err != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("SaaS list parent component %q changed while opening", component)
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func readExistingSaaSList(directory *os.Root, name string) ([]byte, bool, error) {
	file, err := directory.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open existing SaaS list %s: %w", name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("existing SaaS list %s is not a regular file", name)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumSaaSBodySize+1))
	if err != nil || len(content) > maximumSaaSBodySize {
		return nil, false, fmt.Errorf("read existing SaaS list %s: invalid size or content", name)
	}
	return content, true, nil
}

func stageSaaSList(directory *os.Root, targetName string, content []byte) (string, error) {
	for range 128 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", fmt.Errorf("generate SaaS staging name: %w", err)
		}
		name := "." + targetName + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("create SaaS staging file: %w", err)
		}
		if _, err := file.Write(content); err != nil {
			_ = file.Close()
			_ = directory.Remove(name)
			return "", fmt.Errorf("write SaaS staging file: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = directory.Remove(name)
			return "", fmt.Errorf("sync SaaS staging file: %w", err)
		}
		if err := file.Close(); err != nil {
			_ = directory.Remove(name)
			return "", fmt.Errorf("close SaaS staging file: %w", err)
		}
		return name, nil
	}
	return "", errors.New("too many SaaS staging name collisions")
}

func restoreSaaSList(directory *os.Root, name string, content []byte, existed bool) error {
	if !existed {
		if err := directory.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove newly published SaaS list during rollback: %w", err)
		}
		return syncSaaSDirectory(directory)
	}
	stage, err := stageSaaSList(directory, name, content)
	if err != nil {
		return fmt.Errorf("stage SaaS list rollback: %w", err)
	}
	defer func() { _ = directory.Remove(stage) }()
	if err := directory.Rename(stage, name); err != nil {
		return fmt.Errorf("restore SaaS list during rollback: %w", err)
	}
	return syncSaaSDirectory(directory)
}

func syncSaaSDirectory(directory *os.Root) error {
	file, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
