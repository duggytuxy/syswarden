package network

import (
	"bytes"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type saasRetainedFileSnapshot struct {
	content []byte
	info    os.FileInfo
}

func snapshotSaaSRetainedPair(t *testing.T, directory string) (map[string]saasRetainedFileSnapshot, []string) {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]saasRetainedFileSnapshot, len(entries))
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("retained fixture is not a regular file: %s, %v", entry.Name(), err)
		}
		content, err := root.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = saasRetainedFileSnapshot{content: content, info: info}
		names = append(names, entry.Name())
	}
	return files, names
}

func assertSaaSRetainedPairUnchanged(t *testing.T, directory string, before map[string]saasRetainedFileSnapshot, names []string) {
	t.Helper()
	after, actualNames := snapshotSaaSRetainedPair(t, directory)
	if !reflect.DeepEqual(names, actualNames) {
		t.Fatalf("refused publication changed directory entries: before=%v, after=%v", names, actualNames)
	}
	for name, original := range before {
		current := after[name]
		if !bytes.Equal(original.content, current.content) || !os.SameFile(original.info, current.info) ||
			original.info.Mode() != current.info.Mode() || !original.info.ModTime().Equal(current.info.ModTime()) {
			t.Fatalf("refused publication changed retained bytes, inode, mode or modification time: %s", name)
		}
	}
}

func TestSaaSRefreshRefusesDisappearingFamilyWithoutPublishing(t *testing.T) {
	for _, test := range []struct {
		name          string
		body          string
		optionalError bool
	}{
		{name: "IPv4 disappears", body: "2606:4700:4700::2\n"},
		{name: "IPv6 disappears", body: "8.8.8.2\n"},
		{name: "optional IPv4 feed fails", body: "2606:4700:4700::2\n", optionalError: true},
		{name: "optional IPv6 feed fails", body: "8.8.8.2\n", optionalError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			ipv4Path := filepath.Join(directory, "syswarden_saas_monitors.ipv4")
			ipv6Path := filepath.Join(directory, "syswarden_saas_monitors.ipv6")
			if err := publishSaaSListPair(ipv4Path, ipv6Path, []byte("8.8.4.1\n"), []byte("2606:4700:4700::1\n")); err != nil {
				t.Fatal(err)
			}
			before, names := snapshotSaaSRetainedPair(t, directory)
			if len(before) != 3 || before[saasPairManifestName].info == nil {
				t.Fatal("fixture must include both family files and their manifest")
			}
			requests := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				switch request.URL.Path {
				case "/required":
					return textResponse(request, http.StatusOK, test.body), nil
				case "/optional":
					return nil, errors.New("synthetic optional feed unavailable")
				default:
					t.Errorf("unexpected synthetic request: %s", request.URL.Path)
					return nil, errors.New("unexpected synthetic request")
				}
			})}
			feeds := []saasFeed{{url: "https://feeds.example.test/required", required: true}}
			wantRequests := 1
			if test.optionalError {
				feeds = append(feeds, saasFeed{url: "https://feeds.example.test/optional"})
				wantRequests++
			}
			downloader := &SaasMonitorDownloader{
				client: client, feeds: feeds, targetIPv4: ipv4Path, targetIPv6: ipv6Path,
				localInterfaceAddresses: func() ([]netip.Addr, error) { return nil, nil },
				protectedHAPeers:        func() ([]netip.Prefix, error) { return nil, nil },
			}
			if err := downloader.fetchMonitors(); err == nil {
				t.Fatal("refresh accepted the disappearance of a populated address family")
			}
			if requests != wantRequests {
				t.Fatalf("refresh made %d synthetic requests, want %d", requests, wantRequests)
			}
			assertSaaSRetainedPairUnchanged(t, directory, before, names)
		})
	}
}

func TestSaaSPublicationRetainsSingleFamilySupport(t *testing.T) {
	for _, family := range []string{"IPv4", "IPv6"} {
		for _, state := range []string{"fresh", "opposite family already empty", "opposite family already whitespace"} {
			t.Run(family+"/"+state, func(t *testing.T) {
				directory := t.TempDir()
				ipv4Path := filepath.Join(directory, "syswarden_saas_monitors.ipv4")
				ipv6Path := filepath.Join(directory, "syswarden_saas_monitors.ipv6")
				var old4, old6, candidate4, candidate6 []byte
				if family == "IPv4" {
					old4, candidate4 = []byte("8.8.4.1\n"), []byte("8.8.8.2\n")
					if state == "opposite family already whitespace" {
						old6 = []byte(" \t\r\n")
					}
				} else {
					old6, candidate6 = []byte("2606:4700:4700::1\n"), []byte("2606:4700:4700::2\n")
					if state == "opposite family already whitespace" {
						old4 = []byte(" \t\r\n")
					}
				}
				if state != "fresh" {
					if err := publishSaaSListPair(ipv4Path, ipv6Path, old4, old6); err != nil {
						t.Fatal(err)
					}
				}
				if err := publishSaaSListPair(ipv4Path, ipv6Path, candidate4, candidate6); err != nil {
					t.Fatalf("safe single-family publication was refused: %v", err)
				}
				assertFileContent(t, ipv4Path, string(candidate4))
				assertFileContent(t, ipv6Path, string(candidate6))
				assertFileContent(t, filepath.Join(directory, saasPairManifestName), string(renderSaaSPairManifest(candidate4, candidate6)))
				_, names := snapshotSaaSRetainedPair(t, directory)
				if len(names) != 3 {
					t.Fatalf("single-family publication left unexpected files: %v", names)
				}
			})
		}
	}
}

func TestSaaSPublicationRefusesWhitespaceReplacementOfPopulatedFamily(t *testing.T) {
	for _, family := range []string{"IPv4", "IPv6"} {
		t.Run(family, func(t *testing.T) {
			directory := t.TempDir()
			ipv4Path := filepath.Join(directory, "syswarden_saas_monitors.ipv4")
			ipv6Path := filepath.Join(directory, "syswarden_saas_monitors.ipv6")
			if err := publishSaaSListPair(ipv4Path, ipv6Path, []byte("8.8.4.1\n"), []byte("2606:4700:4700::1\n")); err != nil {
				t.Fatal(err)
			}
			before, names := snapshotSaaSRetainedPair(t, directory)
			candidate4, candidate6 := []byte("8.8.8.2\n"), []byte("2606:4700:4700::2\n")
			if family == "IPv4" {
				candidate4 = []byte(" \t\r\n")
			} else {
				candidate6 = []byte(" \t\r\n")
			}
			if err := publishSaaSListPair(ipv4Path, ipv6Path, candidate4, candidate6); err == nil {
				t.Fatal("publication replaced a populated family with whitespace")
			}
			assertSaaSRetainedPairUnchanged(t, directory, before, names)
		})
	}
}
