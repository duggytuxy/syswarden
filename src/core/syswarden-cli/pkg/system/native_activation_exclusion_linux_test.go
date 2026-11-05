//go:build linux

package system

import (
	"bytes"
	"strings"
	"testing"
)

func TestNativeActivationDescriptorDoesNotUpgradeLegacyCapabilities(t *testing.T) {
	cli, core := strings.Repeat("a", 64), strings.Repeat("b", 64)
	legacy := []byte(`{"schema":"syswarden-native-activation-v1","architecture":"linux-amd64","approval_schema":"syswarden-activation-approval-v1","source_contract":"syswarden-toml-source-v1","environment":"toml-only-reject-modular-environment-v1","cli_sha256":"` + cli + `","core_sha256":"` + core + `"}` + "\n")
	current, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(cli, core))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{legacy, current} {
		captured, err := parseNativeActivationDescriptor(raw)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := canonicalNativeActivationDescriptor(captured.descriptor)
		if err != nil || !bytes.Equal(roundTrip, raw) {
			t.Fatal("historical contract bytes were rewritten")
		}
		if captured.publicationExclusion() != bytes.Equal(raw, current) {
			t.Fatal("publication exclusion capability was confused")
		}
		if captured.SHA256() != apkTransitionDigest(raw) {
			t.Fatal("descriptor digest changed")
		}
	}
	if (NativeActivationCandidate{}).publicationExclusion() {
		t.Fatal("zero candidate granted exclusion")
	}
	captured, _ := parseNativeActivationDescriptor(current)
	captured.digest = strings.Repeat("0", 64)
	if captured.publicationExclusion() {
		t.Fatal("unbound descriptor granted exclusion")
	}
	for _, raw := range [][]byte{
		bytes.Replace(current, []byte("syswarden-native-activation-v2"), []byte("syswarden-native-activation-v1"), 1),
		bytes.Replace(legacy, []byte("syswarden-native-activation-v1"), []byte("syswarden-native-activation-v2"), 1),
		bytes.Replace(current, []byte(nativePublicationExclusion), []byte("config-directory-flock-and-native-debt-v9"), 1),
		bytes.Replace(current, []byte(nativePublicationExclusion), nil, 1),
		bytes.Replace(current, []byte("}\n"), []byte(",\"publication_exclusion\":\""+nativePublicationExclusion+"\"}\n"), 1),
	} {
		if candidate, err := parseNativeActivationDescriptor(raw); err == nil || candidate.publicationExclusion() {
			t.Fatal("mixed, incomplete or unknown capability accepted")
		}
	}
}

func TestNativeActivationCandidateRetainsLegacyPackageClassification(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, legacy := range []bool{false, true} {
			t.Run(format+"/legacy="+map[bool]string{true: "yes", false: "no"}[legacy], func(t *testing.T) {
				entries := nativeActivationTestPayload(t)
				if legacy {
					current, err := parseNativeActivationDescriptor(entries[2].payload)
					if err != nil {
						t.Fatal(err)
					}
					entries[2].payload, err = canonicalNativeActivationDescriptor(nativeActivationLegacyDescriptorFor(current.Review().CLISHA256, current.Review().CoreSHA256))
					if err != nil {
						t.Fatal(err)
					}
				}
				candidate, err := nativeActivationTestClassify(t, format, entries)
				if err != nil {
					t.Fatal(err)
				}
				if candidate.publicationExclusion() == legacy {
					t.Fatal("payload classification changed capability generation")
				}
			})
		}
	}
}
