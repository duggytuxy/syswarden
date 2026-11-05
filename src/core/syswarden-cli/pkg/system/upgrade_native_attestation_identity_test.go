package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type selectedNativeAttestationStep struct {
	path string
	args []string
	wire string
}

func selectedNativeAttestationSteps(format, name, binary string) []selectedNativeAttestationStep {
	switch format {
	case packageFormatDEB:
		return []selectedNativeAttestationStep{
			{"/usr/bin/dpkg-query", []string{"--show", "--showformat=${Package}\t${db:Status-Abbrev}\t${Version}\t${Architecture}\n", name}, name + "\tii \t5.00.0\tamd64\n"},
			{"/usr/bin/dpkg-query", []string{"--search", binary}, name + ": " + binary + "\n"},
			{"/usr/bin/dpkg", []string{"--verify", "--verify-format=rpm", name}, ""},
		}
	case packageFormatRPM:
		return []selectedNativeAttestationStep{
			{"/usr/bin/rpm", []string{"--query", name, "--queryformat", "%{NAME}\t%{VERSION}\t%{ARCH}\n"}, name + "\t5.00.0\tx86_64\n"},
			{"/usr/bin/rpm", []string{"--query", "--file", binary, "--queryformat", "%{NAME}\t%{VERSION}\t%{ARCH}\n"}, name + "\t5.00.0\tx86_64\n"},
			{"/usr/bin/rpm", []string{"--verify", name, "--noscripts"}, ""},
		}
	case packageFormatAPK:
		return []selectedNativeAttestationStep{
			{"/sbin/apk", []string{"--no-network", "--repositories-file", "/dev/null", "list", "--installed", name}, name + "-5.00.0-r0 x86_64 {" + name + "} (AGPL-3.0-only) [installed]\n"},
			{"/sbin/apk", []string{"info", "--who-owns", binary}, binary + " is owned by " + name + "-5.00.0-r0\n"},
		}
	default:
		panic("unknown isolated attestation fixture format")
	}
}

func runSelectedNativeAttestation(ctx context.Context, format, name, binary string, output qualificationCommandOutput) (string, error) {
	switch format {
	case packageFormatDEB:
		return attestInstalledDEBVersionForName(ctx, name, binary, output)
	case packageFormatRPM:
		return attestInstalledRPMVersionForName(ctx, name, binary, output)
	case packageFormatAPK:
		return attestInstalledAPKVersionForName(ctx, name, "/sbin/apk", binary, output)
	default:
		panic("unknown isolated attestation fixture format")
	}
}

func selectedNativeAttestationOutput(t *testing.T, steps []selectedNativeAttestationStep, calls *int) qualificationCommandOutput {
	t.Helper()
	return func(_ context.Context, path string, args ...string) ([]byte, error) {
		t.Helper()
		index := *calls
		*calls = index + 1
		if index >= len(steps) {
			t.Fatalf("unexpected fallback query: %s %q", path, args)
		}
		step := steps[index]
		if path != step.path || !reflect.DeepEqual(args, step.args) {
			t.Fatalf("query %d = %s %q, want %s %q", index, path, args, step.path, step.args)
		}
		return []byte(step.wire), nil
	}
}

func TestSelectedNativeAttestationBindsBothIdentities(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			t.Run(format+"/"+name, func(t *testing.T) {
				steps := selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath)
				calls := 0
				version, err := runSelectedNativeAttestation(t.Context(), format, name, installedSyswardenCLIPath,
					selectedNativeAttestationOutput(t, steps, &calls))
				if err != nil || version != "v5.00.0" || calls != len(steps) {
					t.Fatalf("attestation = %q, calls=%d: %v", version, calls, err)
				}
			})
		}
	}
}

func TestSelectedNativeAttestationQueriesPassClosedProductionAllowlist(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			for _, step := range selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath) {
				if !allowedQualificationQuery(step.path, step.args) {
					t.Errorf("selected identity query refused: %s %q", step.path, step.args)
				}
			}
		}
		for _, step := range selectedNativeAttestationSteps(format, "operator-package", installedSyswardenCLIPath) {
			// Ownership queries use only the fixed CLI path and carry no package
			// argument. Every query carrying a foreign identity must be refused.
			if strings.Contains(strings.Join(step.args, " "), "operator-package") && allowedQualificationQuery(step.path, step.args) {
				t.Errorf("foreign package query entered the allowlist: %s %q", step.path, step.args)
			}
		}
	}
}

func TestSelectedNativeAttestationRejectsUnknownIdentityBeforeQuery(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"", "operator-package", "SYSWARDEN", "syswarden-base:amd64", " syswarden", "syswarden\n"} {
			t.Run(format+"/"+name, func(t *testing.T) {
				calls := 0
				output := func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
				version, err := runSelectedNativeAttestation(t.Context(), format, name, installedSyswardenCLIPath, output)
				if err == nil || version != "" || calls != 0 {
					t.Fatalf("unknown identity reached query: version=%q calls=%d error=%v", version, calls, err)
				}
				_, err = attestInstalledQualificationVersionWith(t.Context(), packageTarget{packageName: name, format: format},
					os.Geteuid(), "/definitely-absent-native-attestation/syswarden-cli", output)
				if err == nil || !strings.Contains(err.Error(), "invalid installed-version attestation configuration") || calls != 0 {
					t.Fatalf("unknown identity was not rejected before file IO: calls=%d error=%v", calls, err)
				}
			})
		}
	}
}

func TestSelectedNativeAttestationCancellationCannotBecomeSuccess(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			steps := selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath)
			for cancelAt := -1; cancelAt < len(steps); cancelAt++ {
				label := "before-query"
				if cancelAt >= 0 {
					label = "callback-" + strconv.Itoa(cancelAt)
				}
				t.Run(format+"/"+name+"/"+label, func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					calls := 0
					query := selectedNativeAttestationOutput(t, steps, &calls)
					if cancelAt == -1 {
						cancel()
					}
					output := func(ctx context.Context, path string, args ...string) ([]byte, error) {
						wire, err := query(ctx, path, args...)
						if calls-1 == cancelAt {
							cancel()
						}
						return wire, err // Deliberately successful after cancellation.
					}
					version, err := runSelectedNativeAttestation(ctx, format, name, installedSyswardenCLIPath, output)
					if !errors.Is(err, context.Canceled) || version != "" || calls != cancelAt+1 {
						t.Fatalf("canceled query continued or succeeded: version=%q calls=%d want=%d error=%v", version, calls, cancelAt+1, err)
					}
				})
			}
		}
	}
}

func TestSelectedNativeAttestationRefusesMalformedOrForeignEvidence(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			original := selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath)
			other := "syswarden-base"
			if name == other {
				other = "syswarden"
			}
			foreignOwner := other + ": " + installedSyswardenCLIPath + "\n"
			if format == packageFormatRPM {
				foreignOwner = other + "\t5.00.0\tx86_64\n"
			}
			if format == packageFormatAPK {
				foreignOwner = installedSyswardenCLIPath + " is owned by " + other + "-5.00.0-r0\n"
			}
			cases := []struct {
				label string
				index int
				wire  string
			}{
				{"empty-version", 0, ""}, {"no-final-newline", 0, strings.TrimSuffix(original[0].wire, "\n")},
				{"duplicate-version", 0, original[0].wire + original[0].wire},
				{"nul-version", 0, strings.ReplaceAll(original[0].wire, "5.00.0", "5.00.0\x00")},
				{"foreign-owner", 1, foreignOwner},
				{"duplicate-owner", 1, original[1].wire + original[1].wire},
				{"malformed-owner", 1, strings.TrimSuffix(original[1].wire, "\n")},
			}
			switch format {
			case packageFormatDEB:
				cases = append(cases, struct {
					label string
					index int
					wire  string
				}{"unconfigured", 0, name + "\tiU \t5.00.0\tamd64\n"},
					struct {
						label string
						index int
						wire  string
					}{"unexpected-architecture-field", 0, name + "\tii \t5.00.0\tamd64\tarm64\n"})
			case packageFormatRPM:
				cases = append(cases, struct {
					label string
					index int
					wire  string
				}{"owner-version-mismatch", 1, name + "\t5.01.0\tx86_64\n"},
					struct {
						label string
						index int
						wire  string
					}{"foreign-name", 0, other + "\t5.00.0\tx86_64\n"})
			case packageFormatAPK:
				cases = append(cases, struct {
					label string
					index int
					wire  string
				}{"owner-version-mismatch", 1, installedSyswardenCLIPath + " is owned by " + name + "-5.00.0-r1\n"},
					struct {
						label string
						index int
						wire  string
					}{"foreign-name", 0, other + "-5.00.0-r0 x86_64 {" + other + "} (AGPL-3.0-only) [installed]\n"},
					struct {
						label string
						index int
						wire  string
					}{"unexpected-architecture-field", 0, name + "-5.00.0-r0 x86_64 aarch64 {" + name + "} (AGPL-3.0-only) [installed]\n"})
			}
			for _, tc := range cases {
				t.Run(format+"/"+name+"/"+tc.label, func(t *testing.T) {
					steps := append([]selectedNativeAttestationStep(nil), original...)
					steps[tc.index].wire = tc.wire
					calls := 0
					version, err := runSelectedNativeAttestation(t.Context(), format, name, installedSyswardenCLIPath,
						selectedNativeAttestationOutput(t, steps, &calls))
					if err == nil || version != "" {
						t.Fatalf("foreign or malformed evidence accepted: %q, %v", version, err)
					}
				})
			}
			if format == packageFormatRPM {
				t.Run(format+"/"+name+"/matching-foreign-identity", func(t *testing.T) {
					steps := selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath)
					steps[0].wire = other + "\t5.00.0\tx86_64\n"
					steps[1].wire = steps[0].wire
					calls := 0
					version, err := runSelectedNativeAttestation(t.Context(), format, name, installedSyswardenCLIPath,
						selectedNativeAttestationOutput(t, steps, &calls))
					if err == nil || version != "" || calls != 2 {
						t.Fatalf("foreign selected identity accepted: %q calls=%d error=%v", version, calls, err)
					}
				})
				t.Run(format+"/"+name+"/matching-foreign-architecture", func(t *testing.T) {
					steps := selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath)
					steps[0].wire = name + "\t5.00.0\taarch64\n"
					steps[1].wire = steps[0].wire
					calls := 0
					version, err := runSelectedNativeAttestation(t.Context(), format, name, installedSyswardenCLIPath,
						selectedNativeAttestationOutput(t, steps, &calls))
					if err == nil || version != "" || calls != 2 {
						t.Fatalf("foreign architecture accepted: %q calls=%d error=%v", version, calls, err)
					}
				})
			}
		}
	}
}

func TestSelectedNativeAttestationRejectsArchitectureAndStatusBeforeOwnership(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatAPK} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			steps := selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath)
			valid := steps[0].wire
			other := "syswarden-base"
			if name == other {
				other = "syswarden"
			}
			wireForArchitecture := func(architecture string) string {
				if format == packageFormatDEB {
					return name + "\tii \t5.00.0\t" + architecture + "\n"
				}
				return name + "-5.00.0-r0 " + architecture + " {" + name + "} (AGPL-3.0-only) [installed]\n"
			}
			type invalidEvidence struct{ label, wire string }
			cases := []invalidEvidence{
				{"empty-record", ""},
				{"duplicate-records", valid + valid},
				{"contradictory-records", valid + wireForArchitecture("aarch64")},
				{"missing-final-newline", strings.TrimSuffix(valid, "\n")},
				{"crlf-record", strings.ReplaceAll(valid, "\n", "\r\n")},
				{"empty-version", strings.ReplaceAll(valid, "5.00.0", "")},
			}
			for _, architecture := range []string{"arm64", "aarch64", "noarch", "all", "", "amd64 x86_64", "x86_64/amd64", "x86_64\tamd64", "amd64\x00"} {
				cases = append(cases, invalidEvidence{"architecture-" + strconv.Quote(architecture), wireForArchitecture(architecture)})
			}
			if format == packageFormatDEB {
				cases = append(cases,
					invalidEvidence{"foreign-name", other + "\tii \t5.00.0\tamd64\n"},
					invalidEvidence{"foreign-architecture-spelling", wireForArchitecture("x86_64")},
					invalidEvidence{"extra-architecture-field", wireForArchitecture("amd64\tarm64")},
					invalidEvidence{"architecture-free-record", "ii \t5.00.0\n"},
				)
				for _, status := range []string{"iU ", "ii", "iiR", "hi ", "rc ", "", "ii \tiU "} {
					cases = append(cases, invalidEvidence{"status-" + strconv.Quote(status), name + "\t" + status + "\t5.00.0\tamd64\n"})
				}
			} else {
				cases = append(cases,
					invalidEvidence{"foreign-name", other + "-5.00.0-r0 x86_64 {" + other + "} (AGPL-3.0-only) [installed]\n"},
					invalidEvidence{"foreign-architecture-spelling", wireForArchitecture("amd64")},
					invalidEvidence{"architecture-free-record", name + "-5.00.0-r0\n"},
					invalidEvidence{"oversized-display-metadata", strings.ReplaceAll(valid, "AGPL-3.0-only", strings.Repeat("A", 64<<10))},
					invalidEvidence{"invalid-utf8-display-metadata", strings.ReplaceAll(valid, "AGPL-3.0-only", "license\xff")},
					invalidEvidence{"terminal-control-display-metadata", strings.ReplaceAll(valid, "AGPL-3.0-only", "license\x1b[0m")},
					invalidEvidence{"line-separator-display-metadata", strings.ReplaceAll(valid, "AGPL-3.0-only", "license\u2028suffix")},
				)
				for _, status := range []string{"", "[available]", "[upgradable]", "[installed] [available]", "[installed] [installed]", "[installed", "installed"} {
					cases = append(cases, invalidEvidence{"status-" + strconv.Quote(status), strings.ReplaceAll(valid, "[installed]", status)})
				}
			}
			for _, tc := range cases {
				t.Run(format+"/"+name+"/"+tc.label, func(t *testing.T) {
					first := []selectedNativeAttestationStep{steps[0]}
					first[0].wire = tc.wire
					calls := 0
					version, err := runSelectedNativeAttestation(t.Context(), format, name, installedSyswardenCLIPath,
						selectedNativeAttestationOutput(t, first, &calls))
					if err == nil || version != "" || calls != 1 {
						t.Fatalf("invalid installed identity reached ownership or succeeded: version=%q calls=%d error=%v", version, calls, err)
					}
				})
			}
		}
	}
}

func TestSelectedNativeAttestationDoesNotFallbackToAnotherPackage(t *testing.T) {
	failure := errors.New("selected package is unavailable")
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			t.Run(format+"/"+name, func(t *testing.T) {
				calls := 0
				first := selectedNativeAttestationSteps(format, name, installedSyswardenCLIPath)[:1]
				check := selectedNativeAttestationOutput(t, first, &calls)
				output := func(ctx context.Context, path string, args ...string) ([]byte, error) {
					_, _ = check(ctx, path, args...)
					return nil, failure
				}
				version, err := runSelectedNativeAttestation(t.Context(), format, name, installedSyswardenCLIPath, output)
				if !errors.Is(err, failure) || version != "" || calls != 1 {
					t.Fatalf("selected package failure fell back: %q calls=%d error=%v", version, calls, err)
				}
			})
		}
	}
}

func TestSelectedNativeAttestationTopLevelBindsProtectedCLI(t *testing.T) {
	for _, format := range []string{packageFormatDEB, packageFormatRPM, packageFormatAPK} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			t.Run(format+"/"+name, func(t *testing.T) {
				directory := filepath.Join(t.TempDir(), "opt", "syswarden", "bin")
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				binary := filepath.Join(directory, "syswarden-cli")
				payload := []byte("synthetic selected-package CLI; never executed\n")
				if err := os.WriteFile(binary, payload, 0750); err != nil { // #nosec G306 -- isolated fixture must be owner-executable for attestation
					t.Fatal(err)
				}
				steps := selectedNativeAttestationSteps(format, name, binary)
				calls := 0
				evidence, err := attestInstalledQualificationVersionWith(t.Context(),
					packageTarget{packageName: name, format: format, installer: "/sbin/apk"}, os.Geteuid(), binary,
					selectedNativeAttestationOutput(t, steps, &calls))
				digest := sha256.Sum256(payload)
				if err != nil || evidence.version != "v5.00.0" || evidence.cliSHA256 != hex.EncodeToString(digest[:]) || calls != len(steps) {
					t.Fatalf("top-level selected package proof: %#v calls=%d error=%v", evidence, calls, err)
				}
			})
		}
	}
}

func TestSelectedNativeAttestationTopLevelCancellationPrecedesFileIO(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := 0
	output := func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
	evidence, err := attestInstalledQualificationVersionWith(ctx,
		packageTarget{packageName: "syswarden-base", format: packageFormatDEB}, os.Geteuid(),
		"/definitely-absent-native-attestation/syswarden-cli", output)
	if !errors.Is(err, context.Canceled) || evidence != (installedQualificationEvidence{}) || calls != 0 {
		t.Fatalf("canceled top-level proof reached file IO: %#v calls=%d error=%v", evidence, calls, err)
	}
}

func TestSelectedNativeAttestationWrapperCancellationCannotBecomeEvidence(t *testing.T) {
	for _, label := range []string{"installed", "post-install", "pre-activation"} {
		for _, name := range []string{"syswarden", "syswarden-base"} {
			for _, boundary := range []string{"already-canceled", "child-deadline", "callback-cancels-parent"} {
				t.Run(label+"/"+name+"/"+boundary, func(t *testing.T) {
					parent, cancelParent := context.WithCancel(t.Context())
					defer cancelParent()
					target := packageTarget{packageName: name, format: packageFormatDEB}
					validEvidence := installedQualificationEvidence{
						version: "v5.00.0", cliSHA256: strings.Repeat("a", sha256.Size*2),
					}
					calls, wantCalls := 0, 1
					wantErr := context.Canceled
					timeout := time.Second
					switch boundary {
					case "already-canceled":
						cancelParent()
						wantCalls = 0
					case "child-deadline":
						timeout = 20 * time.Millisecond
						wantErr = context.DeadlineExceeded
					}
					u := updater{
						attestTimeout: timeout,
						effectiveUID:  os.Geteuid(),
						attestInstalled: func(ctx context.Context, gotTarget packageTarget, gotUID int) (installedQualificationEvidence, error) {
							calls++
							if !reflect.DeepEqual(gotTarget, target) || gotUID != os.Geteuid() {
								t.Fatalf("wrapper changed selected identity or UID: %#v, %d", gotTarget, gotUID)
							}
							if _, ok := ctx.Deadline(); !ok {
								t.Fatal("wrapper callback has no attestation deadline")
							}
							switch boundary {
							case "child-deadline":
								<-ctx.Done()
								if err := parent.Err(); err != nil {
									t.Fatalf("child deadline canceled the live parent: %v", err)
								}
							case "callback-cancels-parent":
								cancelParent()
								<-ctx.Done()
							}
							return validEvidence, nil // Deliberately successful despite cancellation.
						},
					}
					evidence, err := u.attestQualificationInstallation(parent, target, label)
					if !errors.Is(err, wantErr) || evidence != (installedQualificationEvidence{}) || calls != wantCalls {
						t.Fatalf("canceled wrapper accepted evidence: %#v calls=%d want=%d error=%v", evidence, calls, wantCalls, err)
					}
					if !strings.Contains(err.Error(), "attest "+label+" SysWarden version:") {
						t.Fatalf("cancellation lost its attestation stage: %v", err)
					}
					if boundary == "child-deadline" && parent.Err() != nil {
						t.Fatalf("child timeout affected parent after return: %v", parent.Err())
					}
				})
			}
		}
	}
}
