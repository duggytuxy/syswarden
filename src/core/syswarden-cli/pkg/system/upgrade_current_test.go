package system

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCurrentReleaseRequiresInstalledPackageAttestation(t *testing.T) {
	for _, kind := range []string{"healthy", "half-configured", "mismatch", "missing-attestor"} {
		t.Run(kind, func(t *testing.T) {
			requests, mutations, attestations := 0, 0, 0
			client := staticHTTPClient(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Path != "/latest" {
					t.Fatalf("unexpected download %s", req.URL.Path)
				}
				return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
			})
			u := testUpdater(client, t.TempDir(), "amd64", nil, func(context.Context, string, ...string) error { mutations++; return nil })
			u.currentVersion = testUpdateVersion
			var output bytes.Buffer
			u.stdout = &output
			if kind != "missing-attestor" {
				u.attestInstalled = func(ctx context.Context, target packageTarget, uid int) (installedQualificationEvidence, error) {
					attestations++
					if _, ok := ctx.Deadline(); !ok {
						t.Fatal("package attestation has no deadline")
					}
					if target.format != packageFormatDEB || uid != u.effectiveUID {
						t.Fatal("wrong installed package identity")
					}
					if kind == "half-configured" {
						return installedQualificationEvidence{}, errors.New("installed DEB status and version are ambiguous")
					}
					version := testUpdateVersion
					if kind == "mismatch" {
						version = "v4.02.8"
					}
					return installedQualificationEvidence{version: version}, nil
				}
			}
			err := u.run(context.Background())
			success := strings.Contains(output.String(), "[SUCCESS]")
			if kind == "healthy" {
				if err != nil || !success || !strings.Contains(output.String(), "does not verify") {
					t.Fatalf("err=%v output=%s", err, output.String())
				}
			} else if err == nil || success {
				t.Fatalf("unhealthy current package passed: %v %s", err, output.String())
			}
			if requests != 1 || mutations != 0 {
				t.Fatalf("requests=%d mutations=%d", requests, mutations)
			}
			if kind != "missing-attestor" && attestations != 1 {
				t.Fatalf("attestations=%d", attestations)
			}
		})
	}
}

func TestCurrentReleaseRefusesExpiredAttestation(t *testing.T) {
	for _, kind := range []string{"late-success", "late-error", "parent-cancelled-success", "expired-before-callback"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			requests, mutations, attestations := 0, 0, 0
			client := staticHTTPClient(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Path != "/latest" {
					t.Fatalf("unexpected download %s", req.URL.Path)
				}
				return testHTTPResponse(http.StatusOK, []byte(`{"tag_name":"`+testUpdateVersion+`"}`)), nil
			})
			u := testUpdater(client, t.TempDir(), "amd64", nil, func(context.Context, string, ...string) error {
				mutations++
				return nil
			})
			u.currentVersion = testUpdateVersion
			u.metadataTimeout = 50 * time.Millisecond
			var output bytes.Buffer
			u.stdout = &output
			if kind == "expired-before-callback" {
				lookup := u.lookPath
				u.lookPath = func(name string) (string, error) {
					path, err := lookup(name)
					cancel()
					return path, err
				}
			}
			callbackError := errors.New("fixture attestation failure")
			u.attestInstalled = func(child context.Context, target packageTarget, uid int) (installedQualificationEvidence, error) {
				attestations++
				if target.packageName != compatibilityNativePackageName || target.format != packageFormatDEB || uid != u.effectiveUID {
					t.Fatal("current-version attestation changed selected identity")
				}
				if _, ok := child.Deadline(); !ok {
					t.Fatal("current-version attestation has no deadline")
				}
				if kind == "expired-before-callback" {
					t.Fatal("already canceled attestation callback ran")
				}
				if kind == "parent-cancelled-success" {
					cancel()
				} else {
					<-child.Done()
					if ctx.Err() != nil {
						t.Fatal("child deadline canceled the live parent")
					}
				}
				evidence := installedQualificationEvidence{version: testUpdateVersion}
				if kind == "late-error" {
					return evidence, callbackError
				}
				return evidence, nil
			}
			err := u.run(ctx)
			wantContextError := context.DeadlineExceeded
			wantAttestations := 1
			if kind == "parent-cancelled-success" || kind == "expired-before-callback" {
				wantContextError = context.Canceled
			}
			if kind == "expired-before-callback" {
				wantAttestations = 0
			}
			if !errors.Is(err, wantContextError) || strings.Contains(output.String(), "[SUCCESS]") {
				t.Fatalf("expired current-version attestation accepted: %v, output=%s", err, output.String())
			}
			if kind == "late-error" && !errors.Is(err, callbackError) {
				t.Fatalf("callback error was lost: %v", err)
			}
			if requests != 1 || mutations != 0 || attestations != wantAttestations {
				t.Fatalf("requests=%d mutations=%d attestations=%d", requests, mutations, attestations)
			}
		})
	}
}
