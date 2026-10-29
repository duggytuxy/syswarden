package system

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestAuthenticatedNativeInstallGuardFollowsEveryPreparation(t *testing.T) {
	for _, selected := range []struct{ format, installer string }{
		{packageFormatDEB, "/usr/bin/apt-get"},
		{packageFormatRPM, "/usr/bin/dnf"},
		{packageFormatRPM, "/usr/bin/yum"},
		{packageFormatAPK, "/sbin/apk"},
		{packageFormatAPK, "/usr/sbin/apk"},
	} {
		for _, offline := range []bool{false, true} {
			for _, outcome := range []string{"success", "preparation-error", "preparation-cancel", "preparation-mutation", "guard-error", "guard-cancel", "execution-error"} {
				t.Run(fmt.Sprintf("%s/%t/%s", selected.installer, offline, outcome), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
					defer cancel()
					target := packageHeaderBoundaryTarget(t, "syswarden", selected.format, "v5.00.0")
					target.installer = selected.installer
					// Command validation uses an inert allowlisted path. The guard
					// hashes a separate isolated descriptor; no executor opens a path.
					packagePath := "/var/tmp/syswarden-update-guard/" + target.filename
					file := packageHeaderBoundaryFile(t)
					payload, err := io.ReadAll(io.NewSectionReader(file, 0, 4096))
					if err != nil {
						t.Fatal(err)
					}
					artifact := updateArtifact{Size: int64(len(payload)), SHA256: fmt.Sprintf("%x", sha256.Sum256(payload))}
					if err := verifyPackageAtNativeExecution(ctx, file, file.Name(), artifact, os.Geteuid()); err != nil {
						t.Fatal(err)
					}
					name, args := target.installer, target.installArguments(packagePath)
					if offline {
						name, args = target.qualificationInstallCommand(packagePath)
					}
					var events []string
					sentinel := errors.New("injected native installation boundary refusal")
					preparation := "retain"
					if selected.format == packageFormatAPK {
						preparation = "plan-apk"
					}
					prepareOutcome := func() error {
						switch outcome {
						case "preparation-error":
							return sentinel
						case "preparation-cancel":
							cancel()
						case "preparation-mutation":
							mutatePackageHeaderBoundaryFile(t, file, len(payload))
						}
						return nil
					}
					prepare := func(gotCtx context.Context, manager string) error {
						if selected.format == packageFormatAPK || gotCtx != ctx || manager != name {
							t.Fatal("native retention changed its context, manager or format")
						}
						events = append(events, "retain")
						return prepareOutcome()
					}
					planAPK := func(gotCtx context.Context, manager string, original []string) ([]string, error) {
						if selected.format != packageFormatAPK || gotCtx != ctx || manager != name || !reflect.DeepEqual(original, args) {
							t.Fatal("APK planning changed its context or original validated command")
						}
						events = append(events, "plan-apk")
						return append(append([]string(nil), original...), "rsyslog"), prepareOutcome()
					}
					guard := func(gotCtx context.Context) error {
						if gotCtx != ctx || !reflect.DeepEqual(events, []string{preparation}) {
							t.Fatalf("final guard preceded native preparation: %q", events)
						}
						events = append(events, "guard")
						if err := verifyPackageAtNativeExecution(gotCtx, file, file.Name(), artifact, os.Geteuid()); err != nil {
							return err
						}
						if outcome == "guard-error" {
							return sentinel
						}
						if outcome == "guard-cancel" {
							cancel()
						}
						return nil
					}
					execute := func(gotCtx context.Context, manager string, actual ...string) error {
						wantArgs := args
						if selected.format == packageFormatAPK {
							wantArgs = append(append([]string(nil), args...), "rsyslog")
						}
						if gotCtx != ctx || manager != name || !reflect.DeepEqual(actual, wantArgs) ||
							!reflect.DeepEqual(events, []string{preparation, "guard"}) {
							t.Fatal("raw execution did not immediately follow the guard with the prepared command")
						}
						events = append(events, "execute")
						if outcome == "execution-error" {
							return sentinel
						}
						return nil
					}
					err = runAuthenticatedNativeInstallWith(ctx, target, packagePath, offline, prepare, planAPK, execute, guard)
					wantEvents := []string{preparation, "guard", "execute"}
					switch outcome {
					case "preparation-error", "preparation-cancel":
						wantEvents = []string{preparation}
					case "preparation-mutation", "guard-error", "guard-cancel":
						wantEvents = []string{preparation, "guard"}
					}
					if !reflect.DeepEqual(events, wantEvents) || (err == nil) != (outcome == "success") {
						t.Fatalf("events=%q want=%q error=%v", events, wantEvents, err)
					}
					if (outcome == "preparation-error" || outcome == "guard-error" || outcome == "execution-error") && !errors.Is(err, sentinel) {
						t.Fatalf("boundary refusal was lost: %v", err)
					}
					if (outcome == "preparation-cancel" || outcome == "guard-cancel") && !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled preparation or guard was accepted: %v", err)
					}
				})
			}
		}
	}
}

func TestAuthenticatedNativeInstallRejectsIncompleteOrForeignBoundary(t *testing.T) {
	for _, offline := range []bool{false, true} {
		for _, invalid := range []string{"nil-context", "canceled-context", "nil-retention", "nil-apk-planner", "nil-executor", "nil-guard", "base-not-qualified", "foreign-name", "platform", "architecture", "format", "installer", "package-path"} {
			t.Run(fmt.Sprintf("%t/%s", offline, invalid), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				target := packageHeaderBoundaryTarget(t, "syswarden", packageFormatDEB, "v5.00.0")
				target.installer = "/usr/bin/apt-get"
				path := "/var/tmp/syswarden-update-guard/" + target.filename
				calls := 0
				prepare := func(context.Context, string) error { calls++; return nil }
				planAPK := func(context.Context, string, []string) ([]string, error) { calls++; return nil, nil }
				execute := func(context.Context, string, ...string) error { calls++; return nil }
				guard := func(context.Context) error { calls++; return nil }
				switch invalid {
				case "nil-context":
					ctx = nil
				case "canceled-context":
					cancel()
				case "nil-retention":
					prepare = nil
				case "nil-apk-planner":
					planAPK = nil
				case "nil-executor":
					execute = nil
				case "nil-guard":
					guard = nil
				case "base-not-qualified":
					target.packageName = "syswarden-base"
				case "foreign-name":
					target.packageName = "unrelated-package"
				case "platform":
					target.os = "unsupported"
				case "architecture":
					target.architecture = "386"
				case "format":
					target.format = "tar"
				case "installer":
					target.installer = "/usr/bin/dnf"
				case "package-path":
					path = "/tmp/unverified-package.deb"
				}
				if err := runAuthenticatedNativeInstallWith(ctx, target, path, offline, prepare, planAPK, execute, guard); err == nil || calls != 0 {
					t.Fatalf("invalid installer boundary reached callbacks: calls=%d error=%v", calls, err)
				}
			})
		}
	}
}
