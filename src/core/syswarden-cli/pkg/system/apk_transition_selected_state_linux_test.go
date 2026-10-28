//go:build linux

package system

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAPKExecutionSelectedNativeStatePreservesBothIdentities(t *testing.T) {
	for _, selected := range nativeProductPackageNames {
		t.Run(selected, func(t *testing.T) {
			oldDatabase := strings.ReplaceAll(apkRetentionFixtureDatabase(), "P:syswarden\n", "P:"+selected+"\n")
			oldDatabase = strings.Replace(oldDatabase, "V:4.10.4-r0", "V:5.00.0-r0", 1)
			newDatabase := strings.Replace(oldDatabase, "V:5.00.0-r0", "V:5.00.1-r0", 1)
			oldWorld := selected + "\nunrelated=1.0-r0\n"
			newWorld := selected + "><" + apkRetentionFixtureChecksum + "\nunrelated=1.0-r0\nwireguard-tools\nrsyslog\n"
			plan := apkTransitionPlan{
				PackageName: selected, InstalledVersion: "v5.00.0", CandidateVersion: "v5.00.1",
				CandidateAPKChecksum: apkRetentionFixtureChecksum, RetainedDependencyNames: []string{"wireguard-tools", "rsyslog"},
			}
			if err := attestAPKExecutionNativeState([]byte(oldWorld), []byte(oldDatabase), []byte(newWorld), []byte(newDatabase), plan); err != nil {
				t.Fatal("same-identity replacement changed unrelated authority", err)
			}
			// Historical product aliases may exist only in the original record.
			aliases := strings.Replace(oldDatabase, "F:opt/syswarden\nR:fixture", "F:usr/local/bin\nR:syswarden", 1)
			if err := attestAPKExecutionNativeState([]byte(oldWorld), []byte(aliases), []byte(newWorld), []byte(newDatabase), plan); err != nil {
				t.Fatal("original alias registration was rejected as poststate", err)
			}
			other := compatibilityNativePackageName
			if selected == other {
				other = baseNativePackageName
			}
			for _, kind := range []string{"wrong-selection", "old-missing", "old-substitution", "new-substitution", "old-coexistence", "new-coexistence", "old-duplicate-field", "old-duplicate-record", "old-version", "old-architecture", "old-checksum", "old-broken", "new-architecture", "new-checksum", "new-broken", "new-alias", "dependency-edit", "dependency-added", "dependency-removed", "world-reason", "world-product-duplicate", "world-product-unpinned", "world-other-product"} {
				t.Run(kind, func(t *testing.T) {
					before, after, world, review := oldDatabase, newDatabase, newWorld, plan
					switch kind {
					case "wrong-selection":
						review.PackageName = "unrelated"
					case "old-missing":
						before = strings.SplitN(before, "\n\n", 2)[1]
					case "old-substitution":
						before = strings.Replace(before, "P:"+selected+"\n", "P:"+other+"\n", 1)
					case "new-substitution":
						after = strings.Replace(after, "P:"+selected+"\n", "P:"+other+"\n", 1)
					case "old-coexistence":
						before += "P:" + other + "\nV:5.00.0-r0\n\n"
					case "new-coexistence":
						after += "P:" + other + "\nV:5.00.1-r0\n\n"
					case "old-duplicate-field":
						before = strings.Replace(before, "P:"+selected, "P:"+selected+"\nP:"+selected, 1)
					case "old-duplicate-record":
						before += strings.SplitN(before, "\n\n", 2)[0] + "\n\n"
					case "old-version":
						before = strings.Replace(before, "V:5.00.0-r0", "V:5.00.2-r0", 1)
					case "old-architecture":
						before = strings.Replace(before, "A:x86_64", "A:foreign", 1)
					case "old-checksum":
						before = strings.Replace(before, "C:"+apkRetentionFixtureChecksum, "C:invalid", 1)
					case "old-broken":
						before = strings.Replace(before, "f:S", "f:sf", 1)
					case "new-architecture":
						after = strings.Replace(after, "A:x86_64", "A:foreign", 1)
					case "new-checksum":
						after = strings.Replace(after, "C:"+apkRetentionFixtureChecksum, "C:invalid", 1)
					case "new-broken":
						after = strings.Replace(after, "f:S", "f:sf", 1)
					case "new-alias":
						after = strings.Replace(after, "F:opt/syswarden\nR:fixture", "F:usr/local/bin\nR:syswarden", 1)
					case "dependency-edit":
						after = strings.Replace(after, "P:wireguard-tools\nV:1.0-r0", "P:wireguard-tools\nV:1.1-r0", 1)
					case "dependency-added":
						after += "P:unapproved\nV:1.0-r0\n\n"
					case "dependency-removed":
						after = strings.Replace(after, "P:rsyslog\nV:8.0-r0\n\n", "", 1)
					case "world-reason":
						world = strings.Replace(world, "unrelated=1.0-r0", "unrelated", 1)
					case "world-product-duplicate":
						world += selected + "><" + apkRetentionFixtureChecksum + "\n"
					case "world-product-unpinned":
						world = strings.Replace(world, selected+"><"+apkRetentionFixtureChecksum, selected, 1)
					case "world-other-product":
						world += other + "\n"
					}
					if err := attestAPKExecutionNativeState([]byte(oldWorld), []byte(before), []byte(world), []byte(after), review); err == nil {
						t.Fatal("invalid selected native state accepted")
					}
				})
			}
		})
	}
}

func TestAPKPreparationSelectedIdentityRefusesConversionAndCoexistence(t *testing.T) {
	for _, selected := range nativeProductPackageNames {
		for _, kind := range []string{"other-installed", "coexisting", "other-world", "unsupported-selection"} {
			t.Run(selected+"/"+kind, func(t *testing.T) {
				candidate, services, _ := apkTransitionFixtureForName(t, selected)
				other := compatibilityNativePackageName
				if other == selected {
					other = baseNativePackageName
				}
				root, err := os.OpenRoot(services.hostRoot)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := root.Close(); err != nil {
						t.Error(err)
					}
				})
				database, err := root.ReadFile("lib/apk/db/installed")
				if err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "other-installed":
					database = []byte(strings.Replace(string(database), "P:"+selected+"\n", "P:"+other+"\n", 1))
				case "coexisting":
					database = append(database, []byte("P:"+other+"\nV:5.00.0-r0\n\n")...)
				case "other-world":
					if err := root.WriteFile("etc/apk/world", []byte(other+"\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "unsupported-selection":
					candidate.target.packageName = "unrelated"
				}
				if err := root.WriteFile("lib/apk/db/installed", database, 0600); err != nil {
					t.Fatal(err)
				}
				before, err := captureAPKTransitionHost(t.Context(), services.hostRoot)
				if err != nil {
					t.Fatal(err)
				}
				err = prepareAPKTransition(t.Context(), candidate, services)
				var review *APKTransitionApprovalRequiredError
				if err == nil || errors.As(err, &review) {
					t.Fatal("invalid original identity produced preparation review", err)
				}
				after, err := captureAPKTransitionHost(t.Context(), services.hostRoot)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("identity refusal changed host or dependency reasons", err)
				}
			})
		}
	}
}
