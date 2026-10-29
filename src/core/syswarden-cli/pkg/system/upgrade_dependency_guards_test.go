package system

import (
	"slices"
	"testing"
)

// Removing one guard, overriding it later, or injecting a second package must
// not cross the native execution boundary. Production and offline commands are
// deliberately different; this does not attest package-manager rollback.
func TestUpdateDependencyGuardsCannotBeRemovedOrOverridden(t *testing.T) {
	path := "/var/tmp/syswarden-update-safe/package"
	for _, target := range []packageTarget{
		{format: packageFormatDEB, installer: "/usr/bin/apt-get"},
		{format: packageFormatRPM, installer: "/usr/bin/dnf"},
		{format: packageFormatRPM, installer: "/usr/bin/yum"},
	} {
		t.Run(target.installer, func(t *testing.T) {
			for _, offline := range []bool{false, true} {
				name, args := target.installer, target.installArguments(path)
				validate := validateExternalCommand
				if offline {
					name, args = target.qualificationInstallCommand(path)
					validate = validateQualificationExternalCommand
				}
				if err := validate(name, args); err != nil {
					t.Fatal(err)
				}
				for i := range args {
					removed := append(slices.Clone(args[:i]), args[i+1:]...)
					if validate(name, removed) == nil {
						t.Fatalf("accepted omitted argument %d: %q", i, removed)
					}
					changed := slices.Clone(args)
					changed[i] = "--allowerasing"
					if validate(name, changed) == nil {
						t.Fatalf("accepted overridden argument %d: %q", i, changed)
					}
				}
				for _, override := range []string{
					"--setopt=clean_requirements_on_remove=True", "--setopt=install_weak_deps=True",
					"--setopt=obsoletes=True", "--setopt=localpkg_gpgcheck=0", "--nogpgcheck",
					"--allow-unauthenticated", "--force-depends", "--auto-remove", "--autoremove",
					"--no-remove=false", "--install-recommends", "unrelated-package",
				} {
					if validate(name, append(slices.Clone(args), override)) == nil {
						t.Fatalf("accepted appended override %q", override)
					}
				}
				badPath := slices.Clone(args)
				badPath[len(badPath)-1] = "/tmp/unverified-package"
				if validate(name, badPath) == nil {
					t.Fatal("accepted unverified package location")
				}
			}
		})
	}
}
