package system

import "testing"

// Dependency retention must not introduce signature, script, trust-store,
// database-root, repository or conflict overrides in product package commands.
func TestAPKTransitionCannotBypassNativeProtection(t *testing.T) {
	packagePath := "/var/tmp/syswarden-update-safe/package.apk"
	for _, path := range []string{"/sbin/apk", "/usr/sbin/apk"} {
		target := packageTarget{format: packageFormatAPK, installer: path}
		_, qualification := target.qualificationInstallCommand(packagePath)
		for _, boundary := range []struct {
			name     string
			args     []string
			validate func(string, []string) error
		}{
			{"production", target.installArguments(packagePath), validateExternalCommand},
			{"qualification", qualification, validateQualificationExternalCommand},
		} {
			if err := boundary.validate(path, boundary.args); err != nil {
				t.Fatal(err)
			}
			for _, override := range [][]string{
				{"--allow-untrusted"}, {"--force-broken-world"}, {"--force-overwrite"},
				{"--force-old-apk"}, {"--no-scripts"}, {"--no-commit-hooks"},
				{"--no-check-certificate"}, {"--keys-dir", "/tmp/other-keys"},
				{"--root", "/tmp/other-root"}, {"--repository", "https://example.invalid"},
			} {
				t.Run(path+"/"+boundary.name+"/"+override[0], func(t *testing.T) {
					for position := 0; position <= len(boundary.args); position++ {
						args := append([]string{}, boundary.args[:position]...)
						args = append(args, override...)
						args = append(args, boundary.args[position:]...)
						if boundary.validate(path, args) == nil {
							t.Fatalf("unsafe package arguments accepted: %q", args)
						}
					}
				})
			}
		}
	}
}
