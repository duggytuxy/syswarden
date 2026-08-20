package cmd

import (
	"sort"
	"testing"
)

func TestHAFenceCommandContract(t *testing.T) {
	command := newHAFenceCommand()
	children := command.Commands()
	names := make([]string, 0, len(children))
	for _, child := range children {
		names = append(names, child.Name())
	}
	sort.Strings(names)
	want := []string{"engage", "manifest", "recover", "release", "status"}
	if len(names) != len(want) {
		t.Fatalf("ha-fence commands = %v", names)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("ha-fence commands = %v", names)
		}
	}
	manifest, _, err := command.Find([]string{"manifest"})
	if err != nil {
		t.Fatal(err)
	}
	manifestChildren := manifest.Commands()
	if len(manifestChildren) != 2 || manifestChildren[0].Name() != "create" || manifestChildren[1].Name() != "verify" {
		t.Fatalf("manifest commands = %v", manifestChildren)
	}
	create, _, err := command.Find([]string{"manifest", "create"})
	if err != nil {
		t.Fatal(err)
	}
	for _, flagName := range []string{"inventory", "output", "assert-complete"} {
		if create.Flags().Lookup(flagName) == nil {
			t.Fatalf("manifest create lacks --%s", flagName)
		}
	}
	release, _, err := command.Find([]string{"release"})
	if err != nil {
		t.Fatal(err)
	}
	for _, flagName := range []string{"manifest", "writer-closure"} {
		if release.Flags().Lookup(flagName) == nil {
			t.Fatalf("release lacks --%s", flagName)
		}
	}
	status, _, err := command.Find([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Flags().Lookup("json") == nil {
		t.Fatal("status lacks --json")
	}
}
