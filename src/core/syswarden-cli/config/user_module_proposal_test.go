package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func proposalFixture(t *testing.T) (string, *UserModuleEdit, []byte, os.FileInfo) {
	t.Helper()
	root, userPath := initializedUserModule(t)
	edit, err := BeginUserModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	return root, edit, edit.Content(), info
}

func prepareProfileProposal(t *testing.T, edit *UserModuleEdit) *UserModuleProposal {
	t.Helper()
	p, err := edit.Prepare(context.Background(), []byte("[user]\nprofile_name = \"Reviewed\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertUserUnchanged(t *testing.T, root string, before []byte, info os.FileInfo) {
	t.Helper()
	after, err := ReadUserModule(root)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.Lstat(filepath.Join(root, "modules", userModuleName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !os.SameFile(info, current) {
		t.Fatal("refused proposal changed live content or inode")
	}
}

func TestUserModuleProposalRequiresExactApprovalAndCannotBeReplayed(t *testing.T) {
	for _, approval := range []string{"", "yes", "other-proposal"} {
		t.Run(approval, func(t *testing.T) {
			root, edit, before, info := proposalFixture(t)
			p := prepareProfileProposal(t, edit)
			preflight := func() error { t.Fatal("unapproved proposal reached preflight"); return nil }
			if err := p.Publish(context.Background(), approval, preflight); err == nil {
				t.Fatal("accepted mismatched approval")
			}
			if err := p.Publish(context.Background(), p.Review().ApprovalID, preflight); err == nil {
				t.Fatal("reused refused proposal")
			}
			assertUserUnchanged(t, root, before, info)
		})
	}
}

func TestUserModuleProposalIsImmutableAndPublicationDoesNotActivate(t *testing.T) {
	root, edit, _, _ := proposalFixture(t)
	global, load := GlobalConfig, CurrentLoadState()
	original := edit.Content()
	original[0] = '!'
	if bytes.Equal(original, edit.Content()) {
		t.Fatal("editable bytes alias captured state")
	}
	candidate := []byte("[user]\nprofile_name = \"Reviewed\"\n")
	p, err := edit.Prepare(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidate[0] = '!'
	review := p.Review()
	if review.Target != "modules/99-user.toml" || len(review.ApprovalID) != 64 || len(review.ModulePlan) == 0 {
		t.Fatalf("incomplete review: %+v", review)
	}
	review.ModulePlan[0] = "modified"
	if p.Review().ModulePlan[0] == "modified" {
		t.Fatal("review aliases authoritative state")
	}
	calls := 0
	if err := p.Publish(context.Background(), review.ApprovalID, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls < 3 {
		t.Fatalf("lifecycle barrier not rechecked around publication: %d", calls)
	}
	assertFileContent(t, filepath.Join(root, "modules", userModuleName), "[user]\nprofile_name = \"Reviewed\"\n")
	if err := p.Publish(context.Background(), review.ApprovalID, func() error { return nil }); err == nil {
		t.Fatal("successful approval replayed")
	}
	if GlobalConfig != global || !reflect.DeepEqual(CurrentLoadState(), load) {
		t.Fatal("configuration publication changed runtime state")
	}
}

func TestUserModuleProposalRefusesChangesSinceEditingOrReview(t *testing.T) {
	for _, phase := range []string{"editing", "review"} {
		for _, target := range []string{"user", "master", "module", "new_module", "marker"} {
			t.Run(phase+"/"+target, func(t *testing.T) {
				root, edit, before, info := proposalFixture(t)
				var p *UserModuleProposal
				if phase == "review" {
					p = prepareProfileProposal(t, edit)
				}
				dir, name := filepath.Join(root, "modules"), userModuleName
				switch target {
				case "master":
					dir, name = root, "config.toml"
				case "module":
					name = "40-integrations.toml"
				case "new_module":
					name = "98-concurrent.toml"
				case "marker":
					dir, name = root, migrationMarkerName
				}
				if err := writeSecureFileAtomically(dir, name, []byte("# concurrent operator change\n")); err != nil {
					t.Fatal(err)
				}
				var err error
				if phase == "editing" {
					_, err = edit.Prepare(context.Background(), []byte("[user]\nprofile_name = \"Reviewed\"\n"))
				} else {
					err = p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil })
				}
				if err == nil {
					t.Fatal("proposal accepted stale baseline")
				}
				if target == "user" {
					assertFileContent(t, filepath.Join(dir, name), "# concurrent operator change\n")
				} else {
					assertUserUnchanged(t, root, before, info)
				}
			})
		}
	}
}

func TestUserModuleProposalRefusesExpiryCancellationAndUnsafeLifecycle(t *testing.T) {
	for _, refusal := range []string{"expired", "cancelled", "preflight", "cancel_in_preflight", "ssh_environment", "policy_environment", "missing_preflight"} {
		t.Run(refusal, func(t *testing.T) {
			root, edit, before, info := proposalFixture(t)
			p := prepareProfileProposal(t, edit)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			preflight := func() error { return nil }
			switch refusal {
			case "expired":
				p.state.review.ExpiresAt = time.Now().Add(-time.Second)
			case "cancelled":
				cancel()
			case "preflight":
				preflight = func() error { return errors.New("pending recovery") }
			case "cancel_in_preflight":
				preflight = func() error { cancel(); return nil }
			case "ssh_environment":
				t.Setenv("SYSWARDEN_SSH_HARDENING_ENABLED", "true")
			case "policy_environment":
				t.Setenv("SYSWARDEN_OPERATOR_POLICY_RULES", "standard")
			case "missing_preflight":
				preflight = nil
			}
			if err := p.Publish(ctx, p.Review().ApprovalID, preflight); err == nil {
				t.Fatal("unsafe publication accepted")
			}
			assertUserUnchanged(t, root, before, info)
		})
	}
}

func TestUserModuleProposalRollbackOnLateBarrierFailure(t *testing.T) {
	root, edit, before, info := proposalFixture(t)
	p := prepareProfileProposal(t, edit)
	barrier := func() error {
		current, err := ReadUserModule(root)
		if err != nil {
			return err
		}
		if bytes.Contains(current, []byte("Reviewed")) {
			return errors.New("recovery started during publication")
		}
		return nil
	}
	if err := p.Publish(context.Background(), p.Review().ApprovalID, barrier); err == nil {
		t.Fatal("late barrier failure accepted")
	}
	assertUserUnchanged(t, root, before, info)
}

func TestUserModuleProposalRepairsInvalidUserModuleButPreservesIncompleteFreshBarrier(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing", false: "invalid"}[missing], func(t *testing.T) {
			root, path := initializedUserModule(t)
			if missing {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := writeSecureFileAtomically(filepath.Dir(path), userModuleName, []byte("[invalid\n")); err != nil {
					t.Fatal(err)
				}
			}
			edit, err := BeginUserModuleEdit(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if missing {
				if _, err := edit.Prepare(context.Background(), []byte("[user]\nprofile_name='Reviewed'\n")); err == nil {
					t.Fatal("proposal bypassed incomplete fresh publication")
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("missing fresh file was recreated")
				}
				return
			}
			p := prepareProfileProposal(t, edit)
			if err := p.Publish(context.Background(), p.Review().ApprovalID, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateModularConfig(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUserModuleProposalRejectsInvalidCandidateAndRedactsReview(t *testing.T) {
	root, edit, before, info := proposalFixture(t)
	for _, invalid := range [][]byte{[]byte("[invalid\n"), []byte("[core]\nssh_port=\"70000\"\n"), bytes.Repeat([]byte("x"), int(maximumUserModuleSize)+1)} {
		if _, err := edit.Prepare(context.Background(), invalid); err == nil {
			t.Fatal("invalid candidate accepted")
		}
		assertUserUnchanged(t, root, before, info)
	}
	candidate := []byte("[user]\nprofile_name=\"PRIVATE-NAME\"\n[private_extension]\nsecret_value=\"PRIVATE-SECRET\"\n")
	p, err := edit.Prepare(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	review := p.Review()
	if review.UnknownKeyCount == 0 {
		t.Fatal("unknown keys not reported")
	}
	if strings.Contains(strings.Join(review.ModulePlan, "\n"), "PRIVATE") {
		t.Fatal("review disclosed arbitrary configuration value")
	}
	if _, err := edit.Prepare(context.Background(), candidate); err == nil {
		t.Fatal("edit prepared twice")
	}
}

func TestUserModuleProposalConcurrentCopiesAreSingleUse(t *testing.T) {
	root, edit, _, _ := proposalFixture(t)
	p := prepareProfileProposal(t, edit)
	copied := *p
	id := p.Review().ApprovalID
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, candidate := range []*UserModuleProposal{p, &copied} {
		wait.Add(1)
		go func(candidate *UserModuleProposal) {
			defer wait.Done()
			results <- candidate.Publish(context.Background(), id, func() error { return nil })
		}(candidate)
	}
	wait.Wait()
	close(results)
	successful := 0
	for err := range results {
		if err == nil {
			successful++
		}
	}
	if successful != 1 {
		t.Fatalf("successful publications = %d", successful)
	}
	assertFileContent(t, filepath.Join(root, "modules", userModuleName), "[user]\nprofile_name = \"Reviewed\"\n")
}
