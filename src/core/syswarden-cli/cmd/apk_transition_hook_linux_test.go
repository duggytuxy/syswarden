//go:build linux

package cmd

import (
	"context"
	"errors"
	"github.com/spf13/cobra"
	"strings"
	"testing"
)

func TestInternalAPKTransitionHookDispatchIsStrictAndPropagatesRefusal(t *testing.T) {
	original := runInternalAPKTransitionHook
	defer func() { runInternalAPKTransitionHook = original }()
	for _, test := range []struct {
		name, digest, phase string
		cancel, valid       bool
	}{
		{"pre", strings.Repeat("a", 64), "pre-commit", false, true},
		{"post", strings.Repeat("b", 64), "post-commit", false, true},
		{"pre-upgrade", strings.Repeat("c", 64), "pre-upgrade", false, true},
		{"post-upgrade", strings.Repeat("d", 64), "post-upgrade", false, true},
		{"missing", "", "pre-commit", false, false},
		{"uppercase", strings.Repeat("A", 64), "pre-commit", false, false},
		{"path", "../../plan", "pre-commit", false, false},
		{"activation", strings.Repeat("a", 64), "install", false, false},
		{"empty-phase", strings.Repeat("a", 64), "", false, false},
		{"cancel", strings.Repeat("a", 64), "pre-commit", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			refused := errors.New("no live authenticated coordinator")
			runInternalAPKTransitionHook = func(ctx context.Context, digest, phase string) error {
				called = true
				if digest != test.digest || phase != test.phase {
					t.Fatal("wrong dispatch")
				}
				return refused
			}
			command := &cobra.Command{}
			command.Flags().String("execution-plan", test.digest, "")
			command.Flags().String("phase", test.phase, "")
			ctx := t.Context()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			command.SetContext(ctx)
			err := internalAPKTransitionHookCmd.RunE(command, nil)
			if err == nil || called != test.valid {
				t.Fatalf("unexpected authority: called=%v, err=%v", called, err)
			}
			if test.valid && !errors.Is(err, refused) {
				t.Fatal("lost coordinator refusal")
			}
		})
	}
	if !internalAPKTransitionHookCmd.Hidden {
		t.Fatal("internal command exposed as normal operator entry")
	}
	if err := internalAPKTransitionHookCmd.Args(internalAPKTransitionHookCmd, []string{"unexpected"}); err == nil {
		t.Fatal("accepted positional arguments")
	}
}
