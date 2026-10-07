//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"time"
)

// Only already authorized target hook strings may become empty or disappear
// with their stopped jail. Every other live value and membership must still
// match the immutable installed-parser view. Empty hooks do not themselves
// prove quiescence; the final stop must complete and membership must vanish.
func verifyLegacyFail2banQuiescenceRuntime(expected legacyFail2banConfiguredActions, live legacyFail2banRuntimeSnapshot, targets map[string]bool, allowProgress, requireClear bool) error {
	unchangedExpected := make(legacyFail2banConfiguredActions)
	unchangedLive := legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail)}
	for name, actions := range expected {
		if !targets[name] {
			unchangedExpected[name] = actions
			continue
		}
		actual, present := live.jails[name]
		if !present {
			if !allowProgress {
				return fmt.Errorf("Fail2ban target disappeared before durable retirement intent")
			}
			continue
		}
		if len(actions) != len(actual.actions) {
			return fmt.Errorf("Fail2ban target action membership changed")
		}
		for action, properties := range actions {
			current, present := actual.actions[action]
			if !present || len(current) != len(properties) {
				return fmt.Errorf("Fail2ban target properties changed outside the retirement plan")
			}
			for key, original := range properties {
				value, present := current[key]
				if !present {
					return fmt.Errorf("Fail2ban target property disappeared")
				}
				if legacyFail2banHookProperty(key) {
					if original.kind != 's' || value.kind != 's' || requireClear && value.text != "" {
						return fmt.Errorf("Fail2ban target hook is not neutralized before stop")
					}
					if allowProgress && value.text == "" {
						continue
					}
				}
				if key == "banEpoch" && original.kind == 'i' && original.number == 0 && value.kind == 'i' && value.number >= 0 {
					continue
				}
				if !reflect.DeepEqual(original, value) {
					return fmt.Errorf("Fail2ban live target differs from the original or neutralized action")
				}
			}
		}
	}
	for name, jail := range live.jails {
		if targets[name] {
			if _, configured := expected[name]; !configured {
				return fmt.Errorf("Fail2ban disabled target unexpectedly became active")
			}
		} else {
			unchangedLive.jails[name] = jail
		}
	}
	return verifyLegacyFail2banConfiguredRuntime(unchangedExpected, unchangedLive)
}

func verifyLegacyFail2banUnrelatedRuntime(before, after legacyFail2banRuntimeSnapshot, targets map[string]bool) error {
	retained := func(snapshot legacyFail2banRuntimeSnapshot) legacyFail2banRuntimeSnapshot {
		result := legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail)}
		for name, jail := range snapshot.jails {
			if !targets[name] {
				result.jails[name] = jail
			}
		}
		return result
	}
	return verifyLegacyFail2banRuntimePreservation(retained(before), retained(after), nil)
}

// This production adapter publishes exact private intent before changing any
// target. It keeps active configuration and kernel rules in place. The caller
// must hold removal locks and provide a read-only guard for the durable removal
// barrier and independently verified shared-kernel ownership/dependencies.
// Kernel retirement and journal-bound file moves remain subsequent phases.
func quiesceVerifiedLegacyFail2banPlan(ctx context.Context, host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, inspection *legacyFail2banServiceInspection, liveGuard func(context.Context) error, ops legacyRetirementFileOps) error {
	if inspection == nil || liveGuard == nil || !validLegacyRetirementOperations(func() error { return liveGuard(ctx) }, ops) {
		return fmt.Errorf("Fail2ban targeted retirement lacks complete service and removal guards")
	}
	ctx, cancelAll := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelAll()
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := liveGuard(ctx); err != nil {
			return err
		}
		return inspection.verify(ctx)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	probe := legacyFail2banConfigurationProbeUsingParser(host, inspection.parser)
	if err := revalidateLegacyFail2banPlanViews(host, plan.binding, probe); err != nil {
		return err
	}
	record, err := makeLegacyFail2banQuiescenceRecord(host, plan, inspection)
	if err != nil {
		return err
	}
	content, digest, err := encodeLegacyFail2banQuiescenceRecord(record)
	if err != nil {
		return err
	}
	path := legacyFail2banPlanPath(plan.sha256) + "/runtime/" + digest + "/intent.json"
	existing, err := host.snapshot(path)
	resuming := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) || resuming && (existing.identity.Mode().Perm() != 0600 || !bytes.Equal(existing.content, content)) {
		return fmt.Errorf("Fail2ban runtime recovery intent is unavailable or differs; preserve the evidence")
	}
	targets := make(map[string]bool)
	for _, name := range record.Targets {
		targets[name] = true
	}
	before, err := inspection.readRuntime(ctx)
	if err != nil {
		return err
	}
	if err := verifyLegacyFail2banQuiescenceRuntime(inspection.actions, before, targets, resuming, false); err != nil {
		return err
	}
	if err := persistLegacyFail2banPlanUsing(host, plan, func() error { return guard(ctx) }, ops); err != nil {
		return err
	}
	journal, err := publishLegacyFail2banQuiescenceIntent(ctx, host, record, guard, ops)
	if err != nil {
		return err
	}
	writer := legacyFail2banRetirementSocket{client: inspection.client}
	readHook := func(ctx context.Context, command []string) (legacyFail2banValue, error) {
		child, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		value, err := inspection.client.query(child, []string{"get", command[1], "action", command[3], command[4]})
		original := inspection.actions[command[1]][command[3]][command[4]]
		if err != nil || original.kind != 's' || value.kind != 's' || value.text != "" && value.text != original.text {
			return legacyFail2banValue{}, fmt.Errorf("Fail2ban hook changed outside its original or neutralized value")
		}
		return value, nil
	}
	writer.authorize = func(ctx context.Context, command []string) error {
		if err := journal.verifyTransition(ctx, command); err != nil {
			return err
		}
		if command[0] != "stop" {
			if command[2] == "action" {
				_, err := readHook(ctx, command)
				return err
			}
			return nil
		}
		current, err := inspection.readRuntime(ctx)
		if err != nil {
			return err
		}
		if err := verifyLegacyFail2banUnrelatedRuntime(before, current, targets); err != nil {
			return err
		}
		return verifyLegacyFail2banQuiescenceRuntime(inspection.actions, current, targets, true, command[0] == "stop")
	}
	for _, command := range record.Transitions {
		if err := journal.verify(ctx); err != nil {
			return err
		}
		if _, active := before.jails[command[1]]; !active {
			continue
		}
		if command[0] == "set" && command[2] == "action" {
			value, err := readHook(ctx, command)
			if err != nil {
				return err
			}
			if value.text == "" {
				continue
			}
		}
		child, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = writer.command(child, command)
		cancel()
		if err != nil {
			return err
		}
		if err := ops.checkpoint("quiescence-transition-confirmed"); err != nil {
			return err
		}
	}
	after, err := inspection.readRuntime(ctx)
	if err != nil {
		return err
	}
	if err := verifyLegacyFail2banRuntimePreservation(before, after, targets); err != nil {
		return err
	}
	return guard(ctx)
}
