package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

func stubInstallFirewallCompatibility(t *testing.T) {
	t.Helper()
	previousClassifierError := classifyInstallFirewallCompatibilityError
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	classifyInstallFirewallCompatibilityError = func(error) (installFirewallCompatibilityClass, bool) {
		return "", false
	}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		t.Fatal("historical default firewall compatibility inspection ran without typed eligibility")
		return nil, nil
	}
	applyInstallFirewallCompatibility = func(*config.HistoricalDefaultFirewallCompatibilityPlan, func() error) error {
		t.Fatal("historical default firewall compatibility apply ran without an inspected plan")
		return nil
	}
	t.Cleanup(func() {
		classifyInstallFirewallCompatibilityError = previousClassifierError
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
	})
}

func TestInstallCommandReturnsFailureBeforeCompletion_SW_CFG_001(t *testing.T) {
	stubInstallFirewallCompatibility(t)
	previous := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	installConfigPreflight = func(string) error { return errors.New("adversarial invalid configuration") }
	hostFirewallBackendPreflight = func(string) error { return nil }
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		installConfigPreflight = previous
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil {
		t.Fatal("install command reported success after configuration preflight failure")
	}
	if !strings.Contains(err.Error(), "[ERROR] configuration preflight failed") {
		t.Fatalf("install error = %q, want explicit configuration failure", err)
	}
	if strings.Contains(err.Error(), "Installation Complete") {
		t.Fatalf("failed install emitted a completion result: %q", err)
	}
}

func TestInstallProcessExitsNonZeroWithoutCompletion_SW_CFG_001(t *testing.T) {
	stubInstallFirewallCompatibility(t)
	previousPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	installConfigPreflight = func(string) error { return errors.New("command invalid configuration") }
	hostFirewallBackendPreflight = func(string) error { return nil }
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		installConfigPreflight = previousPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})
	previousInit := initConfigHook
	initConfigHook = func() {}
	t.Cleanup(func() { initConfigHook = previousInit })

	testRoot := &cobra.Command{Use: "syswarden"}
	testInstall := &cobra.Command{Use: "install", RunE: installCmd.RunE}
	testRoot.AddCommand(testInstall)
	testRoot.SetArgs([]string{"install"})
	_, err := testRoot.ExecuteC()
	if err == nil {
		t.Fatal("install Cobra execution returned success")
	}
	if !strings.Contains(err.Error(), "[ERROR] configuration preflight failed") {
		t.Fatalf("install Cobra execution omitted explicit failure: %v", err)
	}
	if strings.Contains(err.Error(), "Installation Complete") {
		t.Fatalf("failed install Cobra execution emitted completion: %v", err)
	}
}

func TestInstallRejectsBackendBeforeConfigurationRepair_SW2_FWBACKEND_009(t *testing.T) {
	stubInstallFirewallCompatibility(t)
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "iptables"}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after the backend was rejected")
		return nil
	}
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "iptables" {
			t.Fatalf("backend = %q, want iptables", backend)
		}
		return errors.New("iptables is not operational")
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "before configuration repair") {
		t.Fatalf("install backend refusal = %v", err)
	}
}

func TestInstallRevalidatesBackendAfterConfigurationRepair_SW2_FWBACKEND_009(t *testing.T) {
	stubInstallFirewallCompatibility(t)
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "keep"}
	installConfigPreflight = func(string) error {
		config.GlobalConfig = &config.Config{FirewallBackend: "iptables"}
		return nil
	}
	seen := []string{}
	hostFirewallBackendPreflight = func(backend string) error {
		seen = append(seen, backend)
		if backend == "iptables" {
			return errors.New("iptables is not operational")
		}
		return nil
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "firewall backend preflight failed") {
		t.Fatalf("install backend revalidation = %v", err)
	}
	if got := strings.Join(seen, ","); got != "keep,iptables" {
		t.Fatalf("backend preflights = %q, want keep,iptables", got)
	}
}

func TestInstallAppliesHistoricalDefaultFirewallCompatibilityBeforeConfigurationRepair(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
	})

	plan := &config.HistoricalDefaultFirewallCompatibilityPlan{}
	eligibleErr := errors.New("typed historical default host state")
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables", HAEnabled: false}
	var events []string
	classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
		if errors.Is(err, eligibleErr) {
			return installFirewallCompatibilitySystemd, true
		}
		return "", false
	}
	inspectInstallFirewallCompatibility = func(path string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		if path != "/etc/syswarden/config" {
			t.Fatalf("compatibility inspection path = %q", path)
		}
		events = append(events, "inspect")
		return plan, nil
	}
	hostCronSchedulingPreflight = func(haEnabled bool) error {
		if haEnabled {
			t.Fatal("historical default compatibility test unexpectedly enabled HA")
		}
		events = append(events, "cron")
		return nil
	}
	preflightCalls := 0
	hostFirewallBackendPreflight = func(backend string) error {
		preflightCalls++
		events = append(events, "firewall:"+backend)
		switch preflightCalls {
		case 1:
			if backend != "nftables" {
				t.Fatalf("initial compatibility backend = %q, want nftables", backend)
			}
			return eligibleErr
		case 2:
			if backend != "keep" {
				t.Fatalf("fallback compatibility backend = %q, want keep", backend)
			}
			return nil
		case 3, 4, 5:
			if backend != "nftables" {
				t.Fatalf("transaction host revalidation backend = %q, want nftables", backend)
			}
			return eligibleErr
		case 6:
			if backend != "keep" {
				t.Fatalf("post-repair backend = %q, want keep", backend)
			}
			return errors.New("stop after post-repair keep proof")
		default:
			t.Fatalf("unexpected compatibility preflight call %d", preflightCalls)
		}
		return errors.New("unreachable compatibility preflight")
	}
	applyInstallFirewallCompatibility = func(
		got *config.HistoricalDefaultFirewallCompatibilityPlan,
		revalidateHost func() error,
	) error {
		if got != plan {
			t.Fatal("install applied a different compatibility plan")
		}
		events = append(events, "apply")
		for barrier := 1; barrier <= 3; barrier++ {
			if err := revalidateHost(); err != nil {
				t.Fatalf("host revalidation barrier %d = %v", barrier, err)
			}
		}
		return nil
	}
	installConfigPreflight = func(path string) error {
		if path != "/etc/syswarden/config" {
			t.Fatalf("configuration preflight path = %q", path)
		}
		events = append(events, "config")
		config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: false}
		return nil
	}

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "firewall backend preflight failed") {
		t.Fatalf("post-repair stop = %v", err)
	}
	if got := strings.Join(events, ","); got != "cron,firewall:nftables,inspect,firewall:keep,apply,firewall:nftables,firewall:nftables,firewall:nftables,config,cron,firewall:keep" {
		t.Fatalf("compatibility install events = %q", got)
	}
}

func TestInstallReadyHistoricalNftablesSkipsCompatibility(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
	})

	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	var events []string
	hostCronSchedulingPreflight = func(bool) error {
		events = append(events, "cron")
		return nil
	}
	hostFirewallBackendPreflight = func(backend string) error {
		events = append(events, "firewall:"+backend)
		if backend != "nftables" {
			t.Fatalf("ready historical backend = %q, want nftables", backend)
		}
		if len(events) == 5 {
			return errors.New("stop after post-repair nftables proof")
		}
		return nil
	}
	classifyInstallFirewallCompatibilityError = func(error) (installFirewallCompatibilityClass, bool) {
		t.Fatal("eligibility predicate ran after successful strict nftables preflight")
		return "", false
	}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		t.Fatal("historical compatibility inspection ran for ready nftables")
		return nil, nil
	}
	applyInstallFirewallCompatibility = func(*config.HistoricalDefaultFirewallCompatibilityPlan, func() error) error {
		t.Fatal("historical compatibility apply ran for ready nftables")
		return nil
	}
	installConfigPreflight = func(string) error {
		events = append(events, "config")
		return nil
	}

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "firewall backend preflight failed") {
		t.Fatalf("ready historical post-repair stop = %v", err)
	}
	if got := strings.Join(events, ","); got != "cron,firewall:nftables,config,cron,firewall:nftables" {
		t.Fatalf("ready historical events = %q", got)
	}
}

func TestClassifyInstallFirewallCompatibilityRequiresExactlyOneClass(t *testing.T) {
	previousSystemdPredicate := installSystemdFirewallCompatibilityEligible
	previousOpenRCPredicate := installOpenRCFirewallCompatibilityEligible
	t.Cleanup(func() {
		installSystemdFirewallCompatibilityEligible = previousSystemdPredicate
		installOpenRCFirewallCompatibilityEligible = previousOpenRCPredicate
	})
	systemdSentinel := errors.New("systemd sentinel fixture")
	openRCSentinel := errors.New("OpenRC sentinel fixture")
	installSystemdFirewallCompatibilityEligible = func(err error) bool {
		return errors.Is(err, systemdSentinel)
	}
	installOpenRCFirewallCompatibilityEligible = func(err error) bool {
		return errors.Is(err, openRCSentinel)
	}
	for _, test := range []struct {
		name      string
		err       error
		wantClass installFirewallCompatibilityClass
		wantOK    bool
	}{
		{name: "systemd", err: systemdSentinel, wantClass: installFirewallCompatibilitySystemd, wantOK: true},
		{name: "OpenRC", err: openRCSentinel, wantClass: installFirewallCompatibilityOpenRC, wantOK: true},
		{name: "joined classes", err: errors.Join(systemdSentinel, openRCSentinel)},
		{name: "ordinary error", err: errors.New("ordinary failure")},
		{name: "nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotClass, gotOK := classifyInstallFirewallCompatibility(test.err)
			if gotClass != test.wantClass || gotOK != test.wantOK {
				t.Fatalf("classification = (%q, %t), want (%q, %t)", gotClass, gotOK, test.wantClass, test.wantOK)
			}
		})
	}
}

func TestInstallRejectsAmbiguousCompatibilityClassesBeforeInspection(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	previousSystemdPredicate := installSystemdFirewallCompatibilityEligible
	previousOpenRCPredicate := installOpenRCFirewallCompatibilityEligible
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
		installSystemdFirewallCompatibilityEligible = previousSystemdPredicate
		installOpenRCFirewallCompatibilityEligible = previousOpenRCPredicate
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
	})
	systemdSentinel := errors.New("systemd sentinel fixture")
	openRCSentinel := errors.New("OpenRC sentinel fixture")
	ambiguous := errors.Join(systemdSentinel, openRCSentinel)
	installSystemdFirewallCompatibilityEligible = func(err error) bool { return errors.Is(err, systemdSentinel) }
	installOpenRCFirewallCompatibilityEligible = func(err error) bool { return errors.Is(err, openRCSentinel) }
	classifyInstallFirewallCompatibilityError = classifyInstallFirewallCompatibility
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "nftables" {
			t.Fatalf("ambiguous initial backend = %q, want nftables", backend)
		}
		return ambiguous
	}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		t.Fatal("compatibility inspection ran after ambiguous class error")
		return nil, nil
	}
	applyInstallFirewallCompatibility = func(*config.HistoricalDefaultFirewallCompatibilityPlan, func() error) error {
		t.Fatal("compatibility apply ran after ambiguous class error")
		return nil
	}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after ambiguous class error")
		return nil
	}

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !errors.Is(err, systemdSentinel) || !errors.Is(err, openRCSentinel) ||
		!strings.Contains(err.Error(), "firewall backend preflight failed before configuration repair") {
		t.Fatalf("ambiguous initial class refusal = %v", err)
	}
}

func TestInstallHistoricalDefaultHostRevalidationRequiresTypedSentinel(t *testing.T) {
	for _, test := range []struct {
		name      string
		preflight error
		eligible  bool
		wantError bool
	}{
		{name: "typed sentinel", preflight: errors.New("typed sentinel"), eligible: true},
		{name: "strict nftables became ready", preflight: nil, wantError: true},
		{name: "different failure", preflight: errors.New("different failure"), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			previousFirewallPreflight := hostFirewallBackendPreflight
			previousClassifierError := classifyInstallFirewallCompatibilityError
			t.Cleanup(func() {
				hostFirewallBackendPreflight = previousFirewallPreflight
				classifyInstallFirewallCompatibilityError = previousClassifierError
			})
			hostFirewallBackendPreflight = func(backend string) error {
				if backend != "nftables" {
					t.Fatalf("transaction host revalidation backend = %q, want nftables", backend)
				}
				return test.preflight
			}
			classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
				if test.eligible && errors.Is(err, test.preflight) {
					return installFirewallCompatibilitySystemd, true
				}
				return "", false
			}
			err := revalidateInstallFirewallCompatibilityHost(installFirewallCompatibilitySystemd)
			if (err != nil) != test.wantError {
				t.Fatalf("transaction host revalidation error = %v, wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestInstallHistoricalDefaultHostRevalidationRejectsJoinedClasses(t *testing.T) {
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	previousSystemdPredicate := installSystemdFirewallCompatibilityEligible
	previousOpenRCPredicate := installOpenRCFirewallCompatibilityEligible
	t.Cleanup(func() {
		hostFirewallBackendPreflight = previousFirewallPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
		installSystemdFirewallCompatibilityEligible = previousSystemdPredicate
		installOpenRCFirewallCompatibilityEligible = previousOpenRCPredicate
	})
	systemdSentinel := errors.New("systemd sentinel fixture")
	openRCSentinel := errors.New("OpenRC sentinel fixture")
	joined := errors.Join(systemdSentinel, openRCSentinel)
	installSystemdFirewallCompatibilityEligible = func(err error) bool { return errors.Is(err, systemdSentinel) }
	installOpenRCFirewallCompatibilityEligible = func(err error) bool { return errors.Is(err, openRCSentinel) }
	classifyInstallFirewallCompatibilityError = classifyInstallFirewallCompatibility
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "nftables" {
			t.Fatalf("joined callback backend = %q, want nftables", backend)
		}
		return joined
	}
	err := revalidateInstallFirewallCompatibilityHost(installFirewallCompatibilitySystemd)
	if err == nil || !errors.Is(err, systemdSentinel) || !errors.Is(err, openRCSentinel) ||
		!strings.Contains(err.Error(), "host state changed during compatibility publication") {
		t.Fatalf("joined callback class refusal = %v", err)
	}
}

func TestInstallHistoricalDefaultFirewallCompatibilityHostDriftFailsClosed(t *testing.T) {
	for _, driftAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("transaction barrier %d", driftAt), func(t *testing.T) {
			previousConfig := config.GlobalConfig
			previousConfigPreflight := installConfigPreflight
			previousFirewallPreflight := hostFirewallBackendPreflight
			previousCronPreflight := hostCronSchedulingPreflight
			previousClassifierError := classifyInstallFirewallCompatibilityError
			previousInspect := inspectInstallFirewallCompatibility
			previousApply := applyInstallFirewallCompatibility
			t.Cleanup(func() {
				config.GlobalConfig = previousConfig
				installConfigPreflight = previousConfigPreflight
				hostFirewallBackendPreflight = previousFirewallPreflight
				hostCronSchedulingPreflight = previousCronPreflight
				classifyInstallFirewallCompatibilityError = previousClassifierError
				inspectInstallFirewallCompatibility = previousInspect
				applyInstallFirewallCompatibility = previousApply
			})

			eligibleErr := errors.New("typed historical default host state")
			hostDrift := errors.New("host drift during compatibility publication")
			plan := &config.HistoricalDefaultFirewallCompatibilityPlan{}
			config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
			classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
				if errors.Is(err, eligibleErr) {
					return installFirewallCompatibilitySystemd, true
				}
				return "", false
			}
			hostCronSchedulingPreflight = func(bool) error { return nil }
			preflightCalls := 0
			hostFirewallBackendPreflight = func(backend string) error {
				preflightCalls++
				switch preflightCalls {
				case 1:
					if backend != "nftables" {
						t.Fatalf("initial backend = %q, want nftables", backend)
					}
					return eligibleErr
				case 2:
					if backend != "keep" {
						t.Fatalf("fallback backend = %q, want keep", backend)
					}
					return nil
				default:
					if backend != "nftables" {
						t.Fatalf("transaction backend = %q, want nftables", backend)
					}
					if preflightCalls-2 == driftAt {
						return hostDrift
					}
					return eligibleErr
				}
			}
			inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
				return plan, nil
			}
			applyInstallFirewallCompatibility = func(
				got *config.HistoricalDefaultFirewallCompatibilityPlan,
				revalidateHost func() error,
			) error {
				if got != plan {
					t.Fatal("install applied a different compatibility plan")
				}
				for barrier := 1; barrier <= 3; barrier++ {
					if err := revalidateHost(); err != nil {
						return err
					}
				}
				return nil
			}
			installConfigPreflight = func(string) error {
				t.Fatal("configuration repair ran after transaction host drift")
				return nil
			}

			err := installCmd.RunE(installCmd, nil)
			if err == nil || !errors.Is(err, hostDrift) ||
				!strings.Contains(err.Error(), "firewall compatibility migration failed before configuration repair") {
				t.Fatalf("transaction host drift error = %v", err)
			}
		})
	}
}

func TestInstallHistoricalDefaultFirewallCompatibilityRejectsManagerClassTransitionsAtEveryBarrier(t *testing.T) {
	for _, direction := range []struct {
		name         string
		initialClass installFirewallCompatibilityClass
		initialErr   error
		changedClass installFirewallCompatibilityClass
		changedErr   error
	}{
		{
			name:         "systemd-to-OpenRC",
			initialClass: installFirewallCompatibilitySystemd,
			initialErr:   errors.New("systemd sentinel fixture"),
			changedClass: installFirewallCompatibilityOpenRC,
			changedErr:   errors.New("OpenRC sentinel fixture"),
		},
		{
			name:         "OpenRC-to-systemd",
			initialClass: installFirewallCompatibilityOpenRC,
			initialErr:   errors.New("OpenRC sentinel fixture"),
			changedClass: installFirewallCompatibilitySystemd,
			changedErr:   errors.New("systemd sentinel fixture"),
		},
	} {
		for barrier := 1; barrier <= 3; barrier++ {
			t.Run(fmt.Sprintf("%s-barrier-%d", direction.name, barrier), func(t *testing.T) {
				previousConfig := config.GlobalConfig
				previousConfigPreflight := installConfigPreflight
				previousFirewallPreflight := hostFirewallBackendPreflight
				previousCronPreflight := hostCronSchedulingPreflight
				previousClassifierError := classifyInstallFirewallCompatibilityError
				previousInspect := inspectInstallFirewallCompatibility
				previousApply := applyInstallFirewallCompatibility
				t.Cleanup(func() {
					config.GlobalConfig = previousConfig
					installConfigPreflight = previousConfigPreflight
					hostFirewallBackendPreflight = previousFirewallPreflight
					hostCronSchedulingPreflight = previousCronPreflight
					classifyInstallFirewallCompatibilityError = previousClassifierError
					inspectInstallFirewallCompatibility = previousInspect
					applyInstallFirewallCompatibility = previousApply
				})

				plan := &config.HistoricalDefaultFirewallCompatibilityPlan{}
				config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
				classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
					switch {
					case errors.Is(err, direction.initialErr):
						return direction.initialClass, true
					case errors.Is(err, direction.changedErr):
						return direction.changedClass, true
					default:
						return "", false
					}
				}
				hostCronSchedulingPreflight = func(bool) error { return nil }
				preflightCalls := 0
				hostFirewallBackendPreflight = func(backend string) error {
					preflightCalls++
					switch preflightCalls {
					case 1:
						if backend != "nftables" {
							t.Fatalf("initial backend = %q, want nftables", backend)
						}
						return direction.initialErr
					case 2:
						if backend != "keep" {
							t.Fatalf("fallback backend = %q, want keep", backend)
						}
						return nil
					default:
						if backend != "nftables" {
							t.Fatalf("transaction backend = %q, want nftables", backend)
						}
						if preflightCalls-2 == barrier {
							return direction.changedErr
						}
						return direction.initialErr
					}
				}
				inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
					return plan, nil
				}
				applyInstallFirewallCompatibility = func(
					got *config.HistoricalDefaultFirewallCompatibilityPlan,
					revalidateHost func() error,
				) error {
					if got != plan {
						t.Fatal("install applied a different compatibility plan")
					}
					for currentBarrier := 1; currentBarrier <= 3; currentBarrier++ {
						if err := revalidateHost(); err != nil {
							return err
						}
					}
					return nil
				}
				installConfigPreflight = func(string) error {
					t.Fatal("configuration repair ran after manager-class transition")
					return nil
				}

				err := installCmd.RunE(installCmd, nil)
				if err == nil || !errors.Is(err, direction.changedErr) ||
					!strings.Contains(err.Error(), "service-manager class changed") ||
					!strings.Contains(err.Error(), "firewall compatibility migration failed before configuration repair") {
					t.Fatalf("manager-class transition refusal = %v", err)
				}
			})
		}
	}
}

func TestInstallHistoricalDefaultFirewallCompatibilityInspectionFailsClosed(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
	})
	eligibleErr := errors.New("typed historical default host state")
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
		if errors.Is(err, eligibleErr) {
			return installFirewallCompatibilitySystemd, true
		}
		return "", false
	}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		return nil, errors.New("unsafe historical configuration")
	}
	applyInstallFirewallCompatibility = func(*config.HistoricalDefaultFirewallCompatibilityPlan, func() error) error {
		t.Fatal("compatibility apply ran after inspection refusal")
		return nil
	}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after compatibility inspection refusal")
		return nil
	}
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "nftables" {
			t.Fatalf("backend before inspection refusal = %q", backend)
		}
		return eligibleErr
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "historical default firewall compatibility inspection failed before configuration repair") {
		t.Fatalf("compatibility inspection refusal = %v", err)
	}
}

func TestInstallHistoricalDefaultFirewallCompatibilityRequiresExactPlan(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
	})

	eligibleErr := errors.New("typed historical default host state")
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
		if errors.Is(err, eligibleErr) {
			return installFirewallCompatibilitySystemd, true
		}
		return "", false
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "nftables" {
			t.Fatalf("backend without compatibility plan = %q", backend)
		}
		return eligibleErr
	}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		return nil, nil
	}
	applyInstallFirewallCompatibility = func(*config.HistoricalDefaultFirewallCompatibilityPlan, func() error) error {
		t.Fatal("compatibility apply ran without an exact plan")
		return nil
	}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after typed host state lacked an exact plan")
		return nil
	}

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !errors.Is(err, eligibleErr) ||
		!strings.Contains(err.Error(), "firewall backend preflight failed before configuration repair") {
		t.Fatalf("missing compatibility plan refusal = %v", err)
	}
}

func TestInstallHistoricalDefaultFirewallCompatibilityPreservesBothPreflightFailures(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
	})

	eligibleErr := errors.New("typed historical default host state")
	keepErr := errors.New("keep contract rejected host state")
	plan := &config.HistoricalDefaultFirewallCompatibilityPlan{}
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
		if errors.Is(err, eligibleErr) {
			return installFirewallCompatibilitySystemd, true
		}
		return "", false
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	preflightCalls := 0
	hostFirewallBackendPreflight = func(backend string) error {
		preflightCalls++
		switch preflightCalls {
		case 1:
			if backend != "nftables" {
				t.Fatalf("initial backend = %q, want nftables", backend)
			}
			return eligibleErr
		case 2:
			if backend != "keep" {
				t.Fatalf("fallback backend = %q, want keep", backend)
			}
			return keepErr
		default:
			t.Fatalf("unexpected firewall preflight call %d", preflightCalls)
			return nil
		}
	}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		return plan, nil
	}
	applyInstallFirewallCompatibility = func(*config.HistoricalDefaultFirewallCompatibilityPlan, func() error) error {
		t.Fatal("compatibility apply ran after keep-mode refusal")
		return nil
	}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after keep-mode refusal")
		return nil
	}

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !errors.Is(err, eligibleErr) || !errors.Is(err, keepErr) ||
		!strings.Contains(err.Error(), "historical default keep-mode preflight failed") {
		t.Fatalf("combined historical default preflight refusal = %v", err)
	}
}

func TestInstallHistoricalDefaultFirewallCompatibilityApplyFailsClosed(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
	})
	plan := &config.HistoricalDefaultFirewallCompatibilityPlan{}
	eligibleErr := errors.New("typed historical default host state")
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	classifyInstallFirewallCompatibilityError = func(err error) (installFirewallCompatibilityClass, bool) {
		if errors.Is(err, eligibleErr) {
			return installFirewallCompatibilitySystemd, true
		}
		return "", false
	}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		return plan, nil
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	preflightCalls := 0
	hostFirewallBackendPreflight = func(backend string) error {
		preflightCalls++
		if preflightCalls == 1 {
			if backend != "nftables" {
				t.Fatalf("initial compatibility backend = %q, want nftables", backend)
			}
			return eligibleErr
		}
		if backend != "keep" {
			t.Fatalf("fallback compatibility backend = %q, want keep", backend)
		}
		return nil
	}
	applyInstallFirewallCompatibility = func(
		got *config.HistoricalDefaultFirewallCompatibilityPlan,
		_ func() error,
	) error {
		if got != plan {
			t.Fatal("install applied a different compatibility plan")
		}
		return errors.New("compatibility CAS rejected")
	}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after compatibility apply refusal")
		return nil
	}

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "firewall compatibility migration failed before configuration repair") {
		t.Fatalf("compatibility apply refusal = %v", err)
	}
}

func TestInstallFreshNftablesPreflightRemainsStrict(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousInspect := inspectInstallFirewallCompatibility
	previousApply := applyInstallFirewallCompatibility
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousClassifierError := classifyInstallFirewallCompatibilityError
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		inspectInstallFirewallCompatibility = previousInspect
		applyInstallFirewallCompatibility = previousApply
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		classifyInstallFirewallCompatibilityError = previousClassifierError
	})
	config.GlobalConfig = &config.Config{FirewallBackend: "nftables"}
	inspectInstallFirewallCompatibility = func(string) (*config.HistoricalDefaultFirewallCompatibilityPlan, error) {
		t.Fatal("fresh nftables failure invoked historical compatibility inspection")
		return nil, nil
	}
	applyInstallFirewallCompatibility = func(*config.HistoricalDefaultFirewallCompatibilityPlan, func() error) error {
		t.Fatal("fresh nftables install invoked historical compatibility")
		return nil
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	classifyInstallFirewallCompatibilityError = func(error) (installFirewallCompatibilityClass, bool) {
		return "", false
	}
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "nftables" {
			t.Fatalf("fresh backend = %q, want nftables", backend)
		}
		return errors.New("nftables.service is inactive")
	}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after fresh nftables refusal")
		return nil
	}

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "firewall backend preflight failed before configuration repair") {
		t.Fatalf("fresh nftables refusal = %v", err)
	}
}

func TestReloadRejectsBackendBeforeMutation_SW2_FWBACKEND_009(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "iptables"}
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "iptables" {
			t.Fatalf("backend = %q, want iptables", backend)
		}
		return errors.New("iptables is not operational")
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := reloadCmd.RunE(reloadCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "before reload mutation") {
		t.Fatalf("reload backend refusal = %v", err)
	}
}

func TestInstallRejectsCronSchedulingBeforeConfigurationRepair_SW2_CRON_001(t *testing.T) {
	stubInstallFirewallCompatibility(t)
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: true}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after cron scheduling was rejected")
		return nil
	}
	hostFirewallBackendPreflight = func(string) error {
		t.Fatal("firewall preflight ran after the earlier cron refusal")
		return nil
	}
	hostCronSchedulingPreflight = func(haEnabled bool) error {
		if !haEnabled {
			t.Fatal("HA-enabled configuration reached cron preflight as disabled")
		}
		return errors.New("cron provider is not proven")
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "cron scheduling preflight failed before configuration repair") {
		t.Fatalf("install cron scheduling refusal = %v", err)
	}
}

func TestInstallRevalidatesCronSchedulingAfterConfigurationRepair_SW2_CRON_001(t *testing.T) {
	stubInstallFirewallCompatibility(t)
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: false}
	installConfigPreflight = func(string) error {
		config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: true}
		return nil
	}
	hostFirewallBackendPreflight = func(string) error { return nil }
	seen := []bool{}
	hostCronSchedulingPreflight = func(haEnabled bool) error {
		seen = append(seen, haEnabled)
		if haEnabled {
			return errors.New("HA schedule is not proven")
		}
		return nil
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "cron scheduling preflight failed") {
		t.Fatalf("install cron scheduling revalidation = %v", err)
	}
	if len(seen) != 2 || seen[0] || !seen[1] {
		t.Fatalf("cron scheduling preflights = %v, want false,true", seen)
	}
}

func TestReloadRejectsCronSchedulingBeforeMutation_SW2_CRON_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousApply := applyPoliciesForReload
	config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: true}
	hostCronSchedulingPreflight = func(haEnabled bool) error {
		if !haEnabled {
			t.Fatal("HA-enabled reload reached cron preflight as disabled")
		}
		return errors.New("cron provider drift")
	}
	hostFirewallBackendPreflight = func(string) error {
		t.Fatal("firewall preflight ran after the earlier cron refusal")
		return nil
	}
	applyPoliciesForReload = func() error {
		t.Fatal("firewall mutation ran after cron preflight refusal")
		return nil
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		applyPoliciesForReload = previousApply
	})

	err := reloadCmd.RunE(reloadCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "cron scheduling preflight failed before reload mutation") {
		t.Fatalf("reload cron scheduling refusal = %v", err)
	}
}

func TestPrepareInstallConfigurationCompletesPartialConfig_SW_CFG_001(t *testing.T) {
	configRoot := filepath.Join(t.TempDir(), "config")
	modules := filepath.Join(configRoot, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(modules)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	const userConfig = "# operator-owned\n[user]\nwebtui_password = \"remove-this-secret\"\nprofile_name = \"preserve-exactly\"\n"
	const cleanedUserConfig = "# operator-owned\n[user]\nprofile_name = \"preserve-exactly\"\n"
	if err := root.WriteFile("99-user.toml", []byte(userConfig), 0640); err != nil {
		t.Fatal(err)
	}

	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	if err := prepareInstallConfiguration(configRoot); err != nil {
		t.Fatalf("prepareInstallConfiguration() error = %v", err)
	}
	content, err := root.ReadFile("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != cleanedUserConfig {
		t.Fatalf("retired secret cleanup = %q, want %q", content, cleanedUserConfig)
	}
	info, err := root.Lstat("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("operator module mode = %#o, want 0640", info.Mode().Perm())
	}
	if config.GlobalConfig == nil {
		t.Fatalf("validated config = %#v", config.GlobalConfig)
	}
	if state := config.CurrentLoadState(); state.Degraded || state.Source != configRoot {
		t.Fatalf("load state = %#v, want validated install config", state)
	}
}

func TestPrepareInstallConfigurationRejectsInvalidCandidateBeforeHostMutation_SW_CFG_001(t *testing.T) {
	configRoot := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(configRoot, 0750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(configRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("config.toml", []byte("[core\n"), 0600); err != nil {
		t.Fatal(err)
	}

	previous := &config.Config{SSHPort: "2222", FirewallBackend: "keep"}
	config.GlobalConfig = previous
	t.Cleanup(func() { config.GlobalConfig = config.NewFailSafeConfig() })
	if err := prepareInstallConfiguration(configRoot); err == nil {
		t.Fatal("prepareInstallConfiguration() accepted invalid TOML")
	}
	if config.GlobalConfig != previous || config.GlobalConfig.SSHPort != "2222" {
		t.Fatal("invalid install candidate replaced the previous valid configuration")
	}
	if state := config.CurrentLoadState(); !state.Degraded || state.Error == "" {
		t.Fatalf("load state = %#v, want degraded rejection", state)
	}
}
