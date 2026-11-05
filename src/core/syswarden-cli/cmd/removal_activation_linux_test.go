//go:build linux

package cmd

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"syswarden-cli/pkg/integration"

	"github.com/spf13/cobra"
)

func TestRemovalActivationRetirementKeepsRecoveryResources(t *testing.T) {
	for _, command := range []*cobra.Command{uninstallCmd, preparePackageRemovalCmd} {
		for _, failAt := range []string{"barrier", "history", "activation", "configuration", ""} {
			t.Run(command.Name()+"/"+failAt, func(t *testing.T) {
				steps := []*func() error{
					&preflightWireGuardPolicyTransition, &preflightUninstall,
					&preflightKnownNFTPersistenceForRemoval, &preflightHistoricalHostForRemoval,
					&preflightHistoricalFail2banForRemoval, &preflightAdministratorPolicyForRemoval,
					&beginRemoval, &prepareFirewallStateForRemoval, &removeOwnedCronStateForRemoval,
					&removeOwnedWireGuardStateForRemoval, &cleanupFirewallStateForRemoval,
					&requireRemovalTombstoneForCISPolicyRemoval, &removeExactCISHardeningPoliciesForRemoval,
					&removeExactJournaldFragmentForRemoval, &attestHistoricalHostRemovalComplete,
					&retireGeneratedListsForRemoval, &retireCreatedProductLogsForRemoval,
					&retireCreatedUISnapshotsForRemoval, &retireRuntimeHistoryForRemoval,
					&removeEmptyFirewallWrapperStateForRemoval, &retireActivationStateForRemoval,
					&removePristineDefaultConfigurationForRemoval, &removePreparedServiceArtifacts,
					&removePreparedFirewallRuntimeLock, &uninstallHostSystem, &attestRuntimeRetirementBeforeNativeErase,
				}
				for _, step := range steps {
					previous := *step
					t.Cleanup(func() { *step = previous })
					*step = func() error { return nil }
				}
				previousIntegration, previousRetain := removeOwnedIntegrationArtifactsForRemoval, retainAPKPayload
				t.Cleanup(func() {
					removeOwnedIntegrationArtifactsForRemoval, retainAPKPayload = previousIntegration, previousRetain
				})
				retainAPKPayload = false
				removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
					return integration.RsyslogPackageRemovalOfflineAlreadyComplete, nil
				}
				sentinel := errors.New("synthetic bounded retirement refusal")
				var order []string
				record := func(name string) func() error {
					return func() error {
						order = append(order, name)
						if failAt == name {
							return sentinel
						}
						return nil
					}
				}
				beginRemoval, retireRuntimeHistoryForRemoval = record("barrier"), record("history")
				retireActivationStateForRemoval = record("activation")
				removePristineDefaultConfigurationForRemoval = record("configuration")
				removePreparedServiceArtifacts, removePreparedFirewallRuntimeLock = record("services"), record("runtime-lock")
				uninstallHostSystem, attestRuntimeRetirementBeforeNativeErase = record("payload"), record("native-erase")
				err := command.RunE(command, nil)
				if failAt != "" && !errors.Is(err, sentinel) || failAt == "" && err != nil {
					t.Fatalf("retirement result: %v", err)
				}
				if failAt == "activation" && (!strings.Contains(err.Error(), "CLI and removal barrier") || !strings.Contains(err.Error(), "retry the original removal command")) {
					t.Fatalf("activation refusal lost recovery guidance: %v", err)
				}
				want := []string{"barrier", "history", "activation", "configuration", "services", "runtime-lock"}
				if command == uninstallCmd {
					want = append(want, "payload")
				} else {
					want = append(want, "native-erase")
				}
				if failAt != "" {
					for index, name := range want {
						if name == failAt {
							want = want[:index+1]
							break
						}
					}
				}
				if !reflect.DeepEqual(order, want) {
					t.Fatalf("removal crossed a refused retirement boundary: got %v, want %v", order, want)
				}
			})
		}
	}
}
