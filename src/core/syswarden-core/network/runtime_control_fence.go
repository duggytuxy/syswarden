package network

import "fmt"

// Both the CLI and the root control server hold this read lease. This allows
// one coordinated local command to cross the socket while an exclusive fence
// transition remains impossible until both sides release their leases.
func (fence *haFenceController) withLocalOperatorMutation(mutation func() error) error {
	if fence == nil || mutation == nil {
		return fmt.Errorf("local operator fence or mutation is unavailable")
	}
	root, err := fence.openDirectory(false)
	if err != nil {
		return err
	}
	defer root.Close()
	lease, err := openHAFenceLockMode(root, fence.expectedOwnerUID, false, true)
	if err != nil {
		return fmt.Errorf("HA native-sync fence is transitioning: %w", err)
	}
	defer closeHAFenceLock(lease)
	state, err := readHAFenceState(root, fence.expectedOwnerUID)
	if err != nil {
		return err
	}
	if state.State != haFenceStateInactive {
		return fmt.Errorf("local operator mutation is blocked by HA fence state %s", state.State)
	}
	return mutation()
}

func (manager *runtimeLifecycleManager) withOperatorFence(operation func() error) error {
	if manager.operatorFence != nil {
		return manager.operatorFence.withLocalOperatorMutation(operation)
	}
	return operation()
}
