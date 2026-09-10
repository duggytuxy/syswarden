package network

import (
	"context"
	"fmt"
	"syswarden-cli/config"
)

// WithHAUnbanMutation holds the native-sync fence across the caller's local
// list and kernel transaction and its peer synchronization. The supplied sync
// callback uses that held lease and must be invoked before the caller returns.
func WithHAUnbanMutation(mutate func(func([]string) error) error) error {
	cfg := config.GlobalConfig
	if cfg == nil || cfg.HAV2Enabled {
		_, err := acquireHAUnbanLease(cfg, nil)
		return err
	}
	if mutate == nil {
		return fmt.Errorf("local unblock operation is unavailable")
	}
	if !cfg.HAEnabled {
		return mutate(func([]string) error { return nil })
	}
	options, err := defaultHASyncOptions()
	if err != nil {
		return err
	}
	return withHAUnbanMutation(cfg, options, mutate)
}

func withHAUnbanMutation(cfg *config.Config, options haSyncOptions, mutate func(func([]string) error) error) error {
	release, err := acquireHAUnbanLease(cfg, options.legacyFence)
	if err != nil {
		return err
	}
	defer release()
	return mutate(func(ips []string) error {
		return syncHAUnbanUnderLease(context.Background(), cfg, ips, options)
	})
}

func acquireHAUnbanLease(cfg *config.Config, fence *haLegacyWriterFence) (func(), error) {
	if cfg == nil {
		return nil, fmt.Errorf("HA configuration is unavailable before local unblock")
	}
	if cfg.HAV2Enabled {
		return nil, fmt.Errorf("local unblock is unavailable with HA v2: a legacy unban cannot remove replicated runtime ownership")
	}
	if !cfg.HAEnabled {
		return func() {}, nil
	}
	if fence == nil {
		return nil, fmt.Errorf("HA native-sync fence is unavailable before local unblock")
	}
	return acquireHALegacyWriterLease(fence)
}
