//go:build linux

package cmd

import "syswarden-cli/pkg/network"

var runtimeUnblockCmd = newUnblockCommand(network.UnbanRuntime)

func init() {
	runtimeUnblockCmd.Use = "runtime-unblock <IP>..."
	runtimeUnblockCmd.Short = "Remove local runtime claims through the authenticated core"
	runtimeUnblockCmd.Long = "Remove local runtime claims through the authenticated core. Persistent blocklists and independent HA source claims remain effective. The core enforces the active HA writer and commits native changes with its durable model."
	rootCmd.AddCommand(runtimeUnblockCmd)
}
