// syswarden-authority is an opt-in v5 process, not installed by native packages.
// Trusted provisioning must pass the exact inherited descriptors and digest.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"syswarden-core/internal/authorityentry"
	"syswarden-core/journal"
)

func main() { os.Exit(execute()) }

func launchDigest(args []string) (string, bool) {
	if len(args) != 2 || args[0] != "--launch-sha256" || len(args[1]) != 64 || strings.ToLower(args[1]) != args[1] {
		return "", false
	}
	if _, err := hex.DecodeString(args[1]); err != nil {
		return "", false
	}
	return args[1], true
}

func execute() int {
	digest, ok := launchDigest(os.Args[1:])
	if !ok {
		fmt.Fprintln(os.Stderr, "Usage: syswarden-authority --launch-sha256 <trusted-lowercase-sha256>")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	files := [4]*os.File{os.NewFile(3, "launch"), os.NewFile(4, "state"), os.NewFile(5, "endpoint"), os.NewFile(6, "readiness")}
	defer func() {
		for _, file := range files {
			if file != nil {
				_ = file.Close()
			}
		}
	}()
	// The executable offers no approval bypass or configurable test clock.
	// Independent human approval providers are not installed in this slice.
	err := authorityentry.Prepare(files, digest)
	if err == nil {
		err = journal.RunAuthorityProcess(ctx, journal.AuthorityProcessConfig{Launch: files[0], State: files[1], Endpoint: files[2], Readiness: files[3], LaunchSHA256: digest, Now: time.Now})
	}
	if err != nil {
		// Do not disclose private paths, trust roots or operation details.
		fmt.Fprintln(os.Stderr, "Local authority startup or shutdown failed; preserve retained evidence for inspection.")
		return 1
	}
	return 0
}
