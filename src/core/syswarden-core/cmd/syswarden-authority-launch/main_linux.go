// syswarden-authority-launch is an opt-in root-to-service v5 launcher, not installed.
package main

import (
	"fmt"
	"os"

	"syswarden-core/internal/authorityentry"
)

func main() { os.Exit(execute()) }

func execute() int {
	launch, image, ok := authorityentry.ExecDigests(os.Args[1:])
	if !ok {
		fmt.Fprintln(os.Stderr, "Usage: syswarden-authority-launch --launch-sha256 <trusted-lowercase-sha256> --image-sha256 <trusted-lowercase-sha256>")
		return 2
	}
	if err := authorityentry.LaunchSealed(launch, image); err != nil {
		fmt.Fprintln(os.Stderr, "Local authority startup or shutdown failed; preserve retained evidence for inspection.")
		return 1
	}
	// Successful exec never returns. Preserve failure if the implementation does.
	return 1
}
