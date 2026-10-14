// syswarden-authority-exec is an opt-in non-root v5 bootstrap, not installed.
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
		fmt.Fprintln(os.Stderr, "Usage: syswarden-authority-exec --launch-sha256 <trusted-lowercase-sha256> --image-sha256 <trusted-lowercase-sha256>")
		return 2
	}
	if err := authorityentry.ExecSealed(launch, image); err != nil {
		fmt.Fprintln(os.Stderr, "Local authority startup or shutdown failed; preserve retained evidence for inspection.")
		return 1
	}
	// Successful exec never returns. Preserve failure if the implementation does.
	return 1
}
