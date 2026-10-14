// syswarden-authority-exec is an opt-in non-root v5 bootstrap, not installed.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"syswarden-core/internal/authorityentry"
)

func main() { os.Exit(execute()) }

func execDigests(args []string) (string, string, bool) {
	if len(args) != 4 || args[0] != "--launch-sha256" || args[2] != "--image-sha256" {
		return "", "", false
	}
	for _, digest := range []string{args[1], args[3]} {
		if len(digest) != 64 || strings.ToLower(digest) != digest {
			return "", "", false
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return "", "", false
		}
	}
	return args[1], args[3], true
}

func execute() int {
	launch, image, ok := execDigests(os.Args[1:])
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
