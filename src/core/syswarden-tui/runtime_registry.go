package main

import (
	"fmt"
	"io"
)

func printActiveBlockRegistry(output io.Writer, entries []BannedIP) {
	fmt.Fprintln(output, "[ACTIVE BLOCK REGISTRY]")
	count := 0
	for _, entry := range entries {
		if entry.Action != "BANNED" || entry.EnforcementState != "active" {
			continue
		}
		fmt.Fprintf(output, " - %s | state=active | source=%s\n", entry.IP, entry.Jail)
		count++
	}
	if count == 0 {
		fmt.Fprintln(output, " - No active entries in the current registry snapshot.")
	}
}
