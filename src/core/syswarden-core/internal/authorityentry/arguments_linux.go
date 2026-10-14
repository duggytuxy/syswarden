package authorityentry

import (
	"encoding/hex"
	"strings"
)

func ExecDigests(args []string) (string, string, bool) {
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
