//go:build linux

package firewall

import "strings"

// This namespace is accepted only for read-only JSON inspection. It never
// enters any deletion target list and confers no ownership authority.
func validNFTOperatorReceiverTable(name string) bool {
	const prefix = "operator_preserved_"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+20 {
		return false
	}
	for _, character := range name[len(prefix):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func nftOperatorReceiverObservationTarget(args []string) (string, bool) {
	if len(args) != 5 {
		return "", false
	}
	if args[0] != "-j" || args[1] != "list" || args[2] != "table" || args[3] != "inet" || !validNFTOperatorReceiverTable(args[4]) {
		return "", false
	}
	return args[4], true
}
