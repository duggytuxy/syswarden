package main

import (
	"fmt"
	"net/netip"
)

func runSyswardenIPAction(action, target string) error {
	address, err := netip.ParseAddr(target)
	if err != nil || address.Zone() != "" || address.String() != target {
		return fmt.Errorf("invalid canonical IP address")
	}
	switch action {
	case "unblock":
		return runUnblockAction(target)
	case "whitelist":
		return runWhitelistAction(target)
	case "block":
		return runBlockAction(target)
	default:
		return fmt.Errorf("unsupported SysWarden action")
	}
}
