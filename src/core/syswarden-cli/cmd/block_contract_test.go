package cmd

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func executeBlockCommand(t *testing.T, commandArgs []string, block blockEntryOperation, alert blockAlertOperation) error {
	t.Helper()
	command := newBlockCommand(block, alert)
	command.SilenceErrors = true
	command.SilenceUsage = true
	command.SetArgs(commandArgs)
	return command.Execute()
}

func TestBlockCommandReturnsEveryTransactionFailure_SW_LIST_001(t *testing.T) {
	attempts := make([]string, 0)
	alerts := make([]string, 0)
	err := executeBlockCommand(t, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, func(address string) error {
		attempts = append(attempts, address)
		if address == "192.0.2.2" || address == "192.0.2.3" {
			return errors.New("firewall transaction preserved the previous ruleset")
		}
		return nil
	}, func(address string) {
		alerts = append(alerts, address)
	})
	if fmt.Sprint(attempts) != fmt.Sprint([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) {
		t.Fatalf("block attempts = %v", attempts)
	}
	if fmt.Sprint(alerts) != fmt.Sprint([]string{"192.0.2.1"}) {
		t.Fatalf("alerts = %v, want only the committed address", alerts)
	}
	for _, address := range []string{"192.0.2.2", "192.0.2.3"} {
		if err == nil || !strings.Contains(err.Error(), `block "`+address+`"`) {
			t.Fatalf("joined error %q omits %s", err, address)
		}
	}
}

func TestUnblockCommandReturnsEveryTransactionFailure_SW_LIST_001(t *testing.T) {
	attempts := make([]string, 0)
	command := newUnblockCommand(func(address string) error {
		attempts = append(attempts, address)
		if address == "192.0.2.2" {
			return errors.New("firewall transaction preserved the previous ruleset")
		}
		return nil
	})
	command.SilenceErrors = true
	command.SilenceUsage = true
	command.SetArgs([]string{"192.0.2.1", "192.0.2.2"})
	err := command.Execute()
	if fmt.Sprint(attempts) != fmt.Sprint([]string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("unblock attempts = %v", attempts)
	}
	if err == nil || !strings.Contains(err.Error(), `unblock "192.0.2.2"`) {
		t.Fatalf("transaction failure was not returned: %v", err)
	}
}

func TestBlockCommandQuotesUntrustedAddressInReturnedError_SW_LIST_001(t *testing.T) {
	err := executeBlockCommand(t, []string{"bad\nterminal"}, func(string) error {
		return errors.New("rejected")
	}, func(string) {})
	if err == nil || strings.Contains(err.Error(), "bad\nterminal") ||
		!strings.Contains(err.Error(), `"bad\nterminal"`) {
		t.Fatalf("untrusted address was not safely quoted: %q", err)
	}
}
