package firewall

import "errors"

type committedFirewallPolicyError struct {
	cause error
}

func (committed *committedFirewallPolicyError) Error() string {
	if committed == nil || committed.cause == nil {
		return "firewall policy transaction is committed"
	}
	return committed.cause.Error()
}

func (committed *committedFirewallPolicyError) Unwrap() error {
	if committed == nil {
		return nil
	}
	return committed.cause
}

func markCommittedFirewallPolicyError(cause error) error {
	if cause == nil || isCommittedFirewallPolicyError(cause) {
		return cause
	}
	return &committedFirewallPolicyError{cause: cause}
}

func isCommittedFirewallPolicyError(err error) bool {
	var committed *committedFirewallPolicyError
	return errors.As(err, &committed)
}
