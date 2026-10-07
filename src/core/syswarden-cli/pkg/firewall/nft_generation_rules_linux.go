//go:build linux

package firewall

import (
	"context"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

const maximumNFTGenerationRules = 128

// A handle is only a transaction address. Independent source evidence must
// establish ownership before the generation fence is constructed. Restrict
// this additional operation to the historical IPv4 INPUT compatibility path.
type nftGenerationRuleTarget struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Handle uint64 `json:"handle"`
}

func newNFTGenerationRuleFence(ctx context.Context, inspect func(context.Context) ([]nftGenerationRuleTarget, error)) (*nftGenerationFence, error) {
	if inspect == nil {
		return nil, fmt.Errorf("nftables rule fence requires an independent ownership inspector")
	}
	return newNFTMutationFence(ctx, func(ctx context.Context) ([]nftTableTarget, []nftGenerationRuleTarget, error) {
		rules, err := inspect(ctx)
		return nil, rules, err
	})
}

func validateNFTMutationTargets(tables []nftTableTarget, rules []nftGenerationRuleTarget) error {
	if len(rules) == 0 {
		return validateNFTGenerationTargets(tables)
	}
	if len(tables) != 0 || len(rules) > maximumNFTGenerationRules {
		return fmt.Errorf("nftables rule retirement cannot mix table deletion or exceed its rule bound")
	}
	seen := make(map[uint64]bool, len(rules))
	for _, rule := range rules {
		if rule.Family != "ip" || rule.Table != "filter" || rule.Chain != "INPUT" || rule.Handle == 0 || seen[rule.Handle] {
			return fmt.Errorf("nftables rule retirement requires distinct exact historical INPUT handles")
		}
		seen[rule.Handle] = true
	}
	return nil
}

func (socket *nftGenerationSocket) deleteRuleRequest(rule nftGenerationRuleTarget) (nftGenerationMessage, error) {
	if err := validateNFTMutationTargets(nil, []nftGenerationRuleTarget{rule}); err != nil {
		return nftGenerationMessage{}, err
	}
	body := []byte{unix.NFPROTO_IPV4, 0, 0, 0}
	var handle [8]byte
	binary.BigEndian.PutUint64(handle[:], rule.Handle)
	for _, field := range []struct {
		kind  uint16
		value []byte
	}{
		{unix.NFTA_RULE_TABLE, append([]byte(rule.Table), 0)},
		{unix.NFTA_RULE_CHAIN, append([]byte(rule.Chain), 0)},
		{unix.NFTA_RULE_HANDLE, handle[:]},
	} {
		attribute, err := nftGenerationAttribute(field.kind, field.value)
		if err != nil {
			return nftGenerationMessage{}, err
		}
		body = append(body, attribute...)
	}
	return socket.request(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_DELRULE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, unix.NLMSG_ERROR, body)
}
