//go:build linux

package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// ObserveInactiveNativeNFT returns a read-only preservation fingerprint. It
// refuses product-looking state conservatively, without claiming ownership or
// deleting it. The caller must independently bind procfs, legacy backends,
// namespace, services, processes, scheduling, persistent state and provenance.
// Ordinary packet/byte counters are normalized; all other changes invalidate
// the fingerprint. Dynamic unrelated sets may therefore require a new review.
func ObserveInactiveNativeNFT(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", errors.New("inactive firewall observation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	runner, err := newExecNFTCommandRunner()
	if err != nil {
		return "", err
	}
	return observeInactiveNativeNFTWith(ctx, runner)
}

func observeInactiveNativeNFTWith(ctx context.Context, runner nftCommandRunner) (string, error) {
	if ctx == nil || runner == nil {
		return "", errors.New("inactive nftables observer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	raw, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		return "", errors.New("inactive nftables ruleset could not be read")
	}
	digest, err := inactiveNativeNFTDigest(raw)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	confirmed, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		return "", errors.New("inactive nftables ruleset could not be rechecked")
	}
	second, err := inactiveNativeNFTDigest(confirmed)
	if err != nil || second != digest {
		return "", errors.Join(errors.New("inactive nftables preservation state changed"), err)
	}
	return digest, ctx.Err()
}

func inactiveNativeNFTDigest(raw []byte) (string, error) {
	document, err := decodeLegacyFail2banNFTJSON(raw)
	if err != nil {
		return "", err
	}
	entries, ok := document["nftables"].([]any)
	if !ok || len(document) != 1 || len(entries) > 65536 {
		return "", errors.New("invalid inactive nftables inventory")
	}
	canonical := make([]any, 0, len(entries))
	tables := map[nftTableTarget]bool{}
	for _, entry := range entries {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return "", errors.New("ambiguous inactive nftables object")
		}
		for kind, value := range wrapper {
			object, ok := value.(map[string]any)
			if !ok {
				return "", errors.New("malformed inactive nftables object")
			}
			if kind == "metainfo" {
				continue
			}
			switch kind {
			case "table", "chain", "rule", "set", "map", "element", "counter", "quota", "limit", "flowtable", "ct helper", "ct timeout", "ct expectation", "secmark", "synproxy":
			default:
				return "", errors.New("unsupported inactive nftables object kind")
			}
			family, familyOK := object["family"].(string)
			name, nameOK := object["table"].(string)
			if kind == "table" {
				name, nameOK = object["name"].(string)
			}
			if !familyOK || !nameOK || family == "" || name == "" || len(name) > 256 {
				return "", errors.New("inactive nftables object lacks table identity")
			}
			switch family {
			case "ip", "ip6", "inet", "arp", "bridge", "netdev":
			default:
				return "", errors.New("unsupported inactive nftables family")
			}
			target := nftTableTarget{family: family, name: name}
			if kind == "table" {
				if tables[target] {
					return "", errors.New("duplicate inactive nftables table")
				}
				tables[target] = true
			} else if !tables[target] {
				return "", errors.New("inactive nftables object precedes its table")
			}
			if containsInactiveProductReference(object) {
				return "", errors.New("nftables contains possible SysWarden state; ownership requires separate review")
			}
			if kind == "rule" {
				expressions, ok := object["expr"].([]any)
				if !ok || len(expressions) == 0 || len(expressions) > 1024 {
					return "", errors.New("invalid inactive nftables rule")
				}
				for _, expression := range expressions {
					expr, ok := expression.(map[string]any)
					if !ok || len(expr) != 1 {
						return "", errors.New("ambiguous inactive nftables expression")
					}
					if value, found := expr["counter"]; found {
						if named, ok := value.(string); ok {
							if named == "" {
								return "", errors.New("empty named counter")
							}
							continue
						}
						counter, ok := value.(map[string]any)
						if !ok || len(counter) != 2 {
							return "", errors.New("unsupported anonymous counter")
						}
						if err := normalizeInactiveCounter(counter); err != nil {
							return "", err
						}
					}
				}
			}
			if kind == "counter" {
				if err := normalizeInactiveCounter(object); err != nil {
					return "", err
				}
			}
			canonical = append(canonical, wrapper)
		}
	}
	wire, err := json.Marshal(struct {
		Schema  string
		Objects []any
	}{"syswarden-inactive-nft-preservation-v1", canonical})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeInactiveCounter(object map[string]any) error {
	for _, key := range []string{"packets", "bytes"} {
		value, ok := object[key].(json.Number)
		if !ok || !nftJSONNonNegativeInteger(value) {
			return errors.New("invalid inactive nftables counter")
		}
		object[key] = json.Number("0")
	}
	return nil
}

func containsInactiveProductReference(value any) bool {
	switch value := value.(type) {
	case string:
		return strings.Contains(strings.ToLower(value), "syswarden")
	case []any:
		for _, item := range value {
			if containsInactiveProductReference(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range value {
			if strings.Contains(strings.ToLower(key), "syswarden") || containsInactiveProductReference(item) {
				return true
			}
		}
	}
	return false
}
