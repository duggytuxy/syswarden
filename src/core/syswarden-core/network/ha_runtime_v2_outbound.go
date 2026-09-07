package network

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxHARuntimeV2SecretBytes int64 = 4096

type haV2HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type haRuntimeV2Outbound struct {
	adapter        *haRuntimeV2Adapter
	client         haV2HTTPDoer
	baseURL        string
	bearerToken    string
	persist        func(*haReplicationModel) error
	now            func() time.Time
	interval       time.Duration
	requestTimeout time.Duration
}

func readHARuntimeV2Secret(path string, expectedOwnerUID int) ([]byte, error) {
	root, name, err := openHAReplicationStoreDirectory(path, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return nil, fmt.Errorf("HA v2 secret must be an owner-only regular file")
	}
	wire, err := readHARegularFileBounded(root, name, maxHARuntimeV2SecretBytes)
	if err != nil {
		return nil, err
	}
	if bytes.ContainsAny(wire, "\r\n\t ") || len(wire) < 32 || len(wire) > 256 {
		return nil, fmt.Errorf("HA v2 secret must contain 32 to 256 non-whitespace bytes")
	}
	return append([]byte(nil), wire...), nil
}

func newHARuntimeV2Outbound(adapter *haRuntimeV2Adapter, client haV2HTTPDoer, baseURL, bearerToken string, persist func(*haReplicationModel) error, interval, requestTimeout time.Duration) (*haRuntimeV2Outbound, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		adapter == nil || client == nil || persist == nil || bearerToken == "" || strings.TrimSpace(bearerToken) != bearerToken ||
		interval < time.Second || interval > time.Minute || requestTimeout < time.Second || requestTimeout > 30*time.Second {
		return nil, fmt.Errorf("invalid HA v2 outbound configuration")
	}
	return &haRuntimeV2Outbound{adapter: adapter, client: client, baseURL: strings.TrimSuffix(baseURL, "/"), bearerToken: bearerToken, persist: persist, now: time.Now, interval: interval, requestTimeout: requestTimeout}, nil
}

func (outbound *haRuntimeV2Outbound) post(ctx context.Context, path string, wire []byte) (int, error) {
	requestContext, cancel := context.WithTimeout(ctx, outbound.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, outbound.baseURL+path, bytes.NewReader(wire))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+outbound.bearerToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := outbound.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, nil
}

func (outbound *haRuntimeV2Outbound) step(ctx context.Context) error {
	heartbeat, err := outbound.adapter.heartbeat(outbound.now())
	if err != nil {
		return err
	}
	status, err := outbound.post(ctx, "/ha/v2/heartbeat", heartbeat)
	if err != nil || status != http.StatusNoContent {
		outbound.adapter.markOutboundFailure("HA v2 outbound heartbeat failed")
		if err != nil {
			return err
		}
		return fmt.Errorf("HA v2 heartbeat response %d", status)
	}
	operations := outbound.adapter.outboundOperations()
	sort.Slice(operations, func(i, j int) bool {
		if operations[i].NodeID != operations[j].NodeID {
			return operations[i].NodeID < operations[j].NodeID
		}
		if operations[i].Sequence != operations[j].Sequence {
			return operations[i].Sequence < operations[j].Sequence
		}
		return operations[i].OperationID < operations[j].OperationID
	})
	for _, operation := range operations {
		wire, err := outbound.adapter.outboundEnvelope(operation, outbound.now())
		if err != nil {
			return err
		}
		status, err := outbound.post(ctx, "/ha/v2/replication", wire)
		if err != nil {
			outbound.adapter.markOutboundFailure("HA v2 outbound replication failed")
			return err
		}
		if status != http.StatusNoContent && status != http.StatusAlreadyReported {
			outbound.adapter.markOutboundFailure("HA v2 peer rejected replicated state")
			return fmt.Errorf("HA v2 replication response %d", status)
		}
		if err := outbound.adapter.acknowledgeOutbound(operation.OperationID, outbound.persist, outbound.now()); err != nil {
			return err
		}
	}
	return nil
}

func (outbound *haRuntimeV2Outbound) run(ctx context.Context) {
	ticker := time.NewTicker(outbound.interval)
	defer ticker.Stop()
	backoff := outbound.interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := outbound.step(ctx); err != nil {
				backoff *= 2
				if backoff > time.Minute {
					backoff = time.Minute
				}
				ticker.Reset(backoff)
				continue
			}
			backoff = outbound.interval
			ticker.Reset(backoff)
		}
	}
}
