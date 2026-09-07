package network

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type haV2DoerResult struct {
	status int
	err    error
}

type haV2ScriptedDoer struct {
	results  []haV2DoerResult
	requests []*http.Request
}

func (doer *haV2ScriptedDoer) Do(request *http.Request) (*http.Response, error) {
	doer.requests = append(doer.requests, request)
	result := doer.results[0]
	doer.results = doer.results[1:]
	if result.err != nil {
		return nil, result.err
	}
	return &http.Response{StatusCode: result.status, Body: io.NopCloser(&emptyReader{})}, nil
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func testHAV2WriterAdapter(t *testing.T) *haRuntimeV2Adapter {
	t.Helper()
	model, _ := newHAReplicationModel("cluster-a")
	coordinator, err := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.activate(); err != nil {
		t.Fatal(err)
	}
	adapter, err := newHARuntimeV2Adapter(coordinator, haRuntimeV2Writer, "192.0.2.20", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestHARuntimeV2OutboundLostResponseRetriesIdempotently(t *testing.T) {
	adapter := testHAV2WriterAdapter(t)
	operation := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "upsert")
	if _, err := adapter.enqueueLocal(operation); err != nil {
		t.Fatal(err)
	}
	doer := &haV2ScriptedDoer{results: []haV2DoerResult{
		{status: http.StatusNoContent}, {err: errors.New("response lost")},
		{status: http.StatusNoContent}, {status: http.StatusAlreadyReported},
	}}
	persisted := 0
	outbound, err := newHARuntimeV2Outbound(adapter, doer, "https://192.0.2.20:62026", "outer-token", func(model *haReplicationModel) error {
		persisted++
		if len(model.outbox) != 0 {
			t.Fatal("acknowledged snapshot retained outbox")
		}
		return nil
	}, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	outbound.now = func() time.Time { return time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC) }
	if err := outbound.step(context.Background()); err == nil {
		t.Fatal("lost response not reported")
	}
	if len(adapter.coordinator.model.outbox) != 1 {
		t.Fatal("lost response discarded durable outbox")
	}
	if err := outbound.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(adapter.coordinator.model.outbox) != 0 || persisted != 1 {
		t.Fatal("idempotent retry did not commit acknowledgement")
	}
	if len(doer.requests) != 4 || doer.requests[0].URL.Scheme != "https" {
		t.Fatal("unexpected outbound request sequence")
	}
}

func TestHARuntimeV2OutboundMixedVersionDoesNotAcknowledge(t *testing.T) {
	adapter := testHAV2WriterAdapter(t)
	operation := testHAReplicationOperation(t, "node-a", 1, "192.0.2.10", "ssh", "delete")
	if _, err := adapter.enqueueLocal(operation); err != nil {
		t.Fatal(err)
	}
	doer := &haV2ScriptedDoer{results: []haV2DoerResult{{status: http.StatusNotFound}}}
	outbound, _ := newHARuntimeV2Outbound(adapter, doer, "https://192.0.2.20:62026", "outer-token", func(*haReplicationModel) error { return nil }, time.Second, time.Second)
	if err := outbound.step(context.Background()); err == nil {
		t.Fatal("mixed-version peer accepted")
	}
	if len(adapter.coordinator.model.outbox) != 1 || adapter.coordinator.state != haCoordinationDegraded {
		t.Fatal("mixed-version response lost state or promoted node")
	}
}

func TestHARuntimeV2InitialOutboundHeartbeatBootstrapsHealthyStaticPair(t *testing.T) {
	adapter := testHAV2WriterAdapter(t)
	doer := &haV2ScriptedDoer{results: []haV2DoerResult{{status: http.StatusNoContent}}}
	outbound, err := newHARuntimeV2Outbound(adapter, doer, "https://192.0.2.20:62026", "outer-token", func(*haReplicationModel) error { return nil }, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	outbound.now = func() time.Time { return time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC) }
	if err := outbound.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(doer.requests) != 1 {
		t.Fatalf("initial step sent %d requests, want one heartbeat", len(doer.requests))
	}
	wire, err := io.ReadAll(doer.requests[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat, err := decodeHARuntimeV2Heartbeat(wire)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.State != haCoordinationHealthy || heartbeat.PeerView != haCoordinationHealthy {
		t.Fatalf("initial healthy pair was advertised as asymmetric: %#v", heartbeat)
	}
}

func TestHARuntimeV2OutboundPreservesPerNodeSequenceOrder(t *testing.T) {
	adapter := testHAV2WriterAdapter(t)
	second := testHAReplicationOperation(t, "node-a", 2, "8.8.8.112", "ssh", "upsert")
	first := testHAReplicationOperation(t, "node-a", 1, "8.8.8.111", "ssh", "upsert")
	if _, err := adapter.enqueueLocal(second); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.enqueueLocal(first); err != nil {
		t.Fatal(err)
	}
	doer := &haV2ScriptedDoer{results: []haV2DoerResult{
		{status: http.StatusNoContent}, {status: http.StatusNoContent}, {status: http.StatusNoContent},
	}}
	outbound, err := newHARuntimeV2Outbound(adapter, doer, "https://192.0.2.20:62026", "outer-token", func(*haReplicationModel) error { return nil }, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	outbound.now = func() time.Time { return time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC) }
	if err := outbound.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(doer.requests) != 3 {
		t.Fatalf("request count=%d, want heartbeat plus two operations", len(doer.requests))
	}
	var sequences []uint64
	for _, request := range doer.requests[1:] {
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := decodeHACoordinationEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		sequences = append(sequences, envelope.Operation.Sequence)
	}
	if sequences[0] != 1 || sequences[1] != 2 {
		t.Fatalf("outbound sequence order=%v, want [1 2]", sequences)
	}
}

func TestHARuntimeV2SecretFileIsOwnerOnlyAndNeverInline(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only secret fixture directory requires execute permission
		t.Fatal(err)
	}
	path := filepath.Join(directory, "secret")
	secret := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(path, secret, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readHARuntimeV2Secret(path, os.Geteuid())
	if err != nil || string(loaded) != string(secret) {
		t.Fatalf("secret load=%q err=%v", loaded, err)
	}
	if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- this adversarial fixture deliberately makes the secret world-readable
		t.Fatal(err)
	}
	if _, err := readHARuntimeV2Secret(path, os.Geteuid()); err == nil {
		t.Fatal("world-readable secret accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readHARuntimeV2Secret(link, os.Geteuid()); err == nil {
		t.Fatal("secret symlink accepted")
	}
}

func TestHARuntimeV2OutboundStopsWithContext(t *testing.T) {
	adapter := testHAV2WriterAdapter(t)
	doer := &haV2ScriptedDoer{}
	outbound, _ := newHARuntimeV2Outbound(adapter, doer, "https://192.0.2.20:62026", "outer-token", func(*haReplicationModel) error { return nil }, time.Second, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { outbound.run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("outbound loop did not stop")
	}
}
