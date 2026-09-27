package network

import (
	"context"
	"crypto/tls"
	"os"
	"strings"
	"testing"
	"time"
)

// Development reproduction only. These fake firewall/HTTP fixtures are never
// native qualification observations and never replace the failed lab capture.
type qualificationWALNode struct {
	adapter *haRuntimeV2Adapter
	store   *haV2TransactionStore
	fw      *haV2RecoverableFirewall
}

func qualificationWALNodeFor(t *testing.T, writer bool, clock *time.Time) qualificationWALNode {
	t.Helper()
	local, peer, address, role := "node-a", "node-b", "9.9.9.20", haRuntimeV2Writer
	if !writer {
		local, peer, address, role = "node-b", "node-a", "9.9.9.10", haRuntimeV2Standby
	}
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 1)
	if _, err := model.bindRuntimeIdentity(local, peer, string(role)); err != nil {
		t.Fatal(err)
	}
	coordinator, err := newHAReplicationCoordinator("cluster-a", local, peer, []byte("0123456789abcdef0123456789abcdef"), model)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.activate(); err != nil {
		t.Fatal(err)
	}
	if err := store.persist(model); err != nil {
		t.Fatal(err)
	}
	adapter, err := newHARuntimeV2Adapter(coordinator, role, address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fw := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), fw, store, func() time.Time { return *clock }); err != nil {
		t.Fatal(err)
	}
	return qualificationWALNode{adapter: adapter, store: store, fw: fw}
}

func qualificationWALHeartbeat(t *testing.T, from, to qualificationWALNode, clock *time.Time) {
	t.Helper()
	*clock = clock.Add(time.Millisecond)
	wire, err := from.adapter.heartbeat(*clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := to.adapter.receiveHeartbeat(wire, *clock); err != nil {
		t.Fatal(err)
	}
}

func qualificationWALPrepare(t *testing.T, node qualificationWALNode) {
	t.Helper()
	digest, err := node.adapter.coordinator.stateDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := node.adapter.beginOperatorRecovery(node.adapter.coordinator.peerID, digest); err != nil {
		t.Fatal(err)
	}
}

func qualificationWALRestartOnce(t *testing.T, node qualificationWALNode, clock *time.Time) qualificationWALNode {
	t.Helper()
	c := node.adapter.coordinator
	// Reopen the actual durable store. Do not copy or edit state, anchor or WAL.
	store, err := newHAV2TransactionStore(node.store.statePath, node.store.transactionPath, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	fw := newHAV2RecoverableFirewall()
	model, recovered, err := store.recover(context.Background(), fw, c.clusterID, c.epoch, c.localID, c.peerID, string(node.adapter.role), *clock)
	if err != nil || !recovered {
		t.Fatalf("single recovery: recovered=%t err=%v", recovered, err)
	}
	if _, _, pending, err := readHAV2Transaction(store); err != nil || pending {
		t.Fatalf("WAL retained after successful single recovery: pending=%t err=%v", pending, err)
	}
	if model.coordinationState != haCoordinationFenced {
		t.Fatalf("WAL restart resumed writes automatically: %s", model.coordinationState)
	}
	coordinator, err := newHAReplicationCoordinator(c.clusterID, c.localID, c.peerID, c.secret, model)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := newHARuntimeV2Adapter(coordinator, node.adapter.role, node.adapter.peerAddress.String(), node.adapter.heartbeatTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.configureTransactions(context.Background(), fw, store, func() time.Time { return *clock }); err != nil {
		t.Fatal(err)
	}
	if err := store.reconcile(context.Background(), fw, model, *clock); err != nil {
		t.Fatal(err)
	}
	return qualificationWALNode{adapter: adapter, store: store, fw: fw}
}

func TestQualificationWriterWALRequiresPreparedDeliveryBeforeExplicitRejoin(t *testing.T) {
	for _, stage := range []string{"prepare", "mutation", "persist"} {
		t.Run(stage, func(t *testing.T) {
			clock := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
			writer := qualificationWALNodeFor(t, true, &clock)
			standby := qualificationWALNodeFor(t, false, &clock)
			qualificationWALHeartbeat(t, standby, writer, &clock)
			writer.fw.failAfter = stage
			if err := writer.adapter.applyLocalTarget("8.8.8.221", haV2LocalRuntimeSource, "upsert", time.Hour, false); err == nil {
				t.Fatal("crash fixture was not reached")
			}
			writer = qualificationWALRestartOnce(t, writer, &clock)
			operations := writer.adapter.outboundOperations()
			if len(operations) != 1 || len(standby.adapter.coordinator.model.activeClaims(clock)) != 0 {
				t.Fatal("undelivered writer claim was lost or injected into standby")
			}
			if _, err := writer.adapter.outboundEnvelope(operations[0], clock); err == nil {
				t.Fatal("fenced writer emitted before operator recovery")
			}
			qualificationWALHeartbeat(t, writer, standby, &clock)
			qualificationWALPrepare(t, writer)
			qualificationWALPrepare(t, standby)
			qualificationWALHeartbeat(t, writer, standby, &clock)
			qualificationWALHeartbeat(t, standby, writer, &clock)
			for _, node := range []qualificationWALNode{writer, standby} {
				if err := node.adapter.activateAfterRecovery(); err == nil || !strings.Contains(err.Error(), "identical quiescent") {
					t.Fatalf("diverged pair activated: %v", err)
				}
			}
			if err := writer.adapter.applyLocalTarget("8.8.8.222", haV2LocalRuntimeSource, "upsert", time.Hour, false); err == nil {
				t.Fatal("new mutation accepted during incomplete recovery")
			}
			fixture := newHAAPITestFixture(t, noOpFirewallManager{}, []string{"9.9.9.10"})
			standby.adapter.peerCertificateVerifier = func(*tls.ConnectionState) error { return nil }
			fixture.api.replicationV2 = standby.adapter
			fixture.api.now = func() time.Time { return clock }
			doer := &haV2LoopbackDoer{handler: fixture.api.handler(), remote: "9.9.9.10:43123", loseFirstReplication: true}
			outbound, err := newHARuntimeV2Outbound(writer.adapter, doer, "https://9.9.9.20:62026", fixture.api.cfg.Token, writer.store.persist, time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			outbound.now = func() time.Time { return clock }
			clock = clock.Add(time.Second)
			if err := outbound.step(context.Background()); err == nil || !doer.lost {
				t.Fatalf("prepared durable delivery did not reach peer commit: %v", err)
			}
			mutationsAfterCommit := len(standby.fw.mutations)
			clock = clock.Add(time.Second)
			if err := outbound.step(context.Background()); err != nil {
				t.Fatalf("prepared retained replay could not drain outbox: %v", err)
			}
			if mutationsAfterCommit != 1 || len(standby.fw.mutations) != mutationsAfterCommit || len(writer.adapter.outboundOperations()) != 0 {
				t.Fatal("durable replay repeated the firewall mutation or failed to acknowledge")
			}
			qualificationWALHeartbeat(t, writer, standby, &clock)
			qualificationWALHeartbeat(t, standby, writer, &clock)
			for _, node := range []qualificationWALNode{writer, standby} {
				if node.adapter.coordinator.state != haCoordinationRecovering {
					t.Fatal("delivery automatically resumed healthy coordination")
				}
				if err := node.adapter.activateAfterRecovery(); err != nil {
					t.Fatal(err)
				}
			}
			qualificationWALHeartbeat(t, writer, standby, &clock)
			qualificationWALHeartbeat(t, standby, writer, &clock)
			if err := writer.adapter.localMutationReadiness(clock); err != nil {
				t.Fatal(err)
			}
			durable, err := writer.store.loadOrInitialize("cluster-a", 1)
			if err != nil || len(durable.outbox) != 0 || len(durable.activeClaims(clock)) != 1 || durable.coordinationState != haCoordinationHealthy {
				t.Fatalf("explicit recovery did not durably preserve the claim and acknowledgement: %v", err)
			}
		})
	}
}

func TestQualificationStandbyWALRejoinsOnlyAfterReplayAckAndExplicitActivation(t *testing.T) {
	for _, stage := range []string{"prepare", "mutation", "persist"} {
		t.Run(stage, func(t *testing.T) {
			clock := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
			writer := qualificationWALNodeFor(t, true, &clock)
			standby := qualificationWALNodeFor(t, false, &clock)
			qualificationWALHeartbeat(t, standby, writer, &clock)
			if err := writer.adapter.applyLocalTarget("8.8.8.223", haV2LocalRuntimeSource, "upsert", time.Hour, false); err != nil {
				t.Fatal(err)
			}
			qualificationWALHeartbeat(t, writer, standby, &clock)
			operation := writer.adapter.outboundOperations()[0]
			wire, err := writer.adapter.outboundEnvelope(operation, clock)
			if err != nil {
				t.Fatal(err)
			}
			standby.fw.failAfter = stage
			if _, err := standby.adapter.receiveReplication(wire); err == nil {
				t.Fatal("standby crash fixture was not reached")
			}
			writer.adapter.markOutboundFailure("peer crashed before acknowledgement")
			standby = qualificationWALRestartOnce(t, standby, &clock)
			if err := standby.adapter.activateAfterRecovery(); err == nil {
				t.Fatal("standby activated without prepare")
			}
			qualificationWALPrepare(t, standby)
			fixture := newHAAPITestFixture(t, noOpFirewallManager{}, []string{"9.9.9.10"})
			standby.adapter.peerCertificateVerifier = func(*tls.ConnectionState) error { return nil }
			fixture.api.replicationV2 = standby.adapter
			fixture.api.now = func() time.Time { return clock }
			doer := &haV2LoopbackDoer{handler: fixture.api.handler(), remote: "9.9.9.10:43123"}
			outbound, err := newHARuntimeV2Outbound(writer.adapter, doer, "https://9.9.9.20:62026", fixture.api.cfg.Token, writer.store.persist, time.Second, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			outbound.now = func() time.Time { return clock }
			clock = clock.Add(time.Second)
			mutationsBefore := len(standby.fw.mutations)
			if err := outbound.step(context.Background()); err != nil {
				t.Fatalf("retained operation replay and acknowledgement: %v", err)
			}
			if len(writer.adapter.outboundOperations()) != 0 || len(standby.fw.mutations) != mutationsBefore {
				t.Fatal("replay lost its acknowledgement or repeated firewall mutation")
			}
			qualificationWALPrepare(t, writer)
			qualificationWALHeartbeat(t, writer, standby, &clock)
			qualificationWALHeartbeat(t, standby, writer, &clock)
			for _, node := range []qualificationWALNode{writer, standby} {
				if err := node.adapter.activateAfterRecovery(); err != nil {
					t.Fatal(err)
				}
			}
			qualificationWALHeartbeat(t, writer, standby, &clock)
			qualificationWALHeartbeat(t, standby, writer, &clock)
			if err := writer.adapter.localMutationReadiness(clock); err != nil {
				t.Fatalf("explicit rejoin did not restore healthy writer readiness: %v", err)
			}
			if err := standby.adapter.localMutationReadiness(clock); err == nil {
				t.Fatal("static standby became a writer")
			}
			t.Log("Single standby WAL recovery, replay acknowledgement and explicit rejoin succeeded; no role promotion or journal edits.")
		})
	}
}

func qualificationPreparedWriter(t *testing.T, clock *time.Time) (qualificationWALNode, haReplicationOperation) {
	t.Helper()
	writer := qualificationWALNodeFor(t, true, clock)
	standby := qualificationWALNodeFor(t, false, clock)
	qualificationWALHeartbeat(t, standby, writer, clock)
	if err := writer.adapter.applyLocalTarget("8.8.8.224", haV2LocalRuntimeSource, "upsert", time.Hour, false); err != nil {
		t.Fatal(err)
	}
	writer.adapter.coordinator.fence("operator-controlled recovery fixture")
	if err := writer.store.persist(writer.adapter.coordinator.model); err != nil {
		t.Fatal(err)
	}
	qualificationWALHeartbeat(t, writer, standby, clock)
	qualificationWALPrepare(t, writer)
	qualificationWALPrepare(t, standby)
	qualificationWALHeartbeat(t, writer, standby, clock)
	qualificationWALHeartbeat(t, standby, writer, clock)
	return writer, writer.adapter.outboundOperations()[0]
}

func TestQualificationPreparedWriterDeliveryRejectsUnboundOrUnsafeOperations(t *testing.T) {
	cases := map[string]func(*testing.T, *qualificationWALNode, *haReplicationOperation, *time.Time){
		"no-process-local-prepare": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.preparedRecoveryOutbox = nil
		},
		"fenced": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.coordinator.fence("identity conflict")
		},
		"unprepared-reason": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.coordinator.setState(haCoordinationRecovering, "checkpoint divergence")
		},
		"stale-heartbeat": func(_ *testing.T, _ *qualificationWALNode, _ *haReplicationOperation, clock *time.Time) {
			*clock = clock.Add(6 * time.Second)
		},
		"negative-receipt-elapsed": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.elapsedSince = func(time.Time, time.Time) time.Duration { return -time.Second }
		},
		"peer-not-recovering": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.peerState = haCoordinationHealthy
		},
		"peer-fenced": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.peerState = haCoordinationFenced
		},
		"peer-view-not-recovering": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.peerView = haCoordinationDegraded
		},
		"peer-has-outbox": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.peerOutboxDepth = 1
		},
		"pending-local-journal": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.pendingTransaction = true
		},
		"standby-cannot-originate": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.role = haRuntimeV2Standby
		},
		"no-durable-store": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.transactionStore = nil
		},
		"no-firewall-manager": func(_ *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.adapter.transactionManager = nil
		},
		"payload-altered-under-original-id": func(_ *testing.T, _ *qualificationWALNode, operation *haReplicationOperation, _ *time.Time) {
			operation.IP = "8.8.8.225"
		},
		"operation-no-longer-retained": func(_ *testing.T, n *qualificationWALNode, operation *haReplicationOperation, _ *time.Time) {
			delete(n.adapter.coordinator.model.outbox, operation.OperationID)
		},
		"retained-payload-changed": func(_ *testing.T, n *qualificationWALNode, operation *haReplicationOperation, _ *time.Time) {
			altered := *operation
			altered.Source = "different"
			n.adapter.coordinator.model.outbox[operation.OperationID] = altered
		},
		"new-operation-after-prepare": func(t *testing.T, n *qualificationWALNode, operation *haReplicationOperation, _ *time.Time) {
			operation.Sequence++
			operation.IP = "8.8.8.225"
			var err error
			operation.OperationID, err = haReplicationOperationDigest(*operation)
			if err != nil {
				t.Fatal(err)
			}
			n.adapter.coordinator.model.outbox[operation.OperationID] = *operation
		},
		"restart-requires-fresh-prepare": func(t *testing.T, n *qualificationWALNode, _ *haReplicationOperation, clock *time.Time) {
			old := n.adapter
			adapter, err := newHARuntimeV2Adapter(old.coordinator, old.role, old.peerAddress.String(), old.heartbeatTimeout)
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.configureTransactions(context.Background(), n.fw, n.store, func() time.Time { return *clock }); err != nil {
				t.Fatal(err)
			}
			adapter.lastHeartbeat = old.lastHeartbeat
			adapter.lastHeartbeatReceivedAt = old.lastHeartbeatReceivedAt
			adapter.peerState = old.peerState
			adapter.peerView = old.peerView
			n.adapter = adapter
		},
		"failed-prepare-does-not-grant-delivery": func(t *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			n.store.observedHead = strings.Repeat("0", 64)
			digest, err := n.adapter.coordinator.stateDigest()
			if err != nil {
				t.Fatal(err)
			}
			if err := n.adapter.beginOperatorRecovery("node-b", digest); err == nil {
				t.Fatal("stale durable head accepted")
			}
		},
		"wrong-prepare-digest": func(t *testing.T, n *qualificationWALNode, _ *haReplicationOperation, _ *time.Time) {
			if err := n.adapter.beginOperatorRecovery("node-b", strings.Repeat("0", 64)); err == nil {
				t.Fatal("wrong preparation digest accepted")
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			clock := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
			node, operation := qualificationPreparedWriter(t, &clock)
			if _, err := node.adapter.outboundEnvelope(operation, clock); err != nil {
				t.Fatalf("control delivery unavailable: %v", err)
			}
			change(t, &node, &operation, &clock)
			stateBefore, err := os.ReadFile(node.store.statePath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := node.adapter.outboundEnvelope(operation, clock); err == nil {
				t.Fatal("unsafe recovery delivery accepted")
			}
			stateAfter, err := os.ReadFile(node.store.statePath)
			if err != nil {
				t.Fatal(err)
			}
			if string(stateBefore) != string(stateAfter) {
				t.Fatal("rejected delivery changed durable state")
			}
		})
	}
}
