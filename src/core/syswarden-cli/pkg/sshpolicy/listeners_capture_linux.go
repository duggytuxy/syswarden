//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
)

// ListenerSummary describes TCP listening sockets held by the observed process.
// It proves neither exclusive ownership, policy correspondence nor reachability.
type ListenerSummary struct {
	Schema                int            `json:"schema"`
	Process               ProcessSummary `json:"process"`
	TCPListenersObserved  bool           `json:"tcp_listeners_observed"`
	ListenerCount         int            `json:"listener_count"`
	SocketsSHA256         string         `json:"sockets_sha256"`
	ConfigurationVerified bool           `json:"configuration_verified"`
	RuntimeActivated      bool           `json:"runtime_activated"`
	AccessVerified        bool           `json:"access_verified"`
}

type sshListenerCapture struct {
	samples int
	sockets []sshListenerSocket
}

type sshListenerProcessLease struct {
	sshProcessLease
	ctx     context.Context
	read    func(context.Context) ([]sshListenerSocket, error)
	capture *sshListenerCapture
}

func (l *sshListenerProcessLease) observe() (sshProcessIdentity, error) {
	if l == nil || l.sshProcessLease == nil || l.ctx == nil || l.read == nil || l.capture == nil || l.capture.samples >= 2 {
		return sshProcessIdentity{}, ErrInventoryUnsafe
	}
	before, err := l.sshProcessLease.observe()
	if err != nil {
		return sshProcessIdentity{}, err
	}
	sockets, socketErr := l.read(l.ctx)
	after, processErr := l.sshProcessLease.observe()
	if err = errors.Join(socketErr, processErr, l.ctx.Err()); err != nil || !reflect.DeepEqual(before, after) || len(sockets) == 0 || len(sockets) > maxSSHProcessSockets {
		return sshProcessIdentity{}, errors.Join(ErrInventoryChanged, err)
	}
	if l.capture.samples != 0 && !slices.Equal(l.capture.sockets, sockets) {
		return sshProcessIdentity{}, ErrInventoryChanged
	}
	l.capture.samples++
	l.capture.sockets = slices.Clone(sockets)
	return after, nil
}

func summarizeSSHListeners(process ProcessSummary, capture *sshListenerCapture) (ListenerSummary, error) {
	if capture == nil || capture.samples != 2 || len(capture.sockets) == 0 || len(capture.sockets) > maxSSHProcessSockets ||
		!process.ProcessObserved || !process.ExecutableVerified || !lowerDigest.MatchString(process.IdentitySHA256) {
		return ListenerSummary{}, ErrInventoryUnsafe
	}
	unique := make(map[string]sshListenerSocket)
	lastFD := -1
	for _, socket := range capture.sockets {
		if socket.FD <= lastFD || !validSSHListenerSocket(socket) {
			return ListenerSummary{}, ErrInventoryUnsafe
		}
		lastFD = socket.FD
		key := sshListenerKey(socket)
		// Multiple descriptors may refer to the same socket. They do not turn
		// one listening socket into multiple listeners in the public summary.
		socket.FD = 0
		if prior, exists := unique[key]; exists && prior != socket {
			return ListenerSummary{}, ErrInventoryChanged
		}
		unique[key] = socket
	}
	wire, err := json.Marshal(capture.sockets)
	if err != nil {
		return ListenerSummary{}, err
	}
	return ListenerSummary{Schema: 1, Process: process, TCPListenersObserved: true,
		ListenerCount: len(unique), SocketsSHA256: digestBytes(wire)}, nil
}

// ObserveSystemdListeners reads the fixed process's kernel socket descriptors.
// It sends no traffic and never accepts, binds, listens, shuts down, signals or
// changes socket flags. Each duplicate is closed before querying the manager.
func ObserveSystemdListeners() (ListenerSummary, error) {
	capture := &sshListenerCapture{}
	process, err := observeSystemdProcess(func(ctx context.Context, process *sshProcessBinding) sshProcessLease {
		return &sshListenerProcessLease{sshProcessLease: process, ctx: ctx, read: process.listeners, capture: capture}
	})
	if err != nil {
		return ListenerSummary{}, err
	}
	return summarizeSSHListeners(process, capture)
}
