//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxSSHAccessRequestBytes = 256 << 10
const sshAccessRequestDomain = "syswarden-ssh-access-request-v1"

// Public keys only: protected target-side preparation never receives a private
// authentication credential. The request still contains private infrastructure.
type sshAccessPin struct {
	Address   string `json:"address"`
	User      string `json:"user"`
	HostKey   []byte `json:"host_key"`
	ClientKey []byte `json:"client_key"`
}

type sshAccessRoutePins struct {
	ContextID string
	Target    sshAccessPin
	Jump      *sshAccessPin
}

type sshAccessRequestRoute struct {
	Access accessContext `json:"access"`
	Target sshAccessPin  `json:"target"`
	Jump   *sshAccessPin `json:"jump,omitempty"`
}

type sshAccessRequest struct {
	Schema      int                     `json:"schema"`
	Domain      string                  `json:"domain"`
	Transaction string                  `json:"transaction"`
	Plan        string                  `json:"plan_sha256"`
	Intent      string                  `json:"intent_sha256"`
	Target      string                  `json:"target_sha256"`
	Assessment  string                  `json:"assessment_sha256"`
	Routes      []sshAccessRequestRoute `json:"routes"`
}

// Only the independent controller supplies these credentials. No target-side
// file path, agent, remote command or credential discovery is accepted.
type sshAccessCredentials struct {
	ContextID string
	Target    []byte
	Jump      []byte
}

type sshAccessBatchObservation struct {
	RequestSHA256    string
	Observations     []sshAccessObservation
	RecoveryRequired bool
}

func copySSHAccessPin(pin sshAccessPin) (sshAccessPin, error) {
	endpoint, err := netip.ParseAddrPort(pin.Address)
	if err != nil || endpoint.String() != pin.Address || endpoint.Port() == 0 ||
		!contextAddress(endpoint.Addr().String()) || !sshUser.MatchString(pin.User) {
		return sshAccessPin{}, ErrInventoryUnsafe
	}
	for _, wire := range [][]byte{pin.HostKey, pin.ClientKey} {
		if len(wire) == 0 || len(wire) > 16<<10 {
			return sshAccessPin{}, ErrInventoryUnsafe
		}
		key, err := ssh.ParsePublicKey(wire)
		if err != nil || !bytes.Equal(wire, key.Marshal()) || !safeSSHAccessRSA(key) {
			return sshAccessPin{}, ErrInventoryUnsafe
		}
		switch key.Type() {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		default:
			return sshAccessPin{}, ErrInventoryUnsafe
		}
	}
	pin.HostKey, pin.ClientKey = bytes.Clone(pin.HostKey), bytes.Clone(pin.ClientKey)
	return pin, nil
}

func copySSHAccessRoute(route sshAccessRequestRoute) (sshAccessRequestRoute, error) {
	declaration := intent{Schema: 1, Role: "target", Owner: "syswarden", Profile: "forwarding", Contexts: []accessContext{route.Access}}
	if err := declaration.validate(); err != nil {
		return sshAccessRequestRoute{}, err
	}
	if route.Access.Route != "direct" && route.Access.Route != "proxyjump" {
		return sshAccessRequestRoute{}, ErrInventoryUnsafe
	}
	if (route.Access.Route == "proxyjump") != (route.Jump != nil) {
		return sshAccessRequestRoute{}, ErrInventoryUnsafe
	}
	target, err := copySSHAccessPin(route.Target)
	if err != nil || target.User != route.Access.User || target.Address != net.JoinHostPort(route.Access.LocalAddress, strconv.Itoa(int(route.Access.LocalPort))) {
		return sshAccessRequestRoute{}, errors.Join(ErrInventoryUnsafe, err)
	}
	route.Target = target
	if route.Jump != nil {
		jump, err := copySSHAccessPin(*route.Jump)
		if err != nil || jump.Address == target.Address {
			return sshAccessRequestRoute{}, errors.Join(ErrInventoryUnsafe, err)
		}
		route.Jump = &jump
	}
	return route, nil
}

// Return private canonical bytes only after a locked, parser-checked activation
// assessment. Approval of the migration plan does not approve these key pins or
// authorize controller execution. No network, record write or durability repair.
func prepareSSHActivationAccessRequest(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, pins []sshAccessRoutePins) ([]byte, error) {
	if len(pins) == 0 || len(pins) > MaxAccessContexts {
		return nil, ErrInventoryUnsafe
	}
	var wire []byte
	_, err := withSSHActivationAssessment(ctx, journal, approved, parser, run, parserCheck, observe,
		func(_ context.Context, a *sshActivationAssessment, summary ActivationAssessment, guard func() error) error {
			var err error
			wire, err = makeSSHActivationAccessRequest(a, summary, pins)
			if err != nil {
				return err
			}
			return guard()
		})
	if err != nil {
		return nil, err
	}
	return wire, nil
}

func makeSSHActivationAccessRequest(a *sshActivationAssessment, summary ActivationAssessment, pins []sshAccessRoutePins) ([]byte, error) {
	routes, err := bindSSHAccessRoutes(a.owned.plan.intent.Contexts, pins)
	if err != nil {
		return nil, err
	}
	assessment, err := sshActivationDigest(summary)
	if err != nil {
		return nil, err
	}
	request := sshAccessRequest{Schema: 1, Domain: sshAccessRequestDomain, Transaction: a.owned.prepared.Transaction,
		Plan: a.owned.prepared.PlanSHA256, Intent: digestBytes(a.intent.data), Target: a.target, Assessment: assessment, Routes: routes}
	wire, err := json.Marshal(request)
	if err != nil || len(wire) > maxSSHAccessRequestBytes {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	return wire, nil
}

// The same complete route binding is required before publication and when
// preparing post-reload access. Enrollment may not omit or substitute a route.
func bindSSHAccessRoutes(contexts []accessContext, pins []sshAccessRoutePins) ([]sshAccessRequestRoute, error) {
	if len(contexts) == 0 || len(contexts) > MaxAccessContexts || len(pins) != len(contexts) {
		return nil, ErrInventoryUnsafe
	}
	byID := make(map[string]sshAccessRoutePins, len(pins))
	for _, pin := range pins {
		if _, exists := byID[pin.ContextID]; exists || !contextID.MatchString(pin.ContextID) {
			return nil, ErrInventoryUnsafe
		}
		byID[pin.ContextID] = pin
	}
	routes := make([]sshAccessRequestRoute, 0, len(contexts))
	for _, access := range contexts {
		pin, exists := byID[access.ID]
		if !exists {
			return nil, ErrInventoryUnsafe
		}
		delete(byID, access.ID)
		route, err := copySSHAccessRoute(sshAccessRequestRoute{access, pin.Target, pin.Jump})
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func parseSSHAccessRequest(wire []byte, approved string) (sshAccessRequest, error) {
	var request sshAccessRequest
	if len(wire) == 0 || len(wire) > maxSSHAccessRequestBytes || !lowerDigest.MatchString(approved) || digestBytes(wire) != approved {
		return request, ErrInventoryUnsafe
	}
	if err := json.Unmarshal(wire, &request); err != nil {
		return sshAccessRequest{}, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(wire, canonical) || request.Schema != 1 || request.Domain != sshAccessRequestDomain || len(request.Routes) == 0 || len(request.Routes) > MaxAccessContexts {
		return sshAccessRequest{}, ErrInventoryUnsafe
	}
	for _, digest := range []string{request.Transaction, request.Plan, request.Intent, request.Target, request.Assessment} {
		if !lowerDigest.MatchString(digest) {
			return sshAccessRequest{}, ErrInventoryUnsafe
		}
	}
	seen := make(map[string]bool)
	for index, route := range request.Routes {
		if seen[route.Access.ID] {
			return sshAccessRequest{}, ErrInventoryUnsafe
		}
		seen[route.Access.ID] = true
		request.Routes[index], err = copySSHAccessRoute(route)
		if err != nil {
			return sshAccessRequest{}, err
		}
	}
	return request, nil
}

// An approved request is an explicit controller input, not proof that target
// state remains current or that the controller is enrolled. Never accept its
// returned observations as activation completion. Production receipt handling
// must independently recheck target state and authority before any such claim.
func probeSSHActivationAccessRequest(parent context.Context, wire []byte, approved string, credentials []sshAccessCredentials,
	guard func() error) (result sshAccessBatchObservation, err error) {
	if parent == nil || guard == nil {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	defer func() {
		if err == nil {
			err = errors.Join(ctx.Err(), guard())
		}
		if err != nil {
			result = sshAccessBatchObservation{}
		}
	}()
	if err := errors.Join(ctx.Err(), guard()); err != nil {
		return result, err
	}
	if len(wire) == 0 || len(wire) > maxSSHAccessRequestBytes {
		return result, ErrInventoryUnsafe
	}
	request, err := parseSSHAccessRequest(bytes.Clone(wire), approved)
	if err != nil {
		return result, err
	}
	if len(credentials) != len(request.Routes) {
		return result, ErrInventoryUnsafe
	}
	byID := make(map[string]sshAccessCredentials, len(credentials))
	for _, credential := range credentials {
		if _, exists := byID[credential.ContextID]; exists || !contextID.MatchString(credential.ContextID) {
			return result, ErrInventoryUnsafe
		}
		byID[credential.ContextID] = credential
	}
	type peers struct {
		target sshAccessPeer
		jump   *sshAccessPeer
	}
	prepared := make([]peers, 0, len(request.Routes))
	// Clear only owned encoded copies, including partially prepared batches.
	defer func() {
		for _, pair := range prepared {
			clear(pair.target.Identity)
			if pair.jump != nil {
				clear(pair.jump.Identity)
			}
		}
	}()
	prepare := func(pin sshAccessPin, private []byte) (sshAccessPeer, error) {
		if len(private) == 0 || len(private) > 16<<10 {
			return sshAccessPeer{}, ErrInventoryUnsafe
		}
		peer := sshAccessPeer{pin.Address, pin.User, bytes.Clone(pin.HostKey), bytes.Clone(private)}
		_, identity, _, err := prepareSSHAccessPeer(peer)
		if err != nil || identity.ClientKeySHA256 != digestBytes(pin.ClientKey) {
			clear(peer.Identity)
			return sshAccessPeer{}, errors.Join(ErrInventoryUnsafe, err)
		}
		return peer, nil
	}
	// Validate every context, pin and credential before the first connection.
	for _, route := range request.Routes {
		credential, exists := byID[route.Access.ID]
		if !exists {
			return result, ErrInventoryUnsafe
		}
		pair := peers{}
		pair.target, err = prepare(route.Target, credential.Target)
		if err != nil {
			return result, err
		}
		prepared = append(prepared, pair)
		if route.Jump == nil {
			if len(credential.Jump) != 0 {
				return result, ErrInventoryUnsafe
			}
		} else {
			jump, err := prepare(*route.Jump, credential.Jump)
			if err != nil {
				return result, err
			}
			prepared[len(prepared)-1].jump = &jump
		}
	}
	for index, route := range request.Routes {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return result, err
		}
		binding := sshAccessBinding{Transaction: request.Transaction, Plan: request.Plan, Intent: request.Intent, Target: request.Target,
			Request: approved, Access: route.Access}
		observation, err := probeSSHFreshAccess(ctx, binding, prepared[index].target, prepared[index].jump, guard)
		if err != nil {
			return result, err
		}
		result.Observations = append(result.Observations, observation)
	}
	result.RequestSHA256, result.RecoveryRequired = approved, true
	return result, nil
}
