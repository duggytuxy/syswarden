//go:build linux

package sshpolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path"
	"reflect"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	sshAccessAuthorityPath     = "/etc/syswarden/ssh-access-controller-v1.json"
	sshAccessAuthorityDomain   = "syswarden-ssh-access-controller-v1"
	maxSSHAccessAuthorityBytes = maxSSHAccessRequestBytes
)

// Enrollment is independently provisioned and approved. It contains public
// keys only and authorizes one plan's activation-access requests, not policy
// consumption, activation completion or recovery completion.
type sshAccessAuthorityDocument struct {
	Schema     int                       `json:"schema"`
	Domain     string                    `json:"domain"`
	Scope      string                    `json:"scope"`
	PlanSHA256 string                    `json:"plan_sha256"`
	Controller []byte                    `json:"controller_public_key"`
	Routes     []sshAccessAuthorityRoute `json:"routes"`
	NotBefore  int64                     `json:"not_before"`
	ExpiresAt  int64                     `json:"expires_at"`
}

type sshAccessAuthorityRoute struct {
	ContextID string        `json:"context_id"`
	Target    sshAccessPin  `json:"target"`
	Jump      *sshAccessPin `json:"jump,omitempty"`
}

// The handle is an observation, not a lock against a cooperating root writer.
// A replacement, revocation, expiry or clock regression poisons it permanently.
// Callers must recheck at every use and retain the exact enrollment image in
// durable issuance. Do not copy a handle, and close it after use.
type sshAccessAuthority struct {
	mu         sync.Mutex
	root       *os.File
	uid        int
	plan       string
	recovery   string
	pins       []sshAccessRoutePins
	controller ed25519.PublicKey
	image      sshFileImage
	digest     string
	ancestors  map[string]sshDirectoryIdentity
	notBefore  int64
	expiresAt  int64
	clock      func() time.Time
	last       time.Time
	poisoned   bool
}

func decodeSSHAccessAuthority(wire []byte, plan string) (sshAccessAuthorityDocument, []sshAccessRoutePins, error) {
	var document sshAccessAuthorityDocument
	if len(wire) == 0 || len(wire) > maxSSHAccessAuthorityBytes || !lowerDigest.MatchString(plan) {
		return document, nil, ErrInventoryUnsafe
	}
	if err := json.Unmarshal(wire, &document); err != nil {
		return sshAccessAuthorityDocument{}, nil, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, wire) || document.Schema != 1 ||
		document.Domain != sshAccessAuthorityDomain || document.Scope != "activation-access" ||
		document.PlanSHA256 != plan || len(document.Controller) != ed25519.PublicKeySize ||
		document.NotBefore <= 0 || document.ExpiresAt <= document.NotBefore ||
		len(document.Routes) == 0 || len(document.Routes) > MaxAccessContexts {
		return sshAccessAuthorityDocument{}, nil, ErrInventoryUnsafe
	}
	pins := make([]sshAccessRoutePins, 0, len(document.Routes))
	seen := make(map[string]bool)
	for _, route := range document.Routes {
		if !contextID.MatchString(route.ContextID) || seen[route.ContextID] {
			return sshAccessAuthorityDocument{}, nil, ErrInventoryUnsafe
		}
		seen[route.ContextID] = true
		target, err := copySSHAccessPin(route.Target)
		if err != nil {
			return sshAccessAuthorityDocument{}, nil, err
		}
		pin := sshAccessRoutePins{ContextID: route.ContextID, Target: target}
		if route.Jump != nil {
			jump, err := copySSHAccessPin(*route.Jump)
			if err != nil || jump.Address == target.Address {
				return sshAccessAuthorityDocument{}, nil, errors.Join(ErrInventoryUnsafe, err)
			}
			pin.Jump = &jump
		}
		pins = append(pins, pin)
	}
	// Matching this ordered list to the protected plan's complete access contexts
	// remains mandatory when constructing the request.
	return document, pins, nil
}

func readSSHAccessAuthorityForPurpose(root *os.File, uid int, restored bool) (sshFileImage, map[string]sshDirectoryIdentity, error) {
	name := sshAccessAuthorityPath
	if restored {
		name = sshRestoredAccessAuthorityPath
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	parent, err := reader.openDirectory(path.Dir(name))
	if err != nil || parent == nil {
		return sshFileImage{}, nil, errors.Join(ErrInventoryUnsafe, err)
	}
	image, readErr := readSSHPrivateChild(parent, path.Base(name), uid, maxSSHAccessAuthorityBytes)
	if err := errors.Join(readErr, parent.Close()); err != nil {
		return sshFileImage{}, nil, errors.Join(ErrInventoryUnsafe, err)
	}
	ancestors := make(map[string]sshDirectoryIdentity, len(reader.state.nodes))
	for name, node := range reader.state.nodes {
		// Changes to unrelated directory entries do not revoke enrollment. Keep
		// identity, permissions and attributes, not size, timestamps or link count.
		ancestors[name] = sshDirectoryIdentity{node.dev, node.ino, node.mode, node.uid, node.gid, reader.state.attributes[name]}
	}
	return image, ancestors, nil
}

// This private fixture boundary accepts an already-open root and expected UID.
// Production callers use / and UID 0; no path or environment override exists.
// The approved digest must arrive independently of the enrollment and receipt.
func openSSHAccessAuthority(root *os.File, uid int, plan, approvedSHA string, clock func() time.Time) (*sshAccessAuthority, error) {
	return openSSHAccessAuthorityForPurpose(root, uid, plan, "", approvedSHA, clock)
}

func openSSHRestoredAccessAuthority(root *os.File, uid int, plan, recovery, approvedSHA string, clock func() time.Time) (*sshAccessAuthority, error) {
	if !lowerDigest.MatchString(recovery) {
		return nil, ErrInventoryUnsafe
	}
	return openSSHAccessAuthorityForPurpose(root, uid, plan, recovery, approvedSHA, clock)
}

func openSSHAccessAuthorityForPurpose(root *os.File, uid int, plan, recovery, approvedSHA string, clock func() time.Time) (*sshAccessAuthority, error) {
	if root == nil || uid < 0 || uid > math.MaxUint32 || clock == nil ||
		!lowerDigest.MatchString(plan) || !lowerDigest.MatchString(approvedSHA) {
		return nil, ErrInventoryUnsafe
	}
	raw, err := root.SyscallConn()
	if err != nil {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil || openErr != nil {
		return nil, errors.Join(ErrInventoryUnsafe, err, openErr)
	}
	authority := &sshAccessAuthority{root: os.NewFile(uintptr(fd), "ssh-access-authority-root"), uid: uid, plan: plan, recovery: recovery, clock: clock}
	authority.image, authority.ancestors, err = readSSHAccessAuthorityForPurpose(authority.root, uid, recovery != "")
	if err == nil && digestBytes(authority.image.data) != approvedSHA {
		err = ErrInventoryUnsafe
	}
	if err == nil {
		var document sshAccessAuthorityDocument
		if recovery == "" {
			document, authority.pins, err = decodeSSHAccessAuthority(authority.image.data, plan)
		} else {
			document, authority.pins, err = decodeSSHRestoredAccessAuthority(authority.image.data, plan, recovery)
		}
		if err == nil {
			authority.controller = bytes.Clone(document.Controller)
			authority.digest = approvedSHA
			authority.notBefore, authority.expiresAt = document.NotBefore, document.ExpiresAt
			err = authority.recheck()
		}
	}
	if err != nil {
		return nil, errors.Join(err, authority.Close())
	}
	return authority, nil
}

func (authority *sshAccessAuthority) recheck() error {
	if authority == nil {
		return ErrInventoryClosed
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.root == nil {
		return ErrInventoryClosed
	}
	if authority.poisoned {
		return ErrInventoryChanged
	}
	authority.poisoned = true
	last := authority.last
	// Sample time before each filesystem check, including the final check.
	// A clock callback cannot replace the enrollment after our last observation.
	for range 2 {
		now := authority.clock()
		if now.Unix() < authority.notBefore || now.Unix() >= authority.expiresAt ||
			(!last.IsZero() && (now.Before(last) || now.Round(0).Before(last.Round(0)))) {
			return ErrInventoryChanged
		}
		image, ancestors, err := readSSHAccessAuthorityForPurpose(authority.root, authority.uid, authority.recovery != "")
		if err != nil || !reflect.DeepEqual(image, authority.image) || !reflect.DeepEqual(ancestors, authority.ancestors) {
			return errors.Join(ErrInventoryChanged, err)
		}
		last = now
	}
	authority.last = last
	authority.poisoned = false
	return nil
}

func (authority *sshAccessAuthority) Close() error {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.root == nil {
		return nil
	}
	err := authority.root.Close()
	authority.root = nil
	return err
}
