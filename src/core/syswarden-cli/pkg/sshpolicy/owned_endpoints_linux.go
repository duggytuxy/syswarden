//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// OwnedEndpointSummary joins fresh publication and listener observations while
// retaining the original journal lock. It does not establish consumed policy,
// successful activation or independent access, and cannot authorize a mutation.
type OwnedEndpointSummary struct {
	Schema      int             `json:"schema"`
	Publication OwnedSummary    `json:"publication"`
	Endpoints   EndpointSummary `json:"endpoints"`
}

func observeSSHOwnedEndpoints(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver) (OwnedEndpointSummary, error) {
	if observe == nil {
		return OwnedEndpointSummary{}, ErrInventoryUnsafe
	}
	var endpoints EndpointSummary
	publication, err := withSSHOwnedObservation(ctx, journal, approved, parser, run, parserCheck,
		func(ctx context.Context, owned *sshOwnedPublication, guard func() error) error {
			// Collect only the active SSH graph for the parser. The owned guard
			// additionally binds intent, explicit TOML choice, recovery inodes,
			// exact journal membership and record identities throughout.
			inventory, err := collectInventory(owned.journal.root, owned.journal.uid)
			if err := errors.Join(err, guard()); err != nil {
				return err
			}
			endpoints, err = observeSSHEndpoints(ctx, inventory, parser, run, guard, observe)
			return err
		})
	if err != nil {
		return OwnedEndpointSummary{}, err
	}
	return OwnedEndpointSummary{Schema: 1, Publication: publication, Endpoints: endpoints}, nil
}

// ObserveOwnedSystemdEndpoints accepts only the independently approved plan
// and fixed protected paths. Its internal adapter performs no publication,
// activation, durability repair or network authentication.
func ObserveOwnedSystemdEndpoints(approved string) (summary OwnedEndpointSummary, err error) {
	defer func() {
		if err != nil {
			summary = OwnedEndpointSummary{}
		}
	}()
	if os.Geteuid() != 0 || !lowerDigest.MatchString(approved) {
		return summary, fmt.Errorf("owned SSH endpoint observation requires root and the original lowercase plan SHA-256")
	}
	root, err := os.Open("/")
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, daemon.file.Close()) }()
	journal, err := openSSHJournal(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	return observeSSHOwnedEndpoints(context.Background(), journal, approved, daemon.digest,
		daemon.run, func() error { return daemon.recheck(root, 0) }, observeSSHConfiguredListeners)
}
