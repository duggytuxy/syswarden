//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
)

// A private owner keeps the same protected helpers and root alive until the
// process lease has closed. Fixed endpoint identities are rechecked on use;
// no caller-provided summary or environment hint selects a runtime target.
type sshProcessResources struct {
	root                  *os.File
	uid                   int
	tool                  *sshSystemctl
	daemon                *pinnedSSHD
	bus                   *sshBusctl
	endpoint, busEndpoint inventorySnapshot
	startupRequired       bool
}

func openSSHProcessResources(ctx context.Context, startup bool) (*sshProcessResources, error) {
	if ctx == nil || os.Geteuid() != 0 {
		return nil, ErrInventoryUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	return ownSSHProcessResources(ctx, root, 0, startup)
}

// Ownership of root transfers even on failure. Only the fixed production
// opener above supplies the live root; isolated fixtures supply private roots.
func ownSSHProcessResources(ctx context.Context, root *os.File, uid int, startup bool) (_ *sshProcessResources, err error) {
	r := &sshProcessResources{root: root, uid: uid, startupRequired: startup}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.Close())
		}
	}()
	if ctx == nil || root == nil || uid < 0 {
		return nil, ErrInventoryUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.tool, err = openSSHSystemctl(root, uid)
	if err != nil {
		return nil, err
	}
	r.daemon, err = openSSHD(root, uid)
	if err != nil {
		return nil, err
	}
	r.endpoint, err = readSSHSystemdEndpoint(root, uid)
	if err != nil {
		return nil, err
	}
	if startup {
		r.bus, err = openSSHBusctl(root, uid)
		if err != nil {
			return nil, err
		}
		r.busEndpoint, err = readSSHSystemBusEndpoint(root, uid)
		if err != nil {
			return nil, err
		}
	}
	if err := errors.Join(ctx.Err(), r.recheck()); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *sshProcessResources) Close() error {
	if r == nil {
		return nil
	}
	var err error
	for _, file := range []*os.File{r.busFile(), r.daemonFile(), r.toolFile(), r.root} {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	r.bus, r.daemon, r.tool, r.root = nil, nil, nil, nil
	return err
}

func (r *sshProcessResources) busFile() *os.File {
	if r.bus == nil {
		return nil
	}
	return r.bus.file
}

func (r *sshProcessResources) daemonFile() *os.File {
	if r.daemon == nil {
		return nil
	}
	return r.daemon.file
}

func (r *sshProcessResources) toolFile() *os.File {
	if r.tool == nil {
		return nil
	}
	return r.tool.file
}

func (r *sshProcessResources) recheck() error {
	if r == nil || r.root == nil || r.toolFile() == nil || r.daemonFile() == nil || (r.startupRequired && r.busFile() == nil) {
		return ErrInventoryClosed
	}
	files := []struct {
		file  *os.File
		state inventoryStamp
	}{{r.tool.file, r.tool.state}, {r.daemon.file, r.daemon.state}}
	if r.bus != nil {
		files = append(files, struct {
			file  *os.File
			state inventoryStamp
		}{r.bus.file, r.bus.state})
	}
	for _, held := range files {
		var state unix.Stat_t
		if err := unix.Fstat(int(held.file.Fd()), &state); err != nil || stamp(state) != held.state {
			return errors.Join(ErrInventoryChanged, err)
		}
	}
	if r.bus != nil {
		current, err := readSSHSystemBusEndpoint(r.root, r.uid)
		if err != nil || !reflect.DeepEqual(r.busEndpoint, current) {
			return errors.Join(ErrInventoryChanged, err)
		}
		if err := r.bus.recheck(r.root, r.uid); err != nil {
			return err
		}
	}
	current, err := readSSHSystemdEndpoint(r.root, r.uid)
	if err != nil || !reflect.DeepEqual(r.endpoint, current) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return errors.Join(r.tool.recheck(r.root, r.uid), r.daemon.recheck(r.root, r.uid))
}

func (r *sshProcessResources) startup(ctx context.Context, snapshot sshSystemdSnapshot, guard func() error) (StartupSummary, error) {
	if r == nil || !r.startupRequired || r.bus == nil || r.daemon == nil {
		return StartupSummary{}, ErrInventoryClosed
	}
	capture := func(ctx context.Context, unit string) (sshEnvironmentResult, error) {
		return captureSSHStartupEnvironment(ctx, unit, r.root, r.uid, r.bus.run, guard)
	}
	return observeSSHStartupEnvironment(ctx, snapshot, r.daemon.parent+"/sshd", r.bus.run, guard, capture)
}
