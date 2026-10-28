//go:build linux

package system

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
)

// This filesystem observation does not execute init scripts, cron or native
// package commands. It is one part of admission, not runtime or ownership proof.
// A stopped/disabled installed service is not equivalent to a fresh inactive
// installation. Even known inactive definitions require a separate recovery.
func observeNativeInactiveOpenRCWith(ctx context.Context, host nativeOpenRCObserver) (string, error) {
	if ctx == nil {
		return "", errors.New("inactive OpenRC observation requires a context")
	}
	first, err := captureNativeInactiveOpenRC(ctx, host)
	if err != nil {
		return "", err
	}
	second, err := captureNativeInactiveOpenRC(ctx, host)
	if err != nil {
		return "", err
	}
	if !sameNativeOpenRCProofs(first, second) {
		return "", errors.New("inactive OpenRC or scheduling state changed during observation")
	}
	return activationOpenRCProofDigest(second)
}

func captureNativeInactiveOpenRC(ctx context.Context, host nativeOpenRCObserver) (map[string]nativeOpenRCProof, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pair, proofs, err := captureNativeOpenRCServices(host, nil)
	if err != nil {
		return nil, err
	}
	for _, service := range pair {
		if service.load != "not-found" || service.active != "inactive" || service.enabled != "disabled" || service.runlevels != "" {
			return nil, errors.New("inactive native admission requires absent product services and runlevel entries")
		}
	}
	root, err := os.OpenRoot(host.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	reader := &nativeOpenRCRead{host: host, root: root, proofs: proofs}
	for _, name := range []string{"var/lib/syswarden", "var/log/syswarden", "run/syswarden-core.pid", "run/syswarden-firewall.lock", "run/syswarden-core.sock", "etc/wireguard/wg-syswarden.conf", "etc/ssh/sshd_config.d/00-syswarden-hardening.conf"} {
		if err := reader.absent(name); err != nil {
			return nil, errors.New("inactive native admission found retained product state")
		}
	}
	// Any additional product-root entry is preserved and refused, including
	// hidden journals, flat legacy policy and old persistent firewall files.
	entries, err := reader.entries("etc/syswarden")
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 || entries[0].Name() != "config" || !entries[0].IsDir() {
		return nil, errors.New("inactive native admission requires only the staged configuration directory")
	}
	directory, err := reader.directory("etc/syswarden/config")
	if err != nil {
		return nil, err
	}
	if err := directory.Close(); err != nil {
		return nil, err
	}
	// Record complete scheduling inventories, including unrelated administrator
	// entries, so a changed or newly added job invalidates the original review.
	remaining := nativeOpenRCInventoryLimit
	for _, name := range []string{"etc/cron.d", "etc/crontabs", "etc/periodic", "var/spool/cron"} {
		if err := captureInactiveScheduleTree(ctx, reader, name, 0, &remaining); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"etc/crontab", "etc/anacrontab"} {
		raw, err := reader.file(name, 1<<20)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if inactiveScheduleReference(name, raw) {
			return nil, errors.New("inactive native admission found a possible product schedule")
		}
	}
	return proofs, ctx.Err()
}

func inactiveScheduleReference(name string, raw []byte) bool {
	return strings.Contains(strings.ToLower(name), "syswarden") || strings.Contains(strings.ToLower(string(raw)), "syswarden")
}

func captureInactiveScheduleTree(ctx context.Context, r *nativeOpenRCRead, name string, depth int, remaining *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > 8 || *remaining <= 0 {
		return errors.New("inactive schedule inventory exceeds its bound")
	}
	*remaining--
	entries, err := r.entries(name)
	if errors.Is(err, fs.ErrNotExist) {
		// Record absence explicitly, including a missing parent, without creating it.
		return r.absent(name)
	}
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if *remaining <= 0 {
			return errors.New("inactive schedule inventory exceeds its bound")
		}
		*remaining--
		child := path.Join(name, entry.Name())
		names = append(names, entry.Name())
		if entry.IsDir() {
			if err := captureInactiveScheduleTree(ctx, r, child, depth+1, remaining); err != nil {
				return err
			}
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 && child == "var/spool/cron/crontabs" {
			// Alpine's packaged cron alias is read as a link, never followed.
			// Its only supported target is independently pinned and inventoried.
			if _, err := r.link(child, "../../../etc/crontabs"); err != nil {
				return err
			}
			target, err := r.directory("etc/crontabs")
			if err != nil {
				return err
			}
			if err := target.Close(); err != nil {
				return err
			}
			continue
		}
		raw, err := r.file(child, 1<<20)
		if err != nil {
			return err
		}
		if inactiveScheduleReference(child, raw) {
			return errors.New("inactive native admission found a possible product schedule")
		}
	}
	r.proofs[name+"/membership"] = nativeOpenRCProof{content: strings.Join(names, "\n")}
	return ctx.Err()
}
