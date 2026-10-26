//go:build linux

package system

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// Accept only inert settings needed by the supported distribution setup.
// Unknown shell or execution overrides require review; none is sourced here.
func nativeOpenRCConfigLiteral(content []byte) error {
	if strings.ContainsAny(string(content), "\x00\r") {
		return errors.New("invalid OpenRC configuration text")
	}
	seen := make(map[string]bool)
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.Trim(raw, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return errors.New("nonliteral or repeated OpenRC setting")
		}
		seen[key] = true
		if len(value) >= 2 && (value[0] == '"' || value[0] == 39) && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		valid := false
		switch key {
		case "rc_sys":
			valid = value == "" || value == "podman" || value == "docker" || value == "lxc"
		case "rc_env_allow":
			valid = value == ""
		case "rc_cgroup_mode":
			valid = value == "legacy" || value == "hybrid" || value == "unified"
		case "rc_parallel", "rc_interactive", "rc_logger", "rc_verbose", "rc_nocolor":
			valid = value == "yes" || value == "no" || value == "YES" || value == "NO"
		case "rc_tty_number":
			n, err := strconv.ParseUint(value, 10, 32)
			valid = err == nil && strconv.FormatUint(n, 10) == value
		}
		if !valid {
			return errors.New("OpenRC configuration requires administrator review")
		}
	}
	return nil
}

func (r *nativeOpenRCRead) configuration() error {
	content, err := r.file("etc/rc.conf", 64<<10)
	if err != nil {
		return err
	}
	if err := nativeOpenRCConfigLiteral(content); err != nil {
		return err
	}
	entries, err := r.entries("etc/rc.conf.d")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			return errors.New("ambiguous OpenRC global configuration entry")
		}
		if !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		content, err := r.file("etc/rc.conf.d/"+entry.Name(), 64<<10)
		if err != nil {
			return err
		}
		if err := nativeOpenRCConfigLiteral(content); err != nil {
			return err
		}
	}
	entries, err = r.entries("etc/conf.d")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "rc" || name == "syswarden-core" || name == "syswarden-firewall" || strings.HasPrefix(name, "syswarden-core.") || strings.HasPrefix(name, "syswarden-firewall.") {
			return errors.New("OpenRC service overrides require administrator review")
		}
	}
	for _, file := range []string{"etc/profile.env", "sbin/livecd-functions.sh", "var/cache/rc/openrc-run.sh", "usr/local/etc/init.d/syswarden-core", "usr/local/etc/init.d/syswarden-firewall"} {
		if err := r.absent(file); err != nil {
			return err
		}
	}
	for _, directory := range []string{"usr/lib/rc/plugins", "usr/libexec/rc/plugins"} {
		entries, err := r.entries(directory)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if len(entries) != 0 {
			return errors.New("OpenRC plugins require separate administrator review")
		}
	}
	return nil
}

func nativeOpenRCEnvironment() error {
	// Alternate service roots or user mode must not alter a later conditional
	// restart after observing the fixed system-service layout.
	for _, key := range []string{"RC_USER_SERVICES", "RC_SVCDIR", "RC_LIBEXECDIR", "RC_RUNLEVEL", "RC_SERVICE", "RC_SVCNAME", "RC_PREFIX"} {
		if value, exists := os.LookupEnv(key); exists && value != "" {
			return errors.New("inherited OpenRC execution context requires administrator review")
		}
	}
	return nil
}

// These are the saved stop parameters for the supported background command.
// They are read as data. A contradictory retained option must not redirect a
// subsequent conditional restart to a different process or PID file.
func (r *nativeOpenRCRead) coreBookkeeping() error {
	for key, expected := range map[string]string{"command": nativeOpenRCCorePath, "pidfile": "/run/syswarden-core.pid", "chroot": "", "procname": ""} {
		content, err := r.file("run/openrc/options/syswarden-core/"+key, 256)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || string(content) != expected {
			return errors.New("OpenRC core saved stop parameters require review")
		}
	}
	entries, err := r.entries("run/openrc/daemons/syswarden-core")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if len(entries) != 1 || entries[0].Name() != "001" {
		return errors.New("OpenRC core daemon records require review")
	}
	content, err := r.file("run/openrc/daemons/syswarden-core/001", 1024)
	expected := "exec=" + nativeOpenRCCorePath + "\nargv_0=" + nativeOpenRCCorePath + "\npidfile=/run/syswarden-core.pid\n"
	if err != nil || string(content) != expected {
		return errors.New("OpenRC core daemon record contradicts its fixed process contract")
	}
	return nil
}
