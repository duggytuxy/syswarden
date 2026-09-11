//go:build linux

package security

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

type authLogWriter struct {
	name string
	uid  int
}

func authenticationLogWriterOn(host hardeningHost) (authLogWriter, error) {
	if err := host.verifyHardeningPolicyParent("/etc/rsyslog.conf"); err != nil {
		return authLogWriter{}, err
	}
	snapshot, err := host.snapshot("/etc/rsyslog.conf")
	if err != nil {
		return authLogWriter{}, err
	}
	if snapshot.existed && (!snapshot.identity.ownerKnown || snapshot.identity.uid != host.expectedRootUID || snapshot.mode&0022 != 0) {
		return authLogWriter{}, fmt.Errorf("rsyslog configuration has unsafe ownership or write permissions")
	}
	return resolveAuthenticationLogWriter(snapshot.content, user.Lookup)
}

// AuthenticationLogOwner identifies the supported writer without changing the host.
func AuthenticationLogOwner() (string, error) {
	writer, err := authenticationLogWriterOn(productionHardeningHost())
	if err != nil {
		return "", err
	}
	return writer.name, nil
}

func resolveAuthenticationLogWriter(content []byte, lookup func(string) (*user.User, error)) (authLogWriter, error) {
	writer := authLogWriter{name: "root", uid: 0}
	configured := ""
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], "$PrivDropToUser") {
			if len(fields) != 2 || configured != "" {
				return authLogWriter{}, fmt.Errorf("ambiguous rsyslog writer identity")
			}
			configured = fields[1]
		} else if strings.Contains(strings.ToLower(line), "privdrop.user") {
			return authLogWriter{}, fmt.Errorf("unsupported rsyslog writer declaration; preserve authentication log ownership")
		}
	}
	if configured == "" || configured == "root" {
		return writer, nil
	}
	if configured != "syslog" {
		return authLogWriter{}, fmt.Errorf("unsupported rsyslog writer %q; preserve authentication log ownership", configured)
	}
	account, err := lookup("syslog")
	if err != nil {
		return authLogWriter{}, fmt.Errorf("resolve configured rsyslog account: %w", err)
	}
	if account == nil || account.Username != "syslog" {
		return authLogWriter{}, fmt.Errorf("configured rsyslog account identity differs")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 || uint64(uid) >= 1<<32-1 || strconv.Itoa(uid) != account.Uid {
		return authLogWriter{}, fmt.Errorf("configured rsyslog account has invalid UID")
	}
	return authLogWriter{name: "syslog", uid: uid}, nil
}
