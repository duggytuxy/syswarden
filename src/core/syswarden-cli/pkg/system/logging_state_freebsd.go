//go:build freebsd

package system

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const freeBSDLoggingStateName = "logging-service-state.json"

type freeBSDLoggingState struct {
	SchemaVersion   int            `json:"schema_version"`
	SyslogdEnable   freeBSDRCValue `json:"syslogd_enable"`
	RsyslogdEnable  freeBSDRCValue `json:"rsyslogd_enable"`
	RsyslogdPIDFile freeBSDRCValue `json:"rsyslogd_pidfile"`
	SyslogdActive   bool           `json:"syslogd_active"`
	RsyslogdActive  bool           `json:"rsyslogd_active"`
}

func validFreeBSDLoggingState(state freeBSDLoggingState) bool {
	return state.SchemaVersion == 1 &&
		validFreeBSDRCValue(state.SyslogdEnable.Value) &&
		validFreeBSDRCValue(state.RsyslogdEnable.Value) &&
		validFreeBSDRCValue(state.RsyslogdPIDFile.Value) &&
		!(state.SyslogdActive && state.RsyslogdActive)
}

func readFreeBSDLoggingState() (freeBSDLoggingState, bool, error) {
	var state freeBSDLoggingState
	found, err := readFreeBSDOwnedState(freeBSDLoggingStateName, 16<<10, &state)
	if err != nil || !found {
		return state, found, err
	}
	if !validFreeBSDLoggingState(state) {
		return state, false, fmt.Errorf("invalid FreeBSD logging ownership state")
	}
	return state, true, nil
}

func currentFreeBSDLoggingState() (freeBSDLoggingState, error) {
	values, err := freeBSDRCValues()
	if err != nil {
		return freeBSDLoggingState{}, err
	}
	syslogdActive, err := freeBSDServiceActive("syslogd")
	if err != nil {
		return freeBSDLoggingState{}, err
	}
	rsyslogdActive, err := freeBSDServiceActive("rsyslogd")
	if err != nil {
		return freeBSDLoggingState{}, err
	}
	state := freeBSDLoggingState{
		SchemaVersion:   1,
		SyslogdEnable:   capturedFreeBSDRCValue(values, "syslogd_enable"),
		RsyslogdEnable:  capturedFreeBSDRCValue(values, "rsyslogd_enable"),
		RsyslogdPIDFile: capturedFreeBSDRCValue(values, "rsyslogd_pidfile"),
		SyslogdActive:   syslogdActive,
		RsyslogdActive:  rsyslogdActive,
	}
	if !validFreeBSDLoggingState(state) {
		return freeBSDLoggingState{}, fmt.Errorf("refusing ambiguous dual syslogd and rsyslogd state")
	}
	return state, nil
}

func captureFreeBSDLoggingState() (freeBSDLoggingState, error) {
	if state, found, err := readFreeBSDLoggingState(); err != nil || found {
		return state, err
	}
	state, err := currentFreeBSDLoggingState()
	if err != nil {
		return freeBSDLoggingState{}, err
	}
	if err := writeFreeBSDOwnedState(freeBSDLoggingStateName, state); err != nil {
		return freeBSDLoggingState{}, err
	}
	return state, nil
}

func stopFreeBSDLoggingService(name string) error {
	active, err := freeBSDServiceActive(name)
	if err != nil || !active {
		return err
	}
	var command *exec.Cmd
	switch name {
	case "syslogd":
		command = exec.Command("service", "syslogd", "onestop")
	case "rsyslogd":
		command = exec.Command("service", "rsyslogd", "onestop")
	default:
		return fmt.Errorf("unsupported logging service %q", name)
	}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("stop %s: %s: %w", name, strings.TrimSpace(string(output)), err)
	}
	active, err = freeBSDServiceActive(name)
	if err != nil {
		return fmt.Errorf("verify %s stopped: %w", name, err)
	}
	if active {
		return fmt.Errorf("verify %s stopped: service remains active", name)
	}
	return nil
}

func startFreeBSDLoggingService(name string) error {
	var command *exec.Cmd
	switch name {
	case "syslogd":
		command = exec.Command("service", "syslogd", "onestart")
	case "rsyslogd":
		command = exec.Command("service", "rsyslogd", "onestart")
	default:
		return fmt.Errorf("unsupported logging service %q", name)
	}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("start %s: %s: %w", name, strings.TrimSpace(string(output)), err)
	}
	active, err := freeBSDServiceActive(name)
	if err != nil {
		return fmt.Errorf("verify %s running: %w", name, err)
	}
	if !active {
		return fmt.Errorf("verify %s running: service remains inactive", name)
	}
	return nil
}

func applyFreeBSDLoggingState(state freeBSDLoggingState) error {
	if !validFreeBSDLoggingState(state) {
		return fmt.Errorf("refusing invalid FreeBSD logging target state")
	}
	if err := stopFreeBSDLoggingService("rsyslogd"); err != nil {
		return err
	}
	if err := stopFreeBSDLoggingService("syslogd"); err != nil {
		return err
	}
	for _, variable := range []struct {
		name  string
		value freeBSDRCValue
	}{
		{name: "syslogd_enable", value: state.SyslogdEnable},
		{name: "rsyslogd_enable", value: state.RsyslogdEnable},
		{name: "rsyslogd_pidfile", value: state.RsyslogdPIDFile},
	} {
		if err := setFreeBSDRCValue(variable.name, variable.value); err != nil {
			return err
		}
	}
	if state.RsyslogdActive {
		if err := startFreeBSDLoggingService("rsyslogd"); err != nil {
			return err
		}
	} else if state.SyslogdActive {
		if err := startFreeBSDLoggingService("syslogd"); err != nil {
			return err
		}
	}
	syslogdActive, err := freeBSDServiceActive("syslogd")
	if err != nil {
		return err
	}
	rsyslogdActive, err := freeBSDServiceActive("rsyslogd")
	if err != nil {
		return err
	}
	if syslogdActive != state.SyslogdActive || rsyslogdActive != state.RsyslogdActive {
		return fmt.Errorf("FreeBSD logging service state did not converge")
	}
	return nil
}

func applyFreeBSDLoggingStateWithRollback(target, rollback freeBSDLoggingState) error {
	if err := applyFreeBSDLoggingState(target); err != nil {
		if rollbackErr := applyFreeBSDLoggingState(rollback); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback FreeBSD logging state: %w", rollbackErr))
		}
		return err
	}
	return nil
}

// EnsureFreeBSDRsyslogRunning safely replaces the base logger while retaining
// enough exact state for supported uninstall recovery.
func EnsureFreeBSDRsyslogRunning() error {
	if output, err := exec.Command("/usr/local/sbin/rsyslogd", "-N1").CombinedOutput(); err != nil {
		return fmt.Errorf("validate rsyslog configuration: %s: %w", strings.TrimSpace(string(output)), err)
	}
	if _, err := captureFreeBSDLoggingState(); err != nil {
		return fmt.Errorf("capture logging baseline: %w", err)
	}
	current, err := currentFreeBSDLoggingState()
	if err != nil {
		return err
	}
	target := current
	target.SyslogdEnable = freeBSDRCValue{Present: true, Value: "NO"}
	target.RsyslogdEnable = freeBSDRCValue{Present: true, Value: "YES"}
	target.RsyslogdPIDFile = freeBSDRCValue{Present: true, Value: "/var/run/syslog.pid"}
	target.SyslogdActive = false
	target.RsyslogdActive = true
	if err := applyFreeBSDLoggingStateWithRollback(target, current); err != nil {
		return fmt.Errorf("transition FreeBSD logging service ownership: %w", err)
	}
	return nil
}

// RestoreFreeBSDLogging restores the exact pre-SysWarden rc variables and
// active daemon choice after generated fragments have been removed.
func RestoreFreeBSDLogging() error {
	target, found, err := readFreeBSDLoggingState()
	if err != nil {
		return err
	}
	if !found {
		if active, statusErr := freeBSDServiceActive("rsyslogd"); statusErr != nil {
			return statusErr
		} else if active {
			if output, restartErr := exec.Command("service", "rsyslogd", "restart").CombinedOutput(); restartErr != nil {
				return fmt.Errorf("restart legacy rsyslogd after fragment removal: %s: %w", strings.TrimSpace(string(output)), restartErr)
			}
		}
		return nil
	}
	current, err := currentFreeBSDLoggingState()
	if err != nil {
		return err
	}
	if err := applyFreeBSDLoggingStateWithRollback(target, current); err != nil {
		return fmt.Errorf("restore pre-SysWarden logging state: %w", err)
	}
	return removeFreeBSDOwnedState(freeBSDLoggingStateName)
}
