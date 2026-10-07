//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"unicode/utf8"
)

// These values come from inert CommandAction instances populated by the
// installed configuration reader. They contain no executable objects. Each
// level uses arrays so duplicate names can be rejected before map insertion.
type legacyFail2banConfiguredActions map[string]map[string]map[string]legacyFail2banValue

func decodeLegacyFail2banConfiguredActions(content []byte) (legacyFail2banConfiguredActions, error) {
	invalid := func() (legacyFail2banConfiguredActions, error) {
		return nil, fmt.Errorf("configured Fail2ban action data is incomplete or unsupported")
	}
	if len(content) == 0 || len(content) > 8<<20 || !utf8.Valid(content) {
		return invalid()
	}
	array := func(data []byte, maximum int) ([]json.RawMessage, bool) {
		var items []json.RawMessage
		data = bytes.TrimSpace(data)
		if len(data) == 0 || data[0] != '[' || json.Unmarshal(data, &items) != nil || len(items) > maximum {
			return nil, false
		}
		return items, true
	}
	jails, ok := array(content, 128)
	if !ok {
		return invalid()
	}
	result := make(legacyFail2banConfiguredActions)
	for _, record := range jails {
		jail, ok := array(record, 2)
		if !ok || len(jail) != 2 {
			return invalid()
		}
		var name string
		if json.Unmarshal(jail[0], &name) != nil || !validLegacyFail2banJailName(name) {
			return invalid()
		}
		if _, duplicate := result[name]; duplicate {
			return invalid()
		}
		actions, ok := array(jail[1], 32)
		if !ok {
			return invalid()
		}
		result[name] = make(map[string]map[string]legacyFail2banValue)
		for _, record := range actions {
			action, ok := array(record, 2)
			if !ok || len(action) != 2 {
				return invalid()
			}
			var actionName string
			if json.Unmarshal(action[0], &actionName) != nil || !validLegacyFail2banRuntimeName(actionName) {
				return invalid()
			}
			if _, duplicate := result[name][actionName]; duplicate {
				return invalid()
			}
			properties, ok := array(action[1], 128)
			if !ok {
				return invalid()
			}
			values := make(map[string]legacyFail2banValue)
			for _, record := range properties {
				property, ok := array(record, 2)
				if !ok || len(property) != 2 {
					return invalid()
				}
				var key string
				if json.Unmarshal(property[0], &key) != nil || !validLegacyFail2banRuntimeName(key) {
					return invalid()
				}
				if _, duplicate := values[key]; duplicate {
					return invalid()
				}
				primitive, ok := array(property[1], 2)
				if !ok || len(primitive) != 2 {
					return invalid()
				}
				var kind string
				if json.Unmarshal(primitive[0], &kind) != nil || len(kind) != 1 {
					return invalid()
				}
				value := legacyFail2banValue{kind: kind[0]}
				switch value.kind {
				case 's', 'r':
					if json.Unmarshal(primitive[1], &value.text) != nil || len(value.text) > maximumLegacyFail2banReply || bytes.Equal(primitive[1], []byte("null")) {
						return invalid()
					}
					if value.kind == 'r' && (value.text != key || key != "ESCAPE_CRE" && key != "ESCAPE_VN_CRE") {
						return invalid()
					}
				case 'i':
					if json.Unmarshal(primitive[1], &value.number) != nil || bytes.Equal(primitive[1], []byte("null")) {
						return invalid()
					}
				case 'b':
					if bytes.Equal(primitive[1], []byte("true")) {
						value.kind = 0x88
					} else if bytes.Equal(primitive[1], []byte("false")) {
						value.kind = 0x89
					} else {
						return invalid()
					}
				case 'n':
					if !bytes.Equal(primitive[1], []byte("null")) {
						return invalid()
					}
					value.kind = 'N'
				default:
					return invalid()
				}
				if (key == "ESCAPE_CRE" || key == "ESCAPE_VN_CRE") && value.kind != 'r' {
					return invalid()
				}
				values[key] = value
			}
			result[name][actionName] = values
		}
	}
	return result, nil
}

// Read-only equivalence does not authorize stopping jails or executing hooks.
// The one mutable class counter is not configuration: permit its observed
// nonnegative value while preserving it in the separate runtime snapshot.
func verifyLegacyFail2banConfiguredRuntime(expected legacyFail2banConfiguredActions, live legacyFail2banRuntimeSnapshot) error {
	if len(expected) != len(live.jails) {
		return fmt.Errorf("Fail2ban live jail membership differs from the inspected configuration")
	}
	for jail, actions := range expected {
		actual, present := live.jails[jail]
		if !present || len(actions) != len(actual.actions) {
			return fmt.Errorf("Fail2ban live action membership differs from the inspected configuration")
		}
		for name, properties := range actions {
			current, present := actual.actions[name]
			if !present || len(properties) != len(current) {
				return fmt.Errorf("Fail2ban live action properties differ from the inspected configuration")
			}
			for key, value := range properties {
				observed, present := current[key]
				if key == "banEpoch" && present && value.kind == 'i' && value.number == 0 && observed.kind == 'i' && observed.number >= 0 {
					continue
				}
				if !present || !reflect.DeepEqual(value, observed) {
					return fmt.Errorf("Fail2ban live action data differs from the inspected configuration; preserve it for reviewed recovery")
				}
			}
		}
	}
	return nil
}
