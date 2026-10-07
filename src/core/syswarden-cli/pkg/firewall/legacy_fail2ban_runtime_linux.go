//go:build linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
)

type legacyFail2banRuntimeJail struct {
	bans    []string
	actions map[string]map[string]legacyFail2banValue
}

type legacyFail2banRuntimeSnapshot struct {
	jails map[string]legacyFail2banRuntimeJail
}

type legacyFail2banRuntimeQuery func(context.Context, []string) (legacyFail2banValue, error)

// The query adapter must independently attest the live server's identity.
// This snapshot includes every jail, including administrator-owned actions
// and bans. It is private comparison evidence, never public diagnostic output.
// The protocol has no read-only idle-state getter; membership is not proof of
// quiescence. Neither this function nor the preservation check permits stopping a jail:
// exact command ownership and shared kernel dependencies remain mandatory.
func inspectLegacyFail2banRuntime(ctx context.Context, query legacyFail2banRuntimeQuery) (legacyFail2banRuntimeSnapshot, error) {
	var empty legacyFail2banRuntimeSnapshot
	if query == nil {
		return empty, fmt.Errorf("Fail2ban runtime inspection requires an attested query adapter")
	}
	remaining, bytes := 4096, 0
	read := func(args ...string) (legacyFail2banValue, error) {
		if err := ctx.Err(); err != nil {
			return legacyFail2banValue{}, err
		}
		remaining--
		if remaining < 0 {
			return legacyFail2banValue{}, fmt.Errorf("Fail2ban runtime inspection exceeds its query limit")
		}
		value, err := query(ctx, args)
		if err != nil {
			return legacyFail2banValue{}, err
		}
		var pending = []legacyFail2banValue{value}
		for len(pending) > 0 {
			last := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			bytes += len(last.text) + 1
			if bytes > 8<<20 {
				return legacyFail2banValue{}, fmt.Errorf("Fail2ban runtime inspection exceeds its total byte limit")
			}
			pending = append(pending, last.items...)
		}
		return value, nil
	}
	version, err := read("version")
	if err != nil {
		return empty, err
	}
	if version.kind != 's' || version.text != "1.1.0" {
		return empty, fmt.Errorf("unsupported Fail2ban runtime version")
	}
	status, err := read("status")
	if err != nil {
		return empty, err
	}
	names, err := legacyFail2banRuntimeJailNames(status)
	if err != nil {
		return empty, err
	}
	result := legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail, len(names))}
	for _, name := range names {
		jail := legacyFail2banRuntimeJail{actions: make(map[string]map[string]legacyFail2banValue)}
		// The ordinary banip reply contains Python IPAddr instances. The
		// documented time view returns primitive strings and binds expiration
		// as well as the address, without constructing any remote objects.
		bans, err := read("get", name, "banip", "--with-time")
		if err != nil {
			return empty, err
		}
		jail.bans, err = legacyFail2banRuntimeStrings(bans, 32768, func(s string) bool {
			addressText, timing, found := strings.Cut(s, "\t")
			if !found || len(s) > 256 || timing == "" || strings.ContainsAny(timing, "\n\r\t") {
				return false
			}
			addressText = strings.TrimSpace(addressText)
			if address, err := netip.ParseAddr(addressText); err == nil {
				return address.Zone() == ""
			}
			_, err := netip.ParsePrefix(addressText)
			return err == nil
		})
		if err != nil {
			return empty, err
		}
		actions, err := read("get", name, "actions")
		if err != nil {
			return empty, err
		}
		actionNames, err := legacyFail2banRuntimeStrings(actions, 32, validLegacyFail2banRuntimeName)
		if err != nil {
			return empty, err
		}
		for _, action := range actionNames {
			module, err := read("get", name, "action", action, "__module__")
			if err != nil {
				return empty, err
			}
			if module.kind != 's' || module.text != "fail2ban.server.action" {
				return empty, fmt.Errorf("unsupported Fail2ban runtime action implementation")
			}
			properties, err := read("get", name, "actionproperties", action)
			if err != nil {
				return empty, err
			}
			keys, err := legacyFail2banRuntimeStrings(properties, 128, validLegacyFail2banRuntimeName)
			if err != nil {
				return empty, err
			}
			values := make(map[string]legacyFail2banValue, len(keys))
			for _, key := range keys {
				value, err := read("get", name, "action", action, key)
				if err != nil {
					return empty, err
				}
				if value.kind == 'r' && value.text != key || (key == "ESCAPE_CRE" || key == "ESCAPE_VN_CRE") && (value.kind != 'r' || value.text != key) {
					return empty, fmt.Errorf("Fail2ban escape constant differs from the attested implementation")
				}
				values[key] = value
			}
			jail.actions[action] = values
		}
		result.jails[name] = jail
	}
	finalStatus, err := read("status")
	if err != nil {
		return empty, err
	}
	finalNames, err := legacyFail2banRuntimeJailNames(finalStatus)
	if err != nil || !reflect.DeepEqual(names, finalNames) {
		return empty, fmt.Errorf("Fail2ban jail membership changed during inspection")
	}
	return result, nil
}

func legacyFail2banRuntimeJailNames(value legacyFail2banValue) ([]string, error) {
	if value.kind != 'l' || len(value.items) != 2 {
		return nil, fmt.Errorf("invalid Fail2ban server status")
	}
	count, list := value.items[0], value.items[1]
	if count.kind != 't' || len(count.items) != 2 || count.items[0].kind != 's' || count.items[0].text != "Number of jail" || count.items[1].kind != 'i' ||
		list.kind != 't' || len(list.items) != 2 || list.items[0].kind != 's' || list.items[0].text != "Jail list" || list.items[1].kind != 's' {
		return nil, fmt.Errorf("unsupported Fail2ban server status fields")
	}
	if count.items[1].number < 0 || count.items[1].number > 128 {
		return nil, fmt.Errorf("Fail2ban jail count exceeds its bound")
	}
	var values []legacyFail2banValue
	if list.items[1].text != "" {
		for _, name := range strings.Split(list.items[1].text, ", ") {
			values = append(values, legacyFail2banValue{kind: 's', text: name})
		}
	}
	if int64(len(values)) != count.items[1].number {
		return nil, fmt.Errorf("Fail2ban jail count differs from its membership")
	}
	return legacyFail2banRuntimeStrings(legacyFail2banValue{kind: 'l', items: values}, 128, validLegacyFail2banJailName)
}

func legacyFail2banRuntimeStrings(value legacyFail2banValue, maximum int, valid func(string) bool) ([]string, error) {
	if value.kind != 'l' || len(value.items) > maximum {
		return nil, fmt.Errorf("invalid or oversized Fail2ban runtime list")
	}
	values := make([]string, 0, len(value.items))
	for _, item := range value.items {
		if item.kind != 's' || !valid(item.text) {
			return nil, fmt.Errorf("unsupported Fail2ban runtime list item")
		}
		values = append(values, item.text)
	}
	sort.Strings(values)
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return nil, fmt.Errorf("duplicate Fail2ban runtime list item")
		}
	}
	return values, nil
}

// Reject both lost and added administrator state. A concurrent legitimate
// update requires fresh inspection; it is never rolled back. A target name
// alone is not ownership evidence, and must originate in the bound file plan.
func verifyLegacyFail2banRuntimePreservation(before, after legacyFail2banRuntimeSnapshot, retired map[string]bool) error {
	for name, original := range before.jails {
		current, present := after.jails[name]
		if retired[name] {
			if present {
				return fmt.Errorf("retired Fail2ban jail remains active")
			}
			continue
		}
		if !present || !reflect.DeepEqual(original, current) {
			return fmt.Errorf("unrelated Fail2ban actions, bans or jail state changed during retirement")
		}
	}
	for name := range after.jails {
		if _, found := before.jails[name]; !found {
			return fmt.Errorf("Fail2ban jail appeared during retirement; inspect again")
		}
	}
	return nil
}
