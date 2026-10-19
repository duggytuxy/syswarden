package sshpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	IntentPath        = "/etc/syswarden/ssh-policy.json"
	MaxIntentBytes    = 32 << 10
	MaxAccessContexts = 16
	MaxLegacyEdits    = 128
)

// Intent is deliberately private: a decoded value is not protected storage,
// ownership evidence, approval of a plan, or a successful access test.
type intent struct {
	Schema   int             `json:"schema"`
	Role     string          `json:"role"`
	Owner    string          `json:"owner"`
	Profile  string          `json:"profile"`
	Contexts []accessContext `json:"contexts"`
	Legacy   *legacyIntent   `json:"legacy,omitempty"`
}

type accessContext struct {
	ID           string `json:"id"`
	Route        string `json:"route"`
	User         string `json:"user"`
	Host         string `json:"host"`
	Address      string `json:"address"`
	LocalAddress string `json:"local_address"`
	LocalPort    uint16 `json:"local_port"`
}

type legacyIntent struct {
	Attribution string       `json:"attribution"`
	MainSHA256  string       `json:"main_sha256"`
	Edits       []legacyEdit `json:"edits"`
}

type legacyEdit struct {
	Line   int    `json:"line"`
	Action string `json:"action"`
}

var (
	contextID   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	sshUser     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	dnsLabel    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	lowerDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func parseIntent(content []byte) (intent, error) {
	var result intent
	if len(content) == 0 || len(content) > MaxIntentBytes || !utf8.Valid(content) {
		return result, fmt.Errorf("SSH intent is empty, oversized or invalid UTF-8")
	}
	// encoding/json otherwise accepts duplicate keys and case-insensitive field
	// names. Reject both before decoding the exact typed schema.
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := inspectIntentJSON(decoder, 0); err != nil {
		return result, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return result, fmt.Errorf("SSH intent must contain exactly one JSON object")
	}
	decoder = json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return intent{}, fmt.Errorf("SSH intent does not match schema 1")
	}
	if err := result.validate(); err != nil {
		return intent{}, err
	}
	return result, nil
}

func inspectIntentJSON(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return fmt.Errorf("SSH intent JSON exceeds depth bound")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return fmt.Errorf("SSH intent contains invalid JSON or null")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		if depth == 0 {
			return fmt.Errorf("SSH intent must be an object")
		}
		return nil
	}
	if depth == 0 && delimiter != '{' {
		return fmt.Errorf("SSH intent must be an object")
	}
	if delimiter != '{' && delimiter != '[' {
		return fmt.Errorf("SSH intent has unexpected delimiter")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] || !intentKey(name) {
				return fmt.Errorf("SSH intent contains duplicate or unsupported keys")
			}
			seen[name] = true
		}
		if err := inspectIntentJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func intentKey(key string) bool {
	switch key {
	case "schema", "role", "owner", "profile", "contexts", "legacy", "id", "route", "user", "host",
		"address", "local_address", "local_port", "attribution", "main_sha256", "edits", "line", "action":
		return true
	default:
		return false
	}
}

func (value intent) validate() error {
	if value.Schema != 1 || (value.Role != "target" && value.Role != "jump-host") {
		return fmt.Errorf("SSH intent requires schema 1 and an explicit target or jump-host role")
	}
	switch value.Owner {
	case "syswarden":
		if value.Role != "target" || (value.Profile != "forwarding" && value.Profile != "cis") {
			return fmt.Errorf("fixed SysWarden SSH profiles require a target role; bastion publication is not supported")
		}
	case "external":
		if value.Profile != "observe" || value.Legacy != nil {
			return fmt.Errorf("external SSH ownership requires observe mode without migration edits")
		}
	default:
		return fmt.Errorf("SSH intent requires explicit syswarden or external policy ownership")
	}
	if len(value.Contexts) == 0 || len(value.Contexts) > MaxAccessContexts {
		return fmt.Errorf("SSH intent requires 1 to %d access contexts", MaxAccessContexts)
	}
	seen := make(map[string]bool)
	for _, context := range value.Contexts {
		if !contextID.MatchString(context.ID) || seen[context.ID] || !sshUser.MatchString(context.User) ||
			!contextHost(context.Host) || !contextAddress(context.Address) || !contextAddress(context.LocalAddress) || context.LocalPort == 0 {
			return fmt.Errorf("SSH intent contains an invalid or duplicate access context")
		}
		seen[context.ID] = true
		switch context.Route {
		case "direct", "proxyjump", "ansible":
		case "bastion":
			if value.Role != "jump-host" {
				return fmt.Errorf("bastion access context requires an explicit jump-host role")
			}
		default:
			return fmt.Errorf("SSH access route is unsupported")
		}
	}
	if value.Legacy == nil {
		return nil
	}
	legacy := value.Legacy
	if legacy.Attribution != "operator-reviewed" || !lowerDigest.MatchString(legacy.MainSHA256) ||
		len(legacy.Edits) == 0 || len(legacy.Edits) > MaxLegacyEdits {
		return fmt.Errorf("legacy SSH edits require bounded operator-reviewed attribution and an exact main-file SHA-256")
	}
	previous := 0
	for _, edit := range legacy.Edits {
		if edit.Line <= previous || edit.Line > MaxBytes || (edit.Action != "remove" && edit.Action != "restore") {
			return fmt.Errorf("legacy SSH edits must have strictly increasing source line numbers and supported actions")
		}
		previous = edit.Line
	}
	return nil
}

func contextAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == "" && !address.Is4In6() && address.String() == value &&
		!address.IsUnspecified() && !address.IsMulticast()
}

func contextHost(value string) bool {
	if contextAddress(value) {
		return true
	}
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !dnsLabel.MatchString(part) {
			return false
		}
	}
	return true
}

func (value accessContext) sshdArgument() string {
	return fmt.Sprintf("user=%s,host=%s,addr=%s,laddr=%s,lport=%d", value.User, value.Host, value.Address, value.LocalAddress, value.LocalPort)
}
