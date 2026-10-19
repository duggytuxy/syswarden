package sshpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

const validIntentJSON = `{"schema":1,"role":"target","owner":"syswarden","profile":"forwarding","contexts":[{"id":"administrator","route":"direct","user":"administrator","host":"controller.example","address":"192.0.2.10","local_address":"192.0.2.20","local_port":22}]}`

func TestIntentStrictSchema(t *testing.T) {
	mutations := map[string]string{
		"empty": "", "array": "[]", "null": "null", "trailing": validIntentJSON + "{}",
		"version":           strings.Replace(validIntentJSON, `"schema":1`, `"schema":2`, 1),
		"duplicate":         strings.Replace(validIntentJSON, `"schema":1`, `"schema":1,"schema":1`, 1),
		"escaped duplicate": strings.Replace(validIntentJSON, `"schema":1`, `"schema":1,"\u0073chema":1`, 1),
		"case alias":        strings.Replace(validIntentJSON, `"owner"`, `"Owner"`, 1),
		"nested duplicate":  strings.Replace(validIntentJSON, `"user":"administrator"`, `"user":"administrator","user":"other"`, 1),
		"null optional":     strings.Replace(validIntentJSON, `"schema":1`, `"schema":1,"legacy":null`, 1),
		"unknown":           strings.Replace(validIntentJSON, `"schema":1`, `"schema":1,"apply":true`, 1),
		"wrong level":       strings.Replace(validIntentJSON, `"schema":1`, `"schema":1,"user":"root"`, 1),
		"number type":       strings.Replace(validIntentJSON, `"schema":1`, `"schema":"1"`, 1),
		"null contexts":     strings.Replace(validIntentJSON, `"contexts":[`, `"contexts":null,"unused":[`, 1),
		"non UTF8":          validIntentJSON + string([]byte{0xff}),
		"oversized":         validIntentJSON + strings.Repeat(" ", MaxIntentBytes),
	}
	for name, raw := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := parseIntent([]byte(raw)); err == nil {
				t.Fatal("accepted invalid intent")
			}
		})
	}
	if _, err := parseIntent([]byte(validIntentJSON)); err != nil {
		t.Fatal(err)
	}
}

func TestIntentRolesAndContexts(t *testing.T) {
	tests := []struct {
		name   string
		change func(*intent)
		valid  bool
	}{
		{"target", func(*intent) {}, true},
		{"cis", func(v *intent) { v.Profile = "cis" }, true},
		{"external target", func(v *intent) { v.Owner = "external"; v.Profile = "observe" }, true},
		{"external jump", func(v *intent) {
			v.Owner = "external"
			v.Profile = "observe"
			v.Role = "jump-host"
			v.Contexts[0].Route = "bastion"
		}, true},
		{"target via jump", func(v *intent) { v.Contexts[0].Route = "proxyjump" }, true},
		{"ansible", func(v *intent) { v.Contexts[0].Route = "ansible" }, true},
		{"unknown role", func(v *intent) { v.Role = "" }, false},
		{"automatic role", func(v *intent) { v.Role = "auto" }, false},
		{"managed jump", func(v *intent) { v.Role = "jump-host" }, false},
		{"external profile", func(v *intent) { v.Owner = "external" }, false},
		{"missing owner", func(v *intent) { v.Owner = "" }, false},
		{"missing profile", func(v *intent) { v.Profile = "" }, false},
		{"missing contexts", func(v *intent) { v.Contexts = nil }, false},
		{"too many contexts", func(v *intent) { v.Contexts = make([]accessContext, MaxAccessContexts+1) }, false},
		{"duplicate IDs", func(v *intent) { v.Contexts = append(v.Contexts, v.Contexts[0]) }, false},
		{"uppercase ID", func(v *intent) { v.Contexts[0].ID = "Admin" }, false},
		{"target bastion context", func(v *intent) { v.Contexts[0].Route = "bastion" }, false},
		{"context injection", func(v *intent) { v.Contexts[0].User = "root,addr=192.0.2.1" }, false},
		{"host injection", func(v *intent) { v.Contexts[0].Host = "host\nInclude /tmp/a" }, false},
		{"wildcard host", func(v *intent) { v.Contexts[0].Host = "*.example" }, false},
		{"empty label", func(v *intent) { v.Contexts[0].Host = "host..example" }, false},
		{"IP host", func(v *intent) { v.Contexts[0].Host = "2001:db8::10" }, true},
		{"IPv6", func(v *intent) { v.Contexts[0].Address = "2001:db8::10"; v.Contexts[0].LocalAddress = "2001:db8::20" }, true},
		{"mapped IPv6", func(v *intent) { v.Contexts[0].Address = "::ffff:192.0.2.10" }, false},
		{"scope", func(v *intent) { v.Contexts[0].Address = "fe80::1%eth0" }, false},
		{"multicast", func(v *intent) { v.Contexts[0].Address = "224.0.0.1" }, false},
		{"unspecified", func(v *intent) { v.Contexts[0].LocalAddress = "::" }, false},
		{"prefix", func(v *intent) { v.Contexts[0].Address = "192.0.2.0/24" }, false},
		{"zero port", func(v *intent) { v.Contexts[0].LocalPort = 0 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := parseIntent([]byte(validIntentJSON))
			if err != nil {
				t.Fatal(err)
			}
			tt.change(&value)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseIntent(raw)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
			if tt.valid && strings.ContainsAny(got.Contexts[0].sshdArgument(), "\r\n\x00") {
				t.Fatal("unsafe parser argument")
			}
		})
	}
}

func FuzzIntent(f *testing.F) {
	f.Add([]byte(validIntentJSON))
	f.Add([]byte(`{"schema":1,"schema":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := parseIntent(raw)
		if err != nil {
			return
		}
		if err := value.validate(); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseIntent(encoded); err != nil {
			t.Fatal(err)
		}
	})
}
