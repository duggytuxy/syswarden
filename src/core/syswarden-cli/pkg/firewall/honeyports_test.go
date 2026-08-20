package firewall

import (
	"testing"
)

func TestCanonicalHoneyPorts_SW_FW_004(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "modular representation remains distinct", raw: "23 6379", want: "23, 6379"},
		{name: "legacy comma representation", raw: "23,6379", want: "23, 6379"},
		{name: "boundary ports", raw: "1 65535", want: "1, 65535"},
		{name: "concatenation regression", raw: "236379", wantErr: true},
		{name: "zero", raw: "0", wantErr: true},
		{name: "oversized", raw: "65536", wantErr: true},
		{name: "duplicate", raw: "23 23", wantErr: true},
		{name: "noncanonical duplicate", raw: "23 023", wantErr: true},
		{name: "leading zero", raw: "023", wantErr: true},
		{name: "empty item", raw: "23,,6379", wantErr: true},
		{name: "ambiguous empty list", raw: " , ", wantErr: true},
		{name: "shell syntax", raw: "23;6379", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := canonicalHoneyPorts(test.raw)
			if (err != nil) != test.wantErr {
				t.Fatalf("canonicalHoneyPorts(%q) error = %v, wantErr %t", test.raw, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("canonicalHoneyPorts(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}
