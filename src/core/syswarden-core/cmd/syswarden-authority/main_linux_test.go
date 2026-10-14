package main

import (
	"strings"
	"testing"
)

func TestLaunchDigestRequiresExactExplicitInput(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := [][]string{nil, {"--help"}, {"--launch-sha256"}, {"--launch-sha256=" + digest}, {"--launch-sha256", strings.ToUpper(digest)}, {"--launch-sha256", strings.Repeat("g", 64)}, {"--launch-sha256", digest + " "}, {"--launch-sha256", digest[:63]}, {"--launch-sha256", digest, "extra"}, {"--config", digest}, {"--launch-sha256", digest, "--now", "1800000000"}}
	for _, args := range cases {
		if got, ok := launchDigest(args); ok || got != "" {
			t.Fatal("unexpected startup input admitted", args)
		}
	}
	if got, ok := launchDigest([]string{"--launch-sha256", digest}); !ok || got != digest {
		t.Fatal("explicit trusted digest rejected")
	}
}
