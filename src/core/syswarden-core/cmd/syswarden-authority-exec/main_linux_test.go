package main

import (
	"strings"
	"testing"
)

func TestExecDigestsRequireExactInput(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	good := []string{"--launch-sha256", digest, "--image-sha256", digest}
	a, b, ok := execDigests(good)
	if !ok || a != digest || b != digest {
		t.Fatal("valid explicit digests rejected")
	}
	cases := [][]string{nil, {"--help"}, good[:2], append(append([]string{}, good...), "extra"), {"--image-sha256", digest, "--launch-sha256", digest}, {"--config", digest, "--image-sha256", digest}}
	for _, bad := range []string{"", digest[:63], digest + " ", strings.ToUpper(digest), strings.Repeat("g", 64)} {
		for _, i := range []int{1, 3} {
			args := append([]string{}, good...)
			args[i] = bad
			cases = append(cases, args)
		}
	}
	for _, args := range cases {
		a, b, ok := execDigests(args)
		if ok || a != "" || b != "" {
			t.Fatal("unexpected input admitted", args)
		}
	}
}
