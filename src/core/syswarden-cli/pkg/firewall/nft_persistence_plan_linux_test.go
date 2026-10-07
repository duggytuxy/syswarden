//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestNFTPersistenceIncludePlanPreservesAdministratorBytes(t *testing.T) {
	generated := legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n"
	before := "#!/usr/sbin/nft -f\n# Administrator policy\nflush ruleset\n" +
		"table inet administrator { chain ingress { type filter hook input priority 0; policy drop; tcp dport 22022 accept; } }\n\n"
	after := "# Separate application\ninclude \"/etc/nftables.d/application.nft\"\n"
	for _, test := range []struct{ name, input, want string }{
		{"appended", before + generated, before},
		{"middle", before + generated + after, before + after},
		{"duplicates", before + generated + after + generated, before + after},
		{"no_final_newline", before + strings.TrimSuffix(generated, "\n"), before},
		{"absent", before + after, before + after},
		{"comment_only", before + "# " + legacyNFTIncludeLine + "\n", before + "# " + legacyNFTIncludeLine + "\n"},
		{"path_in_comment", before + "# example " + legacyNFTIncludePath + "\n", before + "# example " + legacyNFTIncludePath + "\n"},
		{"other_product_path", "include \"/etc/syswarden/custom.nft\"\n", "include \"/etc/syswarden/custom.nft\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := []byte(test.input)
			plan, err := planLegacyNFTIncludeRetirement(input)
			if err != nil {
				t.Fatal(err)
			}
			if string(plan.content) != test.want || string(input) != test.input {
				t.Fatal("planner changed unrelated content or its input")
			}
			if plan.originalSHA256 != sha256.Sum256(input) {
				t.Fatal("plan does not bind the original bytes")
			}
			again, err := planLegacyNFTIncludeRetirement(plan.content)
			if err != nil || !bytes.Equal(again.content, plan.content) || len(again.removed) != 0 {
				t.Fatalf("plan is not idempotent: %v", err)
			}
			if len(plan.content) > 0 {
				plan.content[0] ^= 1
				if string(input) != test.input {
					t.Fatal("plan output aliases its input")
				}
			}
		})
	}
}

func TestNFTPersistenceGeneratedDefaultDoesNotLeaveGlobalFlush(t *testing.T) {
	input := "#!/usr/sbin/nft -f\nflush ruleset\n" + legacyNFTIncludeLine + "\n"
	plan, err := planLegacyNFTIncludeRetirement([]byte(input))
	if err != nil || string(plan.content) != "#!/usr/sbin/nft -f\n" {
		t.Fatalf("exact generated default was not retired safely: %v", err)
	}
	// A customized file no longer proves that SysWarden owns the global flush.
	for _, suffix := range []string{"# custom\n", "table inet custom {}\n"} {
		if _, err := planLegacyNFTIncludeRetirement([]byte(input + suffix)); err == nil {
			t.Fatal("planner accepted a customized unmarked default file")
		}
	}
}

func TestNFTPersistenceRefusesAmbiguousIncludeEdits(t *testing.T) {
	marker := legacyNFTIncludeMarker + "\n"
	for name, input := range map[string]string{
		"unmarked":         legacyNFTIncludeLine + "\n",
		"indented":         marker + " " + legacyNFTIncludeLine + "\n",
		"trailing_comment": marker + legacyNFTIncludeLine + " # custom\n",
		"trailing_command": marker + legacyNFTIncludeLine + "; flush ruleset\n",
		"nested":           "table inet custom {\n" + marker + legacyNFTIncludeLine + "\n}\n",
		"crlf":             strings.ReplaceAll(marker+legacyNFTIncludeLine+"\n", "\n", "\r\n"),
		"marker_suffix":    "# custom " + marker + legacyNFTIncludeLine + "\n",
		"marker_separated": marker + "\n" + legacyNFTIncludeLine + "\n",
		"continued":        marker + "include \\\n\"" + legacyNFTIncludePath + "\"\n",
		"multiple_mixed":   marker + legacyNFTIncludeLine + "\n" + legacyNFTIncludeLine + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := planLegacyNFTIncludeRetirement([]byte(input))
			if err == nil || len(plan.content) != 0 || len(plan.removed) != 0 {
				t.Fatal("ambiguous input produced an edit plan")
			}
		})
	}
}

func TestNFTPersistenceInspectionDistinguishesSourceFromCommentsAndStrings(t *testing.T) {
	input := `# table inet syswarden_table { include "/etc/ignored.nft" }
table inet custom {
 chain ingress {
  type filter hook input priority 0; policy accept;
  comment "include \"/etc/quoted.nft\" { } # table inet decoy"
  include "/etc/nftables.d/rules.nft"
 }
}
table inet syswarden_table { set addresses { type ipv4_addr; elements = { 192.0.2.1, 192.0.2.2 }; } }
include "/etc/nftables.d/*.nft"
`
	document, err := inspectNFTPersistence([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(document.tables) != 2 || document.tables[0].name != "custom" || document.tables[1].name != "syswarden_table" {
		t.Fatalf("unexpected table inventory: %#v", document.tables)
	}
	if len(document.includes) != 2 || document.includes[0].depth != 2 || document.includes[1].depth != 0 ||
		document.includes[0].path != "/etc/nftables.d/rules.nft" || document.includes[1].path != "/etc/nftables.d/*.nft" {
		t.Fatalf("unexpected include inventory: %#v", document.includes)
	}
	for _, table := range document.tables {
		if table.start < 0 || table.end <= table.start || table.end > len(input) || input[table.end-1] != '}' {
			t.Fatal("table source bounds are invalid")
		}
	}
	plan, err := planLegacyNFTIncludeRetirement([]byte(input))
	if err != nil || string(plan.content) != input || len(plan.removed) != 0 {
		t.Fatal("a table name was incorrectly treated as edit authorization")
	}
}

func TestNFTPersistenceRejectsMalformedOrUnboundedInput(t *testing.T) {
	for name, input := range map[string][]byte{
		"too_large":       bytes.Repeat([]byte(" "), maximumNFTPersistenceBytes+1),
		"too_many_tokens": bytes.Repeat([]byte(";"), maximumNFTPersistenceTokens+1),
		"too_deep":        []byte(strings.Repeat("{", maximumNFTPersistenceDepth+1)),
		"nul":             []byte("# comment\x00\n"),
		"invalid_utf8":    {0xff},
		"bare_escape":     []byte("include \\x"),
		"unclosed_quote":  []byte("comment \"unfinished"),
		"unclosed_brace":  []byte("table inet custom {"),
		"extra_brace":     []byte("table inet custom {} }"),
		"dynamic_path":    []byte("include $file\n"),
		"escaped_path":    []byte("include \"/etc/\\x61.nft\"\n"),
		"extra_tokens":    []byte("include \"/etc/custom.nft\" extra\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := inspectNFTPersistence(input); err == nil {
				t.Fatal("unsafe input was accepted")
			}
		})
	}
}

func FuzzNFTPersistenceIncludePlan(f *testing.F) {
	f.Add([]byte(legacyNFTIncludeMarker + "\n" + legacyNFTIncludeLine + "\n"))
	f.Add([]byte("table inet custom { chain input { comment \"{ # include\"; } }\n"))
	f.Add([]byte("#!/usr/sbin/nft -f\nflush ruleset\n" + legacyNFTIncludeLine + "\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 128<<10 {
			t.Skip()
		}
		original := bytes.Clone(input)
		plan, err := planLegacyNFTIncludeRetirement(input)
		if !bytes.Equal(input, original) {
			t.Fatal("planner mutated its input")
		}
		if err != nil {
			if len(plan.content) != 0 || len(plan.removed) != 0 {
				t.Fatal("error returned a partial edit")
			}
			return
		}
		if plan.originalSHA256 != sha256.Sum256(input) {
			t.Fatal("plan digest does not bind its input")
		}
		var reconstructed []byte
		cursor := 0
		for _, span := range plan.removed {
			if span.start < cursor || span.end <= span.start || span.end > len(input) {
				t.Fatal("edit range escapes its source")
			}
			reconstructed = append(reconstructed, input[cursor:span.start]...)
			cursor = span.end
		}
		reconstructed = append(reconstructed, input[cursor:]...)
		if !bytes.Equal(reconstructed, plan.content) {
			t.Fatal("plan changed bytes outside its declared edits")
		}
		again, err := planLegacyNFTIncludeRetirement(plan.content)
		if err != nil || !bytes.Equal(again.content, plan.content) || len(again.removed) != 0 {
			t.Fatalf("edit is not idempotent: %v", err)
		}
	})
}
