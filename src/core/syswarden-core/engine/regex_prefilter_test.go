package engine

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestRegexPrefilterPreservesRequiredMatches(t *testing.T) {
	cases := []struct{ pattern, input string }{
		{`(?i)Failed password .* from ([0-9.]+)`, "FAILED PASSWORD for root FROM 192.0.2.8"},
		{`(?i:secret)(?-i:TOKEN)`, "SeCrEtTOKEN"},
		{`(?:optional)?required`, "required"},
		{`(?:optional)*required`, "required"},
		{`(?:repeated){0,3}required`, "required"},
		{`(?:repeated){1,3}`, "repeatedrepeated"},
		{`(?:alpha|bravo)`, "bravo"},
		{`(?:alpha|)`, ""},
		{`(?:prefixA|prefixB)`, "prefixB"},
		{`(?:alpha.*omega|bravo.*zulu)`, "bravo and zulu"},
		{`(?:foo|bar)+`, "barfoo"},
		{`(?i)class`, "cla\u017fs"},
		{`(?i)kelvin`, "\u212aELVIN"},
		{`(?i)CAF\x{c9}`, "café"},
		{`secret.`, "secret\xff"},
		{`(?s)secret.*token`, "secret\nTOKEN token"},
		{`(?m)^secret$`, "prefix\nsecret\nsuffix"},
		{`\bsecret\b`, "a secret here"},
		{`[[:alpha:]]+`, "letters"},
		{`a?`, ""},
		{`(?i)ababac`, strings.Repeat("ABABA", 1000) + "ABABAC"},
		{`(?i)aaaaab`, strings.Repeat("A", 4096) + "B"},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			if !re.MatchString(tc.input) {
				t.Fatal("invalid positive test fixture")
			}
			content := regexScanText{text: tc.input}
			if !content.matches(compileRegexPrefilter(re.String())) {
				t.Fatal("prefilter rejected a full regexp match")
			}
		})
	}
	if filter := compileRegexPrefilter(`(?i)Failed password`); filter == nil {
		t.Fatal("common required literal was not optimized")
	} else if content := (regexScanText{text: "benign record"}); content.matches(filter) {
		t.Fatal("absent required literal was accepted")
	}
}

func TestRegexPrefilterRejectsLongRepeatedPrefixes(t *testing.T) {
	filter := compileRegexPrefilter(`(?i)` + strings.Repeat("a", 128) + "b")
	content := regexScanText{text: strings.Repeat("A", 1<<20)}
	if content.matches(filter) {
		t.Fatal("nonmatching repeated prefix was accepted")
	}
}

// The oracle is Go's complete compiled expression. Inputs rejected by the
// prefilter must never contain any match, including a zero-length match.
func FuzzRegexPrefilterMatches(f *testing.F) {
	for _, seed := range [][2]string{
		{`(?i)alpha.*(bravo|charlie)`, "AlPhA CHARLIE"},
		{`(optional)?required`, "required"},
		{`(alpha|)`, ""},
		{`(?i)class`, "cla\u017fs"},
		{`(?i)kelvin`, "\u212aELVIN"},
		{`secret.`, "secret\xff"},
		{`[a-z]{0,3}token`, "token"},
		{`(?:foo|bar)+`, "barfoo"},
		{`(?i:a)(?-i:secret)`, "Asecret"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, input string) {
		if len(pattern) > 512 || len(input) > 4096 {
			t.Skip()
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		content := regexScanText{text: input}
		if !content.matches(compileRegexPrefilter(re.String())) && re.MatchString(input) {
			t.Fatalf("prefilter rejected full regexp match: pattern=%q input=%q", pattern, input)
		}
	})
}

var prefilterRecordCorpus = []string{
	"",
	"\x00\xff%00%ff",
	"Sep 20 08:00:00 host sshd[123]: Failed password for root from 192.0.2.8 port 40404 ssh2",
	"Sep 20 08:00:00 host sshd[123]: FAILED PASSWORD for root from 2001:db8::8 port 40404 ssh2",
	`198.51.100.8 - - [20/Sep/2026:08:00:00 +0200] "GET /?q=java.lang.ProcessBuilder HTTP/1.1" 403 0`,
	`198.51.100.8 - - [20/Sep/2026:08:00:00 +0200] "GET /?q=java%2elang%2eProcessBuilder HTTP/1.1" 403 0`,
	`198.51.100.8 - - [20/Sep/2026:08:00:00 +0200] "GET /?q=WAITFOR+DELAY HTTP/1.1" 403 0`,
	`198.51.100.8 - - [20/Sep/2026:08:00:00 +0200] "GET /?q=WAITFOR%ZZDELAY HTTP/1.1" 403 0`,
	`198.51.100.8 - - [20/Sep/2026:08:00:00 +0200] "GET /safe HTTP/1.1" 200 0 "SLEEP(5)" "php://filter"`,
	`{"client_ip":"198.51.100.8","path":"/..%2Fetc%2Fpasswd"}`,
	`{"client_ip":"198.51.100.8","path":"/safe","request_uri":"/php://filter"}`,
	`{"remote_ip":"198.51.100.8","client_ip":"192.0.2.8","path":"/?q=SLEEP(5)"}`,
	"scanner user-agent sqlmap",
	"198.51.100.8 invalid user FAKE from 192.0.2.8 Failed password for root from 203.0.113.5 port 22",
}

// Compare every Match field, including source authority and risk attribution,
// against the identical production catalog with literal filtering disabled.
func TestRegexPrefilterProductionScanEquivalence(t *testing.T) {
	filtered := newProductionTestEngine(t)
	oracle := newProductionTestEngine(t)
	for i := range oracle.regexRules {
		oracle.regexRules[i].prefilter = nil
	}
	for i, input := range prefilterRecordCorpus {
		for _, variant := range []string{input, strings.ToUpper(input), input + "\xff", input + "\u212a"} {
			if got, want := filtered.Scan(variant), oracle.Scan(variant); !reflect.DeepEqual(got, want) {
				t.Fatalf("record %d changed match: got %#v want %#v", i, got, want)
			}
		}
	}
}

func FuzzRegexPrefilterProductionScan(f *testing.F) {
	filtered, err := NewEngine("../signatures.json", 5, 60)
	if err != nil {
		f.Fatal(err)
	}
	oracle, err := NewEngine("../signatures.json", 5, 60)
	if err != nil {
		f.Fatal(err)
	}
	for i := range oracle.regexRules {
		oracle.regexRules[i].prefilter = nil
	}
	for _, input := range prefilterRecordCorpus {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		if got, want := filtered.Scan(input), oracle.Scan(input); !reflect.DeepEqual(got, want) {
			t.Fatalf("prefilter changed complete production match: got %#v want %#v", got, want)
		}
	})
}

func BenchmarkRegexPrefilterScan(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "full-regexp"
		if enabled {
			name = "required-literal"
		}
		b.Run(name, func(b *testing.B) {
			detector, err := NewEngine("../signatures.json", 5, 60)
			if err != nil {
				b.Fatal(err)
			}
			if !enabled {
				for i := range detector.regexRules {
					detector.regexRules[i].prefilter = nil
				}
			}
			input := `198.51.100.8 - - [20/Sep/2026:08:00:00 +0200] "GET /syswarden-performance?x=ProcessBuilder&swperf=qualification&sample=aah HTTP/1.1" 200 34 "-" "SysWarden-Native-Performance/4.10.0"`
			if match := detector.Scan(input); match == nil || match.RuleID != "java-ssti-rce" {
				b.Fatal("benchmark fixture lacks the expected detection")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if detector.Scan(input) == nil {
					b.Fatal("detection disappeared")
				}
			}
		})
	}
}
