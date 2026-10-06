//go:build linux

package firewall

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fixtureLegacyFail2banWire(t *testing.T, encoded string) []byte {
	t.Helper()
	data, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLegacyFail2banWirePrimitiveReplies(t *testing.T) {
	for _, encoded := range []string{
		"80024b005805000000312e312e3071008671012e",
		"8004950d000000000000004b008c05312e312e309486942e",
		"8005950d000000000000004b008c05312e312e309486942e",
	} {
		value, err := decodeLegacyFail2banReply(fixtureLegacyFail2banWire(t, encoded))
		if err != nil || value.kind != 's' || value.text != "1.1.0" {
			t.Fatal("version response failed", err)
		}
	}
	for _, encoded := range []string{
		"80024b005d710028580e0000004e756d626572206f66206a61696c71014b0286710258090000004a61696c206c6973747103582500000061646d696e6973747261746f722d7765622c2073797377617264656e2d706f72747363616e7104867105658671062e",
		"80049554000000000000004b005d94288c0e4e756d626572206f66206a61696c944b0286948c094a61696c206c697374948c2561646d696e6973747261746f722d7765622c2073797377617264656e2d706f72747363616e9486946586942e",
	} {
		value, err := decodeLegacyFail2banReply(fixtureLegacyFail2banWire(t, encoded))
		if err != nil {
			t.Fatal(err)
		}
		names, err := legacyFail2banRuntimeJailNames(value)
		if err != nil || len(names) != 2 || names[0] != "administrator-web" || names[1] != "syswarden-portscan" {
			t.Fatal("status failed", err)
		}
	}
	for _, encoded := range []string{
		"80024b005d710028580600000072657065617471016801658671022e",
		"80049514000000000000004b005d94288c067265706561749468016586942e",
	} {
		value, err := decodeLegacyFail2banReply(fixtureLegacyFail2banWire(t, encoded))
		if err != nil || len(value.items) != 2 || value.items[0].text != "repeat" || value.items[1].text != "repeat" {
			t.Fatal("scalar memo failed", err)
		}
	}
	for _, sample := range []struct {
		encoded string
		kind    byte
		number  int64
	}{
		{"80024b004b3c8671002e", 'i', 60},
		{"80024b004d2c01862e", 'i', 300},
		{"80024b004affffffff862e", 'i', -1},
		{"80024b00898671002e", 0x89, 0},
		{"80024b0088862e", 0x88, 0},
		{"80024b004e8671002e", 'N', 0},
	} {
		value, err := decodeLegacyFail2banReply(fixtureLegacyFail2banWire(t, sample.encoded))
		if err != nil || value.kind != sample.kind || value.number != sample.number {
			t.Fatal("primitive failed", err)
		}
	}
}

func TestLegacyFail2banWireRejectsUnsafeAndIncompleteObjects(t *testing.T) {
	valid := fixtureLegacyFail2banWire(t, "8004950d000000000000004b008c05312e312e309486942e")
	for i := 0; i < len(valid); i++ {
		if _, err := decodeLegacyFail2banReply(valid[:i]); err == nil {
			t.Fatalf("accepted truncated response at %d", i)
		}
	}
	cases := [][]byte{
		append(bytes.Clone(valid), '.'),
		bytes.Replace(valid, []byte{0x95, 0x0d}, []byte{0x95, 0x0c}, 1),
		bytes.Replace(valid, []byte{0x95, 0x0d}, []byte{0x95, 0x0e}, 1),
		bytes.Replace(valid, []byte{0x4b, 0}, []byte{0x4b, 1}, 1),
		[]byte("\x80\x02K\x00cos\nsystem\nX\x02\x00\x00\x00id\x85R\x86."),
		[]byte("\x80\x04K\x00\x8c\x02os\x8c\x06system\x93\x86."),
		[]byte("\x80\x02K\x00]q\x00h\x00a\x86."),
		[]byte("\x80\x02K\x00]q\x00(h\x00e\x86."),
		[]byte("\x80\x02K\x00h\x00\x86."),
		[]byte("\x80\x02K\x00Nq\xff\x86."),
		[]byte("\x80\x02K\x00(\x86."),
		[]byte("\x80\x02K\x00X\xff\xff\xff\xff\x86."),
		[]byte("\x80\x02K\x00X\x01\x00\x00\x00\xff\x86."),
		bytes.Repeat([]byte{'x'}, maximumLegacyFail2banReply+1),
		append(append([]byte("\x80\x02K\x00N"), bytes.Repeat([]byte{0x85}, 33)...), []byte{0x86, '.'}...),
		append(append([]byte("\x80\x02K\x00"), bytes.Repeat([]byte{'('}, 130)...), '.'),
	}
	for i, data := range cases {
		if _, err := decodeLegacyFail2banReply(data); err == nil {
			t.Fatalf("accepted unsafe response %d", i)
		}
	}
}

func TestLegacyFail2banWireEscapeConstantsAreExactInertReplies(t *testing.T) {
	for label, encoded := range map[string]string{
		"ESCAPE_CRE":    "80059541000000000000004b008c027265948c085f636f6d70696c659493948c215b5c5c23263b607c2a3f7e3c3e5c5e5c285c295c5b5c5d7b7d2427225c6e5c725d944b208694529486942e",
		"ESCAPE_VN_CRE": "80059522000000000000004b008c027265948c085f636f6d70696c659493948c025c57944b208694529486942e",
	} {
		data := fixtureLegacyFail2banWire(t, encoded)
		for _, protocol := range []byte{4, 5} {
			data[1] = protocol
			value, err := decodeLegacyFail2banReply(data)
			if err != nil || value.kind != 'r' || value.text != label {
				t.Fatal("exact escape constant was not recognized", err)
			}
		}
		for offset := 2; offset < len(data); offset++ {
			changed := bytes.Clone(data)
			changed[offset] ^= 1
			if _, err := decodeLegacyFail2banReply(changed); err == nil {
				t.Fatalf("modified escape constant accepted at byte %d", offset)
			}
		}
		if _, err := decodeLegacyFail2banReply(append(bytes.Clone(data), '.')); err == nil {
			t.Fatal("escape constant with trailing data accepted")
		}
	}
}

func TestLegacyFail2banWireAcceptsBoundedLargeBanLists(t *testing.T) {
	data := []byte{0x80, 4, 'K', 0, ']', '('}
	for i := 0; i < 1000; i++ {
		data = append(data, 0x8c, 1, 'x')
	}
	data = append(data, 'e', 0x86, '.')
	value, err := decodeLegacyFail2banReply(data)
	if err != nil || value.kind != 'l' || len(value.items) != 1000 {
		t.Fatal("bounded protocol batch rejected", err)
	}
}

func TestLegacyFail2banWireQueriesCannotMutate(t *testing.T) {
	for _, query := range [][]string{{"stop"}, {"stop", "syswarden-portscan"}, {"reload"}, {"server-stream"}, {"set", "syswarden-portscan", "idle", "on"}, {"get", "a", "action", "nft", "__class__"}, {"get", "--all", "actions"}, {"get", "a", "action", "x", "stop()"}, {"get", "a"}, {"status", "--all"}} {
		if _, err := encodeLegacyFail2banQuery(query); err == nil {
			t.Fatal("mutation or unsupported query accepted", query)
		}
	}
	for _, query := range [][]string{{"version"}, {"status"}, {"get", "a", "actions"}, {"get", "a", "banip", "--with-time"}, {"get", "a", "actionproperties", "nftables-allports"}, {"get", "a", "action", "nftables-allports", "actionstop?family=inet6"}} {
		data, err := encodeLegacyFail2banQuery(query)
		if err != nil || !bytes.HasSuffix(data, []byte("e."+legacyFail2banEnd)) {
			t.Fatal("valid read-only query rejected", err)
		}
	}
}

func FuzzLegacyFail2banWireReply(f *testing.F) {
	f.Add([]byte("\x80\x02K\x00N\x86."))
	f.Add([]byte("\x80\x02K\x00]q\x00h\x00a\x86."))
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := decodeLegacyFail2banReply(data)
		if err == nil {
			if err := validateLegacyFail2banValueTree(value); err != nil {
				t.Fatal(err)
			}
			if _, err := decodeLegacyFail2banReply(append(bytes.Clone(data), '.')); err == nil {
				t.Fatal("trailing data accepted")
			}
		}
	})
}
