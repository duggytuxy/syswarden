package network

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

const maxHAPayloadFuzzBytes = 32 * 1024

func FuzzHASyncPayloadJSON(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"ips":[]}`),
		[]byte(`{"ips":["192.0.2.10","2001:db8::10"]}`),
		[]byte(`{"ips":["invalid",""],"future_field":{"enabled":true}}`),
		[]byte(`{"ips":null}`),
		[]byte(`{"ips":"192.0.2.10"}`),
		[]byte(`{"ips":[`),
		[]byte{0x00, 0xff, '{', '}'},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > maxHAPayloadFuzzBytes {
			t.Skip()
		}
		original := bytes.Clone(input)

		var first, second HASyncPayload
		firstErr := json.Unmarshal(input, &first)
		secondErr := json.Unmarshal(input, &second)
		if !bytes.Equal(input, original) {
			t.Fatal("json.Unmarshal mutated the HA wire input")
		}
		if errorTextHA(firstErr) != errorTextHA(secondErr) || !reflect.DeepEqual(first, second) {
			t.Fatalf("HA payload decoding is not deterministic: first (%#v, %v), second (%#v, %v)", first, firstErr, second, secondErr)
		}
		if firstErr != nil {
			return
		}

		firstWire, err := json.Marshal(first)
		if err != nil {
			t.Fatalf("marshal decoded HA payload: %v", err)
		}
		secondWire, err := json.Marshal(first)
		if err != nil {
			t.Fatalf("marshal decoded HA payload a second time: %v", err)
		}
		if !bytes.Equal(firstWire, secondWire) {
			t.Fatalf("HA payload encoding is not deterministic: %q, then %q", firstWire, secondWire)
		}

		var roundTrip HASyncPayload
		if err := json.Unmarshal(firstWire, &roundTrip); err != nil {
			t.Fatalf("decode canonical HA payload: %v", err)
		}
		if !reflect.DeepEqual(first, roundTrip) {
			t.Fatalf("HA payload round trip changed the decoded value: before %#v, after %#v", first, roundTrip)
		}
	})
}

func errorTextHA(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
