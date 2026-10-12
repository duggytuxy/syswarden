package v5

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"unicode/utf8"
)

const maxDepth = 8
const maxMembers = 32
const maxValues = 256

// DecodeEvent accepts one complete, bounded document with exact field names.
// All fields are required; unavailable values must use an explicit Field.
// A failure always returns the zero Event, never a partially decoded record.
func DecodeEvent(data []byte) (Event, error) {
	v, err := parseDocument(data)
	if err != nil {
		return Event{}, err
	}
	if !exactShape(v, reflect.TypeFor[Event]()) {
		return Event{}, invalid("object shape")
	}
	var e Event
	if err := json.Unmarshal(data, &e); err != nil {
		return Event{}, invalid("encoding")
	}
	if err := e.Validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}

// EncodeEvent emits the schema-specific canonical form: struct field order,
// compact JSON, explicit fields, Go JSON string escaping, no trailing newline.
// This is not RFC 8785 JCS and is not a signed-evidence format.
func EncodeEvent(e Event) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, invalid("encoding")
	}
	if len(b) > MaxDocumentBytes {
		return nil, invalid("size")
	}
	return b, nil
}

func exactShape(v any, t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String:
		_, ok := v.(string)
		return ok
	case reflect.Struct:
		object, ok := v.(map[string]any)
		if !ok || len(object) != t.NumField() {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			value, exists := object[field.Tag.Get("json")]
			if !exists || !exactShape(value, field.Type) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func parseDocument(data []byte) (any, error) {
	if len(data) == 0 || len(data) > MaxDocumentBytes || !utf8.Valid(data) ||
		!json.Valid(data) || !validSurrogates(data) {
		return nil, invalid("encoding or size")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	remaining := maxValues
	v, err := readValue(d, 0, &remaining)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, invalid("trailing data")
	}
	return v, nil
}

func readValue(d *json.Decoder, depth int, remaining *int) (any, error) {
	*remaining -= 1
	if depth > maxDepth || *remaining < 0 {
		return nil, invalid("complexity")
	}
	t, err := d.Token()
	if err != nil {
		return nil, invalid("encoding")
	}
	switch t {
	case json.Delim('{'):
		object := make(map[string]any)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, invalid("object key")
			}
			name, ok := key.(string)
			if !ok {
				return nil, invalid("object key")
			}
			if _, exists := object[name]; exists || len(object) >= maxMembers {
				return nil, invalid("duplicate key or object size")
			}
			value, err := readValue(d, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		if _, err := d.Token(); err != nil {
			return nil, invalid("object end")
		}
		return object, nil
	case json.Delim('['):
		values := make([]any, 0)
		for d.More() {
			if len(values) >= maxMembers {
				return nil, invalid("array size")
			}
			value, err := readValue(d, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if _, err := d.Token(); err != nil {
			return nil, invalid("array end")
		}
		return values, nil
	default:
		return t, nil
	}
}

// encoding/json replaces unpaired UTF-16 surrogates. Reject that lossy input
// instead. JSON grammar and raw UTF-8 have already been checked by the caller.
func validSurrogates(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
