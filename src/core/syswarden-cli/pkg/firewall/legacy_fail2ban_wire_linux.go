//go:build linux

package firewall

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

const (
	maximumLegacyFail2banReply  = 1 << 20
	maximumLegacyFail2banValues = 65536
	legacyFail2banEnd           = "<F2B_END_COMMAND>"
)

// Fail2ban's local protocol uses pickle. Never deserialize it with a general
// object loader: even an error response can instantiate Python objects. This
// bounded decoder accepts primitive values, lists and tuples. Two exact wire
// constants for the audited CommandAction escape patterns are recognized as
// inert labels before decoding. No pattern is compiled. Object construction,
// global lookup, reducers, persistent references and container aliases are
// deliberately unsupported by the decoder.
type legacyFail2banValue struct {
	kind   byte
	text   string
	number int64
	items  []legacyFail2banValue
}

type legacyFail2banWireDecoder struct {
	data     []byte
	offset   int
	frameEnd int
	stack    []legacyFail2banValue
	memo     []legacyFail2banValue
	values   int
}

func (p *legacyFail2banWireDecoder) take(n int) ([]byte, error) {
	if n < 0 || n > len(p.data)-p.offset || p.frameEnd > 0 && n > p.frameEnd-p.offset {
		return nil, fmt.Errorf("incomplete Fail2ban primitive response")
	}
	part := p.data[p.offset : p.offset+n]
	p.offset += n
	return part, nil
}

func (p *legacyFail2banWireDecoder) push(v legacyFail2banValue) error {
	p.values++
	if p.values > maximumLegacyFail2banValues || len(p.stack) >= 2048 {
		return fmt.Errorf("Fail2ban primitive response exceeds its value or stack limit")
	}
	p.stack = append(p.stack, v)
	return nil
}

func decodeLegacyFail2banReply(data []byte) (legacyFail2banValue, error) {
	var empty legacyFail2banValue
	if len(data) < 4 || len(data) > maximumLegacyFail2banReply || data[0] != 0x80 || data[1] < 2 || data[1] > 5 {
		return empty, fmt.Errorf("unsupported Fail2ban primitive response")
	}
	if label := exactLegacyFail2banEscapeConstant(data); label != "" {
		return legacyFail2banValue{kind: 'r', text: label}, nil
	}
	p := legacyFail2banWireDecoder{data: data, offset: 2}
	framed := false
	for p.offset < len(data) {
		if p.offset == p.frameEnd {
			p.frameEnd = 0
		}
		if framed && p.frameEnd == 0 && data[p.offset] != 0x95 {
			return empty, fmt.Errorf("Fail2ban response contains data outside its declared frames")
		}
		opcode, err := p.take(1)
		if err != nil {
			return empty, err
		}
		switch opcode[0] {
		case 0x95: // FRAME
			if data[1] < 4 || p.frameEnd != 0 {
				return empty, fmt.Errorf("invalid Fail2ban response frame")
			}
			b, err := p.take(8)
			if err != nil {
				return empty, err
			}
			n := binary.LittleEndian.Uint64(b)
			if n == 0 || n > maximumLegacyFail2banReply {
				return empty, fmt.Errorf("invalid Fail2ban response frame length")
			}
			p.frameEnd = p.offset + int(n)
			if p.frameEnd > len(data) {
				return empty, fmt.Errorf("incomplete Fail2ban response frame")
			}
			framed = true
		case 'N', 0x88, 0x89:
			if err := p.push(legacyFail2banValue{kind: opcode[0]}); err != nil {
				return empty, err
			}
		case 'K', 'M', 'J':
			n := map[byte]int{'K': 1, 'M': 2, 'J': 4}[opcode[0]]
			b, err := p.take(n)
			if err != nil {
				return empty, err
			}
			value := int64(b[0])
			if n == 2 {
				value = int64(binary.LittleEndian.Uint16(b))
			}
			if n == 4 {
				value = int64(binary.LittleEndian.Uint32(b))
				if value > 1<<31-1 {
					value -= 1 << 32
				}
			}
			if err := p.push(legacyFail2banValue{kind: 'i', number: value}); err != nil {
				return empty, err
			}
		case 'X', 0x8c: // BINUNICODE, SHORT_BINUNICODE
			n := 4
			if opcode[0] == 0x8c {
				n = 1
			}
			b, err := p.take(n)
			if err != nil {
				return empty, err
			}
			length := uint64(b[0])
			if n == 4 {
				length = uint64(binary.LittleEndian.Uint32(b))
			}
			if length > maximumLegacyFail2banReply {
				return empty, fmt.Errorf("Fail2ban response string exceeds its limit")
			}
			b, err = p.take(int(length))
			if err != nil || !utf8.Valid(b) {
				return empty, fmt.Errorf("invalid Fail2ban response string")
			}
			if err := p.push(legacyFail2banValue{kind: 's', text: string(b)}); err != nil {
				return empty, err
			}
		case ']', ')', '(':
			kind := opcode[0]
			if kind == ']' {
				kind = 'l'
			}
			if kind == ')' {
				kind = 't'
			}
			if err := p.push(legacyFail2banValue{kind: kind}); err != nil {
				return empty, err
			}
		case 'a': // APPEND
			n := len(p.stack)
			if n < 2 || p.stack[n-2].kind != 'l' {
				return empty, fmt.Errorf("invalid Fail2ban response list")
			}
			p.stack[n-2].items = append(p.stack[n-2].items, p.stack[n-1])
			p.stack = p.stack[:n-1]
		case 'e', 't': // APPENDS, TUPLE
			mark := len(p.stack) - 1
			for mark >= 0 && p.stack[mark].kind != '(' {
				mark--
			}
			if mark < 0 {
				return empty, fmt.Errorf("missing Fail2ban response mark")
			}
			items := append([]legacyFail2banValue(nil), p.stack[mark+1:]...)
			p.stack = p.stack[:mark]
			if opcode[0] == 't' {
				if err := p.push(legacyFail2banValue{kind: 't', items: items}); err != nil {
					return empty, err
				}
			} else {
				if mark < 1 || p.stack[mark-1].kind != 'l' {
					return empty, fmt.Errorf("invalid Fail2ban response list mark")
				}
				p.stack[mark-1].items = append(p.stack[mark-1].items, items...)
			}
		case 0x85, 0x86, 0x87: // TUPLE1..3
			n := int(opcode[0] - 0x84)
			if len(p.stack) < n {
				return empty, fmt.Errorf("incomplete Fail2ban response tuple")
			}
			items := append([]legacyFail2banValue(nil), p.stack[len(p.stack)-n:]...)
			p.stack = p.stack[:len(p.stack)-n]
			if err := p.push(legacyFail2banValue{kind: 't', items: items}); err != nil {
				return empty, err
			}
		case 0x94, 'q', 'r': // MEMOIZE, BINPUT, LONG_BINPUT
			index := uint64(len(p.memo))
			if opcode[0] != 0x94 {
				n := 1
				if opcode[0] == 'r' {
					n = 4
				}
				b, err := p.take(n)
				if err != nil {
					return empty, err
				}
				index = uint64(b[0])
				if n == 4 {
					index = uint64(binary.LittleEndian.Uint32(b))
				}
			}
			if len(p.stack) == 0 || index != uint64(len(p.memo)) || len(p.memo) >= maximumLegacyFail2banValues {
				return empty, fmt.Errorf("invalid Fail2ban response memo")
			}
			p.memo = append(p.memo, p.stack[len(p.stack)-1])
		case 'h', 'j': // BINGET, LONG_BINGET
			n := 1
			if opcode[0] == 'j' {
				n = 4
			}
			b, err := p.take(n)
			if err != nil {
				return empty, err
			}
			index := uint64(b[0])
			if n == 4 {
				index = uint64(binary.LittleEndian.Uint32(b))
			}
			if index >= uint64(len(p.memo)) {
				return empty, fmt.Errorf("missing Fail2ban response memo")
			}
			value := p.memo[index]
			if value.kind != 's' && value.kind != 'i' && value.kind != 'N' && value.kind != 0x88 && value.kind != 0x89 {
				return empty, fmt.Errorf("Fail2ban response container aliases are unsupported")
			}
			if err := p.push(value); err != nil {
				return empty, err
			}
		case '.':
			if p.offset != len(data) || p.frameEnd != 0 && p.frameEnd != p.offset || len(p.stack) != 1 {
				return empty, fmt.Errorf("trailing or incomplete Fail2ban response")
			}
			value := p.stack[0]
			if value.kind != 't' || len(value.items) != 2 || value.items[0].kind != 'i' || value.items[0].number != 0 {
				return empty, fmt.Errorf("Fail2ban read-only query did not return a successful primitive response")
			}
			if err := validateLegacyFail2banValueTree(value); err != nil {
				return empty, err
			}
			return value.items[1], nil
		default:
			return empty, fmt.Errorf("Fail2ban response contains unsupported opcode 0x%02x", opcode[0])
		}
	}
	return empty, fmt.Errorf("incomplete Fail2ban primitive response")
}

// CommandAction exposes these two compiled regular expressions through its
// public property list. Match the complete successful protocol 4/5 replies for
// the exact Fail2ban 1.1.0 constants, including flags=32. Do not deserialize a
// reducer or accept arbitrary expressions, modified flags or trailing bytes.
func exactLegacyFail2banEscapeConstant(data []byte) string {
	if len(data) > 80 || len(data) < 4 || data[0] != 0x80 || data[1] < 4 || data[1] > 5 {
		return ""
	}
	switch hex.EncodeToString(data[2:]) {
	case "9541000000000000004b008c027265948c085f636f6d70696c659493948c215b5c5c23263b607c2a3f7e3c3e5c5e5c285c295c5b5c5d7b7d2427225c6e5c725d944b208694529486942e":
		return "ESCAPE_CRE"
	case "9522000000000000004b008c027265948c085f636f6d70696c659493948c025c57944b208694529486942e":
		return "ESCAPE_VN_CRE"
	}
	return ""
}

func validateLegacyFail2banValueTree(value legacyFail2banValue) error {
	type entry struct {
		value legacyFail2banValue
		depth int
	}
	pending := []entry{{value, 0}}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current.depth > 32 {
			return fmt.Errorf("Fail2ban primitive response exceeds its nesting limit")
		}
		switch current.value.kind {
		case 's', 'i', 'N', 0x88, 0x89:
		case 'r':
			if current.value.text != "ESCAPE_CRE" && current.value.text != "ESCAPE_VN_CRE" {
				return fmt.Errorf("unknown Fail2ban escape constant")
			}
		case 't', 'l':
			for _, child := range current.value.items {
				pending = append(pending, entry{child, current.depth + 1})
			}
		default:
			return fmt.Errorf("Fail2ban primitive response contains a misplaced mark")
		}
	}
	return nil
}

// Fixed primitive-list encoding is sufficient for read-only protocol queries.
// This function intentionally cannot encode nested server-stream commands.
func encodeLegacyFail2banQuery(query []string) ([]byte, error) {
	if !validLegacyFail2banQuery(query) {
		return nil, fmt.Errorf("unsupported Fail2ban read-only query")
	}
	var out bytes.Buffer
	_, _ = out.Write([]byte{0x80, 2, ']', '('})
	for _, value := range query {
		lengthValue := len(value)
		if lengthValue < 1 || lengthValue > 128 {
			return nil, fmt.Errorf("Fail2ban query value exceeds its limit")
		}
		_ = out.WriteByte('X')
		var length [4]byte
		binary.LittleEndian.PutUint32(length[:], uint32(lengthValue))
		_, _ = out.Write(length[:])
		_, _ = out.WriteString(value)
	}
	_, _ = out.WriteString("e." + legacyFail2banEnd)
	return out.Bytes(), nil
}

func validLegacyFail2banQuery(query []string) bool {
	if len(query) == 1 {
		return query[0] == "version" || query[0] == "status"
	}
	if len(query) < 3 || query[0] != "get" || !validLegacyFail2banJailName(query[1]) || query[1][0] == '-' {
		return false
	}
	if len(query) == 3 {
		return query[2] == "actions"
	}
	if len(query) == 4 && query[2] == "banip" {
		return query[3] == "--with-time"
	}
	if !validLegacyFail2banRuntimeName(query[3]) {
		return false
	}
	if len(query) == 4 {
		return query[2] == "actionproperties"
	}
	return len(query) == 5 && query[2] == "action" && (validLegacyFail2banRuntimeName(query[4]) || query[4] == "__module__")
}

func validLegacyFail2banRuntimeName(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] == '_' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':' || r == '?' || r == '=' {
			continue
		}
		return false
	}
	return true
}
