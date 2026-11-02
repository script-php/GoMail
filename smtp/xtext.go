package smtp

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// encodeXText implements the RFC 3461 xtext encoding used by ENVID and ORCPT.
func encodeXText(value string) string {
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 33 && b <= 126 && b != '+' && b != '=' {
			encoded.WriteByte(b)
			continue
		}
		encoded.WriteByte('+')
		encoded.WriteByte(hex[b>>4])
		encoded.WriteByte(hex[b&0x0f])
	}
	return encoded.String()
}

// decodeUnitext accepts the RFC 6533 utf-8 ORCPT forms, including the
// seven-bit-safe \x{HEXPOINT} encoding used when SMTPUTF8 is unavailable.
func decodeUnitext(value string, nativeUTF8 bool) (string, error) {
	var decoded strings.Builder
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], `\x{`) {
			end := strings.IndexByte(value[i+3:], '}')
			if end < 0 || end < 2 || end > 6 {
				return "", fmt.Errorf("invalid unitext escape")
			}
			hex := value[i+3 : i+3+end]
			point, err := strconv.ParseUint(hex, 16, 32)
			if err != nil || !utf8.ValidRune(rune(point)) || point == 0 || point == '\r' || point == '\n' {
				return "", fmt.Errorf("invalid unitext code point")
			}
			decoded.WriteRune(rune(point))
			i += end + 4
			continue
		}
		r, width := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && width == 1 || r > 127 && !nativeUTF8 || r <= 32 || r == 127 || r == '\\' || r == '+' || r == '=' {
			return "", fmt.Errorf("invalid unitext character")
		}
		decoded.WriteRune(r)
		i += width
	}
	if decoded.Len() == 0 {
		return "", fmt.Errorf("empty unitext address")
	}
	return decoded.String(), nil
}

func decodeXText(value string) (string, error) {
	var decoded strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '+' {
			if value[i] < 33 || value[i] > 126 || value[i] == '=' {
				return "", fmt.Errorf("invalid xtext byte")
			}
			decoded.WriteByte(value[i])
			continue
		}
		if i+2 >= len(value) {
			return "", fmt.Errorf("truncated xtext escape")
		}
		hi, ok1 := fromHex(value[i+1])
		lo, ok2 := fromHex(value[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("invalid xtext escape")
		}
		decoded.WriteByte(hi<<4 | lo)
		i += 2
	}
	return decoded.String(), nil
}

func fromHex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}
