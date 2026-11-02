package mailclient

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

func encodeIMAPMailbox(value string) string {
	var out strings.Builder
	var shifted []rune
	flush := func() {
		if len(shifted) == 0 {
			return
		}
		units := utf16.Encode(shifted)
		data := make([]byte, len(units)*2)
		for index, unit := range units {
			binary.BigEndian.PutUint16(data[index*2:], unit)
		}
		encoded := base64.StdEncoding.EncodeToString(data)
		encoded = strings.TrimRight(strings.ReplaceAll(encoded, "/", ","), "=")
		out.WriteByte('&')
		out.WriteString(encoded)
		out.WriteByte('-')
		shifted = shifted[:0]
	}
	for _, char := range value {
		if char >= 0x20 && char <= 0x7e {
			flush()
			if char == '&' {
				out.WriteString("&-")
			} else {
				out.WriteRune(char)
			}
		} else {
			shifted = append(shifted, char)
		}
	}
	flush()
	return out.String()
}

func decodeIMAPMailbox(value string) (string, error) {
	var out strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '&' {
			if value[index] < 0x20 || value[index] > 0x7e {
				return "", fmt.Errorf("mailbox name is not modified UTF-7")
			}
			out.WriteByte(value[index])
			index++
			continue
		}
		end := strings.IndexByte(value[index:], '-')
		if end < 0 {
			return "", fmt.Errorf("unterminated modified UTF-7 sequence")
		}
		end += index
		if end == index+1 {
			out.WriteByte('&')
			index = end + 1
			continue
		}
		encoded := strings.ReplaceAll(value[index+1:end], ",", "/")
		if strings.Contains(encoded, "=") {
			return "", fmt.Errorf("invalid modified UTF-7 padding")
		}
		if remainder := len(encoded) % 4; remainder != 0 {
			encoded += strings.Repeat("=", 4-remainder)
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(data) == 0 || len(data)%2 != 0 {
			return "", fmt.Errorf("invalid modified UTF-7 data")
		}
		units := make([]uint16, len(data)/2)
		for unitIndex := range units {
			units[unitIndex] = binary.BigEndian.Uint16(data[unitIndex*2:])
		}
		decoded := utf16.Decode(units)
		for _, char := range decoded {
			if char == '\uFFFD' {
				return "", fmt.Errorf("invalid modified UTF-7 surrogate")
			}
		}
		out.WriteString(string(decoded))
		index = end + 1
	}
	return out.String(), nil
}
