package security

import (
	"bufio"
	"errors"
	"strings"
)

var ErrLineTooLong = errors.New("protocol line too long")
var ErrInvalidLineEnding = errors.New("protocol line requires CRLF framing")

// ParseCRLFCommandLine accepts exactly one CRLF-terminated command line.
// A bare CR inside the command is invalid, not whitespace to be trimmed.
func ParseCRLFCommandLine(line string) (string, error) {
	if !strings.HasSuffix(line, "\r\n") {
		return "", ErrInvalidLineEnding
	}
	command := strings.TrimSuffix(line, "\r\n")
	if strings.ContainsAny(command, "\r\n") {
		return "", ErrInvalidLineEnding
	}
	return command, nil
}

// ReadLineLimited bounds memory while reading a CRLF-terminated protocol line.
// The limit includes the line terminator; callers must close the connection on
// ErrLineTooLong because unread bytes remain in the stream.
func ReadLineLimited(reader *bufio.Reader, limit int) (string, error) {
	if limit <= 0 {
		return "", ErrLineTooLong
	}
	line := make([]byte, 0, min(limit, 4096))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > limit-len(line) {
			return "", ErrLineTooLong
		}
		line = append(line, fragment...)
		if err == nil {
			return string(line), nil
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
}
