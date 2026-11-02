package security

// SMTPPathEnd finds the closing angle bracket of an SMTP path, ignoring
// brackets inside a quoted local-part (RFC 5321). start is the byte after '<'.
func SMTPPathEnd(path string, start int) int {
	quoted, escaped := false, false
	for i := start; i < len(path); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && path[i] == '\\':
			escaped = true
		case path[i] == '"':
			quoted = !quoted
		case !quoted && path[i] == '<':
			return -1
		case !quoted && path[i] == '>':
			return i
		}
	}
	return -1
}
