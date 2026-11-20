package delivery

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

// sevenBitMIME converts eligible 8-bit MIME bodies before GoMail signs the
// queued message. It leaves already-signed or opaque content untouched: a
// relay must not invalidate signatures merely to reach a 7-bit-only peer.
func sevenBitMIME(raw []byte) []byte {
	separator := []byte("\r\n\r\n")
	cut := bytes.Index(raw, separator)
	if cut < 0 || !containsEightBit(raw[cut+len(separator):]) || !canonicalCRLF(raw) {
		return raw
	}
	headerBytes := raw[:cut]
	if containsEightBit(headerBytes) {
		return raw // SMTPUTF8 headers need a separate downgrade policy.
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil || message.Header.Get("MIME-Version") != "1.0" || message.Header.Get("DKIM-Signature") != "" ||
		message.Header.Get("ARC-Message-Signature") != "" || message.Header.Get("ARC-Seal") != "" {
		return raw
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil && message.Header.Get("Content-Type") != "" {
		return raw
	}
	if mediaType == "" {
		mediaType = "text/plain"
	}
	if protectedMIMEType(mediaType) {
		return raw
	}
	if strings.HasPrefix(mediaType, "multipart/") && strings.EqualFold(strings.TrimSpace(message.Header.Get("Content-Transfer-Encoding")), "binary") {
		return raw
	}
	body := raw[cut+len(separator):]
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		converted, changed, ok := sevenBitMultipart(body, boundary, 0)
		if !ok || !changed || containsEightBit(converted) {
			return raw
		}
		if strings.EqualFold(strings.TrimSpace(message.Header.Get("Content-Transfer-Encoding")), "8bit") {
			headerBytes, ok = setRawTransferEncoding(headerBytes, "7bit")
			if !ok {
				return raw
			}
		}
		result := make([]byte, 0, len(headerBytes)+len(separator)+len(converted))
		result = append(result, headerBytes...)
		result = append(result, separator...)
		return append(result, converted...)
	}
	converted, ok := sevenBitLeaf(body, message.Header.Get("Content-Transfer-Encoding"))
	if !ok {
		return raw
	}
	newHeaders, ok := setRawTransferEncoding(headerBytes, "quoted-printable")
	if !ok {
		return raw
	}
	result := make([]byte, 0, len(newHeaders)+len(separator)+len(converted))
	result = append(result, newHeaders...)
	result = append(result, separator...)
	return append(result, converted...)
}

func sevenBitMultipart(body []byte, boundary string, depth int) ([]byte, bool, bool) {
	if depth >= 8 || boundary == "" {
		return nil, false, false
	}
	first := []byte("--" + boundary + "\r\n")
	boundaryStart := 0
	if !bytes.HasPrefix(body, first) {
		index := bytes.Index(body, append([]byte("\r\n"), first...))
		if index < 0 {
			return nil, false, false
		}
		boundaryStart = index + 2
	}
	preamble := body[:boundaryStart]
	// The closing delimiter must begin a line. Preserve any legal epilogue;
	// it is part of the submitted MIME entity even though MIME readers ignore it.
	closing := []byte("--" + boundary + "--")
	end := -1
	if bytes.HasPrefix(body, closing) {
		end = 0
	}
	for search := 0; search < len(body); {
		index := bytes.Index(body[search:], append([]byte("\r\n"), closing...))
		if index < 0 {
			break
		}
		end = search + index + 2
		search = end + len(closing)
	}
	if end < 0 {
		return nil, false, false
	}
	epilogue := body[end+len(closing):]
	if containsEightBit(epilogue) {
		return nil, false, false
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var output bytes.Buffer
	writer := multipart.NewWriter(&output)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, false, false
	}
	changed := false
	partCount := 0
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, false
		}
		partCount++
		partBody, err := io.ReadAll(part)
		if err != nil || hasEightBitMIMEHeaders(part.Header) {
			return nil, false, false
		}
		partType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil && part.Header.Get("Content-Type") != "" {
			return nil, false, false
		}
		if partType == "" {
			partType = "text/plain"
		}
		if protectedMIMEType(partType) {
			return nil, false, false
		}
		headers := part.Header
		if strings.HasPrefix(partType, "multipart/") {
			if strings.EqualFold(strings.TrimSpace(headers.Get("Content-Transfer-Encoding")), "binary") {
				return nil, false, false
			}
			var nestedChanged, ok bool
			partBody, nestedChanged, ok = sevenBitMultipart(partBody, params["boundary"], depth+1)
			if !ok {
				return nil, false, false
			}
			changed = changed || nestedChanged
			if nestedChanged && strings.EqualFold(strings.TrimSpace(headers.Get("Content-Transfer-Encoding")), "8bit") {
				headers.Set("Content-Transfer-Encoding", "7bit")
			}
		} else if containsEightBit(partBody) {
			var ok bool
			partBody, ok = sevenBitLeaf(partBody, headers.Get("Content-Transfer-Encoding"))
			if !ok {
				return nil, false, false
			}
			headers.Set("Content-Transfer-Encoding", "quoted-printable")
			changed = true
		}
		partWriter, err := writer.CreatePart(headers)
		if err != nil {
			return nil, false, false
		}
		if _, err := partWriter.Write(partBody); err != nil {
			return nil, false, false
		}
	}
	if partCount == 0 || writer.Close() != nil {
		return nil, false, false
	}
	converted := append(append([]byte(nil), preamble...), output.Bytes()...)
	// multipart.Writer writes its own closing delimiter and CRLF. Retain the
	// original post-delimiter bytes, omitting only the CRLF it already wrote.
	if bytes.HasPrefix(epilogue, []byte("\r\n")) {
		epilogue = epilogue[2:]
	}
	return append(converted, epilogue...), changed, true
}

func sevenBitLeaf(body []byte, transferEncoding string) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(transferEncoding)) {
	case "", "7bit", "8bit":
	default:
		return nil, false
	}
	var output bytes.Buffer
	writer := quotedprintable.NewWriter(&output)
	if _, err := writer.Write(body); err != nil || writer.Close() != nil {
		return nil, false
	}
	if containsEightBit(output.Bytes()) {
		return nil, false
	}
	return output.Bytes(), true
}

func setRawTransferEncoding(headers []byte, encoding string) ([]byte, bool) {
	lines := bytes.Split(headers, []byte("\r\n"))
	var output [][]byte
	found := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if bytes.HasPrefix(line, []byte(" ")) || bytes.HasPrefix(line, []byte("\t")) {
			return nil, false // Unexpected continuation without its field.
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 1 {
			return nil, false
		}
		if strings.EqualFold(string(line[:colon]), "Content-Transfer-Encoding") {
			if found {
				return nil, false
			}
			found = true
			output = append(output, []byte("Content-Transfer-Encoding: "+encoding))
			for i+1 < len(lines) && (bytes.HasPrefix(lines[i+1], []byte(" ")) || bytes.HasPrefix(lines[i+1], []byte("\t"))) {
				i++
			}
			continue
		}
		output = append(output, line)
		for i+1 < len(lines) && (bytes.HasPrefix(lines[i+1], []byte(" ")) || bytes.HasPrefix(lines[i+1], []byte("\t"))) {
			i++
			output = append(output, lines[i])
		}
	}
	if !found {
		output = append(output, []byte("Content-Transfer-Encoding: "+encoding))
	}
	return bytes.Join(output, []byte("\r\n")), true
}

func hasEightBitMIMEHeaders(headers textproto.MIMEHeader) bool {
	for key, values := range headers {
		if containsEightBit([]byte(key)) {
			return true
		}
		for _, value := range values {
			if containsEightBit([]byte(value)) {
				return true
			}
		}
	}
	return false
}

func protectedMIMEType(mediaType string) bool {
	return mediaType == "multipart/signed" || mediaType == "multipart/encrypted" ||
		strings.HasPrefix(mediaType, "message/") || mediaType == "application/pkcs7-mime" ||
		mediaType == "application/x-pkcs7-mime"
}

func containsEightBit(data []byte) bool {
	for _, b := range data {
		if b >= 0x80 {
			return true
		}
	}
	return false
}

func canonicalCRLF(data []byte) bool {
	for i, b := range data {
		if b == '\r' && (i+1 == len(data) || data[i+1] != '\n') ||
			b == '\n' && (i == 0 || data[i-1] != '\r') {
			return false
		}
	}
	return true
}
