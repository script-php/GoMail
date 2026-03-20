package parser

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

// parseMIME parses a MIME multipart message body and extracts text, HTML, and attachments.
func parseMIME(parsed *ParsedMessage, contentType string, body []byte) error {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("parsing media type: %w", err)
	}

	boundary, ok := params["boundary"]
	if !ok {
		return fmt.Errorf("no boundary in Content-Type")
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	return walkParts(parsed, reader, mediaType)
}

// walkParts recursively walks MIME parts.
func walkParts(parsed *ParsedMessage, reader *multipart.Reader, parentType string) error {
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading MIME part: %w", err)
		}

		ct := part.Header.Get("Content-Type")
		if ct == "" {
			ct = "text/plain"
		}
		mediaType, params, _ := mime.ParseMediaType(ct)

		// Nested multipart
		if strings.HasPrefix(mediaType, "multipart/") {
			boundary := params["boundary"]
			if boundary != "" {
				data, _ := io.ReadAll(part)
				subReader := multipart.NewReader(bytes.NewReader(data), boundary)
				if err := walkParts(parsed, subReader, mediaType); err != nil {
					return err
				}
				continue
			}
		}

		data, err := readPartData(part)
		if err != nil {
			return fmt.Errorf("reading part data: %w", err)
		}

		disposition := part.Header.Get("Content-Disposition")

		// Is this an attachment?
		if isAttachment(disposition, mediaType) {
			filename := extractFilename(part.Header, params)
			parsed.Attachments = append(parsed.Attachments, ParsedAttachment{
				Filename:    filename,
				ContentType: mediaType,
				Data:        data,
			})
			continue
		}

		// Text content
		switch {
		case mediaType == "text/plain" && parsed.TextBody == "":
			parsed.TextBody = string(data)
		case mediaType == "text/html" && parsed.HTMLBody == "":
			parsed.HTMLBody = string(data)
		}
	}
	return nil
}

// readPartData reads and decodes a MIME part's content based on Content-Transfer-Encoding.
func readPartData(part *multipart.Part) ([]byte, error) {
	encoding := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))
	raw, err := io.ReadAll(part)
	if err != nil {
		return nil, err
	}

	switch encoding {
	case "base64":
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
		n, err := base64.StdEncoding.Decode(decoded, bytes.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		return decoded[:n], nil
	case "quoted-printable":
		// Go's multipart reader already handles QP if Content-Transfer-Encoding is set
		return raw, nil
	default:
		return raw, nil
	}
}

// isAttachment determines if a MIME part is an attachment.
func isAttachment(disposition, mediaType string) bool {
	if strings.HasPrefix(strings.ToLower(disposition), "attachment") {
		return true
	}
	// Inline images and other non-text types with filenames
	if strings.HasPrefix(strings.ToLower(disposition), "inline") &&
		!strings.HasPrefix(mediaType, "text/") {
		return true
	}
	return false
}

// extractFilename gets the filename from Content-Disposition or Content-Type params.
func extractFilename(headers textproto.MIMEHeader, ctParams map[string]string) string {
	// Try Content-Disposition first
	disposition := headers.Get("Content-Disposition")
	if disposition != "" {
		_, dParams, err := mime.ParseMediaType(disposition)
		if err == nil {
			if name := dParams["filename"]; name != "" {
				return name
			}
		}
	}
	// Fallback to Content-Type name parameter
	if name := ctParams["name"]; name != "" {
		return name
	}
	return "unnamed"
}
