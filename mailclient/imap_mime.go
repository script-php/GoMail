package mailclient

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strconv"
	"strings"
)

const maxIMAPMIMEDepth = 30

type imapMIMEEntity struct {
	header    textproto.MIMEHeader
	headerRaw []byte
	bodyRaw   []byte
	mediaType string
	params    map[string]string
	encoding  string
	children  []*imapMIMEEntity
	embedded  *imapMIMEEntity
}

func parseIMAPMIME(raw []byte) (*imapMIMEEntity, error) {
	return parseIMAPMIMEEntity(raw, 0)
}

func parseIMAPMIMEEntity(raw []byte, depth int) (*imapMIMEEntity, error) {
	if depth > maxIMAPMIMEDepth {
		return nil, fmt.Errorf("MIME nesting exceeds limit")
	}
	headerRaw, body := splitRawEntity(raw)
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(headerRaw)))
	header, err := reader.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("reading MIME header: %w", err)
	}
	contentType := header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType, params = "application/octet-stream", map[string]string{}
	}
	entity := &imapMIMEEntity{
		header: header, headerRaw: headerRaw, bodyRaw: body,
		mediaType: strings.ToLower(mediaType), params: params,
		encoding: strings.ToUpper(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))),
	}
	if entity.encoding == "" {
		entity.encoding = "7BIT"
	}
	if strings.HasPrefix(entity.mediaType, "multipart/") && params["boundary"] != "" {
		rawHeaders := multipartPartHeaders(body, params["boundary"])
		parts := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			part, partErr := parts.NextRawPart()
			if partErr == io.EOF {
				break
			}
			if partErr != nil {
				return nil, fmt.Errorf("reading MIME multipart: %w", partErr)
			}
			if len(entity.children) >= len(rawHeaders) {
				return nil, fmt.Errorf("MIME part headers not found in original message")
			}
			partBody, readErr := io.ReadAll(io.LimitReader(part, 128<<20))
			if readErr != nil {
				return nil, readErr
			}
			partRaw := append(append([]byte(nil), rawHeaders[len(entity.children)]...), partBody...)
			child, childErr := parseIMAPMIMEEntity(partRaw, depth+1)
			if childErr != nil {
				return nil, childErr
			}
			entity.children = append(entity.children, child)
		}
		if len(entity.children) != len(rawHeaders) {
			return nil, fmt.Errorf("MIME part count differs from original message")
		}
	}
	if entity.mediaType == "message/rfc822" {
		decoded := entity.bodyRaw
		switch entity.encoding {
		case "BASE64":
			if value, decodeErr := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(entity.bodyRaw))); decodeErr == nil {
				decoded = value
			}
		case "QUOTED-PRINTABLE":
			if value, decodeErr := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(entity.bodyRaw))); decodeErr == nil {
				decoded = value
			}
		}
		if embedded, embeddedErr := parseIMAPMIMEEntity(decoded, depth+1); embeddedErr == nil {
			entity.embedded = embedded
		}
	}
	return entity, nil
}

func splitRawEntity(raw []byte) ([]byte, []byte) {
	if index := bytes.Index(raw, []byte("\r\n\r\n")); index >= 0 {
		return raw[:index+4], raw[index+4:]
	}
	if index := bytes.Index(raw, []byte("\n\n")); index >= 0 {
		return raw[:index+2], raw[index+2:]
	}
	return raw, nil
}

// multipart.Part exposes parsed headers but not their original bytes. Locate
// delimiter lines in the stored body so BODY[part.MIME] can return the exact
// header octets rather than a reserialized map.
func multipartPartHeaders(body []byte, boundary string) [][]byte {
	marker := []byte("--" + boundary)
	var headers [][]byte
	for start := 0; start < len(body); {
		end := bytes.IndexByte(body[start:], '\n')
		if end < 0 {
			end = len(body)
		} else {
			end += start + 1
		}
		line := bytes.TrimSuffix(body[start:end], []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, marker) {
			rest := bytes.TrimSpace(line[len(marker):])
			if len(rest) == 0 {
				headerStart := end
				for headerEnd := headerStart; headerEnd < len(body); {
					lineEnd := bytes.IndexByte(body[headerEnd:], '\n')
					if lineEnd < 0 {
						break
					}
					lineEnd += headerEnd + 1
					if bytes.Equal(body[headerEnd:lineEnd], []byte("\r\n")) || bytes.Equal(body[headerEnd:lineEnd], []byte("\n")) {
						headers = append(headers, body[headerStart:lineEnd])
						break
					}
					headerEnd = lineEnd
				}
			} else if bytes.Equal(rest, []byte("--")) {
				break
			}
		}
		start = end
	}
	return headers
}

func (entity *imapMIMEEntity) part(path []int) *imapMIMEEntity {
	if len(path) == 0 {
		return entity
	}
	current := entity
	implicitPartOne := len(current.children) == 0
	for _, number := range path {
		if current.embedded != nil {
			current = current.embedded
			implicitPartOne = len(current.children) == 0
		}
		if len(current.children) == 0 {
			// RFC 3501 numbers a non-multipart top-level body as part 1.
			if number == 1 && implicitPartOne {
				implicitPartOne = false
				continue
			}
			return nil
		}
		if number < 1 || number > len(current.children) {
			return nil
		}
		current = current.children[number-1]
		implicitPartOne = false
	}
	return current
}

func (entity *imapMIMEEntity) bodyStructure(extended bool) string {
	if len(entity.children) > 0 && strings.HasPrefix(entity.mediaType, "multipart/") {
		parts := make([]string, 0, len(entity.children)+5)
		for _, child := range entity.children {
			parts = append(parts, child.bodyStructure(extended))
		}
		subtype := strings.TrimPrefix(entity.mediaType, "multipart/")
		parts = append(parts, quoteIMAP(strings.ToUpper(subtype)))
		if extended {
			parts = append(parts, imapBodyParams(entity.params), imapDisposition(entity.header.Get("Content-Disposition")), "NIL", "NIL")
		}
		return "(" + strings.Join(parts, " ") + ")"
	}
	major, subtype := "APPLICATION", "OCTET-STREAM"
	if pieces := strings.SplitN(entity.mediaType, "/", 2); len(pieces) == 2 {
		major, subtype = strings.ToUpper(pieces[0]), strings.ToUpper(pieces[1])
	}
	values := []string{
		quoteIMAP(major), quoteIMAP(subtype), imapBodyParams(entity.params),
		nstring(strings.Trim(entity.header.Get("Content-ID"), "<> ")), nstring(entity.header.Get("Content-Description")),
		quoteIMAP(entity.encoding), strconv.Itoa(len(entity.bodyRaw)),
	}
	if major == "TEXT" {
		values = append(values, strconv.Itoa(bytes.Count(entity.bodyRaw, []byte("\n"))))
	} else if major == "MESSAGE" && subtype == "RFC822" {
		if entity.embedded != nil {
			values = append(values, imapEnvelopeHeader(entity.embedded.header), entity.embedded.bodyStructure(extended), strconv.Itoa(bytes.Count(entity.bodyRaw, []byte("\n"))))
		} else {
			values = append(values, "NIL", "NIL", strconv.Itoa(bytes.Count(entity.bodyRaw, []byte("\n"))))
		}
	}
	if extended {
		values = append(values, "NIL", imapDisposition(entity.header.Get("Content-Disposition")), "NIL", "NIL")
	}
	return "(" + strings.Join(values, " ") + ")"
}

func imapBodyParams(params map[string]string) string {
	if len(params) == 0 {
		return "NIL"
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	// Stable output is valuable for clients, tests and debugging.
	slicesSort(keys)
	values := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		values = append(values, quoteIMAP(strings.ToUpper(key)), quoteIMAP(params[key]))
	}
	return "(" + strings.Join(values, " ") + ")"
}

func slicesSort(values []string) {
	for index := 1; index < len(values); index++ {
		for current := index; current > 0 && values[current] < values[current-1]; current-- {
			values[current], values[current-1] = values[current-1], values[current]
		}
	}
}

func imapDisposition(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	disposition, params, err := mime.ParseMediaType(value)
	if err != nil {
		return "NIL"
	}
	return "(" + quoteIMAP(strings.ToUpper(disposition)) + " " + imapBodyParams(params) + ")"
}

func filterRawHeaders(header []byte, wanted map[string]bool, invert bool) []byte {
	lines := strings.Split(strings.ReplaceAll(string(header), "\r\n", "\n"), "\n")
	var output strings.Builder
	include := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			name, _, _ := strings.Cut(line, ":")
			include = wanted[strings.ToUpper(strings.TrimSpace(name))]
			if invert {
				include = !include
			}
		}
		if include {
			output.WriteString(line)
			output.WriteString("\r\n")
		}
	}
	output.WriteString("\r\n")
	return []byte(output.String())
}

type imapBodyRequest struct {
	label        string
	section      string
	peek         bool
	partialStart int
	partialCount int
	hasPartial   bool
}

func parseIMAPBodyRequest(item string) (imapBodyRequest, bool) {
	upper := strings.ToUpper(strings.TrimSpace(item))
	request := imapBodyRequest{partialCount: -1}
	if strings.HasPrefix(upper, "BODY.PEEK[") {
		request.peek = true
	} else if !strings.HasPrefix(upper, "BODY[") {
		return request, false
	}
	open := strings.Index(upper, "[")
	close := strings.LastIndex(upper, "]")
	if open < 0 || close < open {
		return request, false
	}
	request.section = strings.TrimSpace(upper[open+1 : close])
	request.label = "BODY[" + request.section + "]"
	suffix := strings.TrimSpace(upper[close+1:])
	if suffix != "" {
		if len(suffix) < 5 || suffix[0] != '<' || suffix[len(suffix)-1] != '>' {
			return imapBodyRequest{}, false
		}
		pieces := strings.Split(suffix[1:len(suffix)-1], ".")
		if len(pieces) != 2 {
			return imapBodyRequest{}, false
		}
		start, startErr := strconv.Atoi(pieces[0])
		count, countErr := strconv.Atoi(pieces[1])
		if startErr != nil || countErr != nil || start < 0 || count < 0 {
			return imapBodyRequest{}, false
		}
		request.partialStart, request.partialCount, request.hasPartial = start, count, true
		request.label += "<" + strconv.Itoa(start) + ">"
	}
	return request, true
}

func (entity *imapMIMEEntity) section(request imapBodyRequest, raw []byte) ([]byte, error) {
	if request.section == "" {
		return raw, nil
	}
	components := strings.Split(request.section, ".")
	var path []int
	for len(components) > 0 {
		number, err := strconv.Atoi(components[0])
		if err != nil {
			break
		}
		if number < 1 {
			return nil, fmt.Errorf("invalid MIME part number")
		}
		path = append(path, number)
		components = components[1:]
	}
	target := entity.part(path)
	if target == nil {
		return nil, fmt.Errorf("MIME part does not exist")
	}
	selector := strings.Join(components, ".")
	switch {
	case selector == "":
		return target.bodyRaw, nil
	case selector == "MIME":
		return target.headerRaw, nil
	case selector == "HEADER":
		if target.embedded != nil {
			return target.embedded.headerRaw, nil
		}
		return target.headerRaw, nil
	case selector == "TEXT":
		if target.embedded != nil {
			return target.embedded.bodyRaw, nil
		}
		return target.bodyRaw, nil
	case strings.HasPrefix(selector, "HEADER.FIELDS.NOT "):
		fields, ok := parseHeaderFieldList(strings.TrimPrefix(selector, "HEADER.FIELDS.NOT "))
		if !ok {
			return nil, fmt.Errorf("invalid HEADER.FIELDS.NOT list")
		}
		return filterRawHeaders(target.headerRaw, fields, true), nil
	case strings.HasPrefix(selector, "HEADER.FIELDS "):
		fields, ok := parseHeaderFieldList(strings.TrimPrefix(selector, "HEADER.FIELDS "))
		if !ok {
			return nil, fmt.Errorf("invalid HEADER.FIELDS list")
		}
		return filterRawHeaders(target.headerRaw, fields, false), nil
	default:
		return nil, fmt.Errorf("unsupported body section")
	}
}

func parseHeaderFieldList(value string) (map[string]bool, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
		return nil, false
	}
	result := make(map[string]bool)
	for _, field := range strings.Fields(value[1 : len(value)-1]) {
		if strings.ContainsAny(field, "():[]{}\\\"") {
			return nil, false
		}
		result[strings.ToUpper(field)] = true
	}
	return result, len(result) > 0
}

func applyIMAPPartial(data []byte, request imapBodyRequest) []byte {
	if !request.hasPartial {
		return data
	}
	if request.partialStart >= len(data) {
		return []byte{}
	}
	end := request.partialStart + request.partialCount
	if end < request.partialStart || end > len(data) {
		end = len(data)
	}
	return data[request.partialStart:end]
}
