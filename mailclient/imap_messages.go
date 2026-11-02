package mailclient

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"gomail/logging"
	"gomail/metrics"
	"gomail/parser"
	"gomail/store"
)

func (s *imapSession) appendMessage(tag string, arguments []string) {
	if len(arguments) < 1 || s.literal == nil {
		s.tagged(tag, "BAD APPEND requires a mailbox and synchronized literal")
		return
	}
	folder := s.findFolder(arguments[0])
	if folder == nil {
		s.tagged(tag, "NO [TRYCREATE] destination mailbox not found")
		return
	}
	flags := parsedIMAPFlags{system: make(map[string]bool)}
	remaining := arguments[1:]
	if len(remaining) > 0 && strings.HasPrefix(remaining[0], "(") {
		end := -1
		for index, value := range remaining {
			if strings.HasSuffix(value, ")") {
				end = index
				break
			}
		}
		if end < 0 {
			s.tagged(tag, "BAD invalid APPEND flag list")
			return
		}
		var valid bool
		flags, valid = parseStoreFlags(strings.Join(remaining[:end+1], " "))
		if !valid {
			s.tagged(tag, "BAD invalid APPEND flag list")
			return
		}
		remaining = remaining[end+1:]
	}
	receivedAt := time.Now().UTC()
	if len(remaining) > 1 {
		s.tagged(tag, "BAD invalid APPEND arguments")
		return
	}
	if len(remaining) == 1 {
		var err error
		receivedAt, err = time.Parse("02-Jan-2006 15:04:05 -0700", remaining[0])
		if err != nil {
			s.tagged(tag, "BAD invalid APPEND date-time")
			return
		}
	}
	parsed, err := parser.Parse(s.literal)
	if err != nil {
		s.tagged(tag, "NO invalid RFC 5322 message")
		return
	}
	direction := "inbound"
	if folder.FolderType == "drafts" {
		direction = "draft"
	} else if folder.FolderType == "sent" {
		direction = "outbound"
	}
	messageID := parsed.MessageID
	if messageID == "" {
		messageID = fmt.Sprintf("%d.append@%s", time.Now().UnixNano(), s.server.cfg.Server.Hostname)
	}
	message := &store.Message{
		AccountID: s.account.ID, FolderID: &folder.ID, MessageID: messageID, Direction: direction,
		MailFrom: parsed.From, RcptTo: parsed.To, FromAddr: parsed.From, ToAddr: parsed.To,
		CcAddr: parsed.Cc, ReplyTo: parsed.ReplyTo, Subject: parsed.Subject, TextBody: parsed.TextBody,
		HTMLBody: parsed.HTMLBody, RawHeaders: parsed.RawHeaders, RawMessage: append([]byte(nil), s.literal...),
		Size: int64(len(s.literal)), HasAttachments: len(parsed.Attachments) > 0,
		IsDeleted: folder.FolderType == "trash", MDNRequested: parsed.MDNRequestedBy != "",
		MDNAddress: parsed.MDNRequestedBy, ReceivedAt: receivedAt,
	}
	mutation := appendFlagMutation(flags)
	attachments := make([]store.IMAPAppendAttachment, 0, len(parsed.Attachments))
	for _, attachment := range parsed.Attachments {
		attachments = append(attachments, store.IMAPAppendAttachment{Filename: attachment.Filename, ContentType: attachment.ContentType, Data: attachment.Data})
	}
	_, uid, err := s.server.db.AppendIMAPMessageWithAttachments(message, mutation, attachments)
	if err != nil {
		if errors.Is(err, store.ErrDiskPressure) {
			s.tagged(tag, "NO [UNAVAILABLE] insufficient system storage")
		} else if errors.Is(err, store.ErrQuotaExceeded) {
			metrics.IncQuota("imap")
			s.tagged(tag, "NO [OVERQUOTA] mailbox quota exceeded")
		} else {
			s.tagged(tag, "NO APPEND failed")
		}
		return
	}
	mailbox, err := s.server.db.GetIMAPMailboxState(s.account.ID, folder.ID)
	if err != nil || mailbox == nil {
		logging.Warn(fmt.Sprintf("[imap] APPEND committed but mailbox identity lookup failed: %v", err))
		s.tagged(tag, "OK APPEND completed")
		return
	}
	s.tagged(tag, fmt.Sprintf("OK [APPENDUID %d %d] APPEND completed", mailbox.UIDValidity, uid))
}

func appendFlagMutation(flags parsedIMAPFlags) store.IMAPFlagMutation {
	value := func(present bool) *bool { result := present; return &result }
	return store.IMAPFlagMutation{
		Mode: "replace", Seen: value(flags.system["\\SEEN"]), Flagged: value(flags.system["\\FLAGGED"]),
		Answered: value(flags.system["\\ANSWERED"]), Deleted: value(flags.system["\\DELETED"]),
		Draft: value(flags.system["\\DRAFT"]), Keywords: flags.keywords,
	}
}

func (s *imapSession) fetch(tag string, arguments []string, byUID bool) {
	if len(arguments) < 2 {
		s.tagged(tag, "BAD FETCH requires a sequence set and data items")
		return
	}
	dataEnd := 2
	if arguments[1] == "(" {
		depth := 0
		dataEnd = -1
		for index := 1; index < len(arguments); index++ {
			switch arguments[index] {
			case "(":
				depth++
			case ")":
				depth--
				if depth == 0 {
					dataEnd = index + 1
				}
			}
			if dataEnd > 0 {
				break
			}
		}
		if dataEnd < 0 {
			s.tagged(tag, "BAD unterminated FETCH data items")
			return
		}
	}
	if dataEnd > len(arguments) {
		s.tagged(tag, "BAD invalid FETCH data items")
		return
	}
	requested := parseFetchItems(strings.Join(arguments[1:dataEnd], " "))
	if len(requested) == 0 {
		s.tagged(tag, "BAD empty FETCH data items")
		return
	}
	var changedSince uint64
	hasChangedSince := false
	if dataEnd < len(arguments) {
		modifier := strings.ToUpper(strings.Join(arguments[dataEnd:], " "))
		fields := strings.Fields(strings.Trim(modifier, "() "))
		if len(fields) != 2 || fields[0] != "CHANGEDSINCE" {
			s.tagged(tag, "BAD unsupported FETCH modifier")
			return
		}
		var parseErr error
		changedSince, parseErr = strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			s.tagged(tag, "BAD invalid CHANGEDSINCE value")
			return
		}
		hasChangedSince = true
		s.condstore = true
		if !containsFetchItem(requested, "MODSEQ") {
			requested = append(requested, "MODSEQ")
		}
	}
	refs, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		s.tagged(tag, "NO unable to list messages")
		return
	}
	selected, err := resolveIMAPSequenceSet(arguments[0], refs, byUID)
	if err != nil {
		s.tagged(tag, "BAD "+err.Error())
		return
	}
	if hasChangedSince {
		filtered := selected[:0]
		for _, ref := range selected {
			if ref.ModSeq > changedSince {
				filtered = append(filtered, ref)
			}
		}
		selected = filtered
	}
	for _, ref := range selected {
		message, err := s.server.db.GetMessage(ref.MessageID, s.account.ID)
		if err != nil || message == nil {
			s.tagged(tag, "NO message disappeared during FETCH")
			return
		}
		if byUID && !containsFetchItem(requested, "UID") {
			requested = append([]string{"UID"}, requested...)
		}
		if err := s.writeFetch(ref, message, requested); err != nil {
			s.tagged(tag, "NO FETCH failed")
			return
		}
	}
	s.tagged(tag, "OK FETCH completed")
}

func parseFetchItems(value string) []string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	var items []string
	start, bracketDepth, parenDepth := -1, 0, 0
	for index, char := range value {
		if start < 0 && char != ' ' && char != '\t' {
			start = index
		}
		if start < 0 {
			continue
		}
		switch char {
		case '[':
			bracketDepth++
		case ']':
			bracketDepth--
		case '(':
			parenDepth++
		case ')':
			parenDepth--
		case ' ', '\t':
			if bracketDepth == 0 && parenDepth == 0 {
				items = append(items, value[start:index])
				start = -1
			}
		}
		if bracketDepth < 0 || parenDepth < 0 {
			return nil
		}
	}
	if start >= 0 {
		items = append(items, value[start:])
	}
	if bracketDepth != 0 || parenDepth != 0 {
		return nil
	}
	if len(items) == 1 {
		switch strings.ToUpper(items[0]) {
		case "ALL":
			items = []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"}
		case "FAST":
			items = []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE"}
		case "FULL":
			items = []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"}
		}
	}
	for index := range items {
		items[index] = strings.ToUpper(items[index])
	}
	return items
}

func containsFetchItem(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func (s *imapSession) writeFetch(ref store.IMAPMessageRef, message *store.Message, items []string) error {
	ref = s.sessionRef(ref)
	type responsePart struct {
		value     string
		literal   []byte
		isLiteral bool
	}
	parts := make([]responsePart, 0, len(items))
	markSeen := false
	var entity *imapMIMEEntity
	getEntity := func() (*imapMIMEEntity, error) {
		if entity != nil {
			return entity, nil
		}
		var err error
		entity, err = parseIMAPMIME(message.RawMessage)
		return entity, err
	}
	for _, item := range items {
		if request, ok := parseIMAPBodyRequest(item); ok {
			parsed, err := getEntity()
			if err != nil {
				return err
			}
			_, err = parsed.section(request, message.RawMessage)
			if err != nil {
				return err
			}
			markSeen = markSeen || !request.peek
			continue
		}
		switch item {
		case "BODYSTRUCTURE", "BODY":
			_, err := getEntity()
			if err != nil {
				return err
			}
		case "RFC822", "RFC822.HEADER", "RFC822.TEXT":
			markSeen = markSeen || item != "RFC822.HEADER"
		}
	}
	if markSeen && !ref.Seen && !s.readOnly {
		if err := s.server.db.MarkRead(ref.MessageID); err != nil {
			return err
		}
		ref.Seen = true
	}
	// Scalar fields are added after Seen is updated so a FLAGS response in the
	// same FETCH reflects the side effect of a non-PEEK body retrieval.
	for _, item := range items {
		if request, ok := parseIMAPBodyRequest(item); ok {
			parsed, err := getEntity()
			if err != nil {
				return err
			}
			literal, err := parsed.section(request, message.RawMessage)
			if err != nil {
				return err
			}
			parts = append(parts, responsePart{value: request.label, literal: applyIMAPPartial(literal, request), isLiteral: true})
			continue
		}
		switch item {
		case "UID":
			parts = append(parts, responsePart{value: "UID " + strconv.FormatUint(uint64(ref.UID), 10)})
		case "FLAGS":
			parts = append(parts, responsePart{value: "FLAGS " + imapFlags(ref)})
		case "MODSEQ":
			s.condstore = true
			parts = append(parts, responsePart{value: fmt.Sprintf("MODSEQ (%d)", ref.ModSeq)})
		case "RFC822.SIZE":
			parts = append(parts, responsePart{value: "RFC822.SIZE " + strconv.Itoa(len(message.RawMessage))})
		case "INTERNALDATE":
			parts = append(parts, responsePart{value: "INTERNALDATE " + quoteIMAP(message.ReceivedAt.Format("02-Jan-2006 15:04:05 -0700"))})
		case "ENVELOPE":
			parts = append(parts, responsePart{value: "ENVELOPE " + imapEnvelope(message)})
		case "BODYSTRUCTURE", "BODY":
			parsed, err := getEntity()
			if err != nil {
				return err
			}
			parts = append(parts, responsePart{value: item + " " + parsed.bodyStructure(item == "BODYSTRUCTURE")})
		case "RFC822", "RFC822.HEADER", "RFC822.TEXT":
			literal := message.RawMessage
			if item == "RFC822.HEADER" {
				literal = rawHeader(message.RawMessage)
			} else if item == "RFC822.TEXT" {
				literal = rawBody(message.RawMessage)
			}
			parts = append(parts, responsePart{value: item, literal: literal, isLiteral: true})
		default:
			if _, ok := parseIMAPBodyRequest(item); !ok {
				return fmt.Errorf("unsupported FETCH item %s", item)
			}
		}
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.server.writeTimeout()))
	if _, err := s.writer.WriteString(fmt.Sprintf("* %d FETCH (", ref.Sequence)); err != nil {
		return err
	}
	for index, part := range parts {
		if index > 0 {
			if _, err := s.writer.WriteString(" "); err != nil {
				return err
			}
		}
		if !part.isLiteral {
			if _, err := s.writer.WriteString(part.value); err != nil {
				return err
			}
			continue
		}
		if _, err := s.writer.WriteString(fmt.Sprintf("%s {%d}\r\n", part.value, len(part.literal))); err != nil {
			return err
		}
		if _, err := s.writer.Write(part.literal); err != nil {
			return err
		}
	}
	if _, err := s.writer.WriteString(")\r\n"); err != nil {
		return err
	}
	return s.writer.Flush()
}

func imapFlags(ref store.IMAPMessageRef) string {
	var flags []string
	if ref.Seen {
		flags = append(flags, "\\Seen")
	}
	if ref.Answered {
		flags = append(flags, "\\Answered")
	}
	if ref.Flagged {
		flags = append(flags, "\\Flagged")
	}
	if ref.Deleted {
		flags = append(flags, "\\Deleted")
	}
	if ref.Draft {
		flags = append(flags, "\\Draft")
	}
	if ref.Recent {
		flags = append(flags, "\\Recent")
	}
	flags = append(flags, ref.Keywords...)
	return "(" + strings.Join(flags, " ") + ")"
}

func rawHeader(raw []byte) []byte {
	if index := bytes.Index(raw, []byte("\r\n\r\n")); index >= 0 {
		return raw[:index+4]
	}
	if index := bytes.Index(raw, []byte("\n\n")); index >= 0 {
		return raw[:index+2]
	}
	return raw
}

func rawBody(raw []byte) []byte {
	if index := bytes.Index(raw, []byte("\r\n\r\n")); index >= 0 {
		return raw[index+4:]
	}
	if index := bytes.Index(raw, []byte("\n\n")); index >= 0 {
		return raw[index+2:]
	}
	return nil
}

func imapEnvelope(message *store.Message) string {
	if parsed, err := mail.ReadMessage(bytes.NewReader(message.RawMessage)); err == nil {
		return imapEnvelopeHeader(textproto.MIMEHeader(parsed.Header))
	}
	header := textproto.MIMEHeader{
		"Date":       []string{message.ReceivedAt.Format(time.RFC1123Z)},
		"Subject":    []string{message.Subject},
		"From":       []string{message.FromAddr},
		"Reply-To":   []string{message.ReplyTo},
		"To":         []string{message.ToAddr},
		"Cc":         []string{message.CcAddr},
		"Message-Id": []string{message.MessageID},
	}
	return imapEnvelopeHeader(header)
}

func imapEnvelopeHeader(header textproto.MIMEHeader) string {
	from := imapAddressList(header.Get("From"))
	sender := imapAddressList(header.Get("Sender"))
	if sender == "NIL" {
		sender = from
	}
	replyTo := imapAddressList(header.Get("Reply-To"))
	if replyTo == "NIL" {
		replyTo = from
	}
	return fmt.Sprintf("(%s %s %s %s %s %s %s %s %s %s)",
		nstring(header.Get("Date")), nstring(header.Get("Subject")), from, sender, replyTo,
		imapAddressList(header.Get("To")), imapAddressList(header.Get("Cc")), imapAddressList(header.Get("Bcc")),
		nstring(header.Get("In-Reply-To")), nstring(header.Get("Message-ID")))
}

func imapAddressList(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "NIL"
	}
	addresses, err := mail.ParseAddressList(value)
	if err != nil || len(addresses) == 0 {
		return "NIL"
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		mailbox, host, found := splitIMAPMailbox(address.Address)
		if !found {
			continue
		}
		result = append(result, "("+nstring(address.Name)+" NIL "+nstring(mailbox)+" "+nstring(host)+")")
	}
	if len(result) == 0 {
		return "NIL"
	}
	return "(" + strings.Join(result, " ") + ")"
}

// An RFC 5322 quoted local-part can contain '@'. IMAP ENVELOPE stores the
// unquoted local-part and host as separate fields (RFC 3501 section 9).
func splitIMAPMailbox(address string) (mailbox, host string, ok bool) {
	quoted, escaped, separator := false, false, -1
	for i := 0; i < len(address); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && address[i] == '\\':
			escaped = true
		case address[i] == '"':
			quoted = !quoted
		case !quoted && address[i] == '@':
			separator = i
		}
	}
	if quoted || escaped || separator < 1 || separator == len(address)-1 {
		return "", "", false
	}
	mailbox, host = address[:separator], address[separator+1:]
	if len(mailbox) >= 2 && mailbox[0] == '"' && mailbox[len(mailbox)-1] == '"' {
		var unquoted strings.Builder
		for i := 1; i < len(mailbox)-1; i++ {
			if mailbox[i] == '\\' && i+1 < len(mailbox)-1 {
				i++
			}
			unquoted.WriteByte(mailbox[i])
		}
		mailbox = unquoted.String()
	}
	return mailbox, host, mailbox != "" && host != ""
}

func nstring(value string) string {
	if value == "" {
		return "NIL"
	}
	return quoteIMAP(value)
}

func (s *imapSession) search(tag string, arguments []string, byUID bool) {
	if len(arguments) >= 2 && strings.EqualFold(arguments[0], "CHARSET") {
		if !strings.EqualFold(arguments[1], "UTF-8") && !strings.EqualFold(arguments[1], "US-ASCII") {
			s.tagged(tag, "NO [BADCHARSET (UTF-8 US-ASCII)] unsupported charset")
			return
		}
		arguments = arguments[2:]
	}
	if len(arguments) == 0 {
		arguments = []string{"ALL"}
	}
	refs, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		s.tagged(tag, "NO SEARCH failed")
		return
	}
	for index := range refs {
		refs[index] = s.sessionRef(refs[index])
	}
	predicate, err := parseIMAPSearch(arguments, refs)
	if err != nil {
		s.tagged(tag, "BAD "+err.Error())
		return
	}
	var matches []string
	var highestMatchedModSeq uint64
	for _, ref := range refs {
		message, err := s.server.db.GetMessage(ref.MessageID, s.account.ID)
		if err != nil || message == nil {
			s.tagged(tag, "NO SEARCH failed")
			return
		}
		if predicate(ref, message) {
			if ref.ModSeq > highestMatchedModSeq {
				highestMatchedModSeq = ref.ModSeq
			}
			value := ref.Sequence
			if byUID {
				value = ref.UID
			}
			matches = append(matches, strconv.FormatUint(uint64(value), 10))
		}
	}
	response := "SEARCH " + strings.Join(matches, " ")
	if containsIMAPToken(arguments, "MODSEQ") {
		s.condstore = true
		response += fmt.Sprintf(" (MODSEQ %d)", highestMatchedModSeq)
	}
	s.untagged(response)
	s.tagged(tag, "OK SEARCH completed")
}

func containsIMAPToken(tokens []string, wanted string) bool {
	for _, token := range tokens {
		if strings.EqualFold(token, wanted) {
			return true
		}
	}
	return false
}

func (s *imapSession) storeFlags(tag string, arguments []string, byUID bool) {
	if s.readOnly {
		s.tagged(tag, "NO [READ-ONLY] mailbox is read-only")
		return
	}
	if len(arguments) < 3 {
		s.tagged(tag, "BAD STORE requires sequence set, operation and flags")
		return
	}
	operationIndex := 1
	var unchangedSince uint64
	hasUnchangedSince := false
	if arguments[1] == "(" {
		if len(arguments) < 7 || !strings.EqualFold(arguments[2], "UNCHANGEDSINCE") || arguments[4] != ")" {
			s.tagged(tag, "BAD unsupported STORE modifier")
			return
		}
		var parseErr error
		unchangedSince, parseErr = strconv.ParseUint(arguments[3], 10, 64)
		if parseErr != nil {
			s.tagged(tag, "BAD invalid UNCHANGEDSINCE value")
			return
		}
		hasUnchangedSince, s.condstore, operationIndex = true, true, 5
	}
	if len(arguments) <= operationIndex+1 {
		s.tagged(tag, "BAD STORE requires an operation and flags")
		return
	}
	refs, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		s.tagged(tag, "NO STORE failed")
		return
	}
	selected, err := resolveIMAPSequenceSet(arguments[0], refs, byUID)
	if err != nil {
		s.tagged(tag, "BAD "+err.Error())
		return
	}
	operation := strings.ToUpper(arguments[operationIndex])
	silent := strings.HasSuffix(operation, ".SILENT")
	operation = strings.TrimSuffix(operation, ".SILENT")
	mode := map[string]string{"FLAGS": "replace", "+FLAGS": "add", "-FLAGS": "remove"}[operation]
	if mode == "" {
		s.tagged(tag, "BAD invalid STORE operation")
		return
	}
	flags, valid := parseStoreFlags(strings.Join(arguments[operationIndex+1:], " "))
	if !valid {
		s.tagged(tag, "BAD invalid flag list")
		return
	}
	mutation := store.IMAPFlagMutation{Mode: mode}
	setValue := func(present bool) *bool {
		if mode == "replace" {
			value := present
			return &value
		}
		if !present {
			return nil
		}
		value := mode == "add"
		return &value
	}
	mutation.Seen = setValue(flags.system["\\SEEN"])
	mutation.Flagged = setValue(flags.system["\\FLAGGED"])
	mutation.Answered = setValue(flags.system["\\ANSWERED"])
	mutation.Deleted = setValue(flags.system["\\DELETED"])
	mutation.Draft = setValue(flags.system["\\DRAFT"])
	mutation.Keywords = flags.keywords
	ids := make([]int64, len(selected))
	for index := range selected {
		ids[index] = selected[index].MessageID
	}
	var modified []store.IMAPMessageRef
	if len(ids) > 0 {
		if hasUnchangedSince {
			modifiedIDs, updateErr := s.server.db.UpdateIMAPFlagsConditional(s.account.ID, s.selected.ID, ids, unchangedSince, mutation)
			if updateErr != nil {
				s.tagged(tag, "NO STORE failed")
				return
			}
			modifiedSet := make(map[int64]bool, len(modifiedIDs))
			for _, id := range modifiedIDs {
				modifiedSet[id] = true
			}
			eligible := selected[:0]
			for _, ref := range selected {
				if modifiedSet[ref.MessageID] {
					modified = append(modified, ref)
				} else {
					eligible = append(eligible, ref)
				}
			}
			selected = eligible
			ids = ids[:0]
			for _, ref := range selected {
				ids = append(ids, ref.MessageID)
			}
		} else if err := s.server.db.UpdateIMAPFlags(s.account.ID, s.selected.ID, ids, mutation); err != nil {
			s.tagged(tag, "NO STORE failed")
			return
		}
	}
	if !silent {
		updated, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
		if err != nil {
			logging.Warn(fmt.Sprintf("[imap] STORE committed but updated flags could not be read: %v", err))
			s.finishStore(tag, modified, byUID)
			return
		}
		selectedIDs := make(map[int64]bool, len(ids))
		for _, id := range ids {
			selectedIDs[id] = true
		}
		for _, ref := range updated {
			if selectedIDs[ref.MessageID] {
				ref = s.sessionRef(ref)
				response := fmt.Sprintf("%d FETCH (FLAGS %s UID %d", ref.Sequence, imapFlags(ref), ref.UID)
				if s.condstore {
					response += fmt.Sprintf(" MODSEQ (%d)", ref.ModSeq)
				}
				s.untagged(response + ")")
			}
		}
	}
	s.finishStore(tag, modified, byUID)
}

func (s *imapSession) finishStore(tag string, modified []store.IMAPMessageRef, byUID bool) {
	if len(modified) > 0 {
		s.tagged(tag, "OK [MODIFIED "+formatIMAPRefSet(modified, byUID)+"] STORE completed")
	} else {
		s.tagged(tag, "OK STORE completed")
	}
}

func formatIMAPRefSet(refs []store.IMAPMessageRef, byUID bool) string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		value := ref.Sequence
		if byUID {
			value = ref.UID
		}
		values = append(values, strconv.FormatUint(uint64(value), 10))
	}
	return strings.Join(values, ",")
}

type parsedIMAPFlags struct {
	system   map[string]bool
	keywords []string
}

func parseStoreFlags(value string) (parsedIMAPFlags, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "(") || !strings.HasSuffix(value, ")") {
		return parsedIMAPFlags{}, false
	}
	result := parsedIMAPFlags{system: make(map[string]bool)}
	for _, flag := range strings.Fields(value[1 : len(value)-1]) {
		upper := strings.ToUpper(flag)
		if strings.HasPrefix(flag, "\\") {
			switch upper {
			case "\\SEEN", "\\FLAGGED", "\\ANSWERED", "\\DELETED", "\\DRAFT":
				result.system[upper] = true
			default:
				return parsedIMAPFlags{}, false
			}
			continue
		}
		if len(flag) == 0 || len(flag) > 64 || strings.ContainsAny(flag, "(){%*\\\" ]") {
			return parsedIMAPFlags{}, false
		}
		result.keywords = append(result.keywords, flag)
	}
	return result, true
}

func (s *imapSession) copyOrMove(tag, command string, arguments []string, byUID bool) {
	if len(arguments) != 2 {
		s.tagged(tag, "BAD "+command+" requires sequence set and destination mailbox")
		return
	}
	if command == "MOVE" && s.readOnly {
		s.tagged(tag, "NO [READ-ONLY] mailbox is read-only")
		return
	}
	destination := s.findFolder(arguments[1])
	if destination == nil {
		s.tagged(tag, "NO [TRYCREATE] destination mailbox not found")
		return
	}
	refs, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		s.tagged(tag, "NO "+command+" failed")
		return
	}
	selected, err := resolveIMAPSequenceSet(arguments[0], refs, byUID)
	if err != nil {
		s.tagged(tag, "BAD "+err.Error())
		return
	}
	ids := make([]int64, len(selected))
	for index := range selected {
		ids[index] = selected[index].MessageID
	}
	if len(ids) == 0 {
		s.tagged(tag, "OK "+command+" completed")
		return
	}
	var pairs []store.IMAPUIDPair
	if command == "COPY" {
		pairs, err = s.server.db.CopyIMAPMessages(s.account.ID, s.selected.ID, destination.ID, ids)
	} else {
		pairs, err = s.server.db.MoveIMAPMessages(s.account.ID, s.selected.ID, destination.ID, ids)
	}
	if err != nil {
		s.tagged(tag, "NO "+command+" failed")
		return
	}
	mailbox, stateErr := s.server.db.GetIMAPMailboxState(s.account.ID, destination.ID)
	if stateErr != nil || mailbox == nil {
		logging.Warn(fmt.Sprintf("[imap] %s committed but destination identity lookup failed: %v", command, stateErr))
	}
	copyUID := ""
	if mailbox != nil && stateErr == nil {
		copyUID = fmt.Sprintf("[COPYUID %d %s %s]", mailbox.UIDValidity, formatUIDPairs(pairs, true), formatUIDPairs(pairs, false))
	}
	if command == "MOVE" {
		// RFC 6851 requires COPYUID in an untagged OK before EXPUNGE/VANISHED.
		if copyUID != "" {
			s.untagged("OK " + copyUID)
		}
		if s.qresync {
			uids := make([]uint32, len(selected))
			for index := range selected {
				uids[index] = selected[index].UID
			}
			s.untagged("VANISHED " + compactUIDSet(uids))
		} else {
			removed := 0
			for _, ref := range selected {
				s.untagged(fmt.Sprintf("%d EXPUNGE", int(ref.Sequence)-removed))
				removed++
			}
		}
		s.tagged(tag, "OK MOVE completed")
		return
	}
	if copyUID == "" {
		s.tagged(tag, "OK COPY completed")
		return
	}
	s.tagged(tag, "OK "+copyUID+" COPY completed")
}

func formatUIDPairs(pairs []store.IMAPUIDPair, source bool) string {
	values := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		uid := pair.Destination
		if source {
			uid = pair.Source
		}
		values = append(values, strconv.FormatUint(uint64(uid), 10))
	}
	return strings.Join(values, ",")
}

func (s *imapSession) uidExpunge(tag string, arguments []string) {
	if s.readOnly {
		s.tagged(tag, "NO [READ-ONLY] mailbox is read-only")
		return
	}
	if len(arguments) != 1 {
		s.tagged(tag, "BAD UID EXPUNGE requires a UID set")
		return
	}
	refs, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		s.tagged(tag, "NO UID EXPUNGE failed")
		return
	}
	selected, err := resolveIMAPSequenceSet(arguments[0], refs, true)
	if err != nil {
		s.tagged(tag, "BAD "+err.Error())
		return
	}
	var ids []int64
	var sequences []uint32
	var uids []uint32
	for _, ref := range selected {
		if ref.Deleted {
			ids = append(ids, ref.MessageID)
			sequences = append(sequences, ref.Sequence)
			uids = append(uids, ref.UID)
		}
	}
	if len(ids) > 0 {
		if _, err := s.server.db.ExpungeIMAPMessages(s.account.ID, s.selected.ID, ids); err != nil {
			s.tagged(tag, "NO UID EXPUNGE failed")
			return
		}
		if s.qresync {
			s.untagged("VANISHED " + compactUIDSet(uids))
		} else {
			for index, sequence := range sequences {
				s.untagged(fmt.Sprintf("%d EXPUNGE", int(sequence)-index))
			}
		}
	}
	s.tagged(tag, "OK UID EXPUNGE completed")
}

func (s *imapSession) expungeDeleted(sendResponses bool) error {
	refs, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		return err
	}
	var ids []int64
	var sequences []uint32
	var uids []uint32
	for _, ref := range refs {
		if ref.Deleted {
			ids = append(ids, ref.MessageID)
			sequences = append(sequences, ref.Sequence)
			uids = append(uids, ref.UID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	if _, err := s.server.db.ExpungeIMAPMessages(s.account.ID, s.selected.ID, ids); err != nil {
		return err
	}
	if sendResponses {
		if s.qresync {
			s.untagged("VANISHED " + compactUIDSet(uids))
		} else {
			for index, sequence := range sequences {
				s.untagged(fmt.Sprintf("%d EXPUNGE", int(sequence)-index))
			}
		}
	}
	return nil
}
