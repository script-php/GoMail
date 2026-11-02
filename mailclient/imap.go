package mailclient

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/logging"
	"gomail/security"
	"gomail/store"
)

const imapCapabilities = "IMAP4rev1 AUTH=PLAIN IDLE UIDPLUS MOVE ENABLE CONDSTORE QRESYNC NAMESPACE SPECIAL-USE"

type imapSession struct {
	server    *Server
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	account   *store.Account
	selected  *store.Folder
	readOnly  bool
	literal   []byte
	recent    map[int64]bool
	condstore bool
	qresync   bool
}

func (s *Server) handleIMAP(conn net.Conn) {
	session := &imapSession{server: s, conn: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn)}
	defer conn.Close()
	session.untagged("OK [CAPABILITY " + imapCapabilities + "] GoMail IMAP ready")
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout()))
		line, err := security.ReadLineLimited(session.reader, 8192)
		if err != nil {
			return
		}
		if len(line) > 8192 {
			session.untagged("BAD command line too long")
			return
		}
		line, err = security.ParseCRLFCommandLine(line)
		if err != nil {
			session.untagged("BAD command requires CRLF framing")
			return
		}
		if session.account != nil && !s.accountStillActive(session.account) {
			session.untagged("BYE account no longer active")
			return
		}
		session.literal = nil
		hasLiteral := false
		if commandLine, size, parsedHasLiteral, literalErr := parseLiteralMarker(line); literalErr != nil {
			session.untagged("BAD " + literalErr.Error())
			continue
		} else if parsedHasLiteral {
			hasLiteral = true
			literalTag, literalCommand, _, parseErr := parseIMAPCommand(commandLine)
			if parseErr != nil {
				session.untagged("BAD invalid command before literal")
				continue
			}
			limit := int64(8192)
			if literalCommand == "APPEND" {
				limit = s.cfg.SMTP.MaxMessageSize
			}
			if size > limit {
				session.tagged(literalTag, "NO [TOOBIG] literal exceeds message size limit")
				return
			}
			// APPEND is an authenticated-state command. Reject it before
			// requesting or allocating the message literal, rather than
			// accepting untrusted message-sized input from anonymous clients.
			if literalCommand == "APPEND" && session.account == nil {
				session.tagged(literalTag, "NO authenticate before APPEND")
				continue
			}
			session.write("+ ready for literal")
			session.literal = make([]byte, size)
			if _, err := io.ReadFull(session.reader, session.literal); err != nil {
				return
			}
			terminator := make([]byte, 2)
			if _, err := io.ReadFull(session.reader, terminator); err != nil || string(terminator) != "\r\n" {
				return
			}
			line = commandLine
		}
		tag, command, arguments, err := parseIMAPCommand(line)
		if err != nil {
			session.untagged("BAD " + err.Error())
			continue
		}
		if hasLiteral && command != "APPEND" {
			arguments = append(arguments, string(session.literal))
		}
		if session.account != nil && !s.accountStillActive(session.account) {
			session.untagged("BYE account no longer active")
			return
		}
		if session.command(tag, command, arguments) {
			return
		}
	}
}

func (s *imapSession) command(tag, command string, arguments []string) bool {
	switch command {
	case "CAPABILITY":
		s.untagged("CAPABILITY " + imapCapabilities)
		s.tagged(tag, "OK CAPABILITY completed")
	case "NOOP":
		s.tagged(tag, "OK NOOP completed")
	case "CHECK":
		if !s.requireSelected(tag) {
			break
		}
		if _, err := s.server.db.GetIMAPMailboxSnapshot(s.account.ID, s.selected.ID); err != nil {
			s.tagged(tag, "NO CHECK failed")
		} else {
			s.tagged(tag, "OK CHECK completed")
		}
	case "ENABLE":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.enable(tag, arguments)
	case "NAMESPACE":
		if !s.requireAuthenticated(tag) {
			break
		}
		if len(arguments) != 0 {
			s.tagged(tag, "BAD NAMESPACE takes no arguments")
			break
		}
		s.untagged(`NAMESPACE (("" "/")) NIL NIL`)
		s.tagged(tag, "OK NAMESPACE completed")
	case "LOGOUT":
		s.untagged("BYE logging out")
		s.tagged(tag, "OK LOGOUT completed")
		return true
	case "LOGIN":
		s.login(tag, arguments)
	case "AUTHENTICATE":
		s.authenticate(tag, arguments)
	case "LIST", "LSUB":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.list(tag, command, arguments)
	case "SELECT", "EXAMINE":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.selectMailbox(tag, command, arguments)
	case "UNSELECT", "CLOSE":
		if s.selected == nil {
			s.tagged(tag, "BAD no mailbox selected")
			break
		}
		if command == "CLOSE" && !s.readOnly {
			if err := s.expungeDeleted(false); err != nil {
				s.tagged(tag, "NO CLOSE failed")
				break
			}
		}
		s.selected = nil
		s.recent = nil
		s.tagged(tag, "OK "+command+" completed")
	case "SUBSCRIBE", "UNSUBSCRIBE":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.subscription(tag, command, arguments)
	case "CREATE", "DELETE":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.createOrDeleteMailbox(tag, command, arguments)
	case "RENAME":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.renameMailbox(tag, arguments)
	case "STATUS":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.status(tag, arguments)
	case "APPEND":
		if !s.requireAuthenticated(tag) {
			break
		}
		s.appendMessage(tag, arguments)
	case "FETCH":
		if !s.requireSelected(tag) {
			break
		}
		s.fetch(tag, arguments, false)
	case "SEARCH":
		if !s.requireSelected(tag) {
			break
		}
		s.search(tag, arguments, false)
	case "STORE":
		if !s.requireSelected(tag) {
			break
		}
		s.storeFlags(tag, arguments, false)
	case "COPY", "MOVE":
		if !s.requireSelected(tag) {
			break
		}
		s.copyOrMove(tag, command, arguments, false)
	case "EXPUNGE":
		if !s.requireSelected(tag) {
			break
		}
		if s.readOnly {
			s.tagged(tag, "NO [READ-ONLY] mailbox is read-only")
			break
		}
		if err := s.expungeDeleted(true); err != nil {
			s.tagged(tag, "NO EXPUNGE failed")
		} else {
			s.tagged(tag, "OK EXPUNGE completed")
		}
	case "IDLE":
		if !s.requireSelected(tag) {
			break
		}
		s.idle(tag)
	case "UID":
		if !s.requireSelected(tag) {
			break
		}
		if len(arguments) == 0 {
			s.tagged(tag, "BAD UID requires a command")
			break
		}
		switch strings.ToUpper(arguments[0]) {
		case "FETCH":
			s.fetch(tag, arguments[1:], true)
		case "SEARCH":
			s.search(tag, arguments[1:], true)
		case "STORE":
			s.storeFlags(tag, arguments[1:], true)
		case "COPY", "MOVE":
			s.copyOrMove(tag, strings.ToUpper(arguments[0]), arguments[1:], true)
		case "EXPUNGE":
			s.uidExpunge(tag, arguments[1:])
		default:
			s.tagged(tag, "BAD unsupported UID command")
		}
	default:
		s.tagged(tag, "BAD unsupported command")
	}
	return false
}

func (s *imapSession) enable(tag string, arguments []string) {
	var enabled []string
	for _, capability := range arguments {
		switch strings.ToUpper(capability) {
		case "CONDSTORE":
			s.condstore = true
			if !slices.Contains(enabled, "CONDSTORE") {
				enabled = append(enabled, "CONDSTORE")
			}
		case "QRESYNC":
			s.condstore = true
			s.qresync = true
			if !slices.Contains(enabled, "QRESYNC") {
				enabled = append(enabled, "QRESYNC")
			}
		}
	}
	s.untagged("ENABLED " + strings.Join(enabled, " "))
	s.tagged(tag, "OK ENABLE completed")
}

func (s *imapSession) login(tag string, arguments []string) {
	if s.account != nil {
		s.tagged(tag, "BAD already authenticated")
		return
	}
	if len(arguments) != 2 {
		s.tagged(tag, "BAD LOGIN requires username and password")
		return
	}
	s.finishAuthentication(tag, arguments[0], arguments[1])
}

func (s *imapSession) authenticate(tag string, arguments []string) {
	if s.account != nil {
		s.tagged(tag, "BAD already authenticated")
		return
	}
	if len(arguments) != 1 || !strings.EqualFold(arguments[0], "PLAIN") {
		s.tagged(tag, "NO unsupported authentication mechanism")
		return
	}
	s.write("+")
	_ = s.conn.SetReadDeadline(time.Now().Add(s.server.readTimeout()))
	line, err := security.ReadLineLimited(s.reader, 8192)
	if err != nil {
		return
	}
	line, err = security.ParseCRLFCommandLine(line)
	if err != nil {
		s.tagged(tag, "BAD authentication response requires CRLF framing")
		_ = s.conn.Close()
		return
	}
	if line == "*" {
		s.tagged(tag, "BAD authentication cancelled")
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(line)
	fields := strings.Split(string(decoded), "\x00")
	if err != nil || len(fields) != 3 {
		s.tagged(tag, "BAD invalid AUTHENTICATE response")
		return
	}
	s.finishAuthentication(tag, fields[1], fields[2], fields[0])
}

func (s *imapSession) finishAuthentication(tag, username, password string, authorizationID ...string) {
	if !s.server.allowAuthentication(s.conn.RemoteAddr().String()) {
		s.tagged(tag, "NO [UNAVAILABLE] too many authentication attempts")
		return
	}
	account, err := s.server.db.GetAccountByEmail(strings.ToLower(username))
	hash := dummyBcryptHash
	if err == nil && account != nil {
		hash = account.PasswordHash
	}
	passwordErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		s.tagged(tag, "NO [UNAVAILABLE] authentication temporarily unavailable")
		return
	}
	if passwordErr != nil || account == nil {
		s.server.recordAuthenticationFailure(s.conn.RemoteAddr().String())
		s.tagged(tag, "NO authentication failed")
		return
	}
	// Delegated identities are not supported. A nonempty SASL PLAIN authzid
	// must identify the account whose credentials were verified.
	if len(authorizationID) > 0 && authorizationID[0] != "" && !strings.EqualFold(authorizationID[0], account.Email) {
		s.tagged(tag, "NO authorization identity is not permitted")
		return
	}
	s.account = account
	s.tagged(tag, "OK [CAPABILITY "+imapCapabilities+"] authenticated")
}

func (s *imapSession) requireAuthenticated(tag string) bool {
	if s.account == nil {
		s.tagged(tag, "NO authenticate first")
		return false
	}
	return true
}

func (s *imapSession) requireSelected(tag string) bool {
	if !s.requireAuthenticated(tag) {
		return false
	}
	if s.selected == nil {
		s.tagged(tag, "BAD select a mailbox first")
		return false
	}
	return true
}

func (s *imapSession) list(tag, command string, arguments []string) {
	specialOnly := false
	if command == "LIST" && len(arguments) >= 3 && arguments[0] == "(" {
		if len(arguments) < 5 || !strings.EqualFold(arguments[1], "SPECIAL-USE") || arguments[2] != ")" {
			s.tagged(tag, "BAD unsupported LIST selection option")
			return
		}
		specialOnly = true
		arguments = arguments[3:]
	}
	if command == "LIST" && len(arguments) > 2 {
		if len(arguments) != 6 || !strings.EqualFold(arguments[2], "RETURN") || arguments[3] != "(" || !strings.EqualFold(arguments[4], "SPECIAL-USE") || arguments[5] != ")" {
			s.tagged(tag, "BAD unsupported LIST return option")
			return
		}
		arguments = arguments[:2]
	}
	if len(arguments) != 2 {
		s.tagged(tag, "BAD "+command+" requires reference and pattern")
		return
	}
	folders, err := s.server.db.ListIMAPFolders(s.account.ID, command == "LSUB")
	if err != nil {
		logging.Warn(fmt.Sprintf("[imap] list folders for account %d: %v", s.account.ID, err))
		s.tagged(tag, "NO mailbox listing failed")
		return
	}
	reference, err := decodeIMAPMailbox(arguments[0])
	if err != nil {
		s.tagged(tag, "BAD invalid reference name encoding")
		return
	}
	pattern, err := decodeIMAPMailbox(arguments[1])
	if err != nil {
		s.tagged(tag, "BAD invalid mailbox pattern encoding")
		return
	}
	resolved := reference + pattern
	if strings.HasPrefix(pattern, "/") {
		resolved = strings.TrimPrefix(pattern, "/")
	}
	type listNode struct {
		folder   *store.Folder
		children bool
	}
	nodes := make(map[string]*listNode)
	for _, folder := range folders {
		key := strings.ToLower(folder.Name)
		if nodes[key] == nil {
			nodes[key] = &listNode{}
		}
		nodes[key].folder = folder
		parts := strings.Split(folder.Name, "/")
		for index := 1; index < len(parts); index++ {
			parent := strings.Join(parts[:index], "/")
			key := strings.ToLower(parent)
			if nodes[key] == nil {
				nodes[key] = &listNode{folder: &store.Folder{Name: parent}}
			}
			nodes[key].children = true
		}
	}
	for key, node := range nodes {
		prefix := key + "/"
		for candidate := range nodes {
			if strings.HasPrefix(candidate, prefix) {
				node.children = true
				break
			}
		}
	}
	if resolved == "" {
		s.untagged(fmt.Sprintf("%s (\\Noselect) \"/\" \"\"", command))
		s.tagged(tag, "OK "+command+" completed")
		return
	}
	ordered := make([]*listNode, 0, len(nodes))
	for _, node := range nodes {
		ordered = append(ordered, node)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return strings.ToLower(ordered[i].folder.Name) < strings.ToLower(ordered[j].folder.Name)
	})
	for _, node := range ordered {
		if !imapPatternMatches(resolved, node.folder.Name) {
			continue
		}
		if specialOnly && specialUseAttribute(node.folder.FolderType) == "" {
			continue
		}
		var attributes []string
		if node.folder.ID == 0 {
			attributes = append(attributes, "\\Noselect")
		}
		if special := specialUseAttribute(node.folder.FolderType); special != "" {
			attributes = append(attributes, special)
		}
		if node.children {
			attributes = append(attributes, "\\HasChildren")
		} else {
			attributes = append(attributes, "\\HasNoChildren")
		}
		s.untagged(fmt.Sprintf("%s (%s) \"/\" %s", command, strings.Join(attributes, " "), quoteIMAP(encodeIMAPMailbox(node.folder.Name))))
	}
	s.tagged(tag, "OK "+command+" completed")
}

func specialUseAttribute(folderType string) string {
	return map[string]string{
		"inbox": "\\Inbox", "sent": "\\Sent", "drafts": "\\Drafts",
		"trash": "\\Trash", "spam": "\\Junk",
	}[folderType]
}

func (s *imapSession) selectMailbox(tag, command string, arguments []string) {
	if len(arguments) < 1 {
		s.tagged(tag, "BAD "+command+" requires a mailbox")
		return
	}
	requestCondstore := false
	var resync *qresyncRequest
	if len(arguments) > 1 {
		var err error
		requestCondstore, resync, err = parseSelectOptions(arguments[1:])
		if err != nil {
			s.tagged(tag, "BAD "+err.Error())
			return
		}
		if resync != nil && !s.qresync {
			s.tagged(tag, "BAD QRESYNC must be enabled first")
			return
		}
		s.condstore = true
	}
	folder := s.findFolder(arguments[0])
	if folder == nil {
		s.tagged(tag, "NO [NONEXISTENT] mailbox not found")
		return
	}
	state, err := s.server.db.GetIMAPMailboxState(s.account.ID, folder.ID)
	if err != nil || state == nil {
		s.tagged(tag, "NO mailbox state unavailable")
		return
	}
	snapshot, err := s.server.db.OpenIMAPMailbox(s.account.ID, folder.ID)
	if err != nil {
		s.tagged(tag, "NO unable to open mailbox")
		return
	}
	s.untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
	s.untagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] flags permitted")
	s.untagged(strconv.Itoa(snapshot.Exists) + " EXISTS")
	s.untagged(strconv.Itoa(snapshot.Recent) + " RECENT")
	if snapshot.FirstUnseen > 0 {
		s.untagged(fmt.Sprintf("OK [UNSEEN %d] first unseen message", snapshot.FirstUnseen))
	}
	s.untagged(fmt.Sprintf("OK [UIDVALIDITY %d] UIDs valid", state.UIDValidity))
	s.untagged(fmt.Sprintf("OK [UIDNEXT %d] predicted next UID", state.UIDNext))
	if requestCondstore || s.condstore {
		s.untagged(fmt.Sprintf("OK [HIGHESTMODSEQ %d] highest modification sequence", state.HighestModSeq))
	}
	s.selected, s.readOnly = folder, command == "EXAMINE"
	s.recent = make(map[int64]bool, len(snapshot.RecentIDs))
	for _, messageID := range snapshot.RecentIDs {
		s.recent[messageID] = true
	}
	if resync != nil && resync.uidValidity == state.UIDValidity {
		if err := s.emitQRESYNCDelta(*resync); err != nil {
			s.selected = nil
			s.recent = nil
			s.tagged(tag, "NO QRESYNC state unavailable")
			return
		}
	}
	mode := "READ-WRITE"
	if s.readOnly {
		mode = "READ-ONLY"
	}
	s.tagged(tag, "OK ["+mode+"] "+command+" completed")
}

type qresyncRequest struct {
	uidValidity uint32
	modSeq      uint64
	knownUIDs   string
}

func parseSelectOptions(tokens []string) (bool, *qresyncRequest, error) {
	if len(tokens) == 3 && tokens[0] == "(" && strings.EqualFold(tokens[1], "CONDSTORE") && tokens[2] == ")" {
		return true, nil, nil
	}
	if len(tokens) < 7 || tokens[0] != "(" || !strings.EqualFold(tokens[1], "QRESYNC") || tokens[2] != "(" || tokens[len(tokens)-2] != ")" || tokens[len(tokens)-1] != ")" {
		return false, nil, fmt.Errorf("unsupported SELECT option")
	}
	uidValidity, err := strconv.ParseUint(tokens[3], 10, 32)
	if err != nil || uidValidity == 0 {
		return false, nil, fmt.Errorf("invalid QRESYNC UIDVALIDITY")
	}
	modseq, err := strconv.ParseUint(tokens[4], 10, 64)
	if err != nil {
		return false, nil, fmt.Errorf("invalid QRESYNC modification sequence")
	}
	request := &qresyncRequest{uidValidity: uint32(uidValidity), modSeq: modseq}
	middle := tokens[5 : len(tokens)-2]
	if len(middle) > 0 {
		if middle[0] == "(" {
			return false, nil, fmt.Errorf("QRESYNC sequence match requires known UIDs")
		}
		if err := validateIMAPUIDSet(middle[0]); err != nil {
			return false, nil, fmt.Errorf("invalid QRESYNC known UID set")
		}
		request.knownUIDs = middle[0]
		middle = middle[1:]
	}
	if len(middle) > 0 {
		if len(middle) != 4 || middle[0] != "(" || middle[3] != ")" {
			return false, nil, fmt.Errorf("invalid QRESYNC sequence match data")
		}
		if err := validateIMAPUIDSet(middle[1]); err != nil {
			return false, nil, fmt.Errorf("invalid QRESYNC sequence set")
		}
		if err := validateIMAPUIDSet(middle[2]); err != nil {
			return false, nil, fmt.Errorf("invalid QRESYNC UID set")
		}
	}
	return true, request, nil
}

func (s *imapSession) emitQRESYNCDelta(request qresyncRequest) error {
	expunges, err := s.server.db.GetIMAPExpunges(s.account.ID, s.selected.ID, request.modSeq)
	if err != nil {
		return err
	}
	var vanished []uint32
	for _, expunge := range expunges {
		if request.knownUIDs == "" || imapUIDSetContains(request.knownUIDs, expunge.UID, ^uint32(0)) {
			vanished = append(vanished, expunge.UID)
		}
	}
	if len(vanished) > 0 {
		s.untagged("VANISHED (EARLIER) " + compactUIDSet(vanished))
	}
	refs, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if ref.ModSeq <= request.modSeq || request.knownUIDs != "" && !imapUIDSetContains(request.knownUIDs, ref.UID, ^uint32(0)) {
			continue
		}
		ref = s.sessionRef(ref)
		s.untagged(fmt.Sprintf("%d FETCH (UID %d FLAGS %s MODSEQ (%d))", ref.Sequence, ref.UID, imapFlags(ref), ref.ModSeq))
	}
	return nil
}

func (s *imapSession) claimRecent() error {
	if s.selected == nil {
		return nil
	}
	ids, err := s.server.db.ClaimIMAPRecent(s.account.ID, s.selected.ID)
	if err != nil {
		return err
	}
	if s.recent == nil {
		s.recent = make(map[int64]bool)
	}
	for _, id := range ids {
		s.recent[id] = true
	}
	return nil
}

func (s *imapSession) sessionRef(ref store.IMAPMessageRef) store.IMAPMessageRef {
	ref.Recent = s.recent != nil && s.recent[ref.MessageID]
	return ref
}

func (s *imapSession) subscription(tag, command string, arguments []string) {
	if len(arguments) != 1 {
		s.tagged(tag, "BAD "+command+" requires a mailbox")
		return
	}
	folder := s.findFolder(arguments[0])
	if folder == nil {
		s.tagged(tag, "NO [NONEXISTENT] mailbox not found")
		return
	}
	if err := s.server.db.SetIMAPSubscription(s.account.ID, folder.ID, command == "SUBSCRIBE"); err != nil {
		s.tagged(tag, "NO subscription update failed")
		return
	}
	s.tagged(tag, "OK "+command+" completed")
}

func (s *imapSession) createOrDeleteMailbox(tag, command string, arguments []string) {
	if len(arguments) != 1 {
		s.tagged(tag, "BAD "+command+" requires a mailbox")
		return
	}
	if command == "CREATE" {
		name, err := decodeIMAPMailbox(arguments[0])
		if err != nil {
			s.tagged(tag, "BAD invalid mailbox name encoding")
			return
		}
		if _, err := s.server.db.CreateIMAPFolder(s.account.ID, name); err != nil {
			s.tagged(tag, "NO CREATE failed")
			return
		}
	} else {
		folder := s.findFolder(arguments[0])
		if folder == nil {
			s.tagged(tag, "NO [NONEXISTENT] mailbox not found")
			return
		}
		if s.selected != nil && s.selected.ID == folder.ID {
			s.tagged(tag, "NO [INUSE] mailbox is selected")
			return
		}
		if err := s.server.db.DeleteIMAPFolder(s.account.ID, folder.ID); err != nil {
			s.tagged(tag, "NO DELETE failed: "+err.Error())
			return
		}
	}
	s.tagged(tag, "OK "+command+" completed")
}

func (s *imapSession) renameMailbox(tag string, arguments []string) {
	if len(arguments) != 2 {
		s.tagged(tag, "BAD RENAME requires old and new mailbox names")
		return
	}
	folder := s.findFolder(arguments[0])
	if folder == nil {
		s.tagged(tag, "NO [NONEXISTENT] mailbox not found")
		return
	}
	newName, err := decodeIMAPMailbox(arguments[1])
	if err != nil {
		s.tagged(tag, "BAD invalid mailbox name encoding")
		return
	}
	if err := s.server.db.RenameIMAPFolder(s.account.ID, folder.ID, newName); err != nil {
		s.tagged(tag, "NO RENAME failed")
		return
	}
	if s.selected != nil && s.selected.ID == folder.ID {
		s.selected.Name = newName
	}
	s.tagged(tag, "OK RENAME completed")
}

func (s *imapSession) status(tag string, arguments []string) {
	if len(arguments) < 2 {
		s.tagged(tag, "BAD STATUS requires mailbox and data items")
		return
	}
	folder := s.findFolder(arguments[0])
	if folder == nil {
		s.tagged(tag, "NO [NONEXISTENT] mailbox not found")
		return
	}
	state, err := s.server.db.GetIMAPMailboxState(s.account.ID, folder.ID)
	if err != nil || state == nil {
		s.tagged(tag, "NO mailbox state unavailable")
		return
	}
	snapshot, err := s.server.db.GetIMAPMailboxSnapshot(s.account.ID, folder.ID)
	if err != nil {
		s.tagged(tag, "NO mailbox status failed")
		return
	}
	items := strings.Fields(strings.Trim(strings.Join(arguments[1:], " "), "()"))
	var values []string
	for _, item := range items {
		switch strings.ToUpper(item) {
		case "MESSAGES":
			values = append(values, "MESSAGES", strconv.Itoa(snapshot.Exists))
		case "RECENT":
			values = append(values, "RECENT", strconv.Itoa(snapshot.Recent))
		case "UNSEEN":
			values = append(values, "UNSEEN", strconv.Itoa(snapshot.Unseen))
		case "UIDNEXT":
			values = append(values, "UIDNEXT", strconv.FormatUint(uint64(state.UIDNext), 10))
		case "UIDVALIDITY":
			values = append(values, "UIDVALIDITY", strconv.FormatUint(uint64(state.UIDValidity), 10))
		default:
			s.tagged(tag, "BAD unsupported STATUS item")
			return
		}
	}
	s.untagged("STATUS " + quoteIMAP(encodeIMAPMailbox(folder.Name)) + " (" + strings.Join(values, " ") + ")")
	s.tagged(tag, "OK STATUS completed")
}

func (s *imapSession) findFolder(name string) *store.Folder {
	decoded, err := decodeIMAPMailbox(name)
	if err != nil {
		return nil
	}
	folders, err := s.server.db.ListIMAPFolders(s.account.ID, false)
	if err != nil {
		return nil
	}
	for _, folder := range folders {
		if strings.EqualFold(folder.Name, decoded) {
			return folder
		}
	}
	return nil
}

func parseIMAPCommand(line string) (string, string, []string, error) {
	tokens, err := lexIMAP(line)
	if err != nil || len(tokens) < 2 {
		return "", "", nil, fmt.Errorf("invalid command")
	}
	if strings.ContainsAny(tokens[0], " (){%*\\\"") || len(tokens[0]) > 64 {
		return "", "", nil, fmt.Errorf("invalid tag")
	}
	return tokens[0], strings.ToUpper(tokens[1]), tokens[2:], nil
}

func parseLiteralMarker(line string) (string, int64, bool, error) {
	if !strings.HasSuffix(line, "}") {
		return line, 0, false, nil
	}
	start := strings.LastIndex(line, "{")
	if start < 0 || start == len(line)-1 {
		return "", 0, false, fmt.Errorf("invalid literal marker")
	}
	value := line[start+1 : len(line)-1]
	if strings.HasSuffix(value, "+") {
		return "", 0, false, fmt.Errorf("non-synchronizing literals are not enabled")
	}
	size, err := strconv.ParseInt(value, 10, 64)
	if err != nil || size < 0 {
		return "", 0, false, fmt.Errorf("invalid literal size")
	}
	return strings.TrimSpace(line[:start]), size, true, nil
}

func lexIMAP(line string) ([]string, error) {
	var tokens []string
	for index := 0; index < len(line); {
		for index < len(line) && line[index] == ' ' {
			index++
		}
		if index == len(line) {
			break
		}
		if line[index] == '"' {
			index++
			var value strings.Builder
			closed := false
			for index < len(line) {
				if line[index] == '"' {
					index++
					closed = true
					break
				}
				if line[index] == '\\' {
					index++
					if index == len(line) || (line[index] != '\\' && line[index] != '"') {
						return nil, fmt.Errorf("invalid quoted escape")
					}
				}
				value.WriteByte(line[index])
				index++
			}
			if !closed || (index < len(line) && line[index] != ' ') {
				return nil, fmt.Errorf("invalid quoted string")
			}
			tokens = append(tokens, value.String())
			continue
		}
		if line[index] == '(' || line[index] == ')' {
			tokens = append(tokens, line[index:index+1])
			index++
			continue
		}
		start := index
		for index < len(line) && line[index] != ' ' && line[index] != '(' && line[index] != ')' {
			index++
		}
		tokens = append(tokens, line[start:index])
	}
	return tokens, nil
}

func imapPatternMatches(pattern, name string) bool {
	patternRunes, nameRunes := []rune(strings.ToLower(pattern)), []rune(strings.ToLower(name))
	type state struct{ pattern, name int }
	memo := make(map[state]bool)
	seen := make(map[state]bool)
	var match func(int, int) bool
	match = func(patternIndex, nameIndex int) bool {
		current := state{patternIndex, nameIndex}
		if seen[current] {
			return memo[current]
		}
		seen[current] = true
		result := false
		if patternIndex == len(patternRunes) {
			result = nameIndex == len(nameRunes)
		} else {
			switch patternRunes[patternIndex] {
			case '*':
				result = match(patternIndex+1, nameIndex) || nameIndex < len(nameRunes) && match(patternIndex, nameIndex+1)
			case '%':
				result = match(patternIndex+1, nameIndex) || nameIndex < len(nameRunes) && nameRunes[nameIndex] != '/' && match(patternIndex, nameIndex+1)
			default:
				result = nameIndex < len(nameRunes) && patternRunes[patternIndex] == nameRunes[nameIndex] && match(patternIndex+1, nameIndex+1)
			}
		}
		memo[current] = result
		return result
	}
	return match(0, 0)
}

func quoteIMAP(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func (s *imapSession) untagged(message string)    { s.write("* " + message) }
func (s *imapSession) tagged(tag, message string) { s.write(tag + " " + message) }

func (s *imapSession) write(message string) {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.server.writeTimeout()))
	_, _ = s.writer.WriteString(message + "\r\n")
	_ = s.writer.Flush()
}
