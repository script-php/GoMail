package mailclient

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/config"
	"gomail/store"
)

func TestTopMessage(t *testing.T) {
	raw := []byte("From: user@example.com\nSubject: test\n\nfirst\n.second\nthird\n")
	got := topMessage(raw, 2)
	want := []byte("From: user@example.com\r\nSubject: test\r\n\r\nfirst\r\n.second")
	if !bytes.Equal(got, want) {
		t.Fatalf("TOP mismatch:\n%q\nwant:\n%q", got, want)
	}
}

func TestLexIMAPQuotedStrings(t *testing.T) {
	tokens, err := lexIMAP(`a1 LOGIN "user@example.com" "p\\\"ass"`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a1", "LOGIN", "user@example.com", `p\"ass`}
	if fmt.Sprint(tokens) != fmt.Sprint(want) {
		t.Fatalf("tokens=%q want=%q", tokens, want)
	}
	for _, invalid := range []string{`a1 LOGIN "unterminated`, `a1 LOGIN "bad\q"`} {
		if _, err := lexIMAP(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

func TestIMAPAuthenticationListAndSelectTranscript(t *testing.T) {
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "mail.db"), filepath.Join(root, "attachments"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO domains(id,domain) VALUES(1,'example.com')`); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("long-test-password"), bcrypt.MinCost)
	if _, err := db.Exec(`INSERT INTO accounts(id,domain_id,email,password_hash,is_active) VALUES(1,1,'user@example.com',?,1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	if err := db.DefaultFolders(1); err != nil {
		t.Fatal(err)
	}
	inbox, _ := db.GetFolderByType(1, "inbox")
	if _, err := db.CreateIMAPFolder(1, "Archive"); err != nil {
		t.Fatal(err)
	}
	messageID, err := db.SaveMessage(&store.Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "imap-fixture", Direction: "inbound", FromAddr: "sender@example.net", ToAddr: "user@example.com", Subject: "IMAP fixture", TextBody: "hello from IMAP", RawMessage: []byte("From: sender@example.net\r\nTo: user@example.com\r\nSubject: IMAP fixture\r\nMessage-ID: <imap-fixture>\r\n\r\nhello from IMAP\r\n"), ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Server: config.ServerConfig{Hostname: "mail.example.com"}, SMTP: config.SMTPConfig{MaxMessageSize: 1024 * 1024}, Clients: config.MailClientsConfig{ReadTimeout: 5, WriteTimeout: 5, MaxConnections: 1, AuthAttempts: 10}}
	server := NewServer(cfg, db, nil, nil)
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	go server.handleIMAP(serverSide)
	reader := bufio.NewReader(clientSide)
	readUntil := func(tag string) string {
		t.Helper()
		_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
		var response strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			response.WriteString(line)
			if strings.HasPrefix(line, tag+" ") {
				return response.String()
			}
		}
	}
	if greeting, err := reader.ReadString('\n'); err != nil || !strings.Contains(greeting, "IMAP4rev1") || !strings.Contains(greeting, "UIDPLUS") || !strings.Contains(greeting, "MOVE") {
		t.Fatalf("greeting=%q err=%v", greeting, err)
	}
	_, _ = fmt.Fprintf(clientSide, "a1 LOGIN user@example.com long-test-password\r\n")
	if response := readUntil("a1"); !strings.Contains(response, "a1 OK") {
		t.Fatalf("LOGIN response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a1b ENABLE CONDSTORE QRESYNC unknown-extension\r\n")
	if response := readUntil("a1b"); !strings.Contains(response, "* ENABLED CONDSTORE QRESYNC") {
		t.Fatalf("ENABLE response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a1c NAMESPACE\r\n")
	if response := readUntil("a1c"); !strings.Contains(response, `* NAMESPACE (("" "/")) NIL NIL`) {
		t.Fatalf("NAMESPACE response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a2 LIST \"\" \"*\"\r\n")
	if response := readUntil("a2"); !strings.Contains(response, `LIST (\Inbox \HasNoChildren) "/" "Inbox"`) {
		t.Fatalf("LIST response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a2a CREATE Projects/GoMail\r\n")
	if response := readUntil("a2a"); !strings.Contains(response, "a2a OK CREATE") {
		t.Fatalf("CREATE hierarchy response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a2b LIST \"\" \"%%\"\r\n")
	if response := readUntil("a2b"); !strings.Contains(response, `LIST (\Noselect \HasChildren) "/" "Projects"`) || strings.Contains(response, `"Projects/GoMail"`) {
		t.Fatalf("top-level LIST response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a2c LIST \"Projects/\" \"%%\"\r\n")
	if response := readUntil("a2c"); !strings.Contains(response, `LIST (\HasNoChildren) "/" "Projects/GoMail"`) {
		t.Fatalf("reference LIST response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a2d LIST (SPECIAL-USE) \"\" \"*\"\r\n")
	if response := readUntil("a2d"); !strings.Contains(response, `LIST (\Inbox`) || strings.Contains(response, `"Projects/GoMail"`) {
		t.Fatalf("SPECIAL-USE LIST response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a2e LIST \"\" \"*\" RETURN (SPECIAL-USE)\r\n")
	if response := readUntil("a2e"); !strings.Contains(response, `"Projects/GoMail"`) || !strings.Contains(response, `\Sent`) {
		t.Fatalf("SPECIAL-USE RETURN response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a3 SELECT Inbox (CONDSTORE)\r\n")
	if response := readUntil("a3"); !strings.Contains(response, "* 1 EXISTS") || !strings.Contains(response, "UIDVALIDITY") || !strings.Contains(response, "HIGHESTMODSEQ") || !strings.Contains(response, "a3 OK [READ-WRITE]") {
		t.Fatalf("SELECT response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a3b CHECK\r\n")
	if response := readUntil("a3b"); !strings.Contains(response, "a3b OK CHECK") {
		t.Fatalf("CHECK response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a4 SEARCH UNSEEN SUBJECT \"fixture\"\r\n")
	if response := readUntil("a4"); !strings.Contains(response, "* SEARCH 1") {
		t.Fatalf("SEARCH response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a4b SEARCH OR HEADER X-Missing x (SUBJECT fixture NOT SEEN)\r\n")
	if response := readUntil("a4b"); !strings.Contains(response, "* SEARCH 1") {
		t.Fatalf("grouped SEARCH response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a4c SEARCH SUBJECT {7}\r\n")
	if continuation, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(continuation, "+ ") {
		t.Fatalf("SEARCH literal continuation=%q err=%v", continuation, err)
	}
	_, _ = clientSide.Write([]byte("fixture\r\n"))
	if response := readUntil("a4c"); !strings.Contains(response, "* SEARCH 1") {
		t.Fatalf("literal SEARCH response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a5 UID FETCH 1:* (UID FLAGS MODSEQ RFC822.SIZE BODY.PEEK[])\r\n")
	if response := readUntil("a5"); !strings.Contains(response, "* 1 FETCH (UID 1 FLAGS (\\Recent) MODSEQ (") || !strings.Contains(response, "hello from IMAP") {
		t.Fatalf("FETCH response: %s", response)
	}
	if message, _ := db.GetMessage(messageID, 1); message.IsRead {
		t.Fatal("BODY.PEEK[] incorrectly set Seen")
	}
	_, _ = fmt.Fprintf(clientSide, "a5b FETCH 1 (BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)] BODY.PEEK[]<0.5>)\r\n")
	if response := readUntil("a5b"); !strings.Contains(response, `BODYSTRUCTURE ("TEXT" "PLAIN"`) || !strings.Contains(response, "From: sender@example.net") || !strings.Contains(response, "BODY[]<0> {5}\r\nFrom:") {
		t.Fatalf("structured FETCH response: %s", response)
	}
	if message, _ := db.GetMessage(messageID, 1); message.IsRead {
		t.Fatal("structured PEEK incorrectly set Seen")
	}
	_, _ = fmt.Fprintf(clientSide, "a6 FETCH 1 BODY[]\r\n")
	if response := readUntil("a6"); !strings.Contains(response, "BODY[] {") {
		t.Fatalf("BODY FETCH response: %s", response)
	}
	if message, _ := db.GetMessage(messageID, 1); !message.IsRead {
		t.Fatal("BODY[] did not set Seen")
	}
	_, _ = fmt.Fprintf(clientSide, "a7 STORE 1 +FLAGS (\\Flagged \\Answered client-keyword)\r\n")
	if response := readUntil("a7"); !strings.Contains(response, "FLAGS (\\Seen \\Answered \\Flagged \\Recent client-keyword)") {
		t.Fatalf("STORE response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a7b UID FETCH 1 (FLAGS) (CHANGEDSINCE 1)\r\n")
	if response := readUntil("a7b"); !strings.Contains(response, "MODSEQ (") {
		t.Fatalf("CHANGEDSINCE response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a7c UID STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Draft)\r\n")
	if response := readUntil("a7c"); !strings.Contains(response, "OK [MODIFIED 1]") {
		t.Fatalf("UNCHANGEDSINCE response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a7d UID SEARCH MODSEQ 1\r\n")
	if response := readUntil("a7d"); !strings.Contains(response, "* SEARCH 1 (MODSEQ ") {
		t.Fatalf("MODSEQ SEARCH response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a8 UID STORE 1 -FLAGS.SILENT (\\Seen client-keyword)\r\n")
	if response := readUntil("a8"); strings.Contains(response, "* 1 FETCH") || !strings.Contains(response, "a8 OK") {
		t.Fatalf("silent STORE response: %s", response)
	}
	message, _ := db.GetMessage(messageID, 1)
	state, _ := db.GetIMAPMessageState(1, messageID)
	if message.IsRead || !message.IsStarred || !state.Answered {
		t.Fatalf("stored flags not persisted: message=%#v state=%#v", message, state)
	}
	qresyncState, err := db.GetIMAPMailboxState(1, inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(clientSide, "a8b SELECT Inbox (QRESYNC (%d 1 1))\r\n", qresyncState.UIDValidity)
	if response := readUntil("a8b"); !strings.Contains(response, "FETCH (UID 1 FLAGS") || !strings.Contains(response, "MODSEQ (") || !strings.Contains(response, "a8b OK [READ-WRITE]") {
		t.Fatalf("QRESYNC changed-flags response: %s", response)
	}
	appendRaw := []byte("From: user@example.com\r\nTo: saved@example.net\r\nSubject: client draft\r\nMessage-ID: <client-draft>\r\n\r\ndraft body\r\n")
	_, _ = fmt.Fprintf(clientSide, "a9 APPEND Drafts (\\Seen \\Draft) {%d}\r\n", len(appendRaw))
	if continuation, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(continuation, "+ ") {
		t.Fatalf("APPEND continuation=%q err=%v", continuation, err)
	}
	_, _ = clientSide.Write(appendRaw)
	_, _ = clientSide.Write([]byte("\r\n"))
	if response := readUntil("a9"); !strings.Contains(response, "a9 OK [APPENDUID ") {
		t.Fatalf("APPEND response: %s", response)
	}
	drafts, _ := db.GetFolderByType(1, "drafts")
	draftRefs, _ := db.ListIMAPMessageRefs(1, drafts.ID)
	if len(draftRefs) != 1 || !draftRefs[0].Seen || !draftRefs[0].Draft {
		t.Fatalf("APPEND state=%#v", draftRefs)
	}
	_, _ = fmt.Fprintf(clientSide, "a10 UID COPY 1 Archive\r\n")
	if response := readUntil("a10"); !strings.Contains(response, "a10 OK [COPYUID ") || !strings.Contains(response, " 1 1]") {
		t.Fatalf("UID COPY response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a11 UID STORE 1 +FLAGS.SILENT (\\Deleted)\r\n")
	if response := readUntil("a11"); !strings.Contains(response, "a11 OK") {
		t.Fatalf("UID STORE deleted response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a12 UID EXPUNGE 1\r\n")
	if response := readUntil("a12"); !strings.Contains(response, "* VANISHED 1") || !strings.Contains(response, "a12 OK UID EXPUNGE") {
		t.Fatalf("UID EXPUNGE response: %s", response)
	}
	mailboxState, err := db.GetIMAPMailboxState(1, inbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(clientSide, "a12b SELECT Inbox (QRESYNC (%d 1 1:*))\r\n", mailboxState.UIDValidity)
	if response := readUntil("a12b"); !strings.Contains(response, "* VANISHED (EARLIER) 1") || !strings.Contains(response, "a12b OK [READ-WRITE]") {
		t.Fatalf("QRESYNC SELECT response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a13 IDLE\r\n")
	if continuation, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(continuation, "+ ") {
		t.Fatalf("IDLE continuation=%q err=%v", continuation, err)
	}
	idleMessageID, err := db.SaveMessage(&store.Message{AccountID: 1, FolderID: &inbox.ID, MessageID: "idle-delivery", Direction: "inbound", RawMessage: []byte("Subject: IDLE delivery\r\n\r\nnew"), ReceivedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	if update, err := reader.ReadString('\n'); err != nil || !strings.Contains(update, "1 EXISTS") {
		t.Fatalf("IDLE event update=%q err=%v", update, err)
	}
	if err := db.MarkStarred(idleMessageID, true); err != nil {
		t.Fatal(err)
	}
	if update, err := reader.ReadString('\n'); err != nil || !strings.Contains(update, "FETCH (FLAGS") || !strings.Contains(update, "\\Flagged") {
		t.Fatalf("IDLE flag update=%q err=%v", update, err)
	}
	if err := db.DeleteMessage(idleMessageID); err != nil {
		t.Fatal(err)
	}
	if update, err := reader.ReadString('\n'); err != nil || !strings.Contains(update, "VANISHED 2") {
		t.Fatalf("IDLE expunge update=%q err=%v", update, err)
	}
	_, _ = fmt.Fprintf(clientSide, "DONE\r\n")
	if response := readUntil("a13"); !strings.Contains(response, "a13 OK IDLE terminated") {
		t.Fatalf("IDLE response: %s", response)
	}
	_, _ = fmt.Fprintf(clientSide, "a14 LOGOUT\r\n")
	if response := readUntil("a14"); !strings.Contains(response, "* BYE") {
		t.Fatalf("LOGOUT response: %s", response)
	}
}

func TestParseLiteralMarker(t *testing.T) {
	line, size, ok, err := parseLiteralMarker("a1 APPEND Inbox {123}")
	if err != nil || !ok || size != 123 || line != "a1 APPEND Inbox" {
		t.Fatalf("literal marker=%q %d %v %v", line, size, ok, err)
	}
	for _, invalid := range []string{"a1 APPEND Inbox {}", "a1 APPEND Inbox {-1}", "a1 APPEND Inbox {1+}"} {
		if _, _, _, err := parseLiteralMarker(invalid); err == nil {
			t.Fatalf("accepted invalid marker %q", invalid)
		}
	}
}

func TestParsePath(t *testing.T) {
	if address, rest, ok := parsePath(`FROM:<"a>b"@example.test> SIZE=12`, "FROM:"); !ok || address != `"a>b"@example.test` || rest != "SIZE=12" {
		t.Fatalf("quoted SMTP path=%q rest=%q ok=%v", address, rest, ok)
	}
	address, rest, ok := parsePath("FROM:<user@example.com> SIZE=12 BODY=8BITMIME", "FROM:")
	if !ok || address != "user@example.com" || rest != "SIZE=12 BODY=8BITMIME" {
		t.Fatalf("unexpected path: %q %q %v", address, rest, ok)
	}
	for _, malformed := range []string{"user@example.com", "FROM:user@example.com", "FROM:<>", "FROM:<user@example.com>SIZE=12", "TO:<user@example.com>NOTIFY=FAILURE", "FROM:<user@example.com>\tSIZE=12", `FROM:<"unterminated@example.com>`} {
		if _, _, ok := parsePath(malformed, "FROM:"); ok {
			t.Fatalf("accepted malformed path %q", malformed)
		}
	}
}

func TestValidateSubmittedFrom(t *testing.T) {
	valid := []byte("From: Person <user@example.com>\r\nTo: x@example.net\r\n\r\nhello\r\n")
	if err := validateSubmittedFrom(valid, "USER@example.com"); err != nil {
		t.Fatal(err)
	}
	invalid := []byte("From: attacker@example.net\r\n\r\nhello\r\n")
	if err := validateSubmittedFrom(invalid, "user@example.com"); err == nil {
		t.Fatal("accepted a spoofed From header")
	}
	for _, raw := range []string{
		"From: user@example.com\r\nFrom: attacker@example.net\r\n\r\nhello\r\n",
		"From: attacker@example.net\r\nFrom: user@example.com\r\n\r\nhello\r\n",
		"To: x@example.net\r\n\r\nhello\r\n",
	} {
		if err := validateSubmittedFrom([]byte(raw), "user@example.com"); err == nil {
			t.Fatalf("accepted missing or duplicate From header: %q", raw)
		}
	}
}

func TestStripBccIncludingContinuation(t *testing.T) {
	raw := []byte("From: user@example.com\r\nBcc: hidden@example.net,\r\n next@example.net\r\nSubject: test\r\n\r\nbody\r\n")
	got := stripHeader(raw, "bcc")
	if bytes.Contains(bytes.ToLower(got), []byte("bcc:")) || bytes.Contains(got, []byte("next@example.net")) {
		t.Fatalf("Bcc was not removed: %q", got)
	}
	if !bytes.Contains(got, []byte("Subject: test")) || !bytes.Contains(got, []byte("body")) {
		t.Fatalf("unrelated content was removed: %q", got)
	}
}

func TestNormalizeCRLF(t *testing.T) {
	got := normalizeCRLF([]byte("a\rb\nc\r\nd"))
	if string(got) != "a\r\nb\r\nc\r\nd" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthenticationRateLimit(t *testing.T) {
	server := NewServer(&config.Config{Clients: config.MailClientsConfig{MaxConnections: 1, AuthAttempts: 2}}, nil, nil, nil)
	for i := 0; i < 10; i++ {
		if !server.allowAuthentication("192.0.2.1:1000") {
			t.Fatal("successful authentication checks consumed failure budget")
		}
	}
	server.recordAuthenticationFailure("192.0.2.1:1000")
	if !server.allowAuthentication("192.0.2.1:1001") {
		t.Fatal("one failure exhausted budget")
	}
	server.recordAuthenticationFailure("192.0.2.1:1001")
	if server.allowAuthentication("192.0.2.1:1002") {
		t.Fatal("excess failed authentication was allowed")
	}
	if !server.allowAuthentication("192.0.2.2:1000") {
		t.Fatal("one IP incorrectly affected another")
	}
	server.auth["192.0.2.1"] = authWindow{started: time.Now().Add(-2 * time.Minute), count: 2}
	if !server.allowAuthentication("192.0.2.1:1003") {
		t.Fatal("expired failure window still blocks authentication")
	}
}

func TestAuthenticationLimiterBoundsState(t *testing.T) {
	server := NewServer(&config.Config{Clients: config.MailClientsConfig{MaxConnections: 1, AuthAttempts: 2}}, nil, nil, nil)
	for i := 0; i < maxAuthenticationHosts+5; i++ {
		server.recordAuthenticationFailure(fmt.Sprintf("192.0.%d.%d:1000", i/256, i%256))
	}
	if len(server.auth) > maxAuthenticationHosts {
		t.Fatalf("authentication map has %d entries", len(server.auth))
	}
	server.auth["expired"] = authWindow{started: time.Now().Add(-2 * time.Minute), count: 2}
	server.authCleaned = time.Time{}
	server.allowAuthentication("198.51.100.1:1000")
	if _, exists := server.auth["expired"]; exists {
		t.Fatal("expired authentication window was not removed")
	}
}
