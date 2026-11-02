package mailclient

import (
	"bytes"
	"fmt"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"gomail/store"
)

const maxIMAPSearchDepth = 32

type imapSearchPredicate func(store.IMAPMessageRef, *store.Message) bool

type imapSearchParser struct {
	tokens []string
	index  int
	refs   []store.IMAPMessageRef
	nodes  int
}

func parseIMAPSearch(tokens []string, refs []store.IMAPMessageRef) (imapSearchPredicate, error) {
	parser := &imapSearchParser{tokens: tokens, refs: refs}
	predicate, err := parser.parseAnd(false, 0)
	if err != nil {
		return nil, err
	}
	if parser.index != len(tokens) {
		return nil, fmt.Errorf("unexpected SEARCH token")
	}
	return predicate, nil
}

func (parser *imapSearchParser) parseAnd(group bool, depth int) (imapSearchPredicate, error) {
	if depth > maxIMAPSearchDepth {
		return nil, fmt.Errorf("SEARCH nesting exceeds limit")
	}
	var predicates []imapSearchPredicate
	for parser.index < len(parser.tokens) {
		if parser.tokens[parser.index] == ")" {
			if !group {
				return nil, fmt.Errorf("unexpected SEARCH group end")
			}
			parser.index++
			break
		}
		predicate, err := parser.parseKey(depth)
		if err != nil {
			return nil, err
		}
		predicates = append(predicates, predicate)
	}
	if group && (len(predicates) == 0 || parser.index > len(parser.tokens) || parser.tokens[parser.index-1] != ")") {
		return nil, fmt.Errorf("unterminated SEARCH group")
	}
	if len(predicates) == 0 {
		return nil, fmt.Errorf("empty SEARCH expression")
	}
	return func(ref store.IMAPMessageRef, message *store.Message) bool {
		for _, predicate := range predicates {
			if !predicate(ref, message) {
				return false
			}
		}
		return true
	}, nil
}

func (parser *imapSearchParser) parseKey(depth int) (imapSearchPredicate, error) {
	if parser.index >= len(parser.tokens) {
		return nil, fmt.Errorf("missing SEARCH key")
	}
	parser.nodes++
	if parser.nodes > 512 {
		return nil, fmt.Errorf("too many SEARCH keys")
	}
	token := parser.tokens[parser.index]
	parser.index++
	if token == "(" {
		return parser.parseAnd(true, depth+1)
	}
	key := strings.ToUpper(token)
	if key == "NOT" {
		child, err := parser.parseKey(depth + 1)
		if err != nil {
			return nil, err
		}
		return func(ref store.IMAPMessageRef, message *store.Message) bool { return !child(ref, message) }, nil
	}
	if key == "OR" {
		left, err := parser.parseKey(depth + 1)
		if err != nil {
			return nil, err
		}
		right, err := parser.parseKey(depth + 1)
		if err != nil {
			return nil, err
		}
		return func(ref store.IMAPMessageRef, message *store.Message) bool {
			return left(ref, message) || right(ref, message)
		}, nil
	}
	if looksLikeIMAPSequenceSet(token) {
		selected, err := resolveIMAPSequenceSet(token, parser.refs, false)
		if err != nil {
			return nil, err
		}
		return selectedMessagePredicate(selected), nil
	}
	switch key {
	case "ALL":
		return alwaysIMAPSearch(true), nil
	case "ANSWERED", "DELETED", "DRAFT", "FLAGGED", "RECENT", "SEEN":
		return flagSearchPredicate(key, false), nil
	case "UNANSWERED", "UNDELETED", "UNDRAFT", "UNFLAGGED", "UNSEEN":
		return flagSearchPredicate(strings.TrimPrefix(key, "UN"), true), nil
	case "NEW":
		return func(ref store.IMAPMessageRef, _ *store.Message) bool { return ref.Recent && !ref.Seen }, nil
	case "OLD":
		return func(ref store.IMAPMessageRef, _ *store.Message) bool { return !ref.Recent }, nil
	case "BCC", "BODY", "CC", "FROM", "SUBJECT", "TEXT", "TO":
		value, err := parser.argument(key)
		if err != nil {
			return nil, err
		}
		return textSearchPredicate(key, value), nil
	case "HEADER":
		field, err := parser.argument(key)
		if err != nil {
			return nil, err
		}
		value, err := parser.argument(key)
		if err != nil {
			return nil, err
		}
		if strings.ContainsAny(field, "\r\n:") || field == "" {
			return nil, fmt.Errorf("invalid HEADER field")
		}
		return headerSearchPredicate(field, value), nil
	case "KEYWORD", "UNKEYWORD":
		keyword, err := parser.argument(key)
		if err != nil || !validIMAPKeyword(keyword) {
			return nil, fmt.Errorf("invalid SEARCH keyword")
		}
		return keywordSearchPredicate(keyword, key == "UNKEYWORD"), nil
	case "LARGER", "SMALLER":
		value, err := parser.argument(key)
		if err != nil {
			return nil, err
		}
		size, err := strconv.ParseInt(value, 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("invalid SEARCH size")
		}
		return func(_ store.IMAPMessageRef, message *store.Message) bool {
			if key == "LARGER" {
				return message.Size > size
			}
			return message.Size < size
		}, nil
	case "MODSEQ":
		value, err := parser.argument(key)
		if err != nil {
			return nil, err
		}
		minimum, err := strconv.ParseUint(value, 10, 64)
		if err != nil || minimum == 0 {
			return nil, fmt.Errorf("invalid SEARCH MODSEQ value")
		}
		return func(ref store.IMAPMessageRef, _ *store.Message) bool { return ref.ModSeq >= minimum }, nil
	case "BEFORE", "ON", "SINCE", "SENTBEFORE", "SENTON", "SENTSINCE":
		value, err := parser.argument(key)
		if err != nil {
			return nil, err
		}
		date, err := time.Parse("2-Jan-2006", value)
		if err != nil {
			return nil, fmt.Errorf("invalid SEARCH date")
		}
		return dateSearchPredicate(key, date), nil
	case "UID":
		value, err := parser.argument(key)
		if err != nil {
			return nil, err
		}
		selected, err := resolveIMAPSequenceSet(value, parser.refs, true)
		if err != nil {
			return nil, err
		}
		return selectedMessagePredicate(selected), nil
	default:
		return nil, fmt.Errorf("unsupported SEARCH criterion %s", token)
	}
}

func (parser *imapSearchParser) argument(key string) (string, error) {
	if parser.index >= len(parser.tokens) || parser.tokens[parser.index] == "(" || parser.tokens[parser.index] == ")" {
		return "", fmt.Errorf("SEARCH %s requires an argument", key)
	}
	value := parser.tokens[parser.index]
	parser.index++
	return value, nil
}

func looksLikeIMAPSequenceSet(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && char != '*' && char != ':' && char != ',' {
			return false
		}
	}
	return true
}

func selectedMessagePredicate(refs []store.IMAPMessageRef) imapSearchPredicate {
	ids := make(map[int64]bool, len(refs))
	for _, ref := range refs {
		ids[ref.MessageID] = true
	}
	return func(ref store.IMAPMessageRef, _ *store.Message) bool { return ids[ref.MessageID] }
}

func alwaysIMAPSearch(value bool) imapSearchPredicate {
	return func(store.IMAPMessageRef, *store.Message) bool { return value }
}

func flagSearchPredicate(flag string, invert bool) imapSearchPredicate {
	return func(ref store.IMAPMessageRef, _ *store.Message) bool {
		value := map[string]bool{"ANSWERED": ref.Answered, "DELETED": ref.Deleted, "DRAFT": ref.Draft, "FLAGGED": ref.Flagged, "RECENT": ref.Recent, "SEEN": ref.Seen}[flag]
		return value != invert
	}
}

func textSearchPredicate(key, needle string) imapSearchPredicate {
	needle = strings.ToLower(needle)
	return func(_ store.IMAPMessageRef, message *store.Message) bool {
		header := messageHeader(message)
		var value string
		switch key {
		case "BCC", "CC", "FROM", "SUBJECT", "TO":
			value = header.Get(textproto.CanonicalMIMEHeaderKey(key))
		case "BODY":
			if len(message.RawMessage) > 0 {
				value = string(rawBody(message.RawMessage))
			} else {
				value = message.TextBody + "\n" + message.HTMLBody
			}
		case "TEXT":
			if len(message.RawMessage) > 0 {
				value = string(message.RawMessage)
			} else {
				value = message.RawHeaders + "\n" + message.TextBody + "\n" + message.HTMLBody
			}
		}
		return strings.Contains(strings.ToLower(value), needle)
	}
}

func headerSearchPredicate(field, needle string) imapSearchPredicate {
	needle = strings.ToLower(needle)
	return func(_ store.IMAPMessageRef, message *store.Message) bool {
		header := messageHeader(message)
		values, exists := header[textproto.CanonicalMIMEHeaderKey(field)]
		return exists && strings.Contains(strings.ToLower(strings.Join(values, "\n")), needle)
	}
}

func messageHeader(message *store.Message) textproto.MIMEHeader {
	if parsed, err := mail.ReadMessage(bytes.NewReader(message.RawMessage)); err == nil {
		return textproto.MIMEHeader(parsed.Header)
	}
	return textproto.MIMEHeader{"From": {message.FromAddr}, "To": {message.ToAddr}, "Cc": {message.CcAddr}, "Subject": {message.Subject}}
}

func validIMAPKeyword(keyword string) bool {
	return keyword != "" && len(keyword) <= 64 && !strings.ContainsAny(keyword, "(){%*\\\" ]\r\n")
}

func keywordSearchPredicate(keyword string, invert bool) imapSearchPredicate {
	return func(ref store.IMAPMessageRef, _ *store.Message) bool {
		found := false
		for _, existing := range ref.Keywords {
			if strings.EqualFold(existing, keyword) {
				found = true
				break
			}
		}
		return found != invert
	}
}

func dateSearchPredicate(key string, target time.Time) imapSearchPredicate {
	return func(_ store.IMAPMessageRef, message *store.Message) bool {
		value := message.ReceivedAt
		if strings.HasPrefix(key, "SENT") {
			headerDate := messageHeader(message).Get("Date")
			parsed, err := mail.ParseDate(headerDate)
			if err != nil {
				return false
			}
			value = parsed
		}
		valueDate := time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
		switch key {
		case "BEFORE", "SENTBEFORE":
			return valueDate.Before(target)
		case "ON", "SENTON":
			return valueDate.Equal(target)
		default:
			return !valueDate.Before(target)
		}
	}
}
