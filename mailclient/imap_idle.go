package mailclient

import (
	"fmt"
	"strings"
	"time"

	"gomail/security"
	"gomail/store"
)

type idleReadResult struct {
	line string
	err  error
}

func (s *imapSession) idle(tag string) {
	changes, unsubscribe := s.server.db.SubscribeIMAPChanges(s.account.ID)
	defer unsubscribe()
	if err := s.claimRecent(); err != nil {
		s.tagged(tag, "NO IDLE unavailable")
		return
	}
	previous, err := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
	if err != nil {
		s.tagged(tag, "NO IDLE unavailable")
		return
	}
	for index := range previous {
		previous[index] = s.sessionRef(previous[index])
	}
	s.write("+ idling")
	_ = s.conn.SetReadDeadline(time.Now().Add(29 * time.Minute))
	result := make(chan idleReadResult, 1)
	go func() {
		line, readErr := security.ReadLineLimited(s.reader, 8192)
		if readErr == nil {
			line, readErr = security.ParseCRLFCommandLine(line)
		}
		result <- idleReadResult{line: line, err: readErr}
	}()
	// Process-local events provide immediate updates. The slow refresh protects
	// sessions if another process modifies the shared database directly.
	safetyRefresh := time.NewTicker(30 * time.Second)
	defer safetyRefresh.Stop()
	accountCheck := time.NewTicker(5 * time.Second)
	defer accountCheck.Stop()
	refresh := func() bool {
		if !s.server.accountStillActive(s.account) {
			s.untagged("BYE account no longer active")
			_ = s.conn.Close()
			return false
		}
		if claimErr := s.claimRecent(); claimErr != nil {
			s.untagged("BYE mailbox state unavailable")
			_ = s.conn.Close()
			return false
		}
		current, listErr := s.server.db.ListIMAPMessageRefs(s.account.ID, s.selected.ID)
		if listErr != nil {
			s.untagged("BYE mailbox state unavailable")
			_ = s.conn.Close()
			return false
		}
		for index := range current {
			current[index] = s.sessionRef(current[index])
		}
		s.emitIdleChanges(previous, current)
		previous = current
		return true
	}
	for {
		select {
		case read := <-result:
			_ = s.conn.SetReadDeadline(time.Time{})
			if read.err != nil {
				if read.err == security.ErrInvalidLineEnding {
					s.tagged(tag, "BAD IDLE continuation requires CRLF framing")
					_ = s.conn.Close()
				}
				return
			}
			if !strings.EqualFold(strings.TrimSpace(read.line), "DONE") {
				s.tagged(tag, "BAD expected DONE")
				return
			}
			s.tagged(tag, "OK IDLE terminated")
			return
		case <-changes:
			if !refresh() {
				return
			}
		case <-safetyRefresh.C:
			if !refresh() {
				return
			}
		case <-accountCheck.C:
			if !s.server.accountStillActive(s.account) {
				s.untagged("BYE account no longer active")
				_ = s.conn.Close()
				return
			}
		}
	}
}

func (s *imapSession) emitIdleChanges(previous, current []store.IMAPMessageRef) {
	currentByID := make(map[int64]store.IMAPMessageRef, len(current))
	for _, ref := range current {
		currentByID[ref.MessageID] = ref
	}
	removed := 0
	var vanished []uint32
	for _, old := range previous {
		if _, exists := currentByID[old.MessageID]; !exists {
			if s.qresync {
				vanished = append(vanished, old.UID)
			} else {
				s.untagged(fmt.Sprintf("%d EXPUNGE", int(old.Sequence)-removed))
			}
			removed++
		}
	}
	if len(vanished) > 0 {
		s.untagged("VANISHED " + compactUIDSet(vanished))
	}
	if len(current) != len(previous)-removed {
		s.untagged(fmt.Sprintf("%d EXISTS", len(current)))
	}
	previousByID := make(map[int64]store.IMAPMessageRef, len(previous))
	for _, ref := range previous {
		previousByID[ref.MessageID] = ref
	}
	for _, ref := range current {
		old, exists := previousByID[ref.MessageID]
		if exists && old.ModSeq != ref.ModSeq {
			response := fmt.Sprintf("%d FETCH (FLAGS %s UID %d", ref.Sequence, imapFlags(ref), ref.UID)
			if s.condstore {
				response += fmt.Sprintf(" MODSEQ (%d)", ref.ModSeq)
			}
			s.untagged(response + ")")
		}
	}
}
