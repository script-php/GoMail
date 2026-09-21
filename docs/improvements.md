# Mailbox improvements

The header search now searches the signed-in account's subject, sender, recipient,
and plain-text body. Trash is excluded. Results are paginated and preserve the
search term. Search uses SQLite LIKE; non-ASCII case folding is limited by SQLite.

Select messages using row checkboxes or Select all (the current page). The toolbar
supports read/unread, moving to an existing folder, Trash, and Restore. Restore
returns received messages to Inbox and sent messages to Sent. Moving to Drafts is
not supported. Bulk changes validate ownership and destination before committing
and update folder counts in the same transaction. These actions do not send read
receipts. Individual message viewing retains the existing receipt behavior.

Mutating message endpoints require CSRF tokens and account ownership checks.
Disabled accounts cannot continue using existing sessions. Outgoing sent copies
and all recipient queue entries now commit together; a queue insertion failure is
returned to the sender. Attachment storage remains separate from that transaction.
Unknown delivery errors retry; SMTP 5xx replies are permanent failures. Oversized
BDAT requests are rejected before allocation, and the connection is closed to
avoid interpreting the rejected chunk as commands. DATA reads are bounded by the
remaining message-size allowance; incomplete data is not accepted for delivery.

Run `make test` for all source packages. The package list deliberately excludes
runtime data and release directories, which may contain restricted certificate
files. Tests cover queue rollback, mailbox ownership, literal search wildcards,
trash/restore counts, oversized SMTP chunks, retry classification, rendered pages,
CSRF checks, and disabled sessions. Tests use isolated in-memory databases.

## Remaining work

- Draft save/resume and autosave (the Drafts folder exists, but has no editor flow).
- Replace regex-based email HTML sanitization with a reviewed allowlist sanitizer
  and isolate rendered email from the application layout.
- Trusted proxy configuration for rate limiting and secure cookies behind TLS
  termination.
- SMTP interoperability and email-authentication coverage, operational monitoring,
  and backup/restore.
- Browser-level interaction and accessibility coverage.
