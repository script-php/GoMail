# Open work and completed history

Current open work is consolidated under **Open verification and design work**
below. Later milestone sections retain historical implementation notes and may
repeat the corresponding deployment or interoperability checks; they are not
additional independent bugs. Optional future features are separate from
production-readiness issues.

## Fixed backup archive collision finding (2026-11-18)

- Two manual backup runs in the same second previously chose the same output
  path. When the second run found the first archive already present, its error
  cleanup deleted that valid archive. Failed runs no longer remove the output
  path, names include nanoseconds, and final publication uses an atomic
  no-replace hard link so concurrent runs cannot overwrite one another.
  A regression makes two runs choose the same timestamp and verifies the
  original archive remains byte-identical and verifiable.
- Automatic retention now matches only GoMail's old and current timestamped
  scheduler filenames. The former broad `gomail-*.tar.gz` match could delete
  a `gomail-pre-restore-*` safety archive or an operator-named backup when
  stored in the same directory. A regression keeps both while pruning an old
  scheduler archive.

## Fixed SQLite restore compatibility finding (2026-11-17)

- Staged SQLite restore now checks that the restored schema contains the core
  columns needed for authentication, mailbox access, attachment serving, and
  queued delivery. Integrity checks and matching table counts alone could
  accept an incompatible snapshot. Regressions reject a missing login column
  and accept the current live schema. It also requires full, non-partial unique
  indexes on hosted domain and account email identities; composite-only or
  absent uniqueness is rejected before activation. Full schema-version migration and a
  real operator restore drill remain separate verification work.

## Fixed SQLite restore relationship finding (2026-11-18)

- A restored SQLite database can pass `foreign_key_check` when the relevant
  foreign-key rules were removed entirely. Restore now requires the core
  account-domain, message-account, attachment-message, queue-message, and
  queue-event relationships before activating the snapshot. Regressions
  reject a missing account-domain rule and accept the current schema.

## Fixed permanent-delete integrity finding (2026-11-17)

- Permanent Trash deletion now checks for cursor iteration errors while
  collecting attachment paths and IMAP expunge state before committing the
  deletion. A failed read can no longer silently produce incomplete cleanup
  metadata. Post-commit attachment removal errors are logged so orphaned
  private files are visible to operators rather than silently retained.

## Fixed final-DSN retry finding (2026-11-17)

- Administrator-cancelled outbound entries already requested a failure notice,
  but a temporary failure delivering that notice did not advance its retry
  clock. The final-DSN retry update now includes administrator cancellations
  without admitting other cancelled outcomes. A regression verifies deferred
  retry, recovery, and exactly one delivered notice.

## Fixed attachment recovery finding (2026-11-17)

- Inbound, sent, and IMAP-APPEND attachment writes now include a random
  filename suffix. An interrupted transaction can leave an unreferenced file
  while its rolled-back message ID is later reused; the new delivery no longer
  collides with that file. A store regression simulates an old-format orphan.
- Attachment sidecars now include a random filename suffix. If the server
  crashes after writing a sidecar but before committing its metadata, a later
  repair can write a fresh copy from the preserved raw MIME without trusting
  or overwriting the orphaned file. Repair also verifies message ownership
  before treating existing attachment metadata as success. A regression
  simulates the interrupted-commit sidecar.
- A message view now checks the complete attachment set, including recorded
  file type and size. Missing files or partial metadata trigger an atomic
  rebuild from the preserved raw MIME; failed rebuilds retain the prior
  metadata. Regression tests cover missing sidecars and incomplete rows.
  Old orphaned sidecars are not deleted automatically because damaged metadata
  cannot safely establish whether another message references a path.
- Attachment downloads now reject sidecars whose current file size differs
  from the saved metadata, rather than returning truncated or expanded bytes
  as a successful download. A web regression covers a truncated sidecar.

## Fixed mailbox counter durability finding (2026-11-17)

- POP3 deletion now moves Inbox mail to Trash and updates both folder counts
  in one transaction. Sent-copy creation, requested DSN mailbox notices, and
  permanent draft deletion also update their folder counts before commit.
  Best-effort post-commit counter writes were removed. Regressions inject
  count-update failures into POP3, Sent, and draft flows and verify rollback.
- Inbound SMTP and queued local delivery now recalculate the affected
  account's folder counters inside the same transaction that saves the
  mailbox copy, attachments, and queue outcome. A counter-write failure
  rolls the delivery back instead of leaving a committed message with stale
  Inbox counts. The post-commit best-effort updates were removed, and a
  fault-injection regression covers rollback and successful retry.

## Fixed local-delivery review finding (2026-11-16)

- Delayed-delivery DSNs now save the sender's mailbox notice and mark the
  corresponding queue notice sent in one transaction. A failed commit leaves
  both unchanged, and retries cannot create a duplicate notice. Regression
  coverage injects a mailbox write failure and verifies idempotent retry.
- Outbound SMTP now declares exact RFC 1870 `SIZE` on `MAIL FROM` when the
  remote server advertises it, including the CRLF added before DATA's dot
  terminator when needed. A wire-level regression verifies both forms, so
  remote size limits can reject before the message body is transmitted.
- Mailbox storage reservations now require both an active account and an
  active hosted domain at commit time. This closes the gap where a domain
  disabled after SMTP recipient acceptance could still receive a stored copy;
  a regression verifies rejection without increasing mailbox usage.
- A queued message for a hosted domain disabled after admission now fails
  locally instead of being placed in an active mailbox or routed to an
  external MX. The worker checks the domain state immediately before local
  delivery; regressions cover the disabled-domain transition.
- Queued local delivery now stores the mailbox copy, decoded attachments,
  IMAP state, queue success state, and delivery event in one database
  transaction. A crash cannot leave a saved mailbox copy behind a still-
  sending queue entry, and reuse of the same claim cannot create a duplicate.
  A regression verifies the queue state and exactly one mailbox copy.
- SMTPUTF8 recipients using a Unicode U-label for a hosted internationalized
  domain now resolve to the configured DNS A-label before local-domain,
  duplicate-recipient, alias, and mailbox checks. Queued local delivery uses
  the same canonical domain, so it cannot accidentally route that mailbox to
  external MX hosts. SMTP and queue regressions cover both paths.
- Queued mail for a local account disabled after enqueue now fails once with
  a permanent mailbox-unavailable result instead of retrying until queue
  exhaustion. A regression covers the inactive-recipient transition.
- Stale outbound queue claims are now checked every five minutes while the
  server remains running, not only at startup. They become uncertain for
  operator review and are never automatically resent; a scheduler regression
  covers quarantine without requeue.
- Internationalized DSNs now use RFC 6533 global delivery-status and returned
  message/header media types when UTF-8 fields require them. Final recipients
  retain the UTF-8 address type, and the DSN parser accepts the global part.
- Outbound SMTP now sends Unicode-only envelope domains as IDNA A-labels,
  allowing an ASCII local part and ASCII message headers to reach legacy peers
  without SMTPUTF8. UTF-8 local parts or headers still require SMTPUTF8;
  ORCPT retains the original Unicode address in RFC 6533-safe encoding.
- Webmail compose and forward now emit IDNA A-labels in To/Cc and single-
  recipient Received trace fields for ASCII local parts, before queue signing.
  This lets those ordinary messages use the compatible envelope path; UTF-8
  local parts remain unchanged.

## Fixed protocol review findings (2026-10-21)

34. Submission closes an oversized DATA connection if draining fails before
    the terminating dot, so unread message bytes cannot be parsed as commands.
    A regression covers an overlong line during draining.
35. Greylisting uses a recipient-scoped `450` temporary rejection while
    keeping the SMTP session open, instead of `421`, which promises closure.
36. POP3 maildrop snapshots retain message IDs and canonical sizes, loading
    raw MIME only for RETR/TOP instead of retaining an entire Inbox in RAM.
37. Pre-signing seven-bit MIME conversion handles standards-valid multipart
    preambles, preserving the preamble and converting eligible 8-bit parts.
38. Authenticated HTTP responses, including attachments, now use
    `Cache-Control: no-store`; login pages also avoid storing pre-session data.
39. Login uses a short-lived pre-session CSRF token; logout requires a
    CSRF-protected POST instead of a state-changing GET.
40. Web login distinguishes account-store failure from bad credentials, returning
    a temporary error without incrementing the per-IP bad-password limiter.
41. Forwarding embeds canonical stored `message/rfc822` bytes without rewriting
    line endings. Noncanonical source MIME is rejected before queueing instead
    of silently changing the attached message or its signature; a MIME round-trip
    regression verifies byte-for-byte preservation.

## Open source-review findings (2026-10-24)

- Real-domain report-recipient delivery, bounces, and contact validity still
  require end-to-end testing with external providers. A configured local
  recipient is checked for existence and active status, but GoMail cannot
  prove that external senders will deliver reports until DNS is published.

## Fixed report-generation review findings (2026-10-24)

The former DMARC `ri` interval tag was removed by RFC 9989. GoMail's daily
aggregate scheduler meets its at-least-daily recommendation; subdaily `ri`
scheduling is not a current-standard gap.

1. TLS-RPT ignores a DNS RRset with multiple matching policy records instead
   of combining destinations from conflicting records.
2. DMARC report generation rejects multiple matching policy records and
   malformed or duplicate policy tags instead of choosing the first one.
3. External DMARC authorization records may override `rua` recipients, but
   an override to another destination host is rejected.
4. Scheduled DMARC aggregate reports run daily for complete UTC days and
   catch up unsent days after downtime. Manual generation can still send a
   partial current-day window.

## Fixed transport-policy review findings (2026-10-24)

1. When DANE and MTA-STS `enforce` overlap, outbound TLS must satisfy both
   the authenticated TLSA record and PKIX/hostname validation. An unusable
   TLSA set does not bypass an enforcing MTA-STS policy.
2. MTA-STS policies are cached in the mail database with absolute expiry, so
   restarting GoMail or losing live policy discovery does not discard an
   unexpired policy. Cache database errors defer delivery rather than
   downgrading transport security.
3. MTA-STS `testing` records certificate failures for TLS reporting but does
   not reject delivery solely for that policy. Applicable DANE validation
   remains mandatory even in MTA-STS testing mode.

## Fixed source-review findings (2026-10-24)

1. HTML messages block remote HTTP(S) images by default. A per-message Load
   images action enables them explicitly; CID and bounded data images remain
   available. The opt-in URL carries a session-bound permit.
2. Web and inbound SMTP rate-limit maps have a fixed entry cap and fail closed
   for unknown IPs when full; expired entries are pruned on demand. Inbound
   limiters no longer launch cleanup goroutines.
3. Attachment downloads and IMAP attachment copies open files without following
   symlinks. Attachment creation is exclusive and no-follow, and backup input
   rejects symlinks.
4. Admins can choose an active mailbox on each domain for suggested DMARC and
   TLS-RPT DNS recipients. Suggestions are withheld if the selected recipient
   is no longer deliverable; postmaster remains the default fallback.

## Completed received-report analysis (2026-10-20)

33. Admin → Received Reports is off by default and can scan one selected,
    active local mailbox without a password or restart. Bounded DMARC XML
    and TLS-RPT JSON attachments are parsed into deduplicated history and
    summary counts; source mail is preserved. Admin/CSRF, scanner and
    disabled/idempotent behavior have regressions. External report claims
    remain unverified and DNS recipient provisioning remains separate.

## Fixed source-review findings (2026-10-20, sixth pass)

30. Submission now validates HELO/EHLO identities and distinguishes legacy
    HELO from negotiated ESMTP. HELO cannot enable STARTTLS or MAIL extension
    parameters; greeting mode resets after TLS. Protocol regressions cover it.
31. IMAP and POP3 require CRLF-framed commands. IMAP AUTHENTICATE responses
    and IDLE continuation use the same validation, closing on malformed input.
    Command and AUTHENTICATE regressions cover LF-only and embedded CR.
32. Oversized synchronizing IMAP literals receive a tagged `NO [TOOBIG]`
    completion before the connection closes. A transcript regression covers
    APPEND without transmitting literal bytes.

## Fixed source-review findings (2026-10-20, fifth pass)

26. Outbound queueing and worker-to-local delivery now save decoded attachment
    sidecars and metadata in the same transaction as messages/queue rows.
    Sidecar failures roll back and are reported; tests inject metadata failure.
27. Inbound SMTP requires HELO/EHLO before MAIL. ESMTP MAIL/RCPT parameters
    and BDAT require EHLO; STARTTLS also requires EHLO in the ready state.
    Greeting mode resets after STARTTLS, with protocol regressions.
28. Oversized BDAT chunks are streamed to discard under a read deadline before
    552 is sent. Incomplete chunks time out and close without a premature reply;
    regressions cover both complete and incomplete chunks.
29. HELO/EHLO domain labels now enforce ASCII letter/digit/hyphen syntax,
    while retaining valid address literals; invalid-label cases are tested.

## Fixed source-review findings (2026-10-20, fourth pass)

23. IMAP STORE now returns tagged OK after a successful flag commit even if
    the subsequent FETCH-state read fails; a warning records that read error.
    Ordinary and MODIFIED completion responses have regression coverage.
24. Plain SMTP and submission now reject LF-only or embedded-CR command
    lines and close the connection instead of parsing them. Submission AUTH
    challenge responses follow the same rule. The shared CRLF validator and
    both listeners have regressions.
25. Ordinary mailbox-addressed DSNs are still delivered, but their
    unauthenticated body claims no longer create VERP bounce records. Only
    issued VERP envelope addresses create trusted inbound bounce metadata;
    a forged ordinary DSN regression covers mailbox delivery without a row.

## Fixed source-review findings (2026-10-20, third pass)

17. Inbound VERP bounce records now commit in the same transaction as mailbox
    delivery and requested reports. A failed record defers SMTP acceptance;
    a later failed record also rolls back earlier bounce records. Regressions
    cover failed INSERT and mixed-delivery rollback.
18. IMAP APPEND, COPY, and MOVE now return tagged OK without UIDPLUS identity
    data if a post-commit mailbox lookup fails, avoiding misleading retryable
    NO responses and duplicate messages.
19. Missing or partial SMTP rate-limit configuration now receives the
    documented defaults of 60 connections and 30 messages per minute.
20. Submission DATA now requires CRLF framing and preserves valid message
    octets. Malformed framing closes the unsynchronized connection; an
    LF-only regression is covered.
21. Inbound decoded attachment files and metadata now participate in the
    mailbox/report transaction, and pre-commit files are removed on rollback.
    File/metadata success and injected metadata failure are covered.
22. POP3 STAT/LIST/RETR sizes now count the canonical content emitted by RETR,
    excluding transparency dots. Mixed line-ending cases are covered.

## Fixed source-review findings (2026-10-20)

5. Receiver-generated null-envelope DSNs are now permitted through system
   queue authorization. The worker uses the configured server domain for
   transport policy while retaining `MAIL FROM:<>`. A worker-to-local DSN
   regression passes. Remote-provider delivery remains part of live SMTP
   interoperability verification.
6. Inbound RCPT now differentiates account lookup failure (451 4.3.0) from
   a nonexistent recipient (550 5.1.1), with a protocol regression test.
7. Inbound DATA no longer skips a recipient that became unavailable after
   RCPT and then returns 250. The whole transaction is deferred, with a
   recipient-state race regression test.
8. Standard tagged IPv6 EHLO literals are accepted; untagged or malformed
   IPv6 literals are rejected, with tests.
9. Inbound RFC 6533 `utf-8` ORCPT native/unitext forms are decoded with
   strict validation. Generated seven-bit DSNs retain the UTF-8 address type
   and encode it safely, with decoding/reporting regressions.
10. Submission rejects overlong transmitted or normalized DATA lines before
    queue acceptance and closes the unsynchronized session, with a regression.

## Fixed source-review findings (2026-10-20, second pass)

11. Requested inbound SUCCESS DSNs are signed before acceptance and their
    null-envelope queue entries commit atomically with recipient messages.
    Preparation or queue failure now defers the whole SMTP transaction rather
    than returning 250 and losing the report. A forced queue failure regression
    verifies rollback.
12. MAIL extension state is committed only after every parameter validates.
    A rejected SMTPUTF8/ENVID command cannot grant SMTPUTF8 to the next MAIL.
13. Inbound DATA requires CRLF framing, rejects overlong logical lines, and
    closes after invalid framing. BDAT without BINARYMIME now rejects bare
    line breaks, overlong lines, and NUL octets at completion.
14. Submission, IMAP, and POP3 return temporary authentication errors for
    account-store failures without incrementing the bad-password limiter.
15. Outbound DATA and submission exclude the duplicated transparency dot from
    the RFC 5321 line limit; maximum-length dot-stuffed lines now pass tests.
16. Inbound `rfc822` ORCPT rejects decoded non-ASCII/control bytes rather than
    writing them into a seven-bit `message/delivery-status` field.


## Completed source-review fixes (2026-10-19)

The 2026-10-20 outbound follow-up is also fixed: sender-domain TLS/DANE policy
lookup errors now defer delivery instead of falling back to plaintext or
disabled DANE. The policy is resolved once per SMTP attempt. Queue entries now
retain their originating account ID even after the Sent copy or account is
deleted; pending mail from a disabled, suspended, deleted, or renamed sender is
cancelled before transport. Legacy queue rows with no recoverable sender are
also cancelled rather than sent without authorization. Regression tests cover
sender lifecycle, queue cancellation, and transport-policy lookup failure.

The SMTP standards follow-up is fixed locally: outbound EHLO keywords are
parsed as complete case-insensitive capability lines before and after
STARTTLS; submission rejects unsupported RCPT parameters with 555; DSN ORCPT
uses RFC 6533's UTF-8 address type and encoding for internationalized
recipients; and outbound DATA rejects bare CR/LF and overlong wire lines
before transmitting or mutating the signed message. Protocol tests cover
these cases. Real-provider interoperability remains in the open verification
section.

Addressed in this pass: required-DANE MX/CNAME resolution now requires an
authenticated DNSSEC response; DANE-TA validates reference names; ordinary MX
lookup no longer falls back after a temporary DNS error and rejects null MX;
sender-domain outbound TLS policy is preserved in MTA-STS testing mode; and
greylisting/tarpitting admin POSTs require CSRF tokens. Regression tests cover
the DNS, DANE-TA, and CSRF changes. Outbound SMTP replies now have bounded,
strict line framing; post-STARTTLS EHLO must succeed; and `251` is accepted at
RCPT TO. The reply parser has malformed, truncated, and oversized fixtures.
Inbound SMTP now closes after a failed STARTTLS handshake, and generated MDN
headers normalize untrusted values and encode the subject; both have regression
tests.
TLSA lookup errors now skip the affected MX; insecure and authenticated-absent
answers remain opportunistic, while secure usable records require authenticated
TLS and secure nonempty unusable RRsets require encryption. A failed outbound
STARTTLS handshake never resumes plaintext on the same connection.
Changing an account password now deletes its existing web sessions in the same
database transaction; self-service changes send the user back to login.
Originating-IP headers now use only trusted-proxy-normalized addresses, and the
forward form loads HTML through the existing sandboxed, account-scoped message
content endpoint. Empty SMTP DATA and BDAT LAST transfers receive an explicit
554 rejection and leave the session ready for another transaction.
MTA-STS policy retrieval now rejects redirects away from the prescribed HTTPS
policy URL and requires a text/plain response; local regression tests cover
cross-host and cleartext redirects and invalid media types.
Inbound SMTP now accepts only VERP return paths present in the outbound queue,
records their original recipient and sender from that queue entry, and rejects
lookalike addresses. New VERP encoding round-trips `+`, `=`, and hyphenated
domains. SMTP and store regression tests cover the accepted bounce path.
The optional mail-client authentication limiter now counts failed credentials
only, expires windows, and bounds its per-IP state; regression tests cover
normal shared-IP logins, lockout, expiry, and state growth.
Equal-preference MX hosts are now shuffled independently for each lookup,
including cache hits and authenticated DNSSEC answers, without changing
preference ordering; regression tests cover the tie handling.
Inbound SMTP and optional mail-client shutdown now stop accepting connections,
allow a short session drain, then close tracked sockets and return by a bounded
deadline. Tests cover idle and continuously active connections.
Existing authenticated IMAP, POP3 and submission sessions now lose access when
an account or its domain is disabled; submission rechecks before queueing a
completed DATA transfer, and IMAP IDLE checks periodically. Local protocol
tests cover in-flight deactivation and submission rejection.
Completed-queue pruning now archives genuine issued VERP mappings in the same
transaction before deleting queue history, so later bounces still resolve;
ordinary sender-address fallbacks are no longer recorded as VERP. Tests cover
lookup after pruning and rollback when archival fails.
MDN receipts now queue and mark their source message in one transaction with a
conditional idempotency gate. Automatic mode retries on later views after a
failed enqueue; manual mode reports failures instead of redirecting as if sent.
Regression tests cover queue failure, retry, and concurrent requests.
Requested final SUCCESS and FAILURE DSNs now have a persisted retry clock and
attempt count separate from outbound delivery. The mailbox report and final
sent marker commit atomically, and queue retention preserves entries while a
requested final DSN is outstanding. Tests cover failure, retry, idempotency,
retention, and SQLite upgrade.

Attachment sidecar failures now retain `has_attachments` on the preserved raw
MIME. Account-scoped message views retry extraction when metadata is missing,
and show an unavailable warning if repair still fails. Repair writes metadata
transactionally and removes sidecar files on failure. Tests cover successful
and repeated repair, disk failure, database failure, and retry.
Archived VERP retention is now an independent, opt-in admin setting. Zero
keeps mappings indefinitely; a positive age triggers bounded hourly cleanup
and a manual cleanup action, with active queue references protected. The UI
warns that expired mappings lose late-bounce attribution.

## Open verification and design work

SQLite restore now checkpoints the active database's WAL and refuses a busy
checkpoint before deleting old `-wal`/`-shm` files. If replacement of the
database file then fails, the original file still contains its committed
transactions rather than depending on a WAL that restore already removed.
A regression reopens the original database after simulated sidecar removal.

POP3 `RETR` and `TOP` now recheck that a snapshot message is still inbound
Inbox mail before returning its body. If webmail or IMAP moved it meanwhile,
the read fails rather than exposing mail outside the POP3 maildrop; QUIT's
existing atomic delete check also rejects the stale selection. GoMail's POP3
lock still excludes only other POP3 sessions, not concurrent webmail/IMAP
mutations. A shared cross-protocol maildrop-lock design remains open for
strict RFC 1939 snapshot semantics.

Final delivery-status notices now resolve local virtual addresses, including
an administrator-configured `postmaster@domain` alias, before saving to the
target mailbox. Previously a failed system TLS report could leave its failure
notice retrying indefinitely because DSN delivery looked up only real login
accounts. A regression verifies one notice and a durable sent marker.

IMAP expunge now checks attachment-path iteration errors before committing a
deletion. An incomplete read can no longer silently omit sidecar cleanup
paths; post-commit removal failures are logged for operator investigation.

Attachment downloads now carry a restrictive sandbox CSP in addition to
`Content-Disposition: attachment`, so an HTML attachment remains isolated if a
browser renders it despite the download directive. Webmail view and compose
logs no longer record message subjects or MDN destination addresses.
Inbound SMTP and local-delivery logs now also omit sender-controlled subjects
and Message-ID values while retaining internal delivery IDs and results.

Attachment creation now syncs both file contents and the containing directory
before the database can commit a mailbox reference. A sync failure removes the
new file and rejects the delivery, rather than acknowledging mail with a
database row that could outlive its attachment after a crash. The obsolete
webmail helper that wrote world-readable attachment files outside the active
transactional path has been removed; all active attachment writes use the
durable, exclusive-creation helper. A fault-injection regression covers
directory-sync failure cleanup.

Administrator cancellation of an accepted pending delivery now remains
eligible for a failure DSN and is protected from completed-queue cleanup until
that notice is saved. Automatic cancellation when sender authority disappears
is still excluded, avoiding an undeliverable notice retry loop. Store and
delivery regressions verify one notice and safe cleanup afterward.

Completed-queue retention now uses the same failure-DSN default as the retry
scanner: an empty `NOTIFY` still requires a failure notice. Such rows stay
until the notice is committed; null-sender rows, which cannot receive DSNs,
remain eligible for normal cleanup. Regression tests cover both cases.

Final DSN persistence now requires the queue's current terminal outcome to
match the report being saved. A stale success or failure report built before an
operator retry/outcome change cannot mark the queue notified or insert an
incorrect mailbox notice; regression coverage verifies this race boundary.

SMTPUTF8 capability checks now inspect nested MIME part headers and attached
message headers, as required by RFC 6531. Encoded attached messages and normal
8-bit body text do not spuriously require SMTPUTF8. The inspection is bounded,
uses raw MIME parts, and conservatively requires SMTPUTF8 when malformed or
excessively nested MIME cannot be fully inspected. MIME body inspection now
streams without a 32 MiB size cutoff, so large ASCII attachments are not
rejected by legacy peers; regressions also check a UTF-8 header after a large
body part. The depth and part-count limits remain fail-safe.
Authenticated submission now uses that same MIME-level check before accepting
DATA. Its listener does not advertise SMTPUTF8, so nested UTF-8 MIME or
attached-message headers are rejected at submission instead of creating a
queued message that cannot be relayed to a legacy peer.

Outbound SMTP now accepts the RFC 5321 `252` positive RCPT reply and any well-formed `2yz` DATA completion reply. This removes a provider interoperability failure where GoMail could treat an accepted recipient or message as rejected. Loopback regression coverage is included; live provider testing remains open.
Outbound DSN `NOTIFY` and `RET` queue metadata is now checked against RFC 3461's permitted tokens both at authenticated-submission admission and before SMTP command construction. Malformed persisted values fail permanently before networking instead of becoming SMTP command text.
Outbound SMTP command writes now reject embedded control bytes (including CR/LF) before touching the connection, covering configuration-derived EHLO names as well as stored envelope metadata. Invalid envelope control bytes are classified as permanent address failures rather than retrying an undeliverable queued entry.
Queued delivery now treats a configured but disabled recipient domain as local. Previously the active-domain-only routing check could classify it as remote and attempt MX delivery, potentially disclosing a queued message outside the server. The disabled local mailbox instead fails locally; regression coverage checks both the hosted and genuinely remote cases.
Domain deletion now refuses to remove a hosted routing record while pending, sending, or uncertain queue entries target that domain (including IDN U-label recipients). The admin receives a conflict response directing them to resolve the queue first; terminal entries do not block deletion. Queue entries now also persist whether the recipient domain was hosted at enqueue time, and workers honor that marker even if a concurrent or out-of-band deletion removes the domain. SQLite and MySQL schemas include the marker; an additive, bounded startup migration backfills existing queue entries against currently configured domains. Entries queued before an earlier domain deletion cannot be reconstructed retroactively.
Inbound DATA now returns `552 5.3.4` when a line crosses the configured message-size bound before its CRLF arrives, then closes the transaction. Previously this path closed silently, leaving the sender with an ambiguous disconnect instead of the permanent size failure described by RFC 1870. A loopback regression checks the reply and discarded partial message.
Inbound DATA now also rejects an embedded bare carriage return with `554 5.6.0`, matching the already strict submission path; the regression verifies that malformed message bytes cannot be accepted as a valid CRLF-framed line.
Inbound connection throttling, connection-capacity rejection, and domain-list lookup failure now return a bounded `421` temporary SMTP greeting before closing. Previously all three paths silently closed the socket, making retry behavior less clear to sending peers. The opening reply has a regression test.
Generated DSN envelope IDs are now bounded even when a valid Message-ID is long; malformed or overlong persisted ENVID/ORCPT metadata is rejected before DNS or SMTP transport. Authenticated-submission queue admission also checks ENVID, so an invalid report identifier cannot create a stuck delivery.
Configuration loading now checks `server.hostname` as a syntactically valid SMTP DNS hostname, with `localhost` reserved for local development. This catches malformed EHLO/HELO identity before listeners start; public A/AAAA and PTR alignment still need deployment verification.

RFC 8460 TLS-RPT email now uses a durable system-only queue marker and
opportunistic delivery that does not enforce destination MTA-STS/DANE. A failed
STARTTLS handshake reconnects on a fresh socket before a plaintext retry;
ordinary mail retains its TLS policies. Live-domain behavior still needs
interoperability testing.

- Run live SMTP/DSN/ARC intermediary interoperability and external mail-client
  matrices on a real domain. These cannot be established by local fixtures.
- Continue adding external ARC vectors as available and verify live
  intermediary behavior on a real domain. Local one-, two-, and three-hop
  independent dkimpy fixtures pass, including a tampered middle hop.
- Run the three-engine browser suite in CI. All 15 local Chromium, Firefox,
  and WebKit tests passed after correcting a stale outbound-limits test locator;
  CI remains the cross-host check.
- Copy verified backups to encrypted off-host storage and perform an operator
  restore drill. Local scheduling alone does not cover host loss.
  Automatic scheduling now treats a future-dated last-success timestamp as due
  immediately, so a backward clock correction cannot pause backups until that
  timestamp; scheduler settings-read failures are logged instead of silently
  disabling backup attempts.
- Complete and drill the staged-database MySQL restore described in
  `docs/mysql_staged_restore.md`. An opt-in path now imports into a distinct
  pre-provisioned empty database, verifies manifest table counts and attachment
  references, and switches the configuration while retaining the old database
  and previous attachment/ACME directory generations.
  The fail-closed restore marker now records each completed phase for diagnosis.
  Final-phase startup completion also re-verifies the pre-restore safety archive before clearing the marker; a merely present but corrupt fallback no longer counts as recoverable.
  Full schema compatibility checks, phase-aware rollback and intermediate-phase crash recovery remain. Restores now check SQLite integrity and foreign keys, require counted objects to be real tables, require core MySQL authentication/mailbox/queue columns with their expected data types, require full-column unique MySQL indexes on domain and account email identities, require seven core MySQL mail-store foreign keys with their delete rules, and check installed MySQL single-column foreign keys for orphaned rows; startup also checks active attachment hashes before clearing a final durable marker. Earlier or unverifiable phases still block startup. The staged database switch is implemented but is not atomic with filesystem swaps because
  MySQL and filesystem swaps are not one transaction. The current `gomailtest` grant cannot create a second database;
  use separate disposable test grants or pre-provisioned databases for the
  switch/crash tests. The existing restore still needs manual safety-archive
  recovery after a partial import or activation failure; its marker deliberately
  blocks startup until the operator verifies recovery.

  Durable-marker startup verification now also hashes restored ACME files and
  manual TLS certificate/key files against the archive, and checks the exact
  restored SQLite configuration. A corrupt credential file or changed config
  leaves the marker in place instead of starting a mixed generation. MySQL
  intentionally rewrites destination fields in its config. The marker now
  records the exact hash of that staged, rewritten config and verifies it
  before startup clears the marker. Older markers without this hash retain
  the previous checks. Real staged-database activation still needs an
  isolated restore drill.

  Restore now stages and swaps an empty ACME directory when the destination
  has one, so old account keys or certificates cannot survive a restore whose
  archive contains no ACME files. An archive with ACME files and no configured
  destination is rejected before any live data changes. Durable-marker startup
  verification now also checks that the active ACME tree contains no extra
  credential files or symlinks absent from the archive; a mismatch keeps the
  recovery marker in place.

The standalone backup verifier now applies the same regular-file and canonical, local-path rules as extraction; an archive that restore would reject can no longer be reported as verified.
Backup creation and admin backup-directory settings now also resolve symlinks
before checking that the output is outside the database, configuration,
attachment, and ACME paths. A symlinked directory into the attachment tree is
rejected before an archive can copy itself or become mailbox state.
Backup source collection now rejects symlinked tree roots and non-regular tree entries, and opens files nonblocking before checking their type. A FIFO or device in the attachment/ACME tree or a credential path can no longer stall an online backup indefinitely. Regular TLS certificate/key symlinks to files remain supported.
Backup creation now checks that every database attachment reference points to a regular file of the recorded size before publishing an archive. SQLite uses the captured database snapshot; MySQL checks the live database after its transactional dump, so concurrent same-count MySQL changes and filesystem races still require operational quieting or an isolated restore drill.

The restore guard now applies to SQLite as well as MySQL. SQLite restores
also retain a verified pre-restore safety archive before
replacing the old database, so a later filesystem failure has a recovery source.
The MySQL instance
lock was moved outside the attachment tree so replacing that tree cannot
silently create a new lock identity; the previous lock remains honored during
upgrades. SQLite and opt-in staged MySQL restores also verify manifest row
counts and every attachment path/size against staged files before activation. In-place
MySQL restore now verifies the imported database too; new backups count all
persisted tables, while older six-count manifests remain restorable. An import mismatch leaves
the incomplete-restore marker in place instead of activating the file tree.

Account creation and edits now enforce at the storage boundary that the email
address belongs to its selected hosted domain, even when a caller bypasses the
admin form. Staged backup verification rejects accounts whose addresses do not
match their hosted domain before activation. This closes a routing/policy split
that row counts and foreign-key checks cannot detect.
Restore verification also rejects hosted domains or account addresses that
differ only by case, because GoMail resolves both identities case-insensitively
even when a restored database's unique index uses a binary collation.
Both SQLite and MySQL staged-restore checks now verify the core foreign-key
delete actions as well as their targets. In particular, the outbound queue's
message reference must use `ON DELETE SET NULL`; a restored cascade would
otherwise erase pending delivery when its Sent copy is removed.
Folder ownership and message-folder relationships are also required, including
`ON DELETE SET NULL` for `messages.folder_id`, so deleting a mailbox cannot
silently cascade-delete its messages after a malformed restore.

## Completed work and historical milestones

The sections below preserve implementation history and earlier milestone
checklists. They are not the authoritative open-issue list; actionable work is
listed only in the two open sections above.

- Inbound SMTP now returns temporary `451 4.3.0` when its domain-policy or
  enabled-greylisting database lookup fails at RCPT, instead of accepting the
  recipient while bypassing that policy. A forced greylisting-table failure
  regression verifies the recipient is not added to the transaction.

- On 2026-11-13, the MySQL backup/restore round-trip test passed against the
  dedicated, initially empty `gomailtest` database. It verified the archive,
  attachment and queue-history restoration, and removal of a database change
  made after the backup. The test cleans its tables afterward; the configured
  `gomail` database was not touched. The existing two-disposable-database
  variant remains available when the test user has database-creation rights.
  The MySQL storage integration test also passed against `gomailtest`; its
  test-created schema was removed afterward, leaving the database empty.
- MySQL restore now keeps the selected destination database connection and
  runtime storage/TLS/DKIM paths in the installed configuration rather than
  switching back to source-host paths from the archive. The fixed-database
  round trip verifies those settings after restore. This does not make the
  database import and filesystem activation atomic; staged restore remains
  open above.

- ARC validation covers independent dkimpy one-, two-, and three-hop final-RFC fixtures,
  historical AMS body modification, malformed/ambiguous tags, and chain-status
  transitions. Chromium and Firefox interaction/accessibility suites passed
  locally on 2026-10-20.
- MySQL restore retains a mandatory safety archive and stages filesystem
  objects before import; SQLite restore stages the replacement snapshot before
  clearing old WAL/SHM sidecars. Archive verification rejects missing required
  entries and duplicate paths.

- Added persistent outbound delivery history, recorded transactionally with
  worker claims/results and operator transitions, including SMTP codes when
  observed. The admin queue shows a bounded per-entry timeline without message
  content; backup manifests count the history records.

- Completed outbound queue administration at `/admin/queue`: bounded metadata
  listing, sender/recipient search, status filters, retry failed deliveries,
  cancel pending/failed deliveries, and individual stale-claim recovery.
  Actions require admin access and CSRF tokens and log changed queue IDs.
- Delivery workers now claim queue entries with unique database tokens and
  heartbeat active deliveries. A worker can finalize only the attempt it
  claimed; explicit operator resolution clears its old claim.
- Stale sending entries now enter an `uncertain` quarantine instead of being
  retried automatically. Admins review logs/recipient state and explicitly
  resolve them as delivered, retry, or cancel. Original workers may still
  report a known outcome until the operator resolves the entry.

## Completed security follow-up (2026-09-23)

- Attachment downloads now join through the owning message/account; guessed IDs
  return 404 across accounts. Stored paths are confined to `attachments_path`,
  and download headers use safe media-type formatting.
- Audited the remaining user-facing ID routes for account scoping.
- Corrected `strip_originating_ip`: enabled now removes the address from both
  Received and X-Originating-IP headers.
- Removed the unused outbound ARC helper that hard-coded authentication passes.

## Completed production hardening follow-up (2026-10-14)

- Web compose/forward recipients now use strict mailbox parsing, reject line
  breaks, and cannot reach generated headers or SMTP envelope commands with
  control characters. Outbound SMTP independently rejects unsafe envelopes.
- DMARC enforcement no longer has subject-, MIME- or receipt-header exemptions;
  attacker-controlled message metadata cannot route a DMARC failure to Inbox.
- Queue claims and outcomes use compare-and-set state transitions. Persistence
  is retried and failures produce a critical log/metric instead of silently
  losing the outcome or sending a misleading DSN.
- A still-valid cached MTA-STS policy remains enforced when a newly announced
  replacement cannot be retrieved.
- Attachment metadata batches are transactional, failed batches remove staged
  files, unsafe extensions are replaced, and messages no longer advertise a
  downloadable attachment when extraction fails. Restore trees are fully
  staged before the live directory is swapped.
- Account creation and default-folder provisioning now commit in one
  transaction. Admin metadata/password edits are atomic, account/domain
  deletion failures reach the administrator, and cascade deletion removes
  descendant attachment files only after the database commit succeeds.
- Local-recipient routing now fails closed on database errors instead of
  attempting remote SMTP delivery. Local and outbound delivery require their
  Inbox/Sent folders, and signed messages must parse before being queued.
- Administrator account input now validates numeric fields, selected-domain
  ownership, mailbox syntax and a 12-character minimum for new passwords.
  Backup settings no longer silently replace malformed numbers or ignored
  settings-read failures with zero values.

## Protocol and interoperability

- Selected published ARC draft-suite validation vectors now run in `auth` tests.
  Live intermediary and final-RFC vector breadth remain open. Do not enable
  ARC on ordinary originated mail.
- Run live SMTP interoperability against major providers.

## Mail clients

Mail-client access is now in scope, but every new listener remains disabled by
default. IMAP must not be advertised until the persistence and mutation tests
below pass; a read-only or UID-unstable implementation would corrupt client
synchronization state.

### IMAP milestone 1: persistent synchronization model

- Implemented the initial durable state tables and migration: per-folder
  UIDVALIDITY/UIDNEXT/HIGHESTMODSEQ, folder-scoped message UIDs, IMAP-only
  flags, keywords and subscriptions. Existing messages are backfilled and new
  delivery/draft/Sent messages allocate state in their creation transaction.
- Webmail Seen/Flagged updates, draft edits, POP3 deletion and mailbox moves now
  advance IMAP state. Regression tests cover monotonic/non-reused UIDs,
  destination reassignment, mod-sequences and account isolation.
- Add per-folder, non-repeating `UIDVALIDITY`, monotonic `UIDNEXT` and
  `HIGHESTMODSEQ` state for SQLite and MySQL.
- Give every message a permanent UID scoped to its current folder. COPY/MOVE
  assigns a new destination UID and never reuses an expunged UID.
- Persist `\\Seen`, `\\Answered`, `\\Flagged`, `\\Deleted`, `\\Draft` and
  validated custom keywords without confusing IMAP `\\Deleted` with GoMail's
  Trash folder.
- Make webmail, SMTP delivery, drafts, POP3 deletion and IMAP mutations update
  message state, counters, quota and modification sequences atomically.
- Backfill existing folders/messages deterministically and test restart,
  rollback, deletion and concurrent allocation behavior on SQLite and MySQL.

### IMAP milestone 2: secure IMAPS sessions

- Implemented an explicitly enabled, implicit-TLS port 993 listener using the
  shared connection/authentication limits. The session parser currently covers
  authentication, capability, folder listing/subscriptions, selection/status,
  sequence sets, UID SEARCH/FETCH/STORE, bounded literals and core flags.
- Protocol transcript tests cover LOGIN, LIST, SELECT, SEARCH, UID FETCH,
  BODY.PEEK Seen behavior, STORE, keywords and silent UID mutations.
- Add a separate `mail_clients.imap` switch/listener on port 993 using implicit
  TLS, the shared connection cap and authentication throttle. Keep the master
  `mail_clients.enabled` switch and IMAP service switch false by default.
- Implement the IMAP tagged-command parser, quoted strings/literals, bounded
  command and literal sizes, timeouts, state machine and graceful shutdown.
- Implemented bounded synchronized trailing literals for APPEND and other
  commands (including SEARCH), with command-specific size limits. Literals in
  the middle of a command remain extension work.
- Implement `CAPABILITY`, `NOOP`, `LOGOUT`, `LOGIN` and `AUTHENTICATE PLAIN`;
  never expose cleartext authentication and never log credentials/literals.

### IMAP milestone 3: mailbox and message access

- Implement `LIST`, `LSUB`, `STATUS`, `SELECT`, `EXAMINE`, `CREATE`, `DELETE`,
  `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `CLOSE` and `UNSELECT` with protected
  default folders and correct modified UTF-7 mailbox names.
- Implement sequence sets and `UID` forms for `SEARCH`, `FETCH`, `STORE`,
  `COPY`, `MOVE` and `EXPUNGE`; provide correct envelope/body-section/literal
  responses from the original RFC 5322 message.
- Implemented bounded MIME-tree parsing for `BODY`/`BODYSTRUCTURE`, numbered
  MIME parts, nested `message/rfc822`, `HEADER.FIELDS`/`.NOT`, multiple FETCH
  literals and partial byte ranges. ENVELOPE now handles complete address lists
  and sender/reply-to fallbacks from the original message headers.
- Replaced flat SEARCH matching with a bounded expression parser supporting
  implicit AND, `NOT`, binary `OR`, nested groups, sequence/UID sets, internal
  and sent dates, arbitrary headers, keywords, size, address/body/text and the
  standard system-flag criteria.
- Implement at least IMAP4rev1 plus `UIDPLUS`, `MOVE`, `IDLE`, `ENABLE`,
  `CONDSTORE` and `QRESYNC` only when their complete semantics are available.
- Implemented `ENABLE`, `NAMESPACE`, `SPECIAL-USE` discovery and atomic
  `CONDSTORE`: SELECT/EXAMINE report HIGHESTMODSEQ, FETCH supports MODSEQ and
  CHANGEDSINCE, STORE supports UNCHANGEDSINCE with MODIFIED responses, and
  SEARCH supports MODSEQ.
- Implemented QRESYNC with durable, transactionally recorded expunge history
  across IMAP, webmail, drafts and POP3 moves/deletions. SELECT/EXAMINE accepts
  QRESYNC state, returns changed flags and `VANISHED (EARLIER)`, while live
  removals use `VANISHED`.
- Implemented UIDPLUS response codes for APPEND/COPY/MOVE and selective
  `UID EXPUNGE`; `UIDPLUS` and `MOVE` are advertised by the experimental
  listener and covered by the protocol transcript.
- Implemented `CHECK`, hierarchy-aware LIST/LSUB reference and wildcard
  matching, virtual `\\Noselect` parents, child attributes, recursive hierarchy
  rename, safe non-empty/parent deletion, and RFC-style Inbox rename that
  preserves the old mailbox identity while creating a fresh required Inbox.
- `\\Recent` is now atomically claimed by one selected session, retained in that
  session's FETCH/SEARCH/IDLE view, and claimed for new delivery during IDLE.

### IMAP milestone 4: concurrency and recovery

- Add account/mailbox session coordination and unsolicited EXISTS, EXPUNGE and
  flag updates. `IDLE` must wake without polling races or unbounded goroutines.
- Implemented a bounded, account-scoped, coalescing event hub. Delivery,
  webmail flags/moves/deletes, drafts, POP3 and IMAP mutations wake IDLE
  immediately; a 30-second safety refresh covers direct out-of-process database
  changes without the former one-second polling load.
- Test concurrent webmail and IMAP moves, flag changes, delivery, expunge,
  disconnects, database failures and server restarts. Add protocol transcripts,
  fuzz targets and race/load tests.
- APPEND now commits message state, UID/flags, quota, attachment metadata and
  folder counters in one database transaction; attachment files are removed on
  every rollback path. Concurrent UID allocation has race/regression coverage.
- The protocol transcript now exercises concurrent delivery, flag notification
  and move/EXPUNGE while IDLE is active. The legacy single-delete path was made
  transactional after this exposed that it did not previously move IMAP state.

### Discovery and client compatibility

- Implemented Thunderbird autoconfiguration and Microsoft Autodiscover XML
  endpoints. They accept configured local domains and advertise only services
  enabled behind the master switch with certificate-backed TLS configuration;
  disabled services and plaintext deployments return no discovery document.
- SRV and client-discovery DNS examples are documented in `docs/dns_records.md`.
  Publishing is an operator deployment step, only for enabled and tested
  listeners; live Apple/mobile profile checks remain open.
- Run Thunderbird, Outlook, Apple Mail, iOS and Android interoperability
  matrices for IMAP, POP3 and submission on the real server. Test initial sync,
  large folders, reconnect, IDLE, moves, drafts, Sent, Trash and deletion.

## Product and operations

- Added an admin-only complete configuration editor with CSRF protection,
  write-only secret placeholders, full validation, atomic mode-0600 saves,
  timestamped previous versions, section-only audit logging, live logging
  reconfiguration and explicit restart-required reporting for startup-owned
  components.
- Added configurable filesystem pressure thresholds. All durable message,
  queue, draft, IMAP APPEND/COPY and backup paths preserve the configured free
  space reserve; SMTP/client/web callers receive temporary failures, readiness
  degrades, Prometheus exports free-space/pressure gauges, startup logs the
  condition and the administrator dashboard displays a warning.
- Added persistent per-account outbound abuse limits shared by webmail and
  authenticated submission. Hour/day message and recipient counters commit in
  the same transaction as accepted queue entries; excess use causes a durable
  temporary suspension without partially queued mail. Administrators can edit
  and live-apply policy, inspect bounded usage, reset/unlock or manually suspend
  accounts from the Outbound Limits page. System reports remain exempt.

### 1. Metrics and logging

- Implemented the disabled-by-default dedicated `/metrics` listener with
  loopback-safe defaults, required authentication for non-loopback exposure,
  bounded queue/quota/TLS gauges, tests and initial alert guidance.
- Implemented bounded metrics for queue state/age, SMTP outcomes, login
  failures/blocks, delivery attempts, report delivery, DNSSEC/TLSA, quota
  rejection contexts and active certificate expiry.
- `logging.format` now produces validated text or JSON records, with timestamp,
  severity and a bounded component field extracted from existing prefixes.
- Legacy standard-library server logs are bridged into the configured logger,
  with centralized email/IP redaction and consistent text/JSON output. Continue
  converting high-value events to explicit typed fields as code is touched.

### 2. Backup and restore tooling

- Implemented versioned offline backup, independent verification and guarded
  restore commands covering SQLite/MySQL database export, attachments,
  configuration and ACME/manual certificate state, with SHA-256/count manifests
  and a shared runtime lock. SQLite round-trip restore is automated.
- Added an admin-only, CSRF-protected backup page for manual verified online
  archives and persistent automatic interval/retention settings. Archives are
  server-side only; concurrent jobs are rejected and retention is name-scoped.
- Add live MySQL backup/restore integration coverage and conduct/document an
  operator-run isolated restore drill. Encryption and off-host retention remain
  deployment responsibilities and are documented.

### 3. Scale and test coverage

- Implemented account- and view-scoped signed keyset cursors for mailbox,
  folder and search navigation, ordered by `(received_at, id)`, with matching
  SQLite/MySQL indexes plus tamper, isolation and mutation-stability tests.
- Added native Go fuzz targets for RFC 5322/MIME, DSN, ESMTP parameter and SPF
  macro parsing, with bounded inputs and protocol fixtures. Continue expanding
  reporting/web integration and run longer fuzz campaigns in CI.
- Added an isolated Playwright browser suite covering login, mailbox/message
  keyboard navigation, draft autosave, settings, responsive navigation and the
  backup page across Chromium, Firefox and WebKit. WCAG A/AA checks use
  axe-core; CI installs all three engines and retains traces/screenshots on
  failure. Continue expanding flows as features are added.

### 4. Client discovery and synchronization

- Work is tracked by the detailed Mail clients milestones above. IMAP and its
  discovery records remain unavailable until the required synchronization
  invariants and protocol tests are complete.

## Completed mailbox quota enforcement (2026-10-14)

- Per-account usage is backfilled for existing installations and maintained in
  the same transaction as message, Sent-copy and draft changes. Trash continues
  to count until permanent deletion; draft updates charge only their size delta.
- Inbound multi-recipient delivery reserves all recipients atomically. A full
  mailbox produces temporary SMTP status `452 4.2.2` without partial delivery;
  webmail and submission also return explicit quota-full errors.
- User Settings and the administrator account list show current usage and the
  configured limit. Unlimited, boundary, concurrent-insert, batch-rollback,
  draft-update and deletion-reclamation behavior has regression coverage.

## Completed webmail follow-up (2026-09-23)

- Users can permanently delete account-owned messages from Trash, individually
  or in bulk. Database rows and attachment records are removed atomically, and
  contained attachment files are cleaned up after commit.
- Saved drafts have an explicit, account-scoped permanent delete action.
- The user Settings page supports display-name updates and authenticated
  password changes without exposing administrative account controls.

## Completed protocol follow-up (2026-09-23)

- SPF now enforces the global ten DNS-term limit without charging MX/PTR
  expansion queries as extra terms, caps MX/PTR expansion as RFC 7208 requires,
  applies the two-void-lookup ceiling, and propagates mechanism DNS errors with
  the RFC-specific PTR exceptions.
- SPF validates the complete record before evaluation, rejects malformed dual
  CIDR lengths and duplicate known modifiers, ignores repeated unknown
  modifiers, treats mechanism/modifier names case-insensitively, and makes
  `exists` depend on an IPv4 A result.
- SPF macro strings now enforce the RFC 7208 grammar before evaluation,
  including allowed letters, transformer order, delimiters and escapes.
  Uppercase macros use percent encoding, IPv4/IPv6 expansion has deterministic
  fixtures, and `%{p}` uses cached forward-confirmed reverse DNS bounded to ten
  candidate names.
- TLS-RPT stores successful and failed TLS policy evaluations, preserves STS,
  TLSA and no-policy descriptions, groups summaries/failure details by applied
  policy, and emits RFC 8460 multipart report messages with required headers.

## Completed DANE/DNSSEC audit (2026-09-24)

- TLSA RRsets must be DNSSEC-authenticated; insecure responses, authenticated
  absence, lookup failures and authenticated-but-malformed RRsets remain
  distinct policy outcomes.
- Certificate verification covers Usages 0/1/2/3, selectors 0/1 and matching
  types 0/1/2. Usage 2 can validate an exact full-certificate trust anchor even
  when the SMTP peer correctly omits the root from its transmitted chain.
- Required DANE now always prohibits plaintext fallback, including missing,
  rejected or failed STARTTLS. Optional mode falls back only through ordinary
  PKIX verification.
- Each SMTP attempt uses one authenticated TLSA lookup consistently for the TLS
  handshake and TLS-RPT accounting, avoiding a second lookup during DNS record
  rotation.
- Deterministic tests exercise the full 24-combination usage/selector/matching
  matrix, malformed and mixed RRsets, chain linkage, PKIX/name requirements and
  DNSSEC authentication states.

## Completed MIME and SMTP-status follow-up (2026-09-24)

- MIME text and RFC 2047 headers honor declared character sets and are converted
  to UTF-8, including common legacy encodings.
- RFC 2231 extended and continuation attachment filenames are decoded, nested
  `multipart/alternative` content is retained, and non-text inline resources in
  `multipart/related` are preserved instead of discarded.
- SMTP transactional replies consistently use enhanced status codes and the
  server advertises `ENHANCEDSTATUSCODES`.
- RFC 3464 failure reports now contain distinct per-message/per-recipient
  blocks, safe diagnostics, `Original-Envelope-Id`, `Original-Recipient`, and
  the requested `RET=FULL` or `RET=HDRS` original content. RFC 3461 ENVID/ORCPT
  xtext values are encoded and decoded without changing case.
- DSN parsing now uses the MIME boundary parser instead of a boundary regex,
  unfolds continued fields, preserves multiple recipient blocks, recognizes
  standard `Original-Recipient`, and retains the first recipient's report-level
  result. Fixtures cover complex boundaries, folded diagnostics and success,
  delay and failure status families.
- MIME media types are handled case-insensitively, HTML-only multipart messages
  receive a plain-text representation, nested-part read errors propagate, and
  recursion is bounded. Fixtures cover encoded attachments, legacy charsets,
  related/alternative nesting and excessive nesting.

## Completed TLS-RPT scheduling and transport follow-up (2026-09-24)

- TLS-RPT has its own `tls_rpt.send_reports` switch and scheduler, running for
  complete UTC-day windows independently of DMARC reports.
- TLS-RPT policy parsing accepts validated `mailto:` and HTTPS `rua` URIs.
  HTTPS reports use a gzip-compressed RFC 8460 JSON POST with the
  `application/tlsrpt+gzip` media type and require a successful HTTP response.
- Failed report delivery records attempt count, last error and a bounded next
  attempt time. The original unreported event window is retained across retries
  and events are marked reported only after at least one destination accepts.

## Completed DMARC aggregate-reporting follow-up (2026-09-24)

- Feedback records retain DKIM result, signing domain and selector, plus SPF
  result, evaluated domain and scope. Aggregate XML emits these identities in
  `auth_results` instead of producing empty authentication sections.
- Aggregation groups exact authentication outcomes and identities, preserving
  accurate row counts without reducing mixed results to synthetic `neutral`.
- External `rua` delivery requires the policy-domain authorization TXT record;
  same-domain destinations bypass that external check. Deterministic tests cover
  authorized and unauthorized destinations and DMARC URI size suffixes.

## Completed ARC cryptographic follow-up (2026-09-24)

- ARC-Seal signing and verification cover every earlier ARC set in instance
  order, while `cv=fail` correctly signs only the new set.
- Validation requires exactly one AAR, AMS and Seal per contiguous instance,
  rejects chains over 50 sets and forbidden Seal canonicalization/header tags,
  and cryptographically verifies every AMS and cumulative Seal.
- AMS and Seal selectors are looked up independently, and an intermediary
  derives `cv=pass` or `cv=fail` from validation instead of hard-coding pass.
- Deterministic two-hop RSA tests prove that altering an earlier set breaks the
  later cumulative Seal; Ed25519 AMS coverage remains in place.

## Completed DSN lifecycle follow-up (2026-09-24)

- The inbound server advertises `DSN` and generates `Action: delivered` reports
  after requested recipients are durably stored in their local mailboxes.
- Queue entries can generate one requested `Action: delayed` report after the
  configurable `delivery.dsn_delay_after_seconds` threshold, followed later by
  the requested success or failure report.
- Generated DSNs use a null SMTP reverse path and `NOTIFY=NEVER`, preventing DSN
  failures from creating notification loops. Success and delay reports include
  only original headers even when `RET=FULL` was requested.
- Incoming success and delay DSNs are retained for the recipient instead of
  being discarded or recorded as permanent bounces.

## Completed submission authority follow-up (2026-11-20)

- Outbound queue creation now rechecks the sending account and hosted domain
  inside the same transaction that stores the Sent copy and queue entries.
  MySQL locks those rows until commit so a concurrent admin disable cannot
  slip between authorization and acceptance; SMTP submission returns a
  permanent authorization error instead of accepting a message it cannot queue.
- SQLite regression tests cover disabled/deleted accounts and disabled domains,
  and verify that rejected submissions leave no Sent copy or queue entry.

## Optional future features

- Add an explicit one-time `-setup` bootstrap mode for missing configurations.
  Bind its installation wizard to loopback by default, require a short-lived
  token printed only to the terminal, validate database/TLS/listener settings,
  generate secrets and the initial administrator/DKIM state, write the config
  atomically with mode 0600, and permanently disable setup once configuration
  exists. Preserve the current manual/unattended config-file workflow.
- Vacation responses, Sieve-style filtering and mailing lists.
- Two-factor web authentication and account recovery.
- BIMI, CalDAV/CardDAV and PGP/S/MIME integrations.
