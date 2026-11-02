# Open work and completed history

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
- DMARC `ri` requests shorter than one day remain a best-effort enhancement;
  scheduled aggregate reports now meet the required daily cadence.

## Fixed report-generation review findings (2026-10-24)

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

- Run an isolated MySQL backup/restore round trip with a test-only MySQL user
  permitted to create and drop disposable databases. The opt-in test is
  `GOMAIL_TEST_MYSQL_CONFIG=/absolute/path/to/config.local.json go test ./backup -run TestMySQLBackupRestoreIsolatedRoundTrip -count=1`.
- Run live SMTP/DSN/ARC intermediary interoperability and external mail-client
  matrices on a real domain. These cannot be established by local fixtures.
- Expand independent final-RFC ARC validation vectors beyond the current
  one- and two-hop dkimpy fixtures; verify live intermediary behavior.
- Run the WebKit interaction/accessibility suite in CI or on a host with
  `libwoff1` and `libavif16`. Local Chromium and Firefox suites passed.
- Copy verified backups to encrypted off-host storage and perform an operator
  restore drill. Local scheduling alone does not cover host loss.
- Design a staged-database MySQL restore so database import and filesystem
  activation cannot leave a mixed state. This needs suitable CREATE/DROP
  privileges and an isolated drill.

## Completed work and historical milestones

The sections below preserve implementation history and earlier milestone
checklists. They are not the authoritative open-issue list; actionable work is
listed only in the two open sections above.

- ARC validation covers independent dkimpy one- and two-hop final-RFC fixtures,
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
- Publish/document SRV records and Apple/mobile manual profiles only after the
  corresponding listener is operational.
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
