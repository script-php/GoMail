# Monitoring GoMail

Administrators can inspect delivery metadata at `/admin/queue`, filter by status
or envelope address, and retry failures or cancel pending/failed deliveries.
Cancellation preserves the Sent copy and records a terminal `cancelled` state,
also included in queue metrics. Retries reset the attempt cycle and preserve
notification flags; the sender may already have received a failure notification.
Recovery is available for sending entries unchanged for over 30 minutes. It
quarantines them as `uncertain`, and workers do not automatically retry them.
Check the recipient and delivery logs, then explicitly mark delivered, retry, or
cancel. A retry can duplicate a message already accepted by a remote server.
Each changed entry is logged with the administrator's account ID. The page
displays the latest error, not a complete attempt history, and never loads
message bodies or attachments.

Each queue entry has a bounded **History** view with the most recent 50
claim, result, recovery, and administrator events. An event contains its time,
attempt number, SMTP code when one was observed, and a shortened diagnostic.
`delivery_succeeded` records that GoMail observed the send call succeed;
`outcome_uncertain` means no final outcome was durably recorded. These events
are included in database backups and removed when their queue entry is deleted.

Administrators can configure completed queue retention on the same page. Zero
disables pruning. When enabled, an hourly worker removes up to 500 entries per
run after the selected number of days, but only if their current status is
`sent`, `failed`, or `cancelled`. Pending, sending, and uncertain entries are
not pruned. "Run cleanup now" applies the same bounded rule. Pruning removes
the queued message copy and its history; it does not remove the Sent mailbox
copy. Before deleting a completed entry, GoMail archives its issued VERP
return-path mapping in the same database transaction, so late bounces can still
be attributed. The separate **Archived bounce-address retention** setting
defaults to 0 (keep indefinitely). An administrator may opt into 1–3650 days
and run cleanup immediately; otherwise an hourly job removes up to 500 expired
mappings per run. Mappings referenced by a non-cancelled queue entry remain
protected. Once a mapping is deleted, GoMail will no longer recognize a late
bounce to that address. Archived mappings are included in database backups;
keep backups if older delivery evidence is required.

Entries with an outstanding requested final SUCCESS or FAILURE DSN are not
pruned. Final DSN delivery has its own persisted retry time and attempt count;
mailbox insertion and the sent marker commit together. A missing or unavailable
sender mailbox leaves the notification pending for retry and should be
investigated by an operator.

Workers write a unique claim token when starting delivery and refresh its
heartbeat every 30 seconds. Automatic and manual recovery only act after the
heartbeat has been absent for 30 minutes. A worker can still report a known
outcome from an uncertain entry until an operator resolves it. Once resolved,
its old claim cannot overwrite a newer attempt. SMTP delivery itself cannot be
rolled back after a remote server accepts a message.

GoMail's Prometheus-compatible endpoint is disabled by default. A safe local
configuration is:

```json
"metrics": {
  "enabled": true,
  "listen_addr": "127.0.0.1:9090",
  "bearer_token": ""
}
```

Prometheus running on the same host can scrape
`http://127.0.0.1:9090/metrics`. For a non-loopback listener, GoMail refuses to
start unless `bearer_token` is set. Send that value as
`Authorization: Bearer <token>` and protect the connection with a trusted TLS
reverse proxy or private monitoring network.

## Exported gauges

- `gomail_process_uptime_seconds`
- `gomail_delivery_queue_entries{status="pending|sending|sent|failed"}`
- `gomail_storage_free_bytes`
- `gomail_storage_pressure`
- `gomail_storage_warning_threshold_bytes`
- `gomail_storage_minimum_threshold_bytes`
- `gomail_outbound_limit_rejections_total{outcome="submission|webmail|forward"}`
- `gomail_delivery_queue_oldest_seconds`
- `gomail_mailbox_used_bytes`
- `gomail_mailbox_configured_quota_bytes`
- `gomail_mailbox_quota_limited_accounts`
- `gomail_mailbox_quota_near_limit_accounts`
- `gomail_tls_attempts_24h`
- `gomail_tls_failures_24h`
- `gomail_certificate_expiry_timestamp_seconds` (present when TLS has an active certificate)
- `gomail_smtp_messages_total{outcome="accepted|deferred|rejected"}`
- `gomail_login_events_total{outcome="failed|blocked"}`
- `gomail_delivery_attempts_total{outcome="delivered|retry|failed"}`
- `gomail_report_delivery_total{outcome="dmarc_success|dmarc_failure|tlsrpt_success|tlsrpt_failure"}`
- `gomail_dane_dnssec_total{outcome="authenticated|insecure|no_record|malformed|lookup_error|matched|mismatch"}`
- `gomail_quota_rejections_total{outcome="inbound|submission|webmail|forward|delivery|draft"}`

The status label has a fixed allowlist. No recipient, sender, domain, IP,
message ID or account is exposed as a metric label.

## Initial alerts

Tune thresholds to normal traffic before paging. Useful starting conditions
are:

```promql
up{job="gomail"} == 0
gomail_delivery_queue_oldest_seconds > 900
gomail_delivery_queue_entries{status="failed"} > 0
gomail_mailbox_quota_near_limit_accounts > 0
gomail_tls_failures_24h > 0
gomail_certificate_expiry_timestamp_seconds - time() < 1209600
increase(gomail_delivery_attempts_total{outcome="failed"}[15m]) > 0
increase(gomail_login_events_total{outcome="blocked"}[15m]) > 0
```

Continue monitoring `/readyz`, disk capacity, external SMTP reachability,
and DNSSEC/TLSA correctness. In-process counters reset when GoMail restarts;
Prometheus preserves their time series and `increase()` handles counter resets.
