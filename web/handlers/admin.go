package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"gomail/auth"
	backupops "gomail/backup"
	"gomail/config"
	"gomail/logging"
	"gomail/reporting"
	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

// AdminHandler handles the admin panel for domains and accounts.
type AdminHandler struct {
	cfg                *config.Config
	db                 *store.DB
	sessionMgr         *security.SessionManager
	tmplDashboard      *template.Template
	tmplDomains        *template.Template
	tmplDomainEdit     *template.Template
	tmplAccounts       *template.Template
	tmplAccountEdit    *template.Template
	tmplDMARCFeedback  *template.Template
	tmplTLSRPT         *template.Template
	tmplGreylisting    *template.Template
	tmplTarpitting     *template.Template
	tmplVERPBounces    *template.Template
	tmplBackups        *template.Template
	tmplConfiguration  *template.Template
	tmplOutboundLimits *template.Template
	tmplOutboundQueue  *template.Template
	tmplReportInbox    *template.Template
	tmplAliases        *template.Template
	enqueueFunc        reporting.EnqueueFunc
	tlsReportEnqueue   reporting.EnqueueFunc
	backupManager      *backupops.Manager
}

// NewAdminHandler creates an admin handler.
func (h *AdminHandler) SetTLSReportEnqueue(fn reporting.EnqueueFunc) { h.tlsReportEnqueue = fn }

func NewAdminHandler(cfg *config.Config, db *store.DB, sm *security.SessionManager, enqueueFunc reporting.EnqueueFunc, backupManager *backupops.Manager) *AdminHandler {
	funcMap := template.FuncMap{
		"formatSize": func(size int64) string {
			switch {
			case size >= 1073741824:
				return fmt.Sprintf("%.1f GB", float64(size)/1073741824)
			case size >= 1048576:
				return fmt.Sprintf("%.1f MB", float64(size)/1048576)
			case size >= 1024:
				return fmt.Sprintf("%.1f KB", float64(size)/1024)
			default:
				return fmt.Sprintf("%d B", size)
			}
		},
		"divide": func(a, b int64) int64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
	}

	tmplDashboard := templates.LoadTemplate(funcMap, "base", "admin_dashboard", "welcome")
	tmplDomains := templates.LoadTemplate(funcMap, "base", "admin_domains", "welcome")
	tmplDomainEdit := templates.LoadTemplate(funcMap, "base", "admin_domain_edit", "welcome")
	tmplAccounts := templates.LoadTemplate(funcMap, "base", "admin_accounts", "welcome")
	tmplAccountEdit := templates.LoadTemplate(funcMap, "base", "admin_account_edit", "welcome")
	tmplDMARCFeedback := templates.LoadTemplate(funcMap, "base", "admin_dmarc_feedback", "welcome")
	tmplTLSRPT := templates.LoadTemplate(funcMap, "base", "admin_tls_rpt", "welcome")
	tmplGreylisting := templates.LoadTemplate(funcMap, "base", "admin_greylisting", "welcome")
	tmplTarpitting := templates.LoadTemplate(funcMap, "base", "admin_tarpitting", "welcome")
	tmplVERPBounces := templates.LoadTemplate(funcMap, "base", "admin_verp_bounces", "welcome")
	tmplBackups := templates.LoadTemplate(funcMap, "base", "admin_backups", "welcome")
	tmplConfiguration := templates.LoadTemplate(funcMap, "base", "admin_configuration", "welcome")
	tmplOutboundLimits := templates.LoadTemplate(funcMap, "base", "admin_outbound_limits", "welcome")
	tmplOutboundQueue := templates.LoadTemplate(funcMap, "base", "admin_outbound_queue", "welcome")
	tmplReportInbox := templates.LoadTemplate(funcMap, "base", "admin_report_inbox", "welcome")
	tmplAliases := templates.LoadTemplate(funcMap, "base", "admin_aliases", "welcome")

	return &AdminHandler{
		cfg:                cfg,
		db:                 db,
		sessionMgr:         sm,
		tmplDashboard:      tmplDashboard,
		tmplDomains:        tmplDomains,
		tmplDomainEdit:     tmplDomainEdit,
		tmplAccounts:       tmplAccounts,
		tmplAccountEdit:    tmplAccountEdit,
		tmplDMARCFeedback:  tmplDMARCFeedback,
		tmplTLSRPT:         tmplTLSRPT,
		tmplGreylisting:    tmplGreylisting,
		tmplTarpitting:     tmplTarpitting,
		tmplVERPBounces:    tmplVERPBounces,
		tmplBackups:        tmplBackups,
		tmplConfiguration:  tmplConfiguration,
		tmplOutboundLimits: tmplOutboundLimits,
		tmplOutboundQueue:  tmplOutboundQueue,
		tmplReportInbox:    tmplReportInbox,
		tmplAliases:        tmplAliases,
		enqueueFunc:        enqueueFunc,
		backupManager:      backupManager,
	}
}

// OutboundQueue exposes delivery metadata and race-safe operational controls.
// It deliberately never loads or renders raw queued messages.
func (h *AdminHandler) OutboundQueue(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	errorMessage := ""
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		ids := r.Form["queue_id"]
		action := r.FormValue("action")
		if action == "retention_save" {
			days, parseErr := strconv.Atoi(strings.TrimSpace(r.FormValue("retention_days")))
			if parseErr != nil || days < 0 || days > 3650 {
				errorMessage = "Retention must be between 0 and 3650 days."
			} else if saveErr := h.db.SetQueueRetentionDays(days); saveErr != nil {
				errorMessage = "Unable to save queue retention."
			} else {
				logging.Info(fmt.Sprintf("[admin] queue retention days=%d by_account_id=%d", days, account.ID))
				http.Redirect(w, r, "/admin/queue?updated=retention", http.StatusSeeOther)
				return
			}
		} else if action == "retention_run" {
			days, settingsErr := h.db.QueueRetentionDays()
			if settingsErr != nil || days == 0 {
				errorMessage = "Enable retention before running cleanup."
			} else if removed, runErr := h.db.PruneCompletedQueueEntries(days, time.Now().UTC(), 500); runErr != nil {
				errorMessage = "Queue cleanup failed."
			} else {
				logging.Info(fmt.Sprintf("[admin] queue cleanup removed=%d by_account_id=%d", removed, account.ID))
				http.Redirect(w, r, fmt.Sprintf("/admin/queue?updated=%d", removed), http.StatusSeeOther)
				return
			}
		} else if action == "verp_retention_save" {
			days, parseErr := strconv.Atoi(strings.TrimSpace(r.FormValue("verp_retention_days")))
			if parseErr != nil || days < 0 || days > 3650 {
				errorMessage = "VERP retention must be between 0 and 3650 days."
			} else if saveErr := h.db.SetVERPRetentionDays(days); saveErr != nil {
				errorMessage = "Unable to save VERP retention."
			} else {
				logging.Info(fmt.Sprintf("[admin] VERP retention days=%d by_account_id=%d", days, account.ID))
				http.Redirect(w, r, "/admin/queue?updated=verp_retention", http.StatusSeeOther)
				return
			}
		} else if action == "verp_retention_run" {
			days, settingsErr := h.db.VERPRetentionDays()
			if settingsErr != nil || days == 0 {
				errorMessage = "Enable VERP retention before running cleanup."
			} else if removed, runErr := h.db.PruneIssuedVERP(days, time.Now().UTC(), 500); runErr != nil {
				errorMessage = "VERP cleanup failed."
			} else {
				logging.Info(fmt.Sprintf("[admin] VERP cleanup removed=%d by_account_id=%d", removed, account.ID))
				http.Redirect(w, r, "/admin/queue?updated=verp_cleanup", http.StatusSeeOther)
				return
			}
		}
		if single := strings.TrimSpace(r.FormValue("single")); single != "" {
			parts := strings.SplitN(single, ":", 2)
			if len(parts) == 2 {
				action, ids = parts[0], []string{parts[1]}
			} else {
				ids = nil
			}
		}
		if action == "retention_save" || action == "retention_run" || action == "verp_retention_save" || action == "verp_retention_run" {
			// Render the settings error below.
		} else if len(ids) == 0 || len(ids) > 100 {
			errorMessage = "Select between 1 and 100 queue entries."
		} else {
			updated := 0
			for _, rawID := range ids {
				id, err := strconv.ParseInt(rawID, 10, 64)
				if err != nil || id <= 0 {
					errorMessage = "Invalid queue entry."
					break
				}
				var changed bool
				switch action {
				case "retry":
					changed, err = h.db.RetryQueueEntry(id)
				case "cancel":
					changed, err = h.db.CancelQueueEntry(id)
				case "recover":
					changed, err = h.db.RecoverStaleQueueEntry(id)
				case "retry_uncertain":
					changed, err = h.db.ResolveUncertainQueueEntry(id, "retry")
				case "delivered_uncertain":
					changed, err = h.db.ResolveUncertainQueueEntry(id, "delivered")
				case "cancel_uncertain":
					changed, err = h.db.ResolveUncertainQueueEntry(id, "cancel")
				default:
					err = fmt.Errorf("unknown queue action")
				}
				if err != nil {
					errorMessage = "Unable to update the selected queue entry."
					log.Printf("[admin] outbound queue action error: %v", err)
					break
				}
				if changed {
					updated++
					logging.Info(fmt.Sprintf("[admin] queue_id=%d action=%s by_account_id=%d", id, action, account.ID))
				}
			}
			if errorMessage == "" {
				logging.Info(fmt.Sprintf("[admin] outbound queue action=%s selected=%d updated=%d by_account_id=%d", action, len(ids), updated, account.ID))
				if updated == 0 {
					errorMessage = "No entries changed; their state may have changed while the page was open."
				} else {
					http.Redirect(w, r, fmt.Sprintf("/admin/queue?updated=%d", updated), http.StatusSeeOther)
					return
				}
			}
		}
	}

	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	queuePage, err := h.db.ListQueueAdmin(status, query, page)
	if err != nil {
		if errorMessage == "" {
			errorMessage = "Unable to load the outbound queue."
		}
		log.Printf("[admin] outbound queue list error: %v", err)
	}
	retentionDays, retentionErr := h.db.QueueRetentionDays()
	if retentionErr != nil && errorMessage == "" {
		errorMessage = "Unable to load queue retention settings."
	}
	verpRetentionDays, verpRetentionErr := h.db.VERPRetentionDays()
	if verpRetentionErr != nil && errorMessage == "" {
		errorMessage = "Unable to load VERP retention settings."
	}
	var history []store.QueueEvent
	var historyID int64
	if requested := r.URL.Query().Get("history"); requested != "" {
		historyID, err = strconv.ParseInt(requested, 10, 64)
		if err != nil || historyID <= 0 {
			http.Error(w, "Invalid queue entry", http.StatusBadRequest)
			return
		}
		entryStatus, lookupErr := h.db.QueueEntryStatus(historyID)
		if lookupErr != nil || entryStatus == "" {
			http.Error(w, "Queue entry not found", http.StatusNotFound)
			return
		}
		history, err = h.db.ListQueueEvents(historyID, 50)
		if err != nil {
			http.Error(w, "Unable to load delivery history", http.StatusInternalServerError)
			return
		}
	}
	pageURL := func(number int) string {
		values := url.Values{}
		if status != "" && status != "all" {
			values.Set("status", status)
		}
		if query != "" {
			values.Set("q", query)
		}
		values.Set("page", strconv.Itoa(number))
		return "/admin/queue?" + values.Encode()
	}
	prevURL, nextURL := "", ""
	if queuePage.Page > 1 {
		prevURL = pageURL(queuePage.Page - 1)
	}
	if queuePage.Page < queuePage.TotalPages {
		nextURL = pageURL(queuePage.Page + 1)
	}
	data := map[string]interface{}{
		"Title": "Outbound Queue", "Section": "admin", "AdminPanel": "queue", "Account": account,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r), "Queue": queuePage, "Status": status, "Query": query,
		"Error": errorMessage, "Updated": r.URL.Query().Get("updated"), "PrevURL": prevURL, "NextURL": nextURL,
		"HistoryID": historyID, "History": history,
		"RetentionDays":     retentionDays,
		"VERPRetentionDays": verpRetentionDays,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplOutboundQueue.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] outbound queue template error: %v", err)
	}
}

func (h *AdminHandler) OutboundLimits(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}
	if h.backupManager == nil || strings.TrimSpace(h.backupManager.ConfigPath()) == "" {
		http.Error(w, "Configuration manager unavailable", http.StatusServiceUnavailable)
		return
	}
	path := h.backupManager.ConfigPath()
	current, err := config.Load(path)
	if err != nil {
		http.Error(w, "Unable to load configuration", http.StatusInternalServerError)
		return
	}
	errorMessage := ""
	if r.Method == http.MethodPost {
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		if action == "save" {
			parse := func(name string) (int, error) {
				value, parseErr := strconv.Atoi(strings.TrimSpace(r.FormValue(name)))
				if parseErr != nil || value <= 0 {
					return 0, fmt.Errorf("%s must be a positive number", strings.ReplaceAll(name, "_", " "))
				}
				return value, nil
			}
			limits := config.OutboundLimitsConfig{Enabled: r.FormValue("enabled") == "on"}
			var parseErr error
			if limits.MessagesPerHour, parseErr = parse("messages_per_hour"); parseErr == nil {
				limits.MessagesPerDay, parseErr = parse("messages_per_day")
			}
			if parseErr == nil {
				limits.RecipientsPerHour, parseErr = parse("recipients_per_hour")
			}
			if parseErr == nil {
				limits.RecipientsPerDay, parseErr = parse("recipients_per_day")
			}
			if parseErr == nil {
				limits.MaxRecipientsPerMessage, parseErr = parse("max_recipients_per_message")
			}
			if parseErr == nil {
				limits.SuspensionMinutes, parseErr = parse("suspension_minutes")
			}
			if parseErr != nil {
				errorMessage = parseErr.Error()
			} else {
				current.OutboundLimits = limits
				if validateErr := current.Validate(); validateErr != nil {
					errorMessage = validateErr.Error()
				} else if _, saveErr := config.SaveAtomic(path, current); saveErr != nil {
					errorMessage = saveErr.Error()
				} else {
					h.db.ConfigureOutboundLimits(current.OutboundLimits)
					logging.Info(fmt.Sprintf("[admin] outbound limits changed by account_id=%d", account.ID))
					http.Redirect(w, r, "/admin/outbound-limits?saved=1", http.StatusSeeOther)
					return
				}
			}
		} else {
			accountID, parseErr := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
			if parseErr != nil || accountID <= 0 {
				errorMessage = "Invalid account"
			} else {
				switch action {
				case "reset", "unlock":
					parseErr = h.db.ResetOutboundAccountUsage(accountID)
				case "suspend":
					until := time.Now().UTC().Add(time.Duration(current.OutboundLimits.SuspensionMinutes) * time.Minute)
					parseErr = h.db.SetOutboundAccountSuspension(accountID, &until)
				default:
					parseErr = fmt.Errorf("unknown action")
				}
				if parseErr != nil {
					errorMessage = "Unable to update account outbound state"
				} else {
					logging.Info(fmt.Sprintf("[admin] outbound account action=%s target_account_id=%d by_account_id=%d", action, accountID, account.ID))
					http.Redirect(w, r, "/admin/outbound-limits?updated=1", http.StatusSeeOther)
					return
				}
			}
		}
	}
	usage, usageErr := h.db.ListOutboundAccountUsage(time.Now())
	if usageErr != nil && errorMessage == "" {
		errorMessage = "Unable to load outbound usage"
	}
	data := map[string]interface{}{
		"Title": "Outbound Limits", "Section": "admin", "AdminPanel": "outbound-limits", "Account": account,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r), "Limits": current.OutboundLimits, "Usage": usage,
		"Error": errorMessage, "Saved": r.URL.Query().Get("saved") == "1", "Updated": r.URL.Query().Get("updated") == "1",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplOutboundLimits.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] outbound limits template error: %v", err)
	}
}

// Configuration edits the complete persisted configuration. Only logging is
// applied live; components constructed at startup are explicitly restart-bound.
func (h *AdminHandler) Configuration(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}
	if h.backupManager == nil || strings.TrimSpace(h.backupManager.ConfigPath()) == "" {
		http.Error(w, "Configuration manager unavailable", http.StatusServiceUnavailable)
		return
	}
	path := h.backupManager.ConfigPath()
	current, err := config.Load(path)
	if err != nil {
		http.Error(w, "Unable to load configuration", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodPost {
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Configuration form is too large or invalid", http.StatusBadRequest)
			return
		}
		view := "form"
		if r.FormValue("view") == "json" {
			view = "json"
		}
		var candidate *config.Config
		var parseErr error
		if view == "json" {
			candidate, parseErr = config.ParseEditableJSON([]byte(r.FormValue("configuration")), current)
		} else {
			candidate, parseErr = config.ParseEditableForm(r.PostForm, current)
		}
		if parseErr != nil {
			currentEditable, _ := config.EditableJSON(current)
			h.renderConfiguration(w, r, account, string(currentEditable), parseErr.Error()+" The editor was reset to the last saved configuration so secret values are not reflected in the response.", "", false, config.RestartRequired(h.cfg, current))
			return
		}
		candidateEditable, _ := config.EditableJSON(candidate)
		if r.FormValue("action") == "validate" {
			h.renderConfiguration(w, r, account, string(candidateEditable), "", "Configuration is valid. Nothing was saved. Re-enter any new secret values before saving.", false, config.RestartRequired(h.cfg, candidate))
			return
		}
		if r.FormValue("action") != "save" {
			http.Error(w, "Unknown action", http.StatusBadRequest)
			return
		}
		changed := config.ChangedSections(current, candidate)
		if len(changed) == 0 {
			h.renderConfiguration(w, r, account, string(candidateEditable), "", "No configuration values changed.", false, config.RestartRequired(h.cfg, current))
			return
		}
		backupPath, saveErr := config.SaveAtomic(path, candidate)
		if saveErr != nil {
			h.renderConfiguration(w, r, account, string(candidateEditable), saveErr.Error(), "", false, config.RestartRequired(h.cfg, current))
			return
		}
		logging.Configure(candidate.Logging.Level, candidate.Logging.Format)
		h.db.ConfigureOutboundLimits(candidate.OutboundLimits)
		restartRequired := config.RestartRequired(h.cfg, candidate)
		logging.Info(fmt.Sprintf("[admin] configuration changed by account_id=%d sections=%s backup=%s restart_required=%t", account.ID, strings.Join(changed, ","), filepath.Base(backupPath), restartRequired))
		http.Redirect(w, r, "/admin/configuration?saved=1&view="+view, http.StatusSeeOther)
		return
	}
	editable, err := config.EditableJSON(current)
	if err != nil {
		http.Error(w, "Unable to prepare configuration", http.StatusInternalServerError)
		return
	}
	h.renderConfiguration(w, r, account, string(editable), "", "", r.URL.Query().Get("saved") == "1", config.RestartRequired(h.cfg, current))
}

func (h *AdminHandler) renderConfiguration(w http.ResponseWriter, r *http.Request, account *store.Account, editable, errorMessage, notice string, saved, restartRequired bool) {
	view := "form"
	if r.FormValue("view") == "json" {
		view = "json"
	}
	sections, err := config.EditableFormSections([]byte(editable))
	if err != nil {
		http.Error(w, "Unable to prepare configuration form", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"Title": "Server Configuration", "Section": "admin", "AdminPanel": "configuration", "Account": account,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r), "Configuration": editable, "Error": errorMessage,
		"Notice": notice, "Saved": saved, "RestartRequired": restartRequired, "ViewMode": view, "FormSections": sections,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplConfiguration.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] configuration template error: %v", err)
	}
}

func (h *AdminHandler) Backups(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}
	if h.backupManager == nil {
		http.Error(w, "Backup manager unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPost {
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		switch r.FormValue("action") {
		case "save":
			current, err := h.backupManager.Settings()
			if err != nil {
				http.Error(w, "Unable to load backup settings", http.StatusInternalServerError)
				return
			}
			interval, err := strconv.Atoi(r.FormValue("interval_hours"))
			if err != nil {
				h.renderBackups(w, r, account, current, "Interval must be a whole number", "")
				return
			}
			retention, err := strconv.Atoi(r.FormValue("retention_count"))
			if err != nil {
				h.renderBackups(w, r, account, current, "Archives to retain must be a whole number", "")
				return
			}
			current.Enabled = r.FormValue("enabled") == "1"
			current.Directory = r.FormValue("directory")
			current.IntervalHours = interval
			current.RetentionCount = retention
			if err := h.backupManager.SaveSettings(current); err != nil {
				h.renderBackups(w, r, account, current, err.Error(), "")
				return
			}
			http.Redirect(w, r, "/admin/backups?saved=1", http.StatusSeeOther)
			return
		case "run":
			_, path, err := h.backupManager.RunNow()
			if err != nil {
				settings, settingsErr := h.backupManager.Settings()
				if settingsErr != nil {
					http.Error(w, "Unable to load backup settings", http.StatusInternalServerError)
					return
				}
				h.renderBackups(w, r, account, settings, err.Error(), "")
				return
			}
			http.Redirect(w, r, "/admin/backups?created="+url.QueryEscape(filepath.Base(path)), http.StatusSeeOther)
			return
		default:
			http.Error(w, "Unknown action", http.StatusBadRequest)
			return
		}
	}
	settings, err := h.backupManager.Settings()
	if err != nil {
		http.Error(w, "Unable to load backup settings", http.StatusInternalServerError)
		return
	}
	h.renderBackups(w, r, account, settings, "", r.URL.Query().Get("created"))
}

func (h *AdminHandler) renderBackups(w http.ResponseWriter, r *http.Request, account *store.Account, settings store.BackupSettings, errorMessage, created string) {
	data := map[string]interface{}{
		"Title": "Backups", "Section": "admin", "AdminPanel": "backups", "Account": account,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r), "Settings": settings,
		"Error": errorMessage, "Created": created, "Saved": r.URL.Query().Get("saved") == "1",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplBackups.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] backup template error: %v", err)
	}
}

// getAdmin returns the current admin account or nil.
func (h *AdminHandler) getAdmin(r *http.Request) *store.Account {
	account := getSessionAccount(h.db, h.sessionMgr, r)
	if account == nil || !account.IsAdmin {
		return nil
	}
	return account
}

// --- Dashboard ---

// Dashboard displays the admin dashboard with overview stats.
func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	domains, _ := h.db.ListDomains()
	accounts, _ := h.db.ListAccounts(0)

	domainCount := len(domains)
	accountCount := len(accounts)

	unread, _ := h.db.CountUnread(account.ID)
	diskStatus, _ := h.db.DiskPressureStatus()

	data := map[string]interface{}{
		"Title":        "Admin Dashboard",
		"DomainCount":  domainCount,
		"AccountCount": accountCount,
		"Domains":      domains,
		"Accounts":     accounts,
		"Unread":       unread,
		"CSRFToken":    h.sessionMgr.GenerateCSRFToken(r),
		"Section":      "admin",
		"AdminPanel":   "dashboard",
		"Account":      account,
		"DiskStatus":   diskStatus,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplDashboard.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// --- Domain Handlers ---

// Domains lists all domains.
func (h *AdminHandler) Domains(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	domains, err := h.db.ListDomains()
	if err != nil {
		log.Printf("[admin] list domains error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get account counts per domain
	type domainInfo struct {
		*store.Domain
		AccountCount int
	}
	var domainInfos []domainInfo
	for _, d := range domains {
		count, _ := h.db.CountDomainAccounts(d.ID)
		domainInfos = append(domainInfos, domainInfo{Domain: d, AccountCount: count})
	}

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":      "Manage Domains",
		"Domains":    domainInfos,
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "admin",
		"AdminPanel": "domains",
		"Account":    account,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplDomains.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// DomainEdit shows the add/edit form for a domain (GET) or saves it (POST).
func (h *AdminHandler) DomainEdit(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/domain/edit/")
	var domain *store.Domain
	var isNew bool

	if idStr == "" || idStr == "new" {
		isNew = true
		domain = &store.Domain{
			IsActive:      true,
			DKIMSelector:  h.cfg.DKIM.DefaultSelector,
			DKIMAlgorithm: h.cfg.DKIM.DefaultAlgorithm,
		}
	} else {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		domain, err = h.db.GetDomain(id)
		if err != nil || domain == nil {
			http.NotFound(w, r)
			return
		}
	}

	var message, errMsg string

	if r.Method == http.MethodPost {
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		submittedDomain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
		if isNew {
			domain.Domain = submittedDomain
		} else if !strings.EqualFold(submittedDomain, domain.Domain) {
			errMsg = "Domain name cannot be changed after creation"
		}
		domain.IsActive = r.FormValue("is_active") == "1"
		domain.RequireTLS = r.FormValue("require_tls") == "1"
		domain.DANEEnforcement = r.FormValue("dane_enforcement")
		if domain.DANEEnforcement == "" {
			domain.DANEEnforcement = "disabled" // Default if not set
		}
		domain.GreylistingEnabled = r.FormValue("greylisting_enabled") == "1"
		delayStr := r.FormValue("greylisting_delay_minutes")
		if delayStr == "" {
			domain.GreylistingDelayMins = 15 // Default delay
		} else {
			// Parse delay with error handling
			if delay, err := strconv.Atoi(delayStr); err == nil && delay > 0 {
				domain.GreylistingDelayMins = delay
			} else {
				domain.GreylistingDelayMins = 15
			}
		}
		domain.TarpittingEnabled = r.FormValue("tarpitting_enabled") == "1"
		delayStr2 := r.FormValue("tarpitting_max_delay_seconds")
		if delayStr2 == "" {
			domain.TarpittingMaxDelaySecs = 8 // Default max delay
		} else {
			// Parse delay with error handling
			if delay, err := strconv.Atoi(delayStr2); err == nil && delay > 0 {
				domain.TarpittingMaxDelaySecs = delay
			} else {
				domain.TarpittingMaxDelaySecs = 8
			}
		}
		domain.DKIMSelector = r.FormValue("dkim_selector")
		domain.DKIMAlgorithm = r.FormValue("dkim_algorithm")

		if errMsg == "" {
			if err := store.ValidateMailDomain(domain.Domain); err != nil {
				errMsg = err.Error()
			}
		}
		if errMsg == "" {
			if isNew {
				id, err := h.db.CreateDomain(domain)
				if err != nil {
					errMsg = fmt.Sprintf("Error creating domain: %v", err)
				} else {
					domain.ID = id
					http.Redirect(w, r, fmt.Sprintf("/admin/domain/edit/%d", id), http.StatusSeeOther)
					return
				}
			} else {
				if err := h.db.UpdateDomain(domain); err != nil {
					errMsg = fmt.Sprintf("Error updating domain: %v", err)
				} else {
					message = "Domain updated successfully"
				}
			}
		}
	}

	// Build DNS records info
	dnsRecords := h.buildDNSRecords(domain)
	var reportAccounts []*store.Account
	var reportRecipientID int64
	if !isNew {
		var err error
		reportAccounts, err = h.db.ListAccounts(domain.ID)
		if err != nil {
			http.Error(w, "Unable to list report mailboxes", http.StatusInternalServerError)
			return
		}
		reportRecipientID, _, err = h.db.DomainReportRecipient(domain.ID)
		if err != nil {
			http.Error(w, "Unable to load report recipient", http.StatusInternalServerError)
			return
		}
	}

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":             fmt.Sprintf("Edit Domain - %s", domain.Domain),
		"Domain":            domain,
		"IsNew":             isNew,
		"Message":           message,
		"Error":             errMsg,
		"DNSRecords":        dnsRecords,
		"ReportAccounts":    reportAccounts,
		"ReportRecipientID": reportRecipientID,
		"Unread":            unread,
		"CSRFToken":         h.sessionMgr.GenerateCSRFToken(r),
		"Section":           "admin",
		"AdminPanel":        "domains",
		"Account":           account,
		"Hostname":          h.cfg.Server.Hostname,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplDomainEdit.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// DomainReportRecipient selects a deliverable local mailbox for this domain's
// DMARC and TLS-RPT DNS suggestions. It does not provision external DNS.
func (h *AdminHandler) DomainReportRecipient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	account := h.getAdmin(r)
	if account == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	domainID, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/admin/domain/report-recipient/"), 10, 64)
	if err != nil || domainID <= 0 {
		http.NotFound(w, r)
		return
	}
	domain, err := h.db.GetDomain(domainID)
	if err != nil || domain == nil {
		http.NotFound(w, r)
		return
	}
	accountID, err := strconv.ParseInt(r.FormValue("report_account_id"), 10, 64)
	if err != nil || accountID < 0 {
		http.Error(w, "Invalid report mailbox", http.StatusBadRequest)
		return
	}
	if err := h.db.SetDomainReportRecipient(domainID, accountID); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/domain/edit/%d", domainID), http.StatusSeeOther)
}

// DomainGenerateDKIM generates DKIM keys for a domain.
func (h *AdminHandler) DomainGenerateDKIM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/domain/dkim/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	domain, err := h.db.GetDomain(id)
	if err != nil || domain == nil {
		http.NotFound(w, r)
		return
	}

	algo := domain.DKIMAlgorithm
	if algo == "" {
		algo = h.cfg.DKIM.DefaultAlgorithm
	}

	privPEM, pubPEM, _, err := auth.GenerateDKIMKeyPair(algo)
	if err != nil {
		log.Printf("[admin] DKIM key generation failed: %v", err)
		http.Error(w, "Key generation failed", http.StatusInternalServerError)
		return
	}

	domain.DKIMPrivateKey = privPEM
	domain.DKIMPublicKey = pubPEM
	if domain.DKIMSelector == "" {
		domain.DKIMSelector = h.cfg.DKIM.DefaultSelector
	}

	if err := h.db.UpdateDomain(domain); err != nil {
		log.Printf("[admin] save DKIM keys error: %v", err)
		http.Error(w, "Failed to save keys", http.StatusInternalServerError)
		return
	}

	log.Printf("[admin] generated DKIM keys for %s (algo=%s)", domain.Domain, algo)
	http.Redirect(w, r, fmt.Sprintf("/admin/domain/edit/%d", id), http.StatusSeeOther)
}

// DomainDelete deletes a domain.
func (h *AdminHandler) DomainDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/domain/delete/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := h.db.DeleteDomain(id); err != nil {
		log.Printf("[admin] delete domain %d: %v", id, err)
		if err == store.ErrDomainHasQueuedMail {
			http.Error(w, "This domain has unfinished queued mail. Resolve or cancel those deliveries before deleting it.", http.StatusConflict)
			return
		}
		http.Error(w, "Unable to delete domain", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/domains", http.StatusSeeOther)
}

// --- Account Handlers ---

// Accounts lists all accounts.
func (h *AdminHandler) Accounts(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	// Optional domain filter
	var domainID int64
	if did := r.URL.Query().Get("domain"); did != "" {
		domainID, _ = strconv.ParseInt(did, 10, 64)
	}

	accounts, err := h.db.ListAccounts(domainID)
	if err != nil {
		log.Printf("[admin] list accounts error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	domains, _ := h.db.ListDomains()
	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":          "Manage Accounts",
		"Accounts":       accounts,
		"Domains":        domains,
		"FilterDomainID": domainID,
		"Unread":         unread,
		"CSRFToken":      h.sessionMgr.GenerateCSRFToken(r),
		"Section":        "admin",
		"AdminPanel":     "accounts",
		"Account":        account,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplAccounts.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// AccountEdit shows the add/edit form for an account (GET) or saves it (POST).
func (h *AdminHandler) AccountEdit(w http.ResponseWriter, r *http.Request) {
	admin := h.getAdmin(r)
	if admin == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/account/edit/")
	var acct *store.Account
	var isNew bool

	if idStr == "" || idStr == "new" {
		isNew = true
		acct = &store.Account{
			IsActive:   true,
			QuotaBytes: 1073741824, // 1 GB default
		}
		// Pre-select domain from query param
		if did := r.URL.Query().Get("domain"); did != "" {
			acct.DomainID, _ = strconv.ParseInt(did, 10, 64)
		}
	} else {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		acct, err = h.db.GetAccount(id)
		if err != nil || acct == nil {
			http.NotFound(w, r)
			return
		}
	}

	var message, errMsg string

	if r.Method == http.MethodPost {
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		domainID, domainIDErr := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
		acct.DomainID = domainID
		acct.Email = strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		acct.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
		acct.IsAdmin = r.FormValue("is_admin") == "1"
		acct.IsActive = r.FormValue("is_active") == "1"
		acct.AllowAliases = r.FormValue("allow_aliases") == "1"
		quotaMB, quotaErr := strconv.ParseInt(r.FormValue("quota_mb"), 10, 64)
		if quotaErr == nil && quotaMB >= 0 && quotaMB <= int64(^uint64(0)>>1)/1048576 {
			acct.QuotaBytes = quotaMB * 1048576
		}

		password := r.FormValue("password")

		if domainIDErr != nil || domainID <= 0 {
			errMsg = "A valid domain is required"
		} else if quotaErr != nil {
			errMsg = "Quota must be a whole number"
		} else if quotaMB < 0 {
			errMsg = "Quota cannot be negative"
		} else if quotaMB > int64(^uint64(0)>>1)/1048576 {
			errMsg = "Quota is too large"
		} else if acct.Email == "" {
			errMsg = "Email is required"
		} else {
			domain, err := h.db.GetDomain(acct.DomainID)
			if err != nil || domain == nil {
				errMsg = "Selected domain does not exist"
			} else if err := validateAccountEmail(acct.Email, domain.Domain); err != nil {
				errMsg = err.Error()
			} else if password != "" && len(password) < 12 {
				errMsg = "Password must be at least 12 characters"
			}
		}
		if errMsg == "" && isNew {
			if password == "" {
				errMsg = "Password is required for new accounts"
			} else {
				hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					errMsg = "Error hashing password"
				} else {
					acct.PasswordHash = string(hash)
					id, err := h.db.CreateAccount(acct)
					if err != nil {
						errMsg = fmt.Sprintf("Error creating account: %v", err)
					} else {
						acct.ID = id
						http.Redirect(w, r, fmt.Sprintf("/admin/account/edit/%d", id), http.StatusSeeOther)
						return
					}
				}
			}
		} else if errMsg == "" {
			passwordHash := ""
			if password != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					errMsg = "Error hashing password"
				} else {
					passwordHash = string(hash)
				}
			}
			if errMsg == "" {
				if err := h.db.UpdateAccountWithPassword(acct, passwordHash); err != nil {
					errMsg = fmt.Sprintf("Error updating account: %v", err)
				} else if passwordHash != "" {
					if admin.ID == acct.ID {
						h.sessionMgr.DestroySession(w, r)
						http.Redirect(w, r, "/login", http.StatusSeeOther)
						return
					}
					message = "Account and password updated successfully"
				} else {
					message = "Account updated successfully"
				}
			}
		}
	}

	domains, _ := h.db.ListDomains()
	unread, _ := h.db.CountUnread(admin.ID)

	data := map[string]interface{}{
		"Title":      fmt.Sprintf("Edit Account - %s", acct.Email),
		"Acct":       acct,
		"IsNew":      isNew,
		"Domains":    domains,
		"Message":    message,
		"Error":      errMsg,
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "admin",
		"AdminPanel": "accounts",
		"Account":    admin,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplAccountEdit.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

func validateAccountEmail(address, domain string) error {
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address {
		return fmt.Errorf("Enter a valid email address without a display name")
	}
	parts := strings.Split(address, "@")
	if len(parts) != 2 || parts[0] == "" || !strings.EqualFold(strings.TrimSuffix(parts[1], "."), strings.TrimSuffix(domain, ".")) {
		return fmt.Errorf("Email address must belong to the selected domain")
	}
	return nil
}

// AccountDelete deletes an account.
func (h *AdminHandler) AccountDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	admin := h.getAdmin(r)
	if admin == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/account/delete/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Prevent deleting yourself
	if id == admin.ID {
		http.Error(w, "Cannot delete your own account", http.StatusBadRequest)
		return
	}

	if err := h.db.DeleteAccount(id); err != nil {
		log.Printf("[admin] delete account %d: %v", id, err)
		http.Error(w, "Unable to delete account", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/accounts", http.StatusSeeOther)
}

// --- DNS Records Helper ---

type dnsRecord struct {
	Type    string
	Name    string
	Value   string
	Comment string
}

func (h *AdminHandler) buildDNSRecords(domain *store.Domain) []dnsRecord {
	if domain.Domain == "" {
		return nil
	}

	var records []dnsRecord

	// MX Record
	records = append(records, dnsRecord{
		Type:    "MX",
		Name:    domain.Domain,
		Value:   fmt.Sprintf("10 %s.", h.cfg.Server.Hostname),
		Comment: "Routes mail to this server",
	})

	// A Record
	records = append(records, dnsRecord{
		Type:    "A",
		Name:    h.cfg.Server.Hostname,
		Value:   "<YOUR_SERVER_IP>",
		Comment: "Point to your server's public IP",
	})

	// SPF Record
	records = append(records, dnsRecord{
		Type:    "TXT",
		Name:    domain.Domain,
		Value:   "v=spf1 mx a -all",
		Comment: "SPF: only this server sends mail for this domain",
	})

	// DKIM Record
	if domain.DKIMPublicKey != "" {
		// Extract public key bytes from PEM for DNS record
		pubB64 := extractPubKeyBase64(domain.DKIMPublicKey)
		algo := "ed25519"
		if domain.DKIMAlgorithm == "rsa" {
			algo = "rsa"
		}
		selector := domain.DKIMSelector
		if selector == "" {
			selector = h.cfg.DKIM.DefaultSelector
		}
		records = append(records, dnsRecord{
			Type:    "TXT",
			Name:    fmt.Sprintf("%s._domainkey.%s", selector, domain.Domain),
			Value:   fmt.Sprintf("v=DKIM1; k=%s; p=%s", algo, pubB64),
			Comment: "DKIM public key for email signing verification",
		})
	} else {
		records = append(records, dnsRecord{
			Type:    "TXT",
			Name:    fmt.Sprintf("%s._domainkey.%s", domain.DKIMSelector, domain.Domain),
			Value:   "(Generate DKIM keys first)",
			Comment: "DKIM: click 'Generate DKIM Keys' to create",
		})
	}

	reportAddress := fmt.Sprintf("postmaster@%s", domain.Domain)
	selectionValid := true
	if domain.ID != 0 {
		if selectedID, selected, err := h.db.DomainReportRecipient(domain.ID); err == nil && selectedID != 0 {
			reportAddress = selected
			mailbox, lookupErr := h.db.GetAccount(selectedID)
			selectionValid = lookupErr == nil && mailbox != nil && mailbox.IsActive && mailbox.DomainID == domain.ID
		} else if err != nil {
			selectionValid = false
		}
	}
	reportDestination, lookupErr := h.db.GetDeliveryAccount(reportAddress)
	reportReady := selectionValid && lookupErr == nil && reportDestination != nil
	dmarcValue := "(configure an active local report destination before publishing rua)"
	tlsReportValue := "(configure an active local report destination before publishing rua)"
	if reportReady {
		dmarcValue = fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:%s", reportAddress)
		tlsReportValue = fmt.Sprintf("v=TLSRPTv1; rua=mailto:%s", reportAddress)
	}
	// DMARC Record
	records = append(records, dnsRecord{
		Type:    "TXT",
		Name:    fmt.Sprintf("_dmarc.%s", domain.Domain),
		Value:   dmarcValue,
		Comment: "DMARC policy; publish only when the report destination delivers",
	})

	// MTA-STS Record
	records = append(records, dnsRecord{
		Type:    "TXT",
		Name:    fmt.Sprintf("_mta-sts.%s", domain.Domain),
		Value:   "v=STSv1; id=1",
		Comment: "MTA-STS: enforces TLS for inbound SMTP",
	})

	// TLS-RPT Record
	records = append(records, dnsRecord{
		Type:    "TXT",
		Name:    fmt.Sprintf("_smtp._tls.%s", domain.Domain),
		Value:   tlsReportValue,
		Comment: "TLS reporting endpoint; publish only when the destination delivers",
	})

	// PTR Record
	records = append(records, dnsRecord{
		Type:    "PTR",
		Name:    "<YOUR_SERVER_IP>",
		Value:   h.cfg.Server.Hostname + ".",
		Comment: "Reverse DNS (set via hosting provider)",
	})

	return records
}

// --- DMARC Feedback Handler ---

// DMARCFeedback displays DMARC authentication feedback statistics.
func (h *AdminHandler) DMARCFeedback(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	// Get time range query parameters (default to last 7 days)
	now := time.Now()
	defaultStart := now.AddDate(0, 0, -7)
	startStr := r.URL.Query().Get("start")
	if startStr == "" {
		startStr = defaultStart.Format("2006-01-02")
	}
	startTime, _ := time.Parse("2006-01-02", startStr)

	// Get all DMARC feedback for the time period
	rows, err := h.db.Query(`
		SELECT domain, source_ip, COUNT(*) as count,
		       SUM(CASE WHEN spf_result = 'pass' THEN 1 ELSE 0 END) as spf_pass,
		       SUM(CASE WHEN dkim_result = 'pass' THEN 1 ELSE 0 END) as dkim_pass,
		       disposition
		FROM dmarc_feedback
		WHERE received_at >= ?
		GROUP BY domain, source_ip, disposition
		ORDER BY domain ASC, count DESC
	`, startTime.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		log.Printf("[admin] error querying DMARC feedback: %v", err)
		http.Error(w, "Error querying feedback", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type FeedbackRow struct {
		Domain      string
		SourceIP    string
		Count       int
		SPFPass     int
		DKIMPass    int
		Disposition string
	}

	var feedback []FeedbackRow
	for rows.Next() {
		var row FeedbackRow
		if err := rows.Scan(&row.Domain, &row.SourceIP, &row.Count, &row.SPFPass, &row.DKIMPass, &row.Disposition); err != nil {
			log.Printf("[admin] error scanning feedback row: %v", err)
			continue
		}
		feedback = append(feedback, row)
	}

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":      "DMARC Feedback",
		"Feedback":   feedback,
		"StartStr":   startStr,
		"EndStr":     now.Format("2006-01-02"),
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "admin",
		"AdminPanel": "dmarc",
		"Account":    account,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplDMARCFeedback.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// SendDMARCReportsNow generates and sends DMARC reports immediately (for testing).
func (h *AdminHandler) SendDMARCReportsNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Trigger report sending
	total, sent, err := reporting.SendReportsNow(h.cfg, h.db, h.enqueueFunc)
	if err != nil {
		log.Printf("[admin] error sending reports now: %v", err)
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	// Log the action
	log.Printf("[admin] user %s triggered manual DMARC reports (total: %d, sent: %d)", account.Email, total, sent)

	// Redirect back to DMARC feedback page with success message
	w.Header().Set("X-Report-Status", fmt.Sprintf("Reports sent: %d/%d domains", sent, total))
	http.Redirect(w, r, "/admin/dmarc-feedback?sent=1", http.StatusSeeOther)
}

// TLSRPTReports displays TLS-RPT failure statistics.
func (h *AdminHandler) TLSRPTReports(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	// Get time range query parameters (default to last 30 days)
	now := time.Now()
	defaultStart := now.AddDate(0, 0, -30)
	startStr := r.URL.Query().Get("start")
	if startStr == "" {
		startStr = defaultStart.Format("2006-01-02")
	}
	startTime, _ := time.Parse("2006-01-02", startStr)

	// Get all TLS failures for the time period
	rows, err := h.db.Query(`
		SELECT recipient_domain, failure_reason, COUNT(*) as count,
		       SUM(CASE WHEN sending_mta_ip IS NOT NULL THEN 1 ELSE 0 END) as with_ip
		FROM tls_failures
		WHERE attempted_at >= ?
		GROUP BY recipient_domain, failure_reason
		ORDER BY recipient_domain ASC, count DESC
	`, startTime.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		log.Printf("[admin] error querying TLS failures: %v", err)
		http.Error(w, "Error querying TLS failures", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TLSFailureRow struct {
		Domain        string
		FailureReason string
		Count         int
		WithIP        int
	}

	var failures []TLSFailureRow
	for rows.Next() {
		var row TLSFailureRow
		if err := rows.Scan(&row.Domain, &row.FailureReason, &row.Count, &row.WithIP); err != nil {
			log.Printf("[admin] error scanning TLS failure row: %v", err)
			continue
		}
		failures = append(failures, row)
	}

	// Get count of unreported failures
	var unreportedCount int
	h.db.QueryRow(`
		SELECT COUNT(*) FROM tls_failures WHERE sent_at IS NULL
	`).Scan(&unreportedCount)

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":           "TLS-RPT Reports",
		"Failures":        failures,
		"StartStr":        startStr,
		"EndStr":          now.Format("2006-01-02"),
		"Unread":          unread,
		"CSRFToken":       h.sessionMgr.GenerateCSRFToken(r),
		"Section":         "admin",
		"AdminPanel":      "tls-rpt",
		"Account":         account,
		"UnreportedCount": unreportedCount,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplTLSRPT.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// SendTLSRPTReportsNow generates and sends TLS-RPT reports immediately (for testing).
func (h *AdminHandler) SendTLSRPTReportsNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Trigger TLS-RPT report sending (last 7 days)
	endTime := time.Now().UTC()
	startTime := endTime.AddDate(0, 0, -7)

	domains, err := h.db.GetDomainsWithTLSFailures()
	if err != nil {
		log.Printf("[admin] error getting domains with TLS failures: %v", err)
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	sent := 0
	for _, domain := range domains {
		report, err := reporting.GenerateTLSReport(h.db, h.cfg.Server.Domain, domain, startTime, endTime)
		if err != nil {
			log.Printf("[admin] failed to generate TLS-RPT for %s: %v", domain, err)
			continue
		}

		recipientEmail, err := reporting.ExtractTLSRPTAddress(domain)
		if err != nil {
			log.Printf("[admin] failed to extract TLS-RPT address for %s: %v", domain, err)
			continue
		}

		// Use our organization's domain as sender
		senderEmail := h.cfg.Server.TLSReportSenderAddress()
		messageBody := reporting.BuildTLSRPTEmail(h.cfg.Server.Domain, senderEmail, domain, report, recipientEmail)

		if h.tlsReportEnqueue == nil {
			log.Printf("[admin] TLS-RPT queue unavailable")
			continue
		}
		if err := h.tlsReportEnqueue(senderEmail, recipientEmail, messageBody); err != nil {
			log.Printf("[admin] failed to enqueue TLS-RPT report for %s: %v", domain, err)
			continue
		}

		if err := h.db.MarkTLSFailuresAsReported(domain, startTime, endTime); err != nil {
			log.Printf("[admin] failed to mark TLS-RPT as reported for %s: %v", domain, err)
		}

		sent++
		log.Printf("[admin] queued TLS-RPT for %s -> %s", domain, recipientEmail)
	}

	// Log the action
	log.Printf("[admin] user %s triggered manual TLS-RPT reports (total: %d, sent: %d)", account.Email, len(domains), sent)

	// Redirect back to TLS-RPT page with success message
	http.Redirect(w, r, "/admin/tls-rpt?sent=1", http.StatusSeeOther)
}

// GreylistingEntries displays greylisting entries for a domain.
func (h *AdminHandler) GreylistingEntries(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost && !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Get domain ID from query parameter
	domainIDStr := r.URL.Query().Get("domain")
	if domainIDStr == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	domainID, err := strconv.ParseInt(domainIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid domain ID", http.StatusBadRequest)
		return
	}

	// Get domain
	domain, err := h.db.GetDomain(domainID)
	if err != nil || domain == nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}

	// Handle deletion if requested
	if r.Method == http.MethodPost && r.FormValue("action") == "delete" {
		entryIDStr := r.FormValue("entry_id")
		entryID, _ := strconv.ParseInt(entryIDStr, 10, 64)
		if entryID > 0 {
			if err := h.db.DeleteGreylistingEntry(entryID); err != nil {
				log.Printf("[admin] error deleting greylisting entry %d: %v", entryID, err)
			} else {
				log.Printf("[admin] user %s deleted greylisting entry %d from domain %s", account.Email, entryID, domain.Domain)
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/greylisting?domain=%d", domainID), http.StatusSeeOther)
		return
	}

	// Handle whitelist if requested
	if r.Method == http.MethodPost && r.FormValue("action") == "whitelist" {
		entryIDStr := r.FormValue("entry_id")
		entryID, _ := strconv.ParseInt(entryIDStr, 10, 64)
		if entryID > 0 {
			if err := h.db.WhitelistGreylistingEntry(entryID); err != nil {
				log.Printf("[admin] error whitelisting entry %d: %v", entryID, err)
			} else {
				log.Printf("[admin] user %s whitelisted greylisting entry %d in domain %s", account.Email, entryID, domain.Domain)
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/greylisting?domain=%d", domainID), http.StatusSeeOther)
		return
	}

	// Get greylisting entries for the domain
	entries, err := h.db.GetGreylistingEntriesByDomain(domain.Domain)
	if err != nil {
		log.Printf("[admin] error querying greylisting entries: %v", err)
		entries = []*store.GreylistEntry{}
	}

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":      "Greylisting Entries",
		"Domain":     domain,
		"Entries":    entries,
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "admin",
		"AdminPanel": "greylisting",
		"Account":    account,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplGreylisting.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// TarpittingEntries displays tarpitting entries for a domain.
func (h *AdminHandler) TarpittingEntries(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost && !h.sessionMgr.ValidateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Get domain ID from query parameter
	domainIDStr := r.URL.Query().Get("domain")
	if domainIDStr == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	domainID, err := strconv.ParseInt(domainIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid domain ID", http.StatusBadRequest)
		return
	}

	// Get domain
	domain, err := h.db.GetDomain(domainID)
	if err != nil || domain == nil {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}

	// Handle deletion if requested
	if r.Method == http.MethodPost && r.FormValue("action") == "delete" {
		entryIDStr := r.FormValue("entry_id")
		entryID, _ := strconv.ParseInt(entryIDStr, 10, 64)
		if entryID > 0 {
			if err := h.db.DeleteTarpittingEntry(entryID); err != nil {
				log.Printf("[admin] error deleting tarpitting entry %d: %v", entryID, err)
			} else {
				log.Printf("[admin] user %s deleted tarpitting entry %d from domain %s", account.Email, entryID, domain.Domain)
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/tarpitting?domain=%d", domainID), http.StatusSeeOther)
		return
	}

	// Handle whitelist if requested
	if r.Method == http.MethodPost && r.FormValue("action") == "whitelist" {
		entryIDStr := r.FormValue("entry_id")
		entryID, _ := strconv.ParseInt(entryIDStr, 10, 64)
		if entryID > 0 {
			if err := h.db.WhitelistTarpittingEntry(entryID); err != nil {
				log.Printf("[admin] error whitelisting tarpitting entry %d: %v", entryID, err)
			} else {
				log.Printf("[admin] user %s whitelisted tarpitting entry %d in domain %s", account.Email, entryID, domain.Domain)
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/tarpitting?domain=%d", domainID), http.StatusSeeOther)
		return
	}

	// Get tarpitting entries for the domain with max delay setting
	entries, err := h.db.GetTarpittingEntriesByDomainWithMaxDelay(domain.Domain, domain.TarpittingMaxDelaySecs)
	if err != nil {
		log.Printf("[admin] error querying tarpitting entries: %v", err)
		entries = []*store.TarpittingEntry{}
	}

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":      "Tarpitting Entries",
		"Domain":     domain,
		"Entries":    entries,
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "admin",
		"AdminPanel": "tarpitting",
		"Account":    account,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplTarpitting.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// VERPBounces displays VERP bounce tracking statistics.
func (h *AdminHandler) VERPBounces(w http.ResponseWriter, r *http.Request) {
	account := h.getAdmin(r)
	if account == nil {
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		return
	}

	// Get filter from query parameters
	senderFilter := r.URL.Query().Get("sender")
	statusMsg := r.URL.Query().Get("status")

	// Get recent VERP bounces (limit to 200 most recent)
	var bounces []*store.VERPBounce
	var err error
	if senderFilter != "" {
		bounces, err = h.db.ListVERPBounces(senderFilter, 200)
	} else {
		bounces, err = h.db.ListVERPBounces("", 200)
	}
	if err != nil {
		log.Printf("[admin] error querying VERP bounces: %v", err)
		bounces = []*store.VERPBounce{}
	}

	// Get bounce statistics for the current sender or all senders
	var stats map[string]int
	if senderFilter != "" {
		stats, _ = h.db.GetVERPBounceStats(senderFilter, 7)
	}

	// Get unique senders for dropdown filter
	var senders []string
	for _, bounce := range bounces {
		found := false
		for _, s := range senders {
			if s == bounce.SenderEmail {
				found = true
				break
			}
		}
		if !found {
			senders = append(senders, bounce.SenderEmail)
		}
	}

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":        "VERP Bounce Tracker",
		"Bounces":      bounces,
		"Stats":        stats,
		"Senders":      senders,
		"SenderFilter": senderFilter,
		"StatusMsg":    statusMsg,
		"Unread":       unread,
		"CSRFToken":    h.sessionMgr.GenerateCSRFToken(r),
		"Section":      "admin",
		"AdminPanel":   "verp",
		"Account":      account,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplVERPBounces.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
}

// extractPubKeyBase64 extracts the base64 public key from PEM format.
func extractPubKeyBase64(pubPEM string) string {
	// Strip PEM header/footer and whitespace
	lines := strings.Split(pubPEM, "\n")
	var b64 strings.Builder
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----") || line == "" {
			continue
		}
		b64.WriteString(line)
	}
	return b64.String()
}
