package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"gomail/reporting"
)

// ReceivedReports is deliberately separate from GoMail's own outbound
// DMARC/TLS-RPT event dashboards. It reads one explicitly selected mailbox.
func (h *AdminHandler) ReceivedReports(w http.ResponseWriter, r *http.Request) {
	admin := h.getAdmin(r)
	if admin == nil {
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
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}
		if !h.sessionMgr.ValidateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		switch r.FormValue("action") {
		case "save":
			accountID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("account_id")), 10, 64)
			if err != nil || accountID < 0 {
				errorMessage = "Select a valid local mailbox."
			} else if err := h.db.SaveReportInboxSettings(r.FormValue("enabled") == "on", accountID); err != nil {
				errorMessage = err.Error()
			} else {
				// First scan immediately; the background scanner continues thereafter.
				if _, err := reporting.ScanReceivedReports(h.db); err != nil {
					errorMessage = "Settings saved, but the first scan failed: " + err.Error()
				} else {
					http.Redirect(w, r, "/admin/received-reports?saved=1", http.StatusSeeOther)
					return
				}
			}
		case "scan":
			if _, err := reporting.RescanReceivedReports(h.db); err != nil {
				errorMessage = "Scan failed: " + err.Error()
			} else {
				http.Redirect(w, r, "/admin/received-reports?scanned=1", http.StatusSeeOther)
				return
			}
		default:
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		}
	}
	settings, err := h.db.GetReportInboxSettings()
	if err != nil {
		http.Error(w, "Unable to load report settings", http.StatusInternalServerError)
		return
	}
	accounts, err := h.db.ListAccounts(0)
	if err != nil {
		http.Error(w, "Unable to load accounts", http.StatusInternalServerError)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 || page > 100000 {
		page = 1
	}
	const pageSize = 50
	reports, err := h.db.ListReceivedReports(pageSize, (page-1)*pageSize)
	if err != nil {
		http.Error(w, "Unable to load report history", http.StatusInternalServerError)
		return
	}
	totals, err := h.db.ReceivedReportSummary()
	if err != nil {
		http.Error(w, "Unable to summarize reports", http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"Title": "Received Reports", "Section": "admin", "AdminPanel": "received-reports",
		"Account": admin, "CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Settings": settings, "Accounts": accounts, "Reports": reports,
		"DMARCCount": totals.DMARCCount, "TLSCount": totals.TLSCount,
		"Successes": totals.Successes, "Failures": totals.Failures,
		"Page": page, "PreviousPage": page - 1, "NextPage": page + 1,
		"HasPrevious": page > 1, "HasNext": int64(page*pageSize) < totals.DMARCCount+totals.TLSCount,
		"Error": errorMessage, "Saved": r.URL.Query().Has("saved"), "Scanned": r.URL.Query().Has("scanned"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplReportInbox.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] received reports template: %v", err)
	}
}
