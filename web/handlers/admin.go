package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"gomail/auth"
	"gomail/config"
	"gomail/security"
	"gomail/store"
	"gomail/templates"
)

// AdminHandler handles the admin panel for domains and accounts.
type AdminHandler struct {
	cfg        *config.Config
	db         *store.DB
	sessionMgr *security.SessionManager
	tmplDomains     *template.Template
	tmplDomainEdit  *template.Template
	tmplAccounts    *template.Template
	tmplAccountEdit *template.Template
}

// NewAdminHandler creates an admin handler.
func NewAdminHandler(cfg *config.Config, db *store.DB, sm *security.SessionManager) *AdminHandler {
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

	tmplDomains := templates.LoadTemplate(funcMap, "base", "admin_domains")
	tmplDomainEdit := templates.LoadTemplate(funcMap, "base", "admin_domain_edit")
	tmplAccounts := templates.LoadTemplate(funcMap, "base", "admin_accounts")
	tmplAccountEdit := templates.LoadTemplate(funcMap, "base", "admin_account_edit")

	return &AdminHandler{
		cfg:             cfg,
		db:              db,
		sessionMgr:      sm,
		tmplDomains:     tmplDomains,
		tmplDomainEdit:  tmplDomainEdit,
		tmplAccounts:    tmplAccounts,
		tmplAccountEdit: tmplAccountEdit,
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
		"Title":     "Manage Domains",
		"Domains":   domainInfos,
		"Unread":    unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Section":   "admin",
		"Account":   account,
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

		domain.Domain = strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
		domain.IsActive = r.FormValue("is_active") == "1"
		domain.RequireTLS = r.FormValue("require_tls") == "1"
		domain.DKIMSelector = r.FormValue("dkim_selector")
		domain.DKIMAlgorithm = r.FormValue("dkim_algorithm")

		if domain.Domain == "" {
			errMsg = "Domain name is required"
		} else if isNew {
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

	// Build DNS records info
	dnsRecords := h.buildDNSRecords(domain)

	unread, _ := h.db.CountUnread(account.ID)

	data := map[string]interface{}{
		"Title":      fmt.Sprintf("Edit Domain - %s", domain.Domain),
		"Domain":     domain,
		"IsNew":      isNew,
		"Message":    message,
		"Error":      errMsg,
		"DNSRecords": dnsRecords,
		"Unread":     unread,
		"CSRFToken":  h.sessionMgr.GenerateCSRFToken(r),
		"Section":    "admin",
		"Account":    account,
		"Hostname":   h.cfg.Server.Hostname,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplDomainEdit.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
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

	h.db.DeleteDomain(id)
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

		acct.DomainID, _ = strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
		acct.Email = strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		acct.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
		acct.IsAdmin = r.FormValue("is_admin") == "1"
		acct.IsActive = r.FormValue("is_active") == "1"
		quotaMB, _ := strconv.ParseInt(r.FormValue("quota_mb"), 10, 64)
		acct.QuotaBytes = quotaMB * 1048576

		password := r.FormValue("password")

		if acct.Email == "" {
			errMsg = "Email is required"
		} else if acct.DomainID == 0 {
			errMsg = "Domain is required"
		} else if isNew {
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
		} else {
			if err := h.db.UpdateAccount(acct); err != nil {
				errMsg = fmt.Sprintf("Error updating account: %v", err)
			} else {
				message = "Account updated successfully"
			}

			// Update password if provided
			if password != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					errMsg = "Error hashing password"
				} else {
					h.db.UpdateAccountPassword(acct.ID, string(hash))
					if message != "" {
						message += ". Password updated."
					}
				}
			}
		}
	}

	domains, _ := h.db.ListDomains()
	unread, _ := h.db.CountUnread(admin.ID)

	data := map[string]interface{}{
		"Title":     fmt.Sprintf("Edit Account - %s", acct.Email),
		"Acct":      acct,
		"IsNew":     isNew,
		"Domains":   domains,
		"Message":   message,
		"Error":     errMsg,
		"Unread":    unread,
		"CSRFToken": h.sessionMgr.GenerateCSRFToken(r),
		"Section":   "admin",
		"Account":   admin,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmplAccountEdit.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[admin] template error: %v", err)
	}
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

	h.db.DeleteAccount(id)
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

	// DMARC Record
	records = append(records, dnsRecord{
		Type:    "TXT",
		Name:    fmt.Sprintf("_dmarc.%s", domain.Domain),
		Value:   fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:postmaster@%s", domain.Domain),
		Comment: "DMARC policy for email authentication",
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
		Value:   fmt.Sprintf("v=TLSRPTv1; rua=mailto:postmaster@%s", domain.Domain),
		Comment: "TLS reporting endpoint",
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
