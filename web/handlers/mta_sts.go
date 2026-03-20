package handlers

import (
	"net/http"

	"gomail/mta_sts"
)

// MTASTSHandler returns a handler that serves the MTA-STS policy file.
func MTASTSHandler(policy *mta_sts.Policy) http.HandlerFunc {
	policyText := policy.String()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write([]byte(policyText))
	}
}
