package config

import (
	"net/url"
	"strings"
	"testing"
)

func editableFormValues(t *testing.T, current *Config) url.Values {
	t.Helper()
	redacted, err := EditableJSON(current)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := EditableFormSections(redacted)
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{}
	for _, section := range sections {
		for _, field := range section.Fields {
			values.Set("field."+field.Path, field.Value)
			if strings.Contains(field.Path, "secret") || strings.Contains(field.Path, "password") || strings.Contains(field.Path, "token") || strings.Contains(field.Path, "csrf") {
				if field.Secret && field.Value != "" {
					t.Fatalf("secret exposed in form: %s", field.Path)
				}
			}
		}
	}
	return values
}

func TestEditableFormRoundTripAndValidation(t *testing.T) {
	current := editableConfig()
	current.Delivery.RetryIntervals = []int{30, 90}
	values := editableFormValues(t, current)
	values.Set("field.logging.level", "debug")
	values.Set("field.web.external_https", "true")
	values.Set("field.web.enable_tls", "false")
	values.Set("field.delivery.retry_intervals", "[15,60,180]")
	candidate, err := ParseEditableForm(values, current)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Logging.Level != "debug" || !candidate.Web.ExternalHTTPS || candidate.Web.EnableTLS == nil || *candidate.Web.EnableTLS || len(candidate.Delivery.RetryIntervals) != 3 || candidate.Delivery.RetryIntervals[1] != 60 {
		t.Fatalf("form did not preserve typed changes: %+v", candidate)
	}
	if candidate.Store.MySQL.Password != current.Store.MySQL.Password || candidate.Web.SessionSecret != current.Web.SessionSecret || candidate.Security.CSRFKey != current.Security.CSRFKey {
		t.Fatal("blank secret fields did not preserve saved secrets")
	}
	values.Set("field.web.session_secret", "replacement-secret")
	candidate, err = ParseEditableForm(values, current)
	if err != nil || candidate.Web.SessionSecret != "replacement-secret" {
		t.Fatalf("secret rotation failed: %v", err)
	}
	values.Set("field.delivery.retry_intervals", "not a JSON list")
	if _, err := ParseEditableForm(values, current); err == nil {
		t.Fatal("malformed list accepted")
	}
	values.Set("field.delivery.retry_intervals", "[15,60]")
	values.Set("field.unknown.option", "true")
	if _, err := ParseEditableForm(values, current); err == nil {
		t.Fatal("unknown form field accepted")
	}
}
