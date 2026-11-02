package auth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const arcDKIMPyPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+yT0r1FSXBt979b6MFfoJstrfiR9aKIn5UCFEELXgKk6nESbfiVKMSI/+2ZivyLL/aTdSCpmKmDOL4r+swHw2AmNJxqiYOYDZ8ET96DeCZ9rdsYqkYrUi8IlnVsbJ1zo/D/II5sZIkS/fmqx/fChIZBAE1EzS2S/dj7OlbZHqe9jJMlOeOSgH3RcOQONHeVNV5ZpXghs4QuUipkYjDNM8EZIWIBEzTeAkzrHcqaVK4/wUxMKO8hzykB8mRgY27wIIHQZEf/aCdwaYJ9gWwGGnHMZAtlx2CElqFakEgiEm6xh679gMQcx+qaP9Of4MhoPsd/xyVZvFDf0pDiatruPOQIDAQAB"

// This static fixture was signed by dkimpy 1.1.8, not GoMail. Its public key
// is pinned here so the test never depends on external DNS or private keys.
func TestARCIndependentDKIMPyRFC8617Fixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "arc_dkimpy_rfc8617.eml"))
	if err != nil {
		t.Fatal(err)
	}
	message := bytes.ReplaceAll(fixture, []byte("\n"), []byte("\r\n"))
	previousLookup := lookupARCKey
	lookupARCKey = func(selector, domain string) (*DKIMRecord, error) {
		if selector != "arc" || domain != "example.test" {
			return nil, fmt.Errorf("unexpected ARC key %s._domainkey.%s", selector, domain)
		}
		return &DKIMRecord{RawKey: arcDKIMPyPublicKey}, nil
	}
	defer func() { lookupARCKey = previousLookup }()
	if result := ValidateARCChain(message); !result.IsValid {
		t.Fatalf("independent dkimpy ARC fixture rejected: %+v", result)
	}
	modified := bytes.Replace(message, []byte("Fixture body"), []byte("Changed body"), 1)
	if result := ValidateARCChain(modified); result.IsValid {
		t.Fatalf("modified independent fixture accepted: %+v", result)
	}
}

func TestARCIndependentDKIMPyTwoHopBodyModification(t *testing.T) {
	first, err := os.ReadFile(filepath.Join("testdata", "arc_dkimpy_rfc8617.eml"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join("testdata", "arc_dkimpy_second_set.txt"))
	if err != nil {
		t.Fatal(err)
	}
	first = bytes.ReplaceAll(first, []byte("\n"), []byte("\r\n"))
	second = bytes.ReplaceAll(second, []byte("\n"), []byte("\r\n"))
	first = bytes.Replace(first, []byte("Fixture body"), []byte("Forwarded body"), 1)
	newResults := []byte("Authentication-Results: dkimpy.example; arc=pass; spf=pass smtp.mailfrom=relay@example.test\r\n")
	message := append(append(second, newResults...), first...)
	previousLookup := lookupARCKey
	lookupARCKey = func(selector, domain string) (*DKIMRecord, error) {
		if selector != "arc" || domain != "example.test" {
			return nil, fmt.Errorf("unexpected ARC key %s._domainkey.%s", selector, domain)
		}
		return &DKIMRecord{RawKey: arcDKIMPyPublicKey}, nil
	}
	defer func() { lookupARCKey = previousLookup }()
	if valid, _, _ := ValidateArcChainAtInstance(message, 1); valid {
		t.Fatal("historical AMS unexpectedly verified after body modification")
	}
	if result := ValidateARCChain(message); !result.IsValid || result.HighestValid != 2 {
		t.Fatalf("independent two-hop ARC fixture rejected: %+v", result)
	}
	tampered := bytes.Replace(message, []byte("ARC-Authentication-Results: i=1; dkimpy.example;"), []byte("ARC-Authentication-Results: i=1; forged.example;"), 1)
	if result := ValidateARCChain(tampered); result.IsValid {
		t.Fatalf("tampered historical ARC evidence accepted: %+v", result)
	}
}

func TestARCTwoHopCumulativeSeal(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*rsa.PrivateKey{"one.example": key1, "two.example": key2}
	originalLookup := lookupARCKey
	lookupARCKey = func(_ string, domain string) (*DKIMRecord, error) {
		key := keys[domain]
		if key == nil {
			return nil, fmt.Errorf("unknown test key")
		}
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		return &DKIMRecord{RawKey: base64.StdEncoding.EncodeToString(der)}, nil
	}
	defer func() { lookupARCKey = originalLookup }()

	message := []byte("From: sender@example.com\r\nTo: list@example.net\r\nSubject: ARC test\r\nDate: Tue, 24 Sep 2026 12:00:00 +0000\r\nMessage-ID: <arc@example.com>\r\n\r\nbody\r\n")
	set1, err := ARCChainSigner("one.example", "arc", key1, "pass", "pass", "pass", "one.example", string(message), 1)
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, set1)
	if result := ValidateARCChain(message); !result.IsValid || result.HighestValid != 1 {
		t.Fatalf("first ARC set invalid: %+v", result)
	}

	set2, err := ARCChainSigner("two.example", "arc", key2, "pass", "pass", "pass", "two.example", string(message), 2)
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, set2)
	result := ValidateARCChain(message)
	if !result.IsValid || result.HighestValid != 2 {
		t.Fatalf("two-hop ARC chain invalid: %+v", result)
	}

	sets := ExtractArcHeaders(message)
	sets[1]["auth-results"] += " tampered"
	keyDER, _ := x509.MarshalPKIXPublicKey(&key2.PublicKey)
	valid, _ := verifyARCSeal(sets, 2, &DKIMRecord{RawKey: base64.StdEncoding.EncodeToString(keyDER)})
	if valid {
		t.Fatal("second ARC seal did not cover the prior ARC set")
	}
}

func TestARCChainAcceptsCaseInsensitiveCVTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	previousLookup := lookupARCKey
	lookupARCKey = func(_, _ string) (*DKIMRecord, error) {
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		return &DKIMRecord{RawKey: base64.StdEncoding.EncodeToString(der)}, nil
	}
	defer func() { lookupARCKey = previousLookup }()

	message := []byte("From: sender@example.com\r\nTo: list@example.net\r\nSubject: ARC test\r\nDate: Tue, 24 Sep 2026 12:00:00 +0000\r\nMessage-ID: <arc@example.com>\r\n\r\nbody\r\n")
	first, err := ARCChainSigner("relay.example", "arc", key, "pass", "pass", "pass", "relay.example", string(message), 1)
	if err != nil {
		t.Fatal(err)
	}
	first[2], err = ARCSeal(&ARCSealInput{Instance: 1, Selector: "arc", Domain: "relay.example", PrivateKey: key,
		AuthenticationResults: first[0], MessageSignature: first[1], Timestamp: time.Now(), CVValue: "NONE"})
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, first)
	if result := ValidateARCChain(message); !result.IsValid {
		t.Fatalf("signed cv=NONE chain rejected: %+v", result)
	}
	second, err := ARCChainSigner("relay.example", "arc", key, "pass", "pass", "pass", "relay.example", string(message), 2)
	if err != nil {
		t.Fatal(err)
	}
	second[2], err = ARCSeal(&ARCSealInput{Instance: 2, Selector: "arc", Domain: "relay.example", PrivateKey: key,
		AuthenticationResults: second[0], MessageSignature: second[1], Timestamp: time.Now(), CVValue: "PASS", PriorSets: ExtractArcHeaders(message)})
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, second)
	if result := ValidateARCChain(message); !result.IsValid || result.HighestValid != 2 {
		t.Fatalf("signed cv=PASS chain rejected: %+v", result)
	}
}

func TestARCSignerDoesNotContinueFailedChain(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: sender@example.com\r\nTo: list@example.net\r\nSubject: ARC test\r\nDate: Tue, 24 Sep 2026 12:00:00 +0000\r\nMessage-ID: <arc@example.com>\r\n\r\nbody\r\n")
	first, err := signARCSetWithCVForTest(message, key, 1, "none")
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, first)
	second, err := signARCSetWithCVForTest(message, key, 2, "fail")
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, second)
	if _, err := ARCChainSigner("relay.example", "arc", key, "pass", "pass", "pass", "relay.example", string(message), 3); err == nil || !strings.Contains(err.Error(), "cannot continue ARC chain after cv=fail") {
		t.Fatalf("signer continued a failed ARC chain: %v", err)
	}
}

func TestARCSigningRejectsInvalidInputs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: sender@example.com\r\nTo: recipient@example.net\r\n\r\nbody\r\n")
	ams := &ARCMessageSignatureInput{Instance: 1, Selector: "arc", Domain: "relay.example", PrivateKey: key,
		Message: message, BodyHash: BodyHash("body\r\n")}
	if _, err := ARCMessageSignature(nil); err == nil {
		t.Fatal("nil AMS input accepted")
	}
	for _, instance := range []int{0, 51} {
		copy := *ams
		copy.Instance = instance
		if _, err := ARCMessageSignature(&copy); err == nil {
			t.Fatalf("AMS instance %d accepted", instance)
		}
	}
	copy := *ams
	copy.Message = []byte("To: recipient@example.net\r\n\r\nbody\r\n")
	if _, err := ARCMessageSignature(&copy); err == nil || !strings.Contains(err.Error(), "From") {
		t.Fatalf("AMS without From accepted: %v", err)
	}

	seal := &ARCSealInput{Instance: 1, Selector: "arc", Domain: "relay.example", PrivateKey: key,
		AuthenticationResults: "ARC-Authentication-Results: i=1; relay.example; none",
		MessageSignature:      "ARC-Message-Signature: i=1; a=rsa-sha256; d=relay.example; s=arc; bh=x; b=x",
		Timestamp:             time.Unix(1_700_000_000, 0)}
	if _, err := ARCSeal(nil); err == nil {
		t.Fatal("nil seal input accepted")
	}
	for _, tc := range []struct {
		instance int
		cv       string
	}{
		{0, "none"}, {51, "pass"}, {1, "fail"}, {2, "none"}, {2, ""}, {2, "unknown"},
	} {
		copy := *seal
		copy.Instance, copy.CVValue = tc.instance, tc.cv
		if _, err := ARCSeal(&copy); err == nil {
			t.Fatalf("seal instance %d cv=%q accepted", tc.instance, tc.cv)
		}
	}
	copySeal := *seal
	copySeal.MessageSignature = strings.Replace(seal.MessageSignature, "i=1", "i=2", 1)
	if _, err := ARCSeal(&copySeal); err == nil {
		t.Fatal("seal with mismatched AMS instance accepted")
	}
	copySeal = *seal
	copySeal.Timestamp = time.Unix(-1, 0)
	if _, err := ARCSeal(&copySeal); err == nil {
		t.Fatal("seal with negative timestamp accepted")
	}
}

func TestARCFinalRFCAllowsBrokenHistoricalAMSButRequiresItsSeal(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	originalLookup := lookupARCKey
	lookupARCKey = func(_, _ string) (*DKIMRecord, error) {
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		return &DKIMRecord{RawKey: base64.StdEncoding.EncodeToString(der)}, nil
	}
	defer func() { lookupARCKey = originalLookup }()

	message := []byte("From: sender@example.com\r\nTo: list@example.net\r\nSubject: ARC test\r\nDate: Tue, 24 Sep 2026 12:00:00 +0000\r\nMessage-ID: <arc@example.com>\r\n\r\noriginal body\r\n")
	set1, err := ARCChainSigner("relay.example", "arc", key, "pass", "pass", "pass", "relay.example", string(message), 1)
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, set1)
	message = []byte(strings.Replace(string(message), "original body", "modified body", 1))
	priorMessage := append([]byte(nil), message...)
	set2, err := signARCSetWithCVForTest(message, key, 2, "pass")
	if err != nil {
		t.Fatal(err)
	}
	message = prependARCSet(message, set2)
	if valid, _, _ := ValidateArcChainAtInstance(message, 1); valid {
		t.Fatal("historical AMS unexpectedly survived a body edit")
	}
	if result := ValidateARCChain(message); !result.IsValid || result.Status != "pass" {
		t.Fatalf("RFC 8617 chain rejected solely because of historical AMS: %+v", result)
	}
	brokenSeal := []byte(strings.Replace(string(priorMessage), "ARC-Seal: i=1;", "ARC-Seal: i=1; x=tampered;", 1))
	set2OnBroken, err := signARCSetWithCVForTest(brokenSeal, key, 2, "pass")
	if err != nil {
		t.Fatal(err)
	}
	brokenSeal = prependARCSet(brokenSeal, set2OnBroken)
	if result := ValidateARCChain(brokenSeal); result.Status != "fail" {
		t.Fatalf("historical ARC-Seal tampering accepted: %+v", result)
	}
}

func signARCSetWithCVForTest(message []byte, key *rsa.PrivateKey, instance int, cv string) ([]string, error) {
	_, bodyOffset, err := parseMessageHeaders(message)
	if err != nil {
		return nil, err
	}
	aar := fmt.Sprintf("ARC-Authentication-Results: i=%d; relay.example; spf=pass", instance)
	ams, err := ARCMessageSignature(&ARCMessageSignatureInput{
		Instance: instance, Selector: "arc", Domain: "relay.example", PrivateKey: key,
		Message: message, BodyHash: BodyHash(string(message[bodyOffset:])),
	})
	if err != nil {
		return nil, err
	}
	seal, err := ARCSeal(&ARCSealInput{
		Instance: instance, Selector: "arc", Domain: "relay.example", PrivateKey: key,
		AuthenticationResults: aar, MessageSignature: ams, Timestamp: time.Unix(1_700_000_000, 0),
		CVValue: cv, PriorSets: ExtractArcHeaders(message),
	})
	if err != nil {
		return nil, err
	}
	return []string{aar, ams, seal}, nil
}

func TestARCRejectsDuplicateAndOversizedChains(t *testing.T) {
	duplicate := []byte("ARC-Authentication-Results: i=1; mx; spf=pass\r\nARC-Authentication-Results: i=1; mx; spf=pass\r\nARC-Message-Signature: i=1; a=rsa-sha256; d=x; s=y; bh=x; b=x\r\nARC-Seal: i=1; a=rsa-sha256; cv=none; d=x; s=y; b=x\r\n\r\nbody")
	if result := ValidateARCChain(duplicate); result.Status != "fail" {
		t.Fatalf("duplicate ARC header accepted: %+v", result)
	}
	var oversized []byte
	for i := 1; i <= 51; i++ {
		oversized = append(oversized, []byte(fmt.Sprintf("ARC-Authentication-Results: i=%d; mx; spf=pass\r\nARC-Message-Signature: i=%d; a=rsa-sha256; d=x; s=y; bh=x; b=x\r\nARC-Seal: i=%d; a=rsa-sha256; cv=pass; d=x; s=y; b=x\r\n", i, i, i))...)
	}
	oversized = append(oversized, []byte("\r\nbody")...)
	if result := ValidateARCChain(oversized); result.Status != "fail" {
		t.Fatalf("oversized ARC chain accepted: %+v", result)
	}
}

func TestARCRejectsAmbiguousOrForbiddenTags(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	originalLookup := lookupARCKey
	lookupARCKey = func(_, _ string) (*DKIMRecord, error) {
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		return &DKIMRecord{RawKey: base64.StdEncoding.EncodeToString(der)}, nil
	}
	defer func() { lookupARCKey = originalLookup }()
	base := []byte("From: sender@example.com\r\nTo: list@example.net\r\nSubject: ARC test\r\nDate: Tue, 24 Sep 2026 12:00:00 +0000\r\nMessage-ID: <arc@example.com>\r\n\r\nbody\r\n")
	set, err := ARCChainSigner("relay.example", "arc", key, "pass", "pass", "pass", "relay.example", string(base), 1)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(prependARCSet(base, set))
	if result := ValidateARCChain([]byte(valid)); !result.IsValid {
		t.Fatalf("fixture invalid: %+v", result)
	}
	for _, tc := range []struct{ name, old, new, detail string }{
		{"AAR instance must lead", "ARC-Authentication-Results: i=1;", "ARC-Authentication-Results: mx; i=1;", "must begin"},
		{"AMS instance must lead", "ARC-Message-Signature: i=1;", "ARC-Message-Signature: a=rsa-sha256; i=1;", "must begin"},
		{"AS instance must lead", "ARC-Seal: i=1;", "ARC-Seal: a=rsa-sha256; i=1;", "must begin"},
		{"duplicate AMS algorithm", "ARC-Message-Signature: i=1;", "ARC-Message-Signature: i=1; a=ed25519-sha256;", "duplicate"},
		{"duplicate AS instance", "ARC-Seal: i=1;", "ARC-Seal: i=1; i=1;", "duplicate"},
		{"forbidden AS extension", "ARC-Seal: i=1;", "ARC-Seal: i=1; x=extension;", "forbidden"},
		{"ordinary authentication results in AMS h", "h=from:to:subject", "h=authentication-results:from:to:subject", "authentication-results"},
		{"unsupported AMS algorithm", "ARC-Message-Signature: i=1; a=rsa-sha256", "ARC-Message-Signature: i=1; a=bogus-rsa-sha256", "unsupported ARC-Message-Signature algorithm"},
		{"unsupported Seal algorithm", "ARC-Seal: i=1; a=rsa-sha256", "ARC-Seal: i=1; a=bogus-rsa-sha256", "unsupported ARC-Seal algorithm"},
		{"AMS must sign From", "h=from:to:subject", "h=to:subject", "must include From"},
		{"message must have From", "From: sender@example.com\r\n", "", "message has no From"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := strings.Replace(valid, tc.old, tc.new, 1)
			if modified == valid {
				t.Fatal("fixture mutation did not apply")
			}
			result := ValidateARCChain([]byte(modified))
			if result.Status != "fail" || !strings.Contains(result.Details, tc.detail) {
				t.Fatalf("malformed ARC accepted or wrong failure: %+v", result)
			}
		})
	}
}

func TestARCRejectsSignedEmptyAuthenticationResults(t *testing.T) {
	if err := validateARCHeaderTags("ARC-Authentication-Results: i=1; relay.example; none", "auth-results", 1); err != nil {
		t.Fatalf("valid no-result payload rejected: %v", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: sender@example.com\r\nTo: list@example.net\r\nSubject: ARC test\r\nDate: Tue, 24 Sep 2026 12:00:00 +0000\r\nMessage-ID: <arc@example.com>\r\n\r\nbody\r\n")
	set, err := signARCSetWithCVForTest(message, key, 1, "none")
	if err != nil {
		t.Fatal(err)
	}
	set[0] = "ARC-Authentication-Results: i=1; relay.example;"
	if _, err := ARCSeal(&ARCSealInput{Instance: 1, Selector: "arc", Domain: "relay.example", PrivateKey: key,
		AuthenticationResults: set[0], MessageSignature: set[1], Timestamp: time.Unix(1_700_000_000, 0), CVValue: "none"}); err == nil {
		t.Fatal("signer accepted empty ARC-Authentication-Results")
	}
	unsignedSeal := "ARC-Seal: i=1; a=rsa-sha256; t=1700000000; cv=none; d=relay.example; s=arc; b="
	signedData, err := arcSealSigningData(nil, map[string]string{
		"auth-results": set[0], "message-signature": set[1], "seal": unsignedSeal,
	}, 1, "none")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(signedData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	set[2] = unsignedSeal + base64.StdEncoding.EncodeToString(signature)
	result := ValidateARCChain(prependARCSet(message, set))
	if result.Status != "fail" || !strings.Contains(result.Details, "missing authserv-id or result") {
		t.Fatalf("signed empty ARC-Authentication-Results accepted: %+v", result)
	}
}

func TestARCMessageSignatureCanonicalizationDefaultsToSimple(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("hello  world\r\n")
	headerLines := []string{"From: sender@example.com", "To: recipient@example.net", "Subject: Test", "Date: Tue, 24 Sep 2026 12:00:00 +0000", "Message-ID: <arc@example.com>"}
	message := []byte(strings.Join(headerLines, "\r\n") + "\r\n\r\n" + string(body))
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := &DKIMRecord{RawKey: base64.StdEncoding.EncodeToString(der)}
	makeSignature := func(bodySimple bool, canonicalization string) string {
		t.Helper()
		bodyHash := base64.StdEncoding.EncodeToString(bodyHashFunc(bodySimple, body))
		sig := "ARC-Message-Signature: i=1; a=rsa-sha256; d=relay.example; s=arc; h=from:to:subject:date:message-id; bh=" + bodyHash + canonicalization + "; b="
		var signed bytes.Buffer
		for _, line := range headerLines {
			signed.WriteString(line + "\r\n")
		}
		signed.WriteString(sig)
		hash := sha256.Sum256(signed.Bytes())
		bytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig + base64.StdEncoding.EncodeToString(bytes)
	}
	if valid, detail := verifyARCMessageSignature(message, makeSignature(true, ""), record); !valid {
		t.Fatalf("omitted c= did not use simple/simple: %s", detail)
	}
	if valid, _ := verifyARCMessageSignature(message, makeSignature(false, ""), record); valid {
		t.Fatal("omitted c= incorrectly accepted relaxed body canonicalization")
	}
	if valid, detail := verifyARCMessageSignature(message, makeSignature(true, "; c=unknown/simple"), record); valid || !strings.Contains(detail, "unsupported") {
		t.Fatalf("unknown canonicalization accepted: valid=%v detail=%q", valid, detail)
	}
}

func TestARCSealFailCoversOnlyCurrentSet(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	current := map[string]string{
		"auth-results":      "ARC-Authentication-Results: i=2; relay.example; spf=pass",
		"message-signature": "ARC-Message-Signature: i=2; a=rsa-sha256; d=relay.example; s=arc; bh=x; b=x",
	}
	seal, err := ARCSeal(&ARCSealInput{
		Instance:              2,
		Selector:              "arc",
		Domain:                "relay.example",
		PrivateKey:            key,
		AuthenticationResults: current["auth-results"],
		MessageSignature:      current["message-signature"],
		Timestamp:             time.Unix(1_700_000_000, 0),
		CVValue:               "fail",
		// RFC 8617 scopes cv=fail to the new set, so incomplete prior sets do
		// not prevent an intermediary from sealing the chain failure.
		PriorSets: map[int]map[string]string{1: {"auth-results": "broken"}},
	})
	if err != nil {
		t.Fatalf("signing cv=fail ARC set: %v", err)
	}
	current["seal"] = seal
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	valid, detail := verifyARCSeal(map[int]map[string]string{2: current}, 2, &DKIMRecord{RawKey: base64.StdEncoding.EncodeToString(der)})
	if !valid {
		t.Fatalf("cv=fail seal did not verify independently: %s", detail)
	}
}

func TestARCSealRejectsForbiddenTags(t *testing.T) {
	sets := map[int]map[string]string{1: {
		"auth-results":      "ARC-Authentication-Results: i=1; mx; spf=pass",
		"message-signature": "ARC-Message-Signature: i=1; a=rsa-sha256; d=x; s=y; bh=x; b=x",
		"seal":              "ARC-Seal: i=1; a=rsa-sha256; c=relaxed; cv=none; d=x; s=y; b=x",
	}}
	valid, detail := verifyARCSeal(sets, 1, &DKIMRecord{})
	if valid || !strings.Contains(detail, "forbidden") {
		t.Fatalf("ARC-Seal c= tag was not rejected: valid=%v detail=%q", valid, detail)
	}
}

func prependARCSet(message []byte, set []string) []byte {
	prefix := []byte(set[0] + "\r\n" + set[1] + "\r\n" + set[2] + "\r\n")
	return append(prefix, message...)
}
