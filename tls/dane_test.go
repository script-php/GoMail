package tlsconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"gomail/dns"
)

func makeChain(t *testing.T) ([]*x509.Certificate, *x509.CertPool) {
	t.Helper(); now:=time.Now(); caKey,_:=rsa.GenerateKey(rand.Reader,2048); leafKey,_:=rsa.GenerateKey(rand.Reader,2048)
	caT:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Test CA"},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature}
	caDER,err:=x509.CreateCertificate(rand.Reader,caT,caT,&caKey.PublicKey,caKey); if err!=nil{t.Fatal(err)}; ca,_:=x509.ParseCertificate(caDER)
	leafT:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"mail.example"},DNSNames:[]string{"mail.example"},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER,err:=x509.CreateCertificate(rand.Reader,leafT,ca,&leafKey.PublicKey,caKey); if err!=nil{t.Fatal(err)}; leaf,_:=x509.ParseCertificate(leafDER)
	roots:=x509.NewCertPool(); roots.AddCert(ca); return []*x509.Certificate{leaf,ca},roots
}
func association(cert *x509.Certificate, selector, matching uint8) string { b:=cert.Raw; if selector==1{b=cert.RawSubjectPublicKeyInfo}; if matching==1{s:=sha256.Sum256(b);b=s[:]}; if matching==2{s:=sha512.Sum512(b);b=s[:]}; return hex.EncodeToString(b) }

func TestDANEUsageSelectorAndMatchingSemantics(t *testing.T) {
	chain,roots:=makeChain(t); now:=time.Now()
	tests:=[]struct{name string; usage,selector,matching uint8; cert *x509.Certificate}{
		{"pkix-ta",0,0,1,chain[1]}, {"pkix-ee",1,1,2,chain[0]}, {"dane-ta",2,1,1,chain[1]}, {"dane-ee-exact",3,0,0,chain[0]},
	}
	for _,tc:=range tests { t.Run(tc.name,func(t *testing.T){ r:=dns.TLSARecord{Usage:tc.usage,Selector:tc.selector,MatchingType:tc.matching,CertData:association(tc.cert,tc.selector,tc.matching)}; got,err:=VerifyDANECertificates("mail.example",chain,[]dns.TLSARecord{r},roots,now); if err!=nil||!got.Matched||got.Usage!=tc.usage{t.Fatalf("got=%+v err=%v",got,err)} }) }
}
func TestDANERejectsWrongHostForPKIXButAllowsDANEEE(t *testing.T) {
	chain,roots:=makeChain(t); r:=dns.TLSARecord{Usage:1,Selector:1,MatchingType:1,CertData:association(chain[0],1,1)}
	got,err:=VerifyDANECertificates("wrong.example",chain,[]dns.TLSARecord{r},roots,time.Now()); if err!=nil||got.Matched{t.Fatalf("PKIX-EE unexpectedly matched: %+v %v",got,err)}
	r.Usage=3; got,err=VerifyDANECertificates("wrong.example",chain,[]dns.TLSARecord{r},roots,time.Now()); if err!=nil||!got.Matched{t.Fatalf("DANE-EE did not match: %+v %v",got,err)}
}
func TestDANERejectsMalformedMismatchAndUnlinkedTA(t *testing.T) {
	chain,roots:=makeChain(t)
	bad:=dns.TLSARecord{Usage:3,Selector:1,MatchingType:1,CertData:"xyz"}; if _,err:=VerifyDANECertificates("mail.example",chain,[]dns.TLSARecord{bad},roots,time.Now());err==nil{t.Fatal("expected malformed error")}
	mismatch:=dns.TLSARecord{Usage:3,Selector:1,MatchingType:1,CertData:stringsRepeat("00",32)}; got,err:=VerifyDANECertificates("mail.example",chain,[]dns.TLSARecord{mismatch},roots,time.Now());if err!=nil||got.Matched{t.Fatalf("mismatch got=%+v err=%v",got,err)}
	other,_:=makeChain(t); ta:=dns.TLSARecord{Usage:2,Selector:1,MatchingType:1,CertData:association(other[1],1,1)}; got,err=VerifyDANECertificates("mail.example",append([]*x509.Certificate{chain[0]},other[1]),[]dns.TLSARecord{ta},roots,time.Now());if err!=nil||got.Matched{t.Fatalf("unlinked TA got=%+v err=%v",got,err)}
}
func stringsRepeat(s string,n int)string{ out:="";for i:=0;i<n;i++{out+=s};return out }
