package depot

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"log"
	"sync"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/micromdm/scep/v2/cryptoutil"
	"github.com/micromdm/scep/v2/scep"
)

// Signer signs x509 certificates and stores them in a Depot
type Signer struct {
	depot            Depot
	mu               sync.Mutex
	caPass           string
	allowRenewalDays int
	validityDays     int
	serverAttrs      bool
	pkcs11ctx        *crypto11.Context
	dbBucket         string
	ocspUrl          string
	aiaUrl           string
}

// Option customizes Signer
type Option func(*Signer)

// NewSigner creates a new Signer
func NewSigner(depot Depot, opts ...Option) *Signer {
	s := &Signer{
		depot:            depot,
		allowRenewalDays: 14,
		validityDays:     365,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithPkcs11Ctx(ctx *crypto11.Context) Option {
	return func(s *Signer) {
		s.pkcs11ctx = ctx
	}
}

func WithDynamoDbBucket(bucketname string) Option {
	return func(s *Signer) {
		s.dbBucket = bucketname
	}
}

func WithOcspUrl(url string) Option {
	return func(s *Signer) {
		s.ocspUrl = url
	}
}

func WithAiaUrl(url string) Option {
	return func(s *Signer) {
		s.aiaUrl = url
	}
}

// WithCAPass specifies the password to use with an encrypted CA key
func WithCAPass(pass string) Option {
	return func(s *Signer) {
		s.caPass = pass
	}
}

// WithAllowRenewalDays sets the allowable renewal time for existing certs
func WithAllowRenewalDays(r int) Option {
	return func(s *Signer) {
		s.allowRenewalDays = r
	}
}

// WithValidityDays sets the validity period new certs will use
func WithValidityDays(v int) Option {
	return func(s *Signer) {
		s.validityDays = v
	}
}

func WithSeverAttrs() Option {
	return func(s *Signer) {
		s.serverAttrs = true
	}
}

// SignCSR signs a certificate using Signer's Depot CA
func (s *Signer) SignCSR(m *scep.CSRReqMessage) (*x509.Certificate, error) {
	id, err := cryptoutil.GenerateSubjectKeyID(m.CSR.PublicKey)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	serial, err := s.depot.Serial()
	if err != nil {
		return nil, err
	}

	// create cert template
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      m.CSR.Subject,
		NotBefore:    time.Now().Add(time.Second * -600).UTC(),
		NotAfter:     time.Now().AddDate(0, 0, s.validityDays).UTC(),
		SubjectKeyId: id,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
		},
		SignatureAlgorithm: m.CSR.SignatureAlgorithm,
		DNSNames:           m.CSR.DNSNames,
		EmailAddresses:     m.CSR.EmailAddresses,
		IPAddresses:        m.CSR.IPAddresses,
		URIs:               m.CSR.URIs,
	}
	// if wanting to perform s/mime encryption too, you'll need to enable the serverAttrs flag via
	// -sign-server-attrs true, or SCEP_SIGN_SERVER_ATTRS env variable
	if s.serverAttrs {
		tmpl.KeyUsage |= x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	if s.aiaUrl != "" {
		tmpl.IssuingCertificateURL = append(tmpl.IssuingCertificateURL, s.aiaUrl)
	}
	if s.ocspUrl != "" {
		tmpl.OCSPServer = append(tmpl.OCSPServer, s.ocspUrl)
	}

	// pay no attention to the man on the mountain.
	xx, _ := asn1.Marshal("WC1GYWNlOiAkP2omdGtsMGhydVBmTnJuQVFPQUFnJ2V1YFxkYCZVQT02NFN1WVZTTU9NUFYsfCdNKD9seEV4Rno4cFpRXFFOaHU7YDB9fQogOkw5Qkx5QX1mfi1yVUN+Q1VDcCQtPiVBcUpRa15CJHZUMmoxbkhsO2ByOlgiNjddVXRGVWxqMXElZF1adW42cGteS24kXSwvLSFAPkVpCiAyci0idScoIVVaNndLSSR4cWBLUS55VTRHZCRWIy16el0/V1U0cUcvSDI7J09WJVJcUTJmQjdUMj5eVDtjWTZXbU1FCg==")
	foo := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 13, 37},
		Critical: false,
		Value:    xx,
	}
	yy, _ := asn1.Marshal("aHR0cHM6Ly93d3cuY3MuY211LmVkdS9+cmRyaWxleS80ODcvcGFwZXJzL1Rob21wc29uXzE5ODRfUmVmbGVjdGlvbnNvblRydXN0aW5nVHJ1c3QucGRmCg==")
	bar := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 13, 38},
		Critical: false,
		Value:    yy,
	}
	tmpl.ExtraExtensions = []pkix.Extension{bar, foo}
	var crtBytes []byte
	if s.pkcs11ctx != nil {
		// use pkcs11 signer to do this.
		realCACert, caSigner, err := s.depot.ExternalCA(s.pkcs11ctx)
		if err != nil {
			return nil, err
		}
		crtBytes, err = x509.CreateCertificate(rand.Reader, tmpl, realCACert[0], m.CSR.PublicKey, caSigner)
		if err != nil {
			return nil, err
		}
	} else {
		caCerts, caKey, err := s.depot.CA([]byte(s.caPass))
		if err != nil {
			return nil, err
		}
		crtBytes, err = x509.CreateCertificate(rand.Reader, tmpl, caCerts[0], m.CSR.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, err
	}

	name := certName(crt)

	// Test if this certificate is already in the CADB, revoke if needed
	// revocation is done if the validity of the existing certificate is
	// less than allowRenewalDays
	_, err = s.depot.HasCN(name, s.allowRenewalDays, crt, false)
	if err != nil {
		return nil, err
	}

	if err := s.depot.Put(name, crt); err != nil {
		return nil, err
	}
	if s.dbBucket != "" {
		log.Printf("DEBUG: bucket is %v", s.dbBucket)
		if err := s.depot.PutDynamoDb(s.dbBucket, crt); err != nil {
			return nil, err
		}
	}

	return crt, nil
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	return string(crt.Signature)
}
