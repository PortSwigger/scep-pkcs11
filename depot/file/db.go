package file

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/pkg/errors"
)

var dyndb *dynamodb.DynamoDB

type x509Record struct {
	Status             string
	Requester          string
	SerialNumber       string
	Issuer             string
	Subject            string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	PubKey             []byte
	DerCert            []byte
}

// func addDbRecord(crtBytes []byte) error {
func (d *fileDepot) PutDynamoDb(bucket string, crt *x509.Certificate) error {
	// now parse the cert back and add it to the DB.
	// crt, err := x509.ParseCertificate(crtBytes)
	// if err != nil {
	// 	log.Fatalf("FATAL: %v", err)
	// }
	// chomp out the pub key bytes
	var pubBytes []byte
	var err error
	switch pub := crt.PublicKey.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(*pub)
		if err != nil {
			return err
		}
	case *ecdsa.PublicKey:
		pubBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	default:
		return errors.New("only ECDSA and RSA public keys are supported")
	}

	// marshal the crt to a pem byte array
	record := x509Record{
		Status:             "V", // Valid
		Requester:          crt.Subject.CommonName,
		SerialNumber:       crt.SerialNumber.String(), // serial number should be unique (as in cryptographically) so we can use this as the key
		Issuer:             crt.Issuer.String(),
		Subject:            crt.Subject.String(),
		NotBefore:          crt.NotBefore,
		NotAfter:           crt.NotAfter,
		PublicKeyAlgorithm: crt.PublicKeyAlgorithm,
		SignatureAlgorithm: crt.SignatureAlgorithm,
		DNSNames:           crt.DNSNames,
		EmailAddresses:     crt.EmailAddresses,
		IPAddresses:        crt.IPAddresses,
		URIs:               crt.URIs,
		PubKey:             pubBytes,
		//DerCert:            crtBytes,
	}

	// we should be running under the role given to us by the sts tokens.
	// We'll just use this role to create a new session.
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{},
	})
	if err != nil {
		log.Printf("ERROR: Could not create aws session (%v)", err)
		return err
	}
	dyndb = dynamodb.New(sess)
	av, err := dynamodbattribute.MarshalMap(record)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(bucket),
	}
	_, err = dyndb.PutItem(input)
	if err != nil {
		log.Printf("ERROR: %v", err)
		return err
	}

	return err
}
