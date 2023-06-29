package depot

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"

	"github.com/ThalesIgnite/crypto11"
)

// Depot is a repository for managing certificates
type Depot interface {
	CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error)
	ExternalCA(ctx *crypto11.Context) ([]*x509.Certificate, crypto11.Signer, error)
	Put(name string, crt *x509.Certificate) error
	PutDynamoDb(bucket string, crt *x509.Certificate) error
	Serial() (*big.Int, error)
	HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error)
}
