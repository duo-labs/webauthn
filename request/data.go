package request

import (
	"crypto/x509"

	"duo.com/labs/web-authn/models"
)

type EncodedAttestationStatement struct {
	X509Cert  [][]byte `codec:"x5c"`
	Signature []byte   `codec:"sig"`
}

type EncodedAuthData struct {
	// _struct      struct{}                    `codec:",omitempty"`
	AuthData     []byte                      `codec:"authData"`
	Format       string                      `codec:"fmt"`
	AttStatement EncodedAttestationStatement `codec:"attStmt"`
}

type DecodedAssertionData struct {
	Flags            byte
	Counter          []byte
	RawAssertionData []byte
	RPIDHash         string
	Signature        []byte
}

type DecodedClientData struct {
	RawClientData string `codec:"-" json:"omitempty"`
	Challenge     string `codec:"challenge" json:"challenge"`
	HashAlgorithm string `codec:"hashAlgorithm" json:"hashAlgorithm"`
	Origin        string `codec:"origin" json:"origin"`
}

type DecodedAttestationStatement struct {
	Certificate *x509.Certificate
	Signature   []byte
}

type DecodedAuthData struct {
	Flags        []byte
	Counter      []byte
	RPIDHash     string
	AAGUID       []byte
	CredID       []byte
	PubKey       models.PublicKey
	Format       string
	AttStatement DecodedAttestationStatement
}
