package request

import (
	"crypto/x509"

	"github.com/duo-labs/webauthn/models"
)

//EncodedAttestationStatement is the authenticator's attestation certificate
type EncodedAttestationStatement struct {
	// The attesation certificate in byte form. Returned to us as an array
	// of byte form certs since there may be more than one.
	X509Cert  [][]byte `codec:"x5c"`
	Signature []byte   `codec:"sig"`
}

// EncodedAuthData is a CBOR encoded data structure returned to us by the
// client/authenticator. The AttStatement may be empty depending on format
type EncodedAuthData struct {
	AuthData     []byte                      `codec:"authData"`
	Format       string                      `codec:"fmt"`
	AttStatement EncodedAttestationStatement `codec:"attStmt, omitempty"`
}

// DecodedAssertionData is the decoded assertion object's data
type DecodedAssertionData struct {
	Flags            byte
	Counter          []byte
	RawAssertionData []byte
	RPIDHash         string
	Signature        []byte
}

// DecodedClientData - Decoded ClientDataJSON
type DecodedClientData struct {
	// The raw base 64 encoded ClientDataJSON
	RawClientData string `codec:"-" json:"omitempty"`
	// The challenge we originally provided to the client for the authenticator
	Challenge string `codec:"challenge" json:"challenge"`
	// The Hash Algorithm used to create the credential
	HashAlgorithm string `codec:"hashAlgorithm" json:"hashAlgorithm"`
	// The origin URL of the authentication request
	Origin string `codec:"origin" json:"origin"`
	// Whether the request was for creating a credential or getting a credential
	ActionType string `codec:"type" json:"type"`
}

// DecodedAttestationStatement - The AttStmt returned by the authenticator's
// credential response.
type DecodedAttestationStatement struct {
	// The attestation certificate. This helps us identify the authenticator
	Certificate *x509.Certificate
	Signature   []byte
}

// DecodedAuthData - The AuthData returned by the authenticator's
// credential response.
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
