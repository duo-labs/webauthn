package webauthn

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/duo-labs/webauthn/protocol"
)

type Credential struct {
	ID            []byte
	PublicKey     []byte
	Authenticator Authenticator
}

func MakeNewCredential(c *protocol.ParsedCredentialCreationData) (*Credential, error) {
	keyMaterial := c.Response.AttestationObject.AuthData.PublicKey.KeyMaterial
	newPublicKeyDER, err := x509.MarshalPKIXPublicKey(keyMaterial)

	if err != nil {
		return nil, err
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: newPublicKeyDER,
	}

	newCredential := &Credential{
		ID:        c.Response.AttestationObject.AuthData.CredentialID,
		PublicKey: pem.EncodeToMemory(publicKeyPEM),
		Authenticator: Authenticator{
			AAGUID:    c.Response.AttestationObject.AuthData.AAGUID,
			SignCount: c.Response.AttestationObject.AuthData.Counter,
		},
	}

	return newCredential, nil
}
