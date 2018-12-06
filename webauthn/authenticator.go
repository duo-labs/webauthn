package webauthn

import (
	p "github.com/duo-labs/webauthn/protocol"
)

type Authenticator interface {
	ID() []byte
	AAGUID() []byte
	SignCount() uint32
}

type defaultAuthenticator struct {
	id        []byte
	aaguid    []byte
	signCount uint32
}

var _ Authenticator = (*defaultAuthenticator)(nil)

func (a *defaultAuthenticator) ID() []byte {
	return a.id
}

func (a *defaultAuthenticator) AAGUID() []byte {
	return a.aaguid
}

func (a *defaultAuthenticator) SignCount() uint32 {
	return a.signCount
}

func SelectAuthenticator(att p.AuthenticatorAttachment, rrk bool, uv p.UserVerificationRequirement) p.AuthenticatorSelection {
	return p.AuthenticatorSelection{
		AuthenticatorAttachment: att,
		RequireResidentKey:      rrk,
		UserVerification:        uv,
	}
}
