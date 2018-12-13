package webauthn

import (
	p "github.com/duo-labs/webauthn/protocol"
)

type Authenticator struct {
	// The AAGUID of the authenticator.
	AAGUID []byte
	// SignCount -Upon a new login operation, the Relying Party compares the stored signature counter value
	// with the new signCount value returned in the assertion’s authenticator data. If this new
	// signCount value is less than or equal to the stored value, a cloned authenticator may
	// exist, or the authenticator may be malfunctioning.
	SignCount uint32
}

func SelectAuthenticator(att p.AuthenticatorAttachment, rrk bool, uv p.UserVerificationRequirement) p.AuthenticatorSelection {
	return p.AuthenticatorSelection{
		AuthenticatorAttachment: att,
		RequireResidentKey:      rrk,
		UserVerification:        uv,
	}
}
