package webauthn

import "github.com/duo-labs/webauthn/protocol"

type SessionData struct {
	Challenge            string                               `json:"challenge"`
	UserID               []byte                               `json:"user_id"`
	AllowedCredentialIDs [][]byte                             `json:"allowed_credentials,omitempty"`
	UserVerification     protocol.UserVerificationRequirement `json:"userVerification"`
}
