package webauthn

import (
	"github.com/duo-labs/webauthn/protocol"
)

type SessionData struct {
	Challenge            protocol.Challenge `json:"challenge"`
	UserID               []byte             `json:"user_id"`
	AllowedCredentialIDs [][]byte           `json:"allowed_credentials,omitempty"`
}
