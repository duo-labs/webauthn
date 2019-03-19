package webauthn

type SessionData struct {
	Challenge            string   `json:"challenge"`
	UserID               []byte   `json:"user_id"`
	AllowedCredentialIDs [][]byte `json:"allowed_credentials,omitempty"`
}
