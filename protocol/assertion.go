package protocol

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	Data       []byte `json:"authenticatorData"`
	Signature  []byte `json:"signature"`
	UserHandle []byte `json:"userHandle,omitempty"`
}
