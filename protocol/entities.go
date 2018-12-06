package protocol

type CredentialEntity struct {
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
}

// RelyingPartyEntity - the relying party requesting the credential
type RelyingPartyEntity struct {
	CredentialEntity
	ID string `json:"id"`
}

// UserEntity - the user requesting the credential
type UserEntity struct {
	CredentialEntity
	DisplayName string `json:"displayName,omitempty"`
	ID          []byte `json:"id"`
}
