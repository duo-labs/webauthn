package protocol

type AuthenticatorResponse struct {
	ClientDataJSON []byte `json:"clientDataJSON"`
}

type ParsedAttestationObject struct {
}

type AttestationStatement struct {
}

type AuthenticationExtensionsClientOutputs map[interface{}]interface{}

// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party
// and the client. It is a key-value mapping whose keys are strings. Values can be any type
// that has a valid encoding in JSON. Its structure is defined by the following Web IDL.
// https://www.w3.org/TR/webauthn/#sec-client-data
type CollectedClientData struct {
	// Type the string "webauthn.create" when creating new credentials,
	// and "webauthn.get" when getting an assertion from an existing credential. The
	// purpose of this member is to prevent certain types of signature confusion attacks
	//(where an attacker substitutes one legitimate signature for another).
	Type         CeremonyType  `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

type CeremonyType string

const (
	Create CeremonyType = "webauthn.create"
	Get    CeremonyType = "webauthn.get"
)

type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id,omitempty"`
}

type TokenBindingStatus string

const (
	// Present - Indicates token binding was used when communicating with the
	// Relying Party. In this case, the id member MUST be present.
	Present TokenBindingStatus = "present"
	// Supported -  IIndicates token binding was used when communicating with the
	// negotiated when communicating with the Relying Party.
	Supported TokenBindingStatus = "supported"
)
