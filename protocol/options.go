package protocol

type CredentialCreation struct {
	Response PublicKeyCredentialCreationOptions `json:"publicKey"`
}

type CredentialAssertion struct {
	Options PublicKeyCredentialRequestOptions `json:"publicKey"`
}

type PublicKeyCredentialCreationOptions struct {
	Challenge              Challenge                `json:"challenge"`
	RelyingParty           RelyingPartyEntity       `json:"rp"`
	User                   UserEntity               `json:"user"`
	Parameters             []CredentialParameter    `json:"pubKeyCredParams,omitempty"`
	AuthenticatorSelection AuthenticatorSelection   `json:"authenticatorSelection,omitempty"`
	Timeout                int                      `json:"timeout,omitempty"`
	CredentialExcludeList  []CredentialDescriptor   `json:"excludeCredentials,omitempty"`
	Extensions             AuthenticationExtensions `json:"extenstions,omitempty"`
	Attestation            ConveyancePreference     `json:"attestation,omitempty"`
}

type PublicKeyCredentialRequestOptions struct {
	Challenge          Challenge
	Timeout            int
	RelyingPartyID     string
	AllowedCredentials []CredentialDescriptor
}

type CredentialDescriptor struct {
	Type      CredentialType           `json:"type"`
	ID        []byte                   `json:"id"`
	Transport []AuthenticatorTransport `json:"transports,omitempty"`
}

// CredentialParameter is the credential type and algorithm
// that the relying party wants the authenticator to create
type CredentialParameter struct {
	Type      CredentialType      `json:"type"`
	Algorithm AlgorithmIdentifier `json:"alg"`
}

// CredentialType This enumeration defines the valid credential types.
// It is an extension point; values can be added to it in the future, as
// more credential types are defined. The values of this enumeration are used
// for versioning the Authentication Assertion and attestation structures according
// to the type of the authenticator.
type CredentialType string

const (
	// PublicKeyCredentialType - Currently one credential type is defined, namely "public-key".
	PublicKeyCredentialType CredentialType = "public-key"
)

type AlgorithmIdentifier int

const (
	AlgES256 AlgorithmIdentifier = -7
	AlgRS256 AlgorithmIdentifier = -257
)

// AuthenticationExtensions - referred to as AuthenticationExtensionsClientInputs in the
// spec document, this member contains additional parameters requesting additional processing
// by the client and authenticator.
// This is currently under development
type AuthenticationExtensions map[string]interface{}

//AuthenticatorSelection https://www.w3.org/TR/webauthn/#authenticatorSelection
type AuthenticatorSelection struct {
	AuthenticatorAttachment AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool                        `json:"requireResidentKey,omitempty"`
	UserVerification        UserVerificationRequirement `json:"userVerification,omitempty"`
}
