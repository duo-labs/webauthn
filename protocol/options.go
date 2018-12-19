package protocol

type CredentialCreation struct {
	Response PublicKeyCredentialCreationOptions `json:"publicKey"`
}

type CredentialAssertion struct {
	Response PublicKeyCredentialRequestOptions `json:"publicKey"`
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
	Challenge          Challenge                   `json:"challenge"`
	Timeout            int                         `json:"timeout,omitempty"`
	RelyingPartyID     string                      `json:"rpId,omitempty"`
	AllowedCredentials []CredentialDescriptor      `json:"allowCredentials,omitempty"`
	UserVerification   UserVerificationRequirement `json:"userVerification,omitempty"` // Default is "preferred"
	Extensions         AuthenticationExtensions    `json:"extenstions,omitempty"`
}

type CredentialDescriptor struct {
	Type CredentialType `json:"type"`
	// CredentialID The ID of a credential to allow/disallow
	CredentialID []byte                   `json:"id"`
	Transport    []AuthenticatorTransport `json:"transports,omitempty"`
}

// CredentialParameter is the credential type and algorithm
// that the relying party wants the authenticator to create
type CredentialParameter struct {
	Type      CredentialType          `json:"type"`
	Algorithm COSEAlgorithmIdentifier `json:"alg"`
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

// ConveyancePreference AttestationConveyancePreference
type ConveyancePreference string

const (
	PreferNoAttestation       ConveyancePreference = "none"
	PreferIndirectAttestation ConveyancePreference = "indirect"
	PreferDirectAttestation   ConveyancePreference = "direct"
)

func (a *PublicKeyCredentialRequestOptions) GetAllowedCredentialIDs() [][]byte {
	var allowedCredentialIDs = make([][]byte, len(a.AllowedCredentials))
	for i, credential := range a.AllowedCredentials {
		allowedCredentialIDs[i] = credential.CredentialID
	}
	return allowedCredentialIDs
}
