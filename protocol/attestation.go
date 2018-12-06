package protocol

type CredentialCreationResponse struct {
	PublicKeyCredential
	Response AuthenticatorAttestationResponse `json:"response"`
}

type ParsedCredentialCreationData struct {
	ParsedPublicKeyCredential
	Response ParsedAttestationResponse
	Raw      CredentialCreationResponse
}

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	AttestationObject []byte `json:"attestationObject"`
}

type ParsedAttestationResponse struct {
	ClientData CollectedClientData
}

type AttestationObject struct {
	AuthData     []byte                      `codec:"authData"`
	Format       string                      `codec:"fmt"`
	AttStatement EncodedAttestationStatement `codec:"attStmt, omitempty"`
}

//EncodedAttestationStatement is the authenticator's attestation certificate
type EncodedAttestationStatement struct {
	// The attesation certificate in byte form. Returned to us as an array
	// of byte form certs since there may be more than one.
	X509Cert  [][]byte `codec:"x5c"`
	Signature []byte   `codec:"sig"`
}

// ConveyancePreference AttestationConveyancePreference
type ConveyancePreference string

const (
	PreferNoAttestation       ConveyancePreference = "none"
	PreferIndirectAttestation ConveyancePreference = "indirect"
	PreferDirectAttestation   ConveyancePreference = "direct"
)

func ParseAttestationResponse(ccr CredentialCreationResponse) (*ParsedCredentialCreationData, error) {
	pcc := ParsedCredentialCreationData{}
	pcc.ID, pcc.RawID, pcc.Type = ccr.ID, ccr.RawID, ccr.Type
	pcc.Raw = ccr

	return nil, nil
}
