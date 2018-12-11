package protocol

import "fmt"

type Credential struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type ParsedCredential struct {
	ID   string `codec:"id"`
	Type string `codec:"type"`
}

type PublicKeyCredential struct {
	Credential
	RawID      []byte                                `json:"rawId"`
	Extensions AuthenticationExtensionsClientOutputs `json:"results,omitempty"`
}

type ParsedPublicKeyCredential struct {
	ParsedCredential
	RawID []byte              `json:"rawId"`
	Raw   PublicKeyCredential `json:"raw"`
}

type CredentialCreationResponse struct {
	PublicKeyCredential
	Response AuthenticatorAttestationResponse `json:"response"`
}

type ParsedCredentialCreationData struct {
	ParsedPublicKeyCredential
	Response ParsedAttestationResponse
	Raw      CredentialCreationResponse
}

func ParseCredentialCreationResponse(ccr CredentialCreationResponse) (*ParsedCredentialCreationData, error) {
	var pcc ParsedCredentialCreationData
	pcc.ID, pcc.RawID, pcc.Type = ccr.ID, ccr.RawID, ccr.Type
	pcc.Raw = ccr

	par, err := ParseAttestationResponse(ccr.Response)
	if err != nil {
		return nil, ErrParsingData.WithDetails("Error parsing attestation response")
	}

	pcc.Response = *par

	return &pcc, nil
}

type COSEPublicKey struct {
	_struct bool   `codec:",int"`
	KeyType int64  `codec:"1"`
	Type    int64  `codec:"3"`
	Curve   int64  `codec:"-1,omitempty"`
	XCoord  []byte `codec:"-2,omitempty"`
	YCoord  []byte `codec:"-3,omitempty"`
}

// Validate the steps as laid out by Seciton 7.1. Registering a new credential
// https://www.w3.org/TR/webauthn/#registering-a-new-credential
// By this point we have decoded the clientDataJSON and parsed it
// into CollectedClientData, which are steps 1 & 2.
// The specification refers to this variable as C
func (cr *ParsedCredentialCreationData) Verify(storedChallenge Challenge, relyingPartyID, relyingPartyOrigin string) error {

	// Handles steps 3 through 6
	verifyError := cr.Response.CollectedClientData.Verify(storedChallenge, CreateCeremony, relyingPartyOrigin)
	if verifyError != nil {
		fmt.Println("error during collecting client data")
		return verifyError
	}

	// Step 7. Compute the hash of response.clientDataJSON using SHA-256.
	// clientDataHash := webAuthnEncoding.SHA256Hash(cr.Raw.Response.ClientDataJSON)

	verifyError = cr.Response.AttestationObject.VerifyAuthData()

	return nil
}
