package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
)

// The raw response returned to us from an authenticator when we request a
// credential for login/assertion.
type CredentialAssertionResponse struct {
	PublicKeyCredential
	AssertionResponse AuthenticatorAssertionResponse `json:"response"`
}

// The parsed CredentialAssertionResponse that has been marshalled into a format
// that allows us to verify the client and authenticator data inside the response
type ParsedCredentialAssertionData struct {
	ParsedPublicKeyCredential
	Response ParsedAssertionResponse
	Raw      CredentialAssertionResponse
}

// The AuthenticatorAssertionResponse contains the raw authenticator assertion data and is parsed into
// ParsedAssertionResponse
type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	AuthenticatorData URLEncodedBase64 `json:"authenticatorData"`
	Signature         URLEncodedBase64 `json:"signature"`
	UserHandle        URLEncodedBase64 `json:"userHandle,omitempty"`
}

// Parsed form of AuthenticatorAssertionResponse
type ParsedAssertionResponse struct {
	CollectedClientData CollectedClientData
	AuthenticatorData   AuthenticatorData
	Signature           []byte
	UserHandle          []byte
}

// Parse the credential request response into a format that is either required by the specification
// or makes the assertion verification steps easier to complete. This takes an http.Request that contains
// the attestation response data in a raw, mostly base64 encoded format, and parses the data into
// manageable structures
func ParseCredentialRequestResponse(response *http.Request) (*ParsedCredentialAssertionData, error) {
	var car CredentialAssertionResponse
	err := json.NewDecoder(response.Body).Decode(&car)
	if err != nil {
		return nil, ErrBadRequest.WithDetails("Parse error for Assertion")
	}

	if car.ID == "" {
		return nil, ErrBadRequest.WithDetails("CredentialAssertionResponse with ID missing")
	}

	_, err = base64.RawURLEncoding.DecodeString(car.ID)
	if err != nil {
		return nil, ErrBadRequest.WithDetails("CredentialAssertionResponse with ID not base64url encoded")
	}
	if car.Type != "public-key" {
		return nil, ErrBadRequest.WithDetails("CredentialAssertionResponse with bad type")
	}
	var par ParsedCredentialAssertionData
	par.ID, par.RawID, par.Type = car.ID, car.RawID, car.Type
	par.Raw = car

	par.Response.Signature = car.AssertionResponse.Signature
	par.Response.UserHandle = car.AssertionResponse.UserHandle

	// Step 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
	// We don't call it cData but this is Step 5 in the spec.
	err = json.Unmarshal(car.AssertionResponse.ClientDataJSON, &par.Response.CollectedClientData)
	if err != nil {
		return nil, err
	}

	err = par.Response.AuthenticatorData.Unmarshal(car.AssertionResponse.AuthenticatorData)
	if err != nil {
		return nil, ErrParsingData.WithDetails("Error unmarshalling auth data")
	}
	return &par, nil
}

// Follow the remaining steps outlined in §7.2 Verifying an authentication assertion
// (https://www.w3.org/TR/webauthn/#verifying-assertion) and return an error if there
// is a failure during each step.
func (p *ParsedCredentialAssertionData) Verify(storedChallenge string, relyingPartyID, relyingPartyOrigin string, verifyUser bool, credentialBytes []byte) error {

	// Steps 4 through 6 in verifying the assertion data (https://www.w3.org/TR/webauthn/#verifying-assertion) are
	// "assertive" steps, i.e "Let JSONtext be the result of running UTF-8 decode on the value of cData."
	// We handle these steps in part as we verify but also beforehand

	// Handle steps 7 through 10 of assertion by verifying stored data against the Collected Client Data
	// returned by the authenticator
	validError := p.Response.CollectedClientData.Verify(storedChallenge, AssertCeremony, relyingPartyOrigin)
	if validError != nil {
		fmt.Println("got error, ", validError)
		return validError
	}

	// Begin Step 11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the RP.
	rpIDHash := sha256.Sum256([]byte(relyingPartyID))

	// Handle steps 11 through 14, verifying the authenticator data.
	validError = p.Response.AuthenticatorData.Verify(rpIDHash[:], verifyUser)
	if validError != nil {
		return ErrAuthData.WithInfo(validError.Error())
	}

	// allowedUserCredentialIDs := session.AllowedCredentialIDs

	// Step 15. Let hash be the result of computing a hash over the cData using SHA-256.
	clientDataHash := sha256.Sum256(p.Raw.AssertionResponse.ClientDataJSON)

	// Step 16. Using the credential public key looked up in step 3, verify that sig is
	// a valid signature over the binary concatenation of authData and hash.

	sigData := append(p.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)

	key, err := webauthncose.ParsePublicKey(credentialBytes)

	valid, err := webauthncose.VerifySignature(key, sigData, p.Response.Signature)
	if !valid {
		return ErrAssertionSignature.WithDetails(fmt.Sprintf("Error validating the assertion signature: %+v\n", err))
	}
	return nil
}
