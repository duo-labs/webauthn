package protocol

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
)

type CredentialAssertionResponse struct {
	PublicKeyCredential
	AssertionResponse AuthenticatorAssertionResponse `json:"response"`
}

type ParsedCredentialAssertionData struct {
	ParsedPublicKeyCredential
	Response ParsedAssertionResponse
	Raw      CredentialAssertionResponse
}

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	AuthenticatorData []byte `json:"authenticatorData"`
	Signature         []byte `json:"signature"`
	UserHandle        []byte `json:"userHandle,omitempty"`
}

type ParsedAssertionResponse struct {
	CollectedClientData CollectedClientData
	AuthenticatorData   AuthenticatorData
	Signature           []byte
	UserHandle          []byte
}

func ParseCredentialRequestResponse(response *http.Request) (*ParsedCredentialAssertionData, error) {
	var car CredentialAssertionResponse
	err := json.NewDecoder(response.Body).Decode(&car)
	if err != nil {
		return nil, ErrBadRequest.WithDetails("Parse error for Assertion")
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

// Verify - Verify steps
func (p *ParsedCredentialAssertionData) Verify(storedChallenge []byte, relyingPartyID, relyingPartyOrigin string, verifyUser bool, credentialBytes []byte) error {

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

	// Begin Step 11. Verify that the rpIdHash in authData is
	// the SHA-256 hash of the RP ID expected by the RP.
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

	// Put this into proper certificate format for Step 16
	pemBlock, _ := pem.Decode(credentialBytes)
	if pemBlock == nil {
		return ErrParsingData.WithDetails("Unable to decode stored public key credential")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return ErrParsingData.WithDetails("Unable to parse pem decoded public key").WithInfo(err.Error())
	}

	credentialCertificate := x509.Certificate{PublicKey: parsedKey}

	sigData := append(p.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)

	// For COSE Key signature validation, we currently use ECDSA w/ SHA-256 primarily
	invalidSigError := credentialCertificate.CheckSignature(x509.ECDSAWithSHA256, sigData, p.Response.Signature)
	if invalidSigError != nil {
		fmt.Println("returned error:", invalidSigError.Error())
		return ErrAssertionSignature.WithInfo(invalidSigError.Error())
	}

	return nil
}
