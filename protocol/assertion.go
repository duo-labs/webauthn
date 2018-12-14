package protocol

import (
	"encoding/json"
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

	// Step 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
	// We don't call it cData but this is Step 5 in the spec.
	err = json.Unmarshal(car.AssertionResponse.ClientDataJSON, &par.Response.CollectedClientData)
	if err != nil {
		fmt.Println("ass response parsing error")
		return nil, err
	}

	err = par.Response.AuthenticatorData.Unmarshal(car.AssertionResponse.AuthenticatorData)
	if err != nil {
		fmt.Println(err)
		return nil, ErrParsingData.WithDetails("Error unmarshalling auth data")
	}
	return &par, nil
}

// Verify - Verify
func (p *ParsedCredentialAssertionData) Verify(allowedCredentials, userCredentials [][]byte) error {
	// Step 1. If the allowCredentials option was given when this authentication ceremony was initiated,
	// verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.

	return nil
}
