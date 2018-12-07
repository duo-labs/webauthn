package protocol

import (
	"fmt"
)

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
		fmt.Println("poop")
		fmt.Println(err)
	}

	pcc.Response = *par

	return &pcc, nil
}
