package protocol

import (
	"encoding/json"
	"fmt"

	"github.com/ugorji/go/codec"
)

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	AttestationObject []byte `json:"attestationObject"`
}

type ParsedAttestationResponse struct {
	CollectedClientData CollectedClientData
	AuthenticatorData   AttestationObject
}

type AttestationObject struct {
	AuthData     []byte                      `codec:"authData" json:"fmt"`
	Format       string                      `codec:"fmt" json:"authData"`
	AttStatement EncodedAttestationStatement `codec:"attStmt, omitempty" json:"attStmt"`
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

func ParseAttestationResponse(a AuthenticatorAttestationResponse) (*ParsedAttestationResponse, error) {
	var p ParsedAttestationResponse

	err := json.Unmarshal(a.ClientDataJSON, &p.CollectedClientData)
	if err != nil {
		fmt.Println("parsing error")
		return nil, err
	}
	fmt.Printf("Got Collected Client Data: %+v\n", p.CollectedClientData)

	cborHandler := codec.CborHandle{}
	err = codec.NewDecoderBytes(a.AttestationObject, &cborHandler).Decode(&p.AuthenticatorData)
	if err != nil {
		fmt.Println("parsing error")
		return nil, err
	}

	return &p, nil
}
