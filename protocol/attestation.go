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
	AttestationObject   AttestationObject
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

type DecodedAttestationObject struct {
	AuthData     AuthenticatorData
	Format       string
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
}

type AttestationFormat string

const (
	PackedAttestation  AttestationFormat = "packed"
	NoneAttestation    AttestationFormat = "none"
	FidoU2FAttestation AttestationFormat = "fido-u2f"
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
	err = codec.NewDecoderBytes(a.AttestationObject, &cborHandler).Decode(&p.AttestationObject)
	if err != nil {
		fmt.Println("parsing error")
		return nil, err
	}

	return &p, nil
}

// Decode - Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
// structure to obtain the attestation statement format fmt, the authenticator data authData,
// and the attestation statement attStmt.
func (attestationObject *AttestationObject) VerifyAuthData() error {
	var decodedObject DecodedAttestationObject

	decodedObject.Format = attestationObject.Format
	decodedObject.AuthData.Unmarshal(attestationObject.AuthData)

	fmt.Println("got auth data")
	fmt.Print("GOT: \n %+v \n", decodedObject.AuthData)

	return nil
}

// func (attestationObject *AttestationObject) Decode() (*DecodedAttestationObject, error) {
// 	var decodedObject DecodedAttestationObject

// 	decodedObject.Format = attestationObject.Format
// 	rawAuthData := attestationObject.AuthData.Decode()

// 	return nil, nil
// }
