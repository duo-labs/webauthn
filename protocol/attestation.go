package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/ugorji/go/codec"
)

// From the spec (https://www.w3.org/TR/webauthn/#authenticatorattestationresponse)
// "The authenticator's response to a client’s request for the creation
// of a new public key credential. It contains information about the new credential
// that can be used to identify it for later use, and metadata that can be used by
// the WebAuthn Relying Party to assess the characteristics of the credential
// during registration."

// The initial unpacked 'response' object received by the relying party. This
// contains the clientDataJSON object, which will be marshalled into
// CollectedClientData, and the 'attestationObject', which contains
// infomation about the authenticator, and the newly minted
// public key credential. The information in both objects are used
// to verify the authenticity of the ceremony and new credential
type AuthenticatorAttestationResponse struct {
	// The byte slice of clientDataJSON, which becomes CollectedClientData
	AuthenticatorResponse
	// The byte slice version of AttestationObject
	// This attribute contains an attestation object, which is opaque to, and
	// cryptographically protected against tampering by, the client. The
	// attestation object contains both authenticator data and an attestation
	// statement. The former contains the AAGUID, a unique credential ID, and
	// the credential public key. The contents of the attestation statement are
	// determined by the attestation statement format used by the authenticator.
	// It also contains any additional information that the Relying Party's server
	// requires to validate the attestation statement, as well as to decode and
	// validate the authenticator data along with the JSON-serialized client data.
	AttestationObject []byte `json:"attestationObject"`
}

// The parsed out version of AuthenticatorAttestationResponse.
type ParsedAttestationResponse struct {
	CollectedClientData CollectedClientData
	AttestationObject   AttestationObject
}

type AttestationObject struct {
	AuthData     AuthenticatorData
	RawAuthData  []byte                 `codec:"authData" json:"authData"`
	Format       string                 `codec:"fmt" json:"fmt"`
	AttStatement map[string]interface{} `codec:"attStmt, omitempty" json:"attStmt"`
}

type AttestationFormat string

const (
	PackedAttestation  AttestationFormat = "packed"
	NoneAttestation    AttestationFormat = "none"
	FidoU2FAttestation AttestationFormat = "fido-u2f"
)

type AttestationFormatValidationHandler func(AttestationObject, []byte) error

var attestationRegistry = make(map[string]AttestationFormatValidationHandler)

func RegisterAttestationFormat(format string, handler AttestationFormatValidationHandler) {
	attestationRegistry[format] = handler
}

// Parse - Perform Step 8. CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
// structure to obtain the attestation statement format fmt, the authenticator data authData,
// and the attestation statement attStmt.
func (ccr *AuthenticatorAttestationResponse) Parse() (*ParsedAttestationResponse, error) {
	var p ParsedAttestationResponse

	err := json.Unmarshal(ccr.ClientDataJSON, &p.CollectedClientData)
	if err != nil {
		fmt.Println("attestation response parsing error")
		return nil, err
	}

	cborHandler := codec.CborHandle{}

	// Decode the attestation data with unmarshalled auth data
	err = codec.NewDecoderBytes(ccr.AttestationObject, &cborHandler).Decode(&p.AttestationObject)
	if err != nil {
		fmt.Println("parsing error")
		return nil, err
	}

	// Step 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
	// structure to obtain the attestation statement format fmt, the authenticator data authData, and
	// the attestation statement attStmt.
	err = p.AttestationObject.AuthData.Unmarshal(p.AttestationObject.RawAuthData)
	if err != nil {
		fmt.Println("error decoding auth data")
		return nil, err
	}

	return &p, nil
}

// Verify - Perform Steps 9 through 14 of registration verification, delegating Steps
func (attestationObject *AttestationObject) Verify(relyingPartyID string, clientDataHash []byte, verificationRequired bool) error {
	// Steps 9 through 12 are verified against the auth data.
	// These steps are identical to 11 through 14 for assertion
	// so we handle them with AuthData

	// Begin Step 9. Verify that the rpIdHash in authData is
	// the SHA-256 hash of the RP ID expected by the RP.
	rpIdHash := sha256.Sum256([]byte(relyingPartyID))
	// Handle Steps 9 through 12
	authDataVerificationError := attestationObject.AuthData.Verify(rpIdHash, verificationRequired)
	if authDataVerificationError != nil {
		return authDataVerificationError
	}

	// Step 13. Determine the attestation statement format by performing a
	// USASCII case-sensitive match on fmt against the set of supported
	// WebAuthn Attestation Statement Format Identifier values. The up-to-date
	// list of registered WebAuthn Attestation Statement Format Identifier
	// values is maintained in the IANA registry of the same name
	// [WebAuthn-Registries] (https://www.w3.org/TR/webauthn/#biblio-webauthn-registries).

	// Since there is not an active registry yet, we'll check it against our internal
	// Supported types.

	// But first let's make sure attestation is present. If it isn't, we don't need to handle
	// any of the following steps
	if attestationObject.Format == "none" {
		return nil
	}

	formatHandler, valid := attestationRegistry[attestationObject.Format]
	if !valid {
		return ErrAttestationFormat.WithInfo(fmt.Sprintf("Attestation format %s is unsupported", attestationObject.Format))
	}

	// Step 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.
	err := formatHandler(*attestationObject, clientDataHash)
	if err != nil {
		return err
	}

	return nil
}
