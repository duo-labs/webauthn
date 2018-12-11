package protocol

import (
	"bytes"
	"encoding/base64"
	"fmt"

	webAuthnEncoding "github.com/duo-labs/webauthn/encoding"
)

// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party
// and the client. It is a key-value mapping whose keys are strings. Values can be any type
// that has a valid encoding in JSON. Its structure is defined by the following Web IDL.
// https://www.w3.org/TR/webauthn/#sec-client-data
type CollectedClientData struct {
	// Type the string "webauthn.create" when creating new credentials,
	// and "webauthn.get" when getting an assertion from an existing credential. The
	// purpose of this member is to prevent certain types of signature confusion attacks
	//(where an attacker substitutes one legitimate signature for another).
	Type         CeremonyType  `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

type CeremonyType string

const (
	CreateCeremony CeremonyType = "webauthn.create"
	AssertCeremony CeremonyType = "webauthn.get"
)

type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id,omitempty"`
}

type TokenBindingStatus string

const (
	// Present - Indicates token binding was used when communicating with the
	// Relying Party. In this case, the id member MUST be present.
	Present TokenBindingStatus = "present"
	// Supported -  Indicates token binding was used when communicating with the
	// negotiated when communicating with the Relying Party.
	Supported TokenBindingStatus = "supported"
)

// Verify handles steps 3 through 6 of verfying the registering client data of a
// new credential and steps 7 through 10 of verifying an authentication assertion
// See https://www.w3.org/TR/webauthn/#registering-a-new-credential
// and https://www.w3.org/TR/webauthn/#verifying-assertion
func (c *CollectedClientData) Verify(storedChallenge Challenge, ceremony CeremonyType, relyingPartyOrigin string) error {

	// Registration Step 3. Verify that the value of C.type is webauthn.create.

	// Assertion Step 7. Verify that the value of C.type is the string webauthn.get.
	if c.Type != ceremony {
		fmt.Printf("Expected Value: %s\n Received: %s\n", ceremony, c.Type)
		err := ErrVerification.WithDetails("Error validating ceremony type")
		err.WithInfo(fmt.Sprintf("Expected Value: %s\n Received: %s\n", ceremony, c.Type))
		return err
	}

	// Registration Step 4. Verify that the value of C.challenge matches the challenge
	// that was sent to the authenticator in the create() call.

	// Assertion Step 8. Verify that the value of C.challenge matches the challenge
	// that was sent to the authenticator in the PublicKeyCredentialRequestOptions
	// passed to the get() call.
	byteChallenge, err := webAuthnEncoding.B64Decode(c.Challenge)
	stringStore := base64.RawURLEncoding.EncodeToString(storedChallenge)
	fmt.Printf("Expected Value: %s\nReceived: %s\n", stringStore, byteChallenge)
	if err != nil {
		fmt.Println("r u fkn srs m8", err)
		return ErrParsingData.WithDetails("Error encoding the authenticator challenge")
	}

	if !bytes.Equal(storedChallenge, byteChallenge) {
		fmt.Println("r u fkn srs rn")
		fmt.Printf("Expected Value: %+v\nReceived: %+v\n", storedChallenge, byteChallenge)
		err := ErrVerification.WithDetails("Error validating challenge")
		return err.WithInfo(fmt.Sprintf("Expected Value: %s\n Received: %s\n", storedChallenge, byteChallenge))
	}

	// Registration Step 5 & Assertion Step 9. Verify that the value of C.origin matches
	// the Relying Party's origin.
	clientDataOrigin, err := webAuthnEncoding.URLEncode(c.Origin)
	if err != nil {
		return ErrParsingData.WithDetails("Error decoding clientData origin as URL")
		fmt.Println("r u fkn srs")
	}

	if clientDataOrigin.Hostname() != relyingPartyOrigin {
		fmt.Printf("Expected Value: %s\n Received: %s as Hostname %s\n", relyingPartyOrigin, c.Origin, clientDataOrigin)
		err := ErrVerification.WithDetails("Error validating challenge")
		return err.WithInfo(fmt.Sprintf("Expected Value: %s\n Received: %s as Hostname %s\n", relyingPartyOrigin, c.Origin, clientDataOrigin))
	}

	// Registration Step 6 and Assertion Step 10. Verify that the value of C.tokenBinding.status
	// matches the state of Token Binding for the TLS connection over which the assertion was
	// obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id
	// matches the base64url encoding of the Token Binding ID for the connection.

	// Not yet fully implemented by the spec, browsers, and me.
	return nil
}
