package webauthn

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
)

// BEGIN REGISTRATION
// These objects help us creat the CredentialCreationOptions
// that will be passed to the authenticator via the user client

type RegistrationOption func(*protocol.PublicKeyCredentialCreationOptions)

func (webauthn *WebAuthn) BeginRegistration(user User, opts ...RegistrationOption) (*protocol.CredentialCreation, SessionData, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, SessionData{}, err
	}

	webAuthnUser := protocol.UserEntity{
		ID:          user.WebAuthnID(),
		DisplayName: user.WebAuthnDisplayName(),
		CredentialEntity: protocol.CredentialEntity{
			Name: user.WebAuthnName(),
			Icon: user.WebAuthnIcon(),
		},
	}

	relyingParty := protocol.RelyingPartyEntity{
		ID: webauthn.Config.RelyingPartyID,
		CredentialEntity: protocol.CredentialEntity{
			Name: webauthn.Config.RelyingPartyDisplayName,
			Icon: webauthn.Config.RelyingPartyIcon,
		},
	}

	credentialParams := []protocol.CredentialParameter{
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: protocol.AlgES256,
		},
	}

	authSelection := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.CrossPlatform,
		RequireResidentKey:      false,
		UserVerification:        protocol.VerificationPreferred,
	}

	creationOptions := protocol.PublicKeyCredentialCreationOptions{
		Challenge:              challenge,
		RelyingParty:           relyingParty,
		User:                   webAuthnUser,
		Parameters:             credentialParams,
		AuthenticatorSelection: authSelection,
		Timeout:                webauthn.Config.Timeout,
		Attestation:            protocol.PreferNoAttestation, // default is "none"
	}

	for _, setter := range opts {
		setter(&creationOptions)
	}

	response := protocol.CredentialCreation{Response: creationOptions}
	sessionData := SessionData{
		Challenge: challenge,
		UserID:    user.WebAuthnID(),
	}

	return &response, sessionData, nil
}

func WithAuthenticatorSelection(authenticatorSelection protocol.AuthenticatorSelection) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection = authenticatorSelection
	}
}

func WithExclusions(excludeList []protocol.CredentialDescriptor) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.CredentialExcludeList = excludeList
	}
}

func WithConveyancePreference(preference protocol.ConveyancePreference) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Attestation = preference
	}
}

func (webauthn *WebAuthn) FinishRegistration(user User, session SessionData, response *http.Request) (*Credential, error) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(response)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	shouldVerifyUser := webauthn.Config.AuthenticatorSelection.UserVerification == protocol.VerificationRequired

	fmt.Printf("Origin %+v\n", webauthn.Config.RelyingPartyOrigin)
	fmt.Printf("Parsed Credential Data %+v\n", parsedResponse)
	invalidErr := parsedResponse.Verify(session.Challenge, shouldVerifyUser, webauthn.Config.RelyingPartyID, webauthn.Config.RelyingPartyOrigin)
	if invalidErr != nil {
		fmt.Printf("u beefed it, %s\n ", invalidErr)
	}

	newCredential, err := MakeNewCredential(parsedResponse)
	if err != nil {
		fmt.Printf("u beefed it, %s\n ", err)
	}
}
