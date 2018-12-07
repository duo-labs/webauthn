package webauthn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	p "github.com/duo-labs/webauthn/protocol"
)

// BEGIN REGISTRATION
// These objects help us creat the CredentialCreationOptions
// that will be passed to the authenticator via the user client

type RegistrationOption func(*p.PublicKeyCredentialCreationOptions)

func (webauthn *WebAuthn) BeginRegistration(user User, opts ...RegistrationOption) (*p.CredentialCreation, SessionData, error) {
	challenge, err := p.CreateChallenge()
	if err != nil {
		return nil, SessionData{}, err
	}

	webAuthnUser := p.UserEntity{
		ID:          user.WebAuthnID(),
		DisplayName: user.WebAuthnDisplayName(),
		CredentialEntity: p.CredentialEntity{
			Name: user.WebAuthnName(),
			Icon: user.WebAuthnIcon(),
		},
	}

	relyingParty := p.RelyingPartyEntity{
		ID: webauthn.Config.RelyingPartyID,
		CredentialEntity: p.CredentialEntity{
			Name: webauthn.Config.RelyingPartyDisplayName,
			Icon: webauthn.Config.RelyingPartyIcon,
		},
	}

	credentialParams := []p.CredentialParameter{
		p.CredentialParameter{
			Type:      p.PublicKeyCredentialType,
			Algorithm: p.AlgES256,
		},
	}

	authSelection := p.AuthenticatorSelection{
		AuthenticatorAttachment: p.CrossPlatform,
		RequireResidentKey:      false,
		UserVerification:        p.VerificationPreferred,
	}

	creationOptions := p.PublicKeyCredentialCreationOptions{
		Challenge:              challenge,
		RelyingParty:           relyingParty,
		User:                   webAuthnUser,
		Parameters:             credentialParams,
		AuthenticatorSelection: authSelection,
		Timeout:                webauthn.Config.Timeout,
		Attestation:            p.PreferNoAttestation, // default is "none"
	}

	for _, setter := range opts {
		setter(&creationOptions)
	}

	response := p.CredentialCreation{Response: creationOptions}
	sessionData := SessionData{
		Challenge: challenge,
		UserID:    user.WebAuthnID(),
	}

	return &response, sessionData, nil
}

func WithAuthenticatorSelection(authenticatorSelection p.AuthenticatorSelection) RegistrationOption {
	return func(cco *p.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection = authenticatorSelection
	}
}

func WithExclusions(excludeList []p.CredentialDescriptor) RegistrationOption {
	return func(cco *p.PublicKeyCredentialCreationOptions) {
		cco.CredentialExcludeList = excludeList
	}
}

func WithConveyancePreference(preference p.ConveyancePreference) RegistrationOption {
	return func(cco *p.PublicKeyCredentialCreationOptions) {
		cco.Attestation = preference
	}
}

func parseRegistrationResponse(response *http.Request) (*p.ParsedCredentialCreationData, error) {
	var credentialResponse p.CredentialCreationResponse
	err := json.NewDecoder(response.Body).Decode(&credentialResponse)
	if err != nil {
		return nil, p.ErrBadRequest.WithDetails("fuck")
	}
	return p.ParseCredentialCreationResponse(credentialResponse)
}

func (webauthn *WebAuthn) FinishRegistration(user User, session SessionData, response *http.Request) (*Credential, error) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		p.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	parsedResponse, err := parseRegistrationResponse(response)
	if err != nil {
		fmt.Println(err)
		return nil, p.ErrBadRequest.WithDetails("fuddck")
	}
	fmt.Printf("got the following:\n %+v\n\n", parsedResponse)
	return nil, nil
}
