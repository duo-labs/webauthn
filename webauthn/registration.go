package webauthn

import (
	"bytes"
	"encoding/base64"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
)

// BEGIN REGISTRATION
// These objects help us creat the CredentialCreationOptions
// that will be passed to the authenticator via the user client

type RegistrationOption func(*protocol.PublicKeyCredentialCreationOptions)

// Generate a new set of registration data to be sent to the client and authenticator.
func (webauthn *WebAuthn) BeginRegistration(user User, opts ...RegistrationOption) (*protocol.CredentialCreation, *SessionData, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, nil, err
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
		ID: webauthn.Config.RPID,
		CredentialEntity: protocol.CredentialEntity{
			Name: webauthn.Config.RPDisplayName,
			Icon: webauthn.Config.RPIcon,
		},
	}

	credentialParams := defaultRegistrationCredentialParameters()

	rrk := false
	authSelection := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.CrossPlatform,
		RequireResidentKey:      &rrk,
		UserVerification:        protocol.VerificationPreferred,
	}

	creationOptions := protocol.PublicKeyCredentialCreationOptions{
		Challenge:              challenge,
		RelyingParty:           relyingParty,
		User:                   webAuthnUser,
		Parameters:             credentialParams,
		AuthenticatorSelection: authSelection,
		Timeout:                webauthn.Config.Timeout,
		Attestation:            protocol.PreferDirectAttestation, // default is "none"
	}

	for _, setter := range opts {
		setter(&creationOptions)
	}

	response := protocol.CredentialCreation{Response: creationOptions}
	newSessionData := SessionData{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		UserID:    user.WebAuthnID(),
	}

	if err != nil {
		return nil, nil, protocol.ErrParsingData.WithDetails("Error packing session data")
	}

	return &response, &newSessionData, nil
}

// Provide non-default parameters regarding the authenticator to select.
func WithAuthenticatorSelection(authenticatorSelection protocol.AuthenticatorSelection) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection = authenticatorSelection
	}
}

// Provide non-default parameters regarding credentials to exclude from retrieval.
func WithExclusions(excludeList []protocol.CredentialDescriptor) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.CredentialExcludeList = excludeList
	}
}

// Provide non-default parameters regarding whether the authenticator should attest to the credential.
func WithConveyancePreference(preference protocol.ConveyancePreference) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Attestation = preference
	}
}
func WithExtensions(preference protocol.AuthenticationExtensions) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Extensions = preference
	}
}

// Take the response from the authenticator and client and verify the credential against the user's credentials and
// session data.
func (webauthn *WebAuthn) FinishRegistration(user User, session SessionData, response *http.Request) (*Credential, error) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(response)
	if err != nil {
		return nil, err
	}

	shouldVerifyUser := webauthn.Config.AuthenticatorSelection.UserVerification == protocol.VerificationRequired

	invalidErr := parsedResponse.Verify(session.Challenge, shouldVerifyUser, webauthn.Config.RPID, webauthn.Config.RPOrigin)
	if invalidErr != nil {
		return nil, invalidErr
	}

	return MakeNewCredential(parsedResponse)
}

func defaultRegistrationCredentialParameters() []protocol.CredentialParameter {
	return []protocol.CredentialParameter{
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES256,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES384,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES512,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS256,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS384,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS512,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS256,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS384,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS512,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgEdDSA,
		},
	}
}
