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

type LoginOption func(*protocol.PublicKeyCredentialRequestOptions)

func (webauthn *WebAuthn) BeginLogin(user User, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, nil, err
	}

	if len(user.WebAuthnCredentials()) == 0 {
		return nil, nil, protocol.ErrBadRequest.WithDetails("Found no credentials for user")
	}

	var allowedCredentials = make([]protocol.CredentialDescriptor, len(user.WebAuthnCredentials()))

	for i, credential := range user.WebAuthnCredentials() {
		var credentialDescriptor protocol.CredentialDescriptor
		credentialDescriptor.CredentialID = credential.ID
		credentialDescriptor.Type = protocol.PublicKeyCredentialType
		allowedCredentials[i] = credentialDescriptor
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:          challenge,
		Timeout:            webauthn.Config.Timeout,
		RelyingPartyID:     webauthn.Config.RelyingPartyID,
		UserVerification:   webauthn.Config.AuthenticatorSelection.UserVerification,
		AllowedCredentials: allowedCredentials,
	}

	for _, setter := range opts {
		setter(&requestOptions)
	}

	newSessionData := SessionData{
		Challenge:            challenge,
		UserID:               user.WebAuthnID(),
		AllowedCredentialIDs: requestOptions.GetAllowedCredentialIDs(),
	}

	creationResponse := protocol.CredentialAssertion{
		Response: requestOptions,
	}

	return &creationResponse, &newSessionData, nil
}

func WithAllowedCredentials(allowList []protocol.CredentialDescriptor) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.AllowedCredentials = allowList
	}
}

func (webauthn *WebAuthn) FinishLogin(user User, session SessionData, response *http.Request) (*Credential, error) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(response)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	// Step 1. If the allowCredentials option was given when this authentication ceremony was initiated,
	// verify that credential.id identifies one of the public key credentials that were listed in
	// allowCredentials.

	// NON-NORMATIVE Prior Step: Verify that the allowCredentials for the sesssion are owned by the user provided
	userCredentials := user.WebAuthnCredentials()
	fmt.Printf("got credentials %+v", userCredentials)
	if len(session.AllowedCredentialIDs) > 0 {
		var credentialsOwned bool
		for _, userCredential := range userCredentials {
			for _, allowedCredentialID := range session.AllowedCredentialIDs {
				if bytes.Equal(userCredential.ID, allowedCredentialID) {
					credentialsOwned = true
					break
				}
				credentialsOwned = false
			}
		}
		if !credentialsOwned {
			return nil, protocol.ErrBadRequest.WithDetails("User does not own all credentials from the allowedCredentialList")
		}
		var credentialFound bool
		for _, allowedCredentialID := range session.AllowedCredentialIDs {
			if bytes.Equal(parsedResponse.RawID, allowedCredentialID) {
				credentialFound = true
				break
			}
		}
		if !credentialFound {
			fmt.Println("steele is bad at loops2")
			return nil, protocol.ErrBadRequest.WithDetails("User does not own the credential returned")
		}
	}

	// Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
	// the owner of the public key credential identified by credential.id.

	// This is in part handled by our Step 1

	userHandle := parsedResponse.Response.UserHandle
	if userHandle != nil && len(userHandle) > 0 {
		if !bytes.Equal(userHandle, user.WebAuthnID()) {
			return nil, protocol.ErrBadRequest.WithDetails("userHandle and User ID do not match")
		}
	}

	// allowedUserCredentialIDs := session.AllowedCredentialIDs

	// invalidErr := parsedResponse.Verify()

	// if invalidErr != nil {
	// 	return nil, invalidErr
	// }

	fmt.Printf("got the following:\n %+v\n\n", parsedResponse)
	return nil, nil
}
