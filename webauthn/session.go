package webauthn

import (
	"github.com/duo-labs/webauthn/protocol"
)

// type SessionData struct {
// 	Challenge            string   `json:"challenge"`
// 	UserID               []byte   `json:"webauthn_user_id"`
// 	AllowedCredentialIDs []string `json:"allowed_credentials,omitempty"`
// }

type SessionData struct {
	Challenge            protocol.Challenge `json:"challenge"`
	UserID               []byte             `json:"user_id"`
	AllowedCredentialIDs [][]byte           `json:"allowed_credentials,omitempty"`
}

// func (s *SessionData) Unpack() (*unpackedSessionData, error) {
// 	var usd unpackedSessionData
// 	if s.Challenge == "" {
// 		return nil, protocol.ErrBadRequest.WithDetails("Challenge is unset")
// 	}
// 	var decodeErr error
// 	usd.Challenge, decodeErr = base64.StdEncoding.DecodeString(s.Challenge)
// 	if decodeErr != nil {
// 		return nil, protocol.ErrBadRequest.WithDetails("Error decoding challenge").WithInfo(decodeErr.Error())
// 	}
// 	for i, credentialID := range s.AllowedCredentialIDs {
// 		usd.AllowedCredentialIDs[i], decodeErr = base64.StdEncoding.DecodeString(credentialID)
// 		if decodeErr != nil {
// 			return nil, protocol.ErrBadRequest.WithDetails("Error decoding credential IDs").WithInfo(decodeErr.Error())
// 		}
// 	}
// 	usd.UserID = s.UserID
// 	return &usd, nil
// }

// func (s *unpackedSessionData) Pack() (*SessionData, error) {
// 	var sd SessionData
// 	sd.Challenge = base64.StdEncoding.EncodeToString(s.Challenge)
// 	for i, credentialID := range s.AllowedCredentialIDs {
// 		sd.AllowedCredentialIDs[i] = base64.StdEncoding.EncodeToString(credentialID)
// 	}
// 	sd.UserID = s.UserID
// 	return &sd, nil
// }

// func (s *SessionData) validSession() (bool, error) {
// 	return true, nil
// }
