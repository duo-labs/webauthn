package webauthn

import (
	"github.com/duo-labs/webauthn/protocol"
)

type SessionData struct {
	Challenge protocol.Challenge
	UserID    []byte
}
