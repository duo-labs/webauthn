package protocol

import (
	"encoding/binary"
	"fmt"
)

var minAuthDataLength = 37

type AuthenticatorResponse struct {
	ClientDataJSON []byte `json:"clientDataJSON"`
}

type AuthenticatorData struct {
	Flags        AuthenticatorFlags `json:"flags"`
	Counter      uint32             `json:"sign_count"`
	RPIDHash     []byte             `json:"rpid"`
	AAGUID       []byte             `json:"aaguid"`
	CredentialID []byte             `json:"credential_id"`
	PublicKey    COSEPublicKey      `json:"public_key"`
	RawAuthData  []byte             `json:"raw"`
}

// AuthenticatorAttachment - https://www.w3.org/TR/webauthn/#platform-attachment
type AuthenticatorAttachment string

const (
	// Platform - A platform authenticator is attached using a client device-specific transport, called
	// platform attachment, and is usually not removable from the client device. A public key credential
	//  bound to a platform authenticator is called a platform credential.
	Platform AuthenticatorAttachment = "platform"
	// CrossPlatform A roaming authenticator is attached using cross-platform transports, called
	// cross-platform attachment. Authenticators of this class are removable from, and can "roam"
	// among, client devices. A public key credential bound to a roaming authenticator is called a
	// roaming credential.
	CrossPlatform AuthenticatorAttachment = "cross-platform"
)

type AuthenticatorTransport string

const (
	USB      AuthenticatorTransport = "usb"
	NFC      AuthenticatorTransport = "nfc"
	BLE      AuthenticatorTransport = "ble"
	Internal AuthenticatorTransport = "internal"
)

type UserVerificationRequirement string

const (
	VerificationRequired    UserVerificationRequirement = "required"
	VerificationPreferred   UserVerificationRequirement = "preferred"
	VerificationDiscouraged UserVerificationRequirement = "discouraged"
)

type AuthenticatorFlags byte

const (
	FlagUserPresent            = 0x001 // UP
	FlagUserVerified           = 0x003 // UV
	FlagAttestedCredentialData = 0x040 // AT
	FlagHasExtension           = 0x080 // ED
)

func (flag AuthenticatorFlags) UserPresent() bool {
	return (flag & FlagUserPresent) == FlagUserPresent
}

func (flag AuthenticatorFlags) UserVerified() bool {
	return (flag & FlagUserPresent) == FlagUserPresent
}

func (flag AuthenticatorFlags) HasAttestedCredentialData() bool {
	return (flag & FlagUserPresent) == FlagUserPresent
}

func (flag AuthenticatorFlags) HasExtension() bool {
	return (flag & FlagUserPresent) == FlagUserPresent
}

func (a *AuthenticatorData) Unmarshal(rawAuthData []byte) error {
	if minAuthDataLength > len(rawAuthData) {
		err := ErrBadRequest.WithDetails("Authenticator data length too short")
		info := fmt.Sprintf("Expected data greater than %s bytes. Got %s bytes\n", minAuthDataLength, len(rawAuthData))
		return err.WithInfo(info)
	}

	a.RawAuthData = rawAuthData

	a.RPIDHash = rawAuthData[:32]

	a.Flags = AuthenticatorFlags(rawAuthData[32])

	a.Counter = binary.BigEndian.Uint32(rawAuthData[33:37])

	if a.Flags.HasAttestedCredentialData() {
		if len(rawAuthData) > minAuthDataLength {
			return a.unmarshalAttestedData()
		} else {
			return ErrBadRequest.WithDetails("Attested credential flag set but data is missing")
		}
	}

	return nil
}

func (a *AuthenticatorData) unmarshalAttestedData() error {
	a.AAGUID = a.RawAuthData[37:53]

	idLength := binary.BigEndian.Uint16(a.RawAuthData[53:55])

	a.CredentialID = a.RawAuthData[55 : 55+idLength]

	return nil
}
