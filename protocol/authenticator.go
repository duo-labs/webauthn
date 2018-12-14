package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ugorji/go/codec"
)

var minAuthDataLength = 37

type AuthenticatorResponse struct {
	// From the spec (https://www.w3.org/TR/webauthn/#dom-authenticatorresponse-clientdatajson)
	// This attribute contains a JSON serialization of the client data passed to the authenticator
	// by the client in its call to either create() or get().
	ClientDataJSON []byte `json:"clientDataJSON"`
}

type AuthenticatorData struct {
	Flags        AuthenticatorFlags `json:"flags"`
	Counter      uint32             `json:"sign_count"`
	RPIDHash     []byte             `json:"rpid"`
	AAGUID       []byte             `json:"aaguid"`
	CredentialID []byte             `json:"credential_id"`
	PublicKey    PublicKeyData      `json:"public_key"`
}

type PublicKeyData struct {
	_struct     bool        `codec:",int" json:"public_key"`
	KeyType     int64       `codec:"1" json:"kty"`
	Algorithm   int64       `codec:"3" json:"alg"`
	Curve       int64       `codec:"-1,omitempty" json:"crv"`
	XCoord      []byte      `codec:"-2,omitempty" json:"x-coordinate"`
	YCoord      []byte      `codec:"-3,omitempty" json:"y-coordinate"`
	KeyMaterial interface{} `codec:"-" json:"material"`
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
	return (flag & FlagUserVerified) == FlagUserVerified
}

func (flag AuthenticatorFlags) HasAttestedCredentialData() bool {
	return (flag & FlagAttestedCredentialData) == FlagAttestedCredentialData
}

func (flag AuthenticatorFlags) HasExtension() bool {
	return (flag & FlagHasExtension) == FlagHasExtension
}

func (a *AuthenticatorData) Unmarshal(rawAuthData []byte) error {
	if minAuthDataLength > len(rawAuthData) {
		err := ErrBadRequest.WithDetails("Authenticator data length too short")
		info := fmt.Sprintf("Expected data greater than %d bytes. Got %d bytes\n", minAuthDataLength, len(rawAuthData))
		return err.WithInfo(info)
	}

	a.RPIDHash = rawAuthData[:32]

	a.Flags = AuthenticatorFlags(rawAuthData[32])

	a.Counter = binary.BigEndian.Uint32(rawAuthData[33:37])

	if a.Flags.HasAttestedCredentialData() {
		if len(rawAuthData) > minAuthDataLength {
			return a.unmarshalAttestedData(rawAuthData)
		} else {
			return ErrBadRequest.WithDetails("Attested credential flag set but data is missing")
		}
	}

	if a.Flags.HasExtension() {
		// This is currently not implemented in the spec
		return ErrNotSpecImplemented
	}

	return nil
}

func (a *AuthenticatorData) unmarshalAttestedData(rawAuthData []byte) error {
	a.AAGUID = rawAuthData[37:53]

	idLength := binary.BigEndian.Uint16(rawAuthData[53:55])

	a.CredentialID = rawAuthData[55 : 55+idLength]

	pubKeyBytes := rawAuthData[55+idLength:]

	err := a.PublicKey.parseNewKey(pubKeyBytes)

	return err
}

func (newKey *PublicKeyData) parseNewKey(keyBytes []byte) error {
	var cborHandler codec.Handle = new(codec.CborHandle)
	codec.NewDecoder(bytes.NewReader(keyBytes), cborHandler).Decode(&newKey)
	switch newKey.KeyType {
	case 2:
		return newKey.parseECDSA()
	default:
		return ErrUnsupportedKey
	}
	return nil
}

func (newKey *PublicKeyData) parseECDSA() error {
	var curve elliptic.Curve
	switch newKey.Algorithm {
	case -36: // IANA COSE code for ECDSA w/ SHA-512
		curve = elliptic.P521()
	case -35: // IANA COSE code for ECDSA w/ SHA-384
		curve = elliptic.P384()
	case -7: // IANA COSE code for ECDSA w/ SHA-256
		curve = elliptic.P256()
	default:
		return ErrUnsupportedAlgorithm
	}

	newKey.KeyMaterial = &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(newKey.XCoord),
		Y:     big.NewInt(0).SetBytes(newKey.YCoord),
	}

	return nil
}

func (newKey *PublicKeyData) parseRSA() error {
	return ErrNotImplemented
}

// Verify on AuthenticatorData handles Steps 9 through 12 for Registration
// and Steps 11 through 14 for Assertion.
func (a *AuthenticatorData) Verify(rpIdHash [32]byte, userVerificationRequired bool) error {

	// Registration Step 9 & Assertion Step 11
	// Verify that the RP ID hash in authData is indeed the SHA-256
	// hash of the RP ID expected by the RP.
	if !bytes.Equal(a.RPIDHash[:], rpIdHash[:]) {
		return ErrVerification.WithInfo(fmt.Sprintf("RP Hash mismatch. Expected %+s and Received %+s\n", a.RPIDHash, rpIdHash))
	}

	// Registration Step 10 & Assertion Step 12
	// Verify that the User Present bit of the flags in authData is set.
	if !a.Flags.UserPresent() {
		return ErrVerification.WithInfo(fmt.Sprintln("User presence flag not set by authenticator"))
	}

	// Registration Step 11 & Assertion Step 13
	// If user verification is required for this assertion, verify that
	// the User Verified bit of the flags in authData is set.
	if userVerificationRequired && !a.Flags.UserVerified() {
		return ErrVerification.WithInfo(fmt.Sprintln("User verification required but flag not set by authenticator"))
	}

	// Registration Step 12 & Assertion Step 14
	// Verify that the values of the client extension outputs in clientExtensionResults
	// and the authenticator extension outputs in the extensions in authData are as
	// expected, considering the client extension input values that were given as the
	// extensions option in the create() call. In particular, any extension identifier
	// values in the clientExtensionResults and the extensions in authData MUST be also be
	// present as extension identifier values in the extensions member of options, i.e., no
	// extensions are present that were not requested. In the general case, the meaning
	// of "are as expected" is specific to the Relying Party and which extensions are in use.

	// This is not yet fully implemented by the spec or by browsers

	return nil
}
