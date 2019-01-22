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
	ClientDataJSON URLEncodedBase64 `json:"clientDataJSON"`
}

// AuthenticatorData From §6.1 of the spec.
// The authenticator data structure encodes contextual bindings made by the authenticator. These bindings
// are controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's
// assessment of the security properties of the authenticator. In one extreme case, the authenticator
// may be embedded in the client, and its bindings may be no more trustworthy than the client data.
// At the other extreme, the authenticator may be a discrete entity with high-security hardware and
// software, connected to the client over a secure channel. In both cases, the Relying Party receives
// the authenticator data in the same format, and uses its knowledge of the authenticator to make
// trust decisions.
//
// The authenticator data, at least during attestation, contains the Public Key that the RP stores
// and will associate with the user attempting to register.
type AuthenticatorData struct {
	Flags        AuthenticatorFlags `json:"flags"`
	Counter      uint32             `json:"sign_count"`
	RPIDHash     []byte             `json:"rpid"`
	AAGUID       []byte             `json:"aaguid"`
	CredentialID []byte             `json:"credential_id"`
	PublicKey    PublicKeyData      `json:"public_key"`
}

// PublicKeyData The public key portion of a Relying Party-specific credential key pair, generated
// by an authenticator and returned to a Relying Party at registration time. We unpack this object
// using ugorji's codec library (github.com/ugorji/go/codec) which is why there are codec tags
// included. The tag field values correspond to the IANA COSE keys that give their respective
// values.
// See §6.4.1.1 https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples for examples of this
// COSE data.
type PublicKeyData struct {
	// Decode the results to int by default.
	_struct bool `codec:",int" json:"public_key"`
	// The type of key created. Should be RSA or EC2.
	KeyType int64 `codec:"1" json:"kty"`
	// A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
	Algorithm int64 `codec:"3" json:"alg"`
	// If the key type is EC2, the curve on which we derive the signature from.
	Curve int64 `codec:"-1,omitempty" json:"crv"`
	// A byte string 32 bytes in length that holds the x coordinate of the key.
	XCoord []byte `codec:"-2,omitempty" json:"x-coordinate"`
	// A byte string 32 bytes in length that holds the y coordinate of the key.
	YCoord []byte `codec:"-3,omitempty" json:"y-coordinate"`
	// We use this to hold the constructed key material. Should be either a rsa.PublicKey or ecdsa.PublicKey.
	KeyMaterial interface{} `codec:"-" json:"key_material"`
	// The raw bytes retreived to create this data structure.
	Raw []byte `codec:"-" json:"raw"`
}

// COSEAlgorithmIdentifier From §5.10.5. A number identifying a cryptographic algorithm. The algorithm
// identifiers SHOULD be values registered in the IANA COSE Algorithms registry
// [https://www.w3.org/TR/webauthn/#biblio-iana-cose-algs-reg], for instance, -7 for "ES256"
//  and -257 for "RS256".
type COSEAlgorithmIdentifier int

const (
	// AlgES256 Elliptic Curve with SHA-256
	AlgES256 COSEAlgorithmIdentifier = -7
	// AlgRS256 RSA with SHA-256
	AlgRS256 COSEAlgorithmIdentifier = -257
)

// The Key Type derived from the IANA COSE AuthData
type COSEKeyType int

const (
	// An Elliptic Curve Public Key
	EllipticKey COSEKeyType = 2
	// An RSA Public Key
	RSAKey COSEKeyType = 3
)

// AuthenticatorAttachment https://www.w3.org/TR/webauthn/#platform-attachment
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

// Authenticators may implement various transports for communicating with clients. This enumeration defines
// hints as to how clients might communicate with a particular authenticator in order to obtain an assertion
// for a specific credential. Note that these hints represent the WebAuthn Relying Party's best belief as to
// how an authenticator may be reached. A Relying Party may obtain a list of transports hints from some
// attestation statement formats or via some out-of-band mechanism; it is outside the scope of this
// specification to define that mechanism.
// See §5.10.4. Authenticator Transport https://www.w3.org/TR/webauthn/#transport)
type AuthenticatorTransport string

const (
	// USB The authenticator should transport information over USB
	USB AuthenticatorTransport = "usb"
	// NFC The authenticator should transport information over Near Field Communication Protocol
	NFC AuthenticatorTransport = "nfc"
	// BLE The authenticator should transport information over Bluetooth
	BLE AuthenticatorTransport = "ble"
	// Internal the client should use an internal source like a TPM or SE
	Internal AuthenticatorTransport = "internal"
)

type UserVerificationRequirement string

const (
	// VerificationRequired User verification is required to create/release a credential
	VerificationRequired UserVerificationRequirement = "required"
	// VerificationPreferred User verification is preferred to create/release a credential
	VerificationPreferred UserVerificationRequirement = "preferred"
	// VerificationDiscouraged The authenticator should not verify the user for the credential
	VerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// AuthenticatorFlags A byte of information returned during during ceremonies in the
// authenticatorData that contains bits that give us information about the
// whether the user was present and/or verified during authentication, and whether
// there is attestation or extension data present. Bit 0 is the least significant bit.
type AuthenticatorFlags byte

// The bits that do not have flags are reserved for future use.
const (
	// FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present
	FlagUserPresent = 0x001 // Referred to as UP
	// FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified
	// by the authenticator using a biometric or PIN
	FlagUserVerified = 0x003 // Referred to as UV
	// FlagAttestedCredentialData Bit 01000000 in the byte sequence. Indicates whether
	// the authenticator added attested credential data.
	FlagAttestedCredentialData = 0x040 // Referred to as AT
	// FlagHasExtension Bite 10000000 in the byte sequence. Indicates if the authenticator data has extensions.
	FlagHasExtension = 0x080 //  Referred to as ED
)

// UserPresent returns if the UP flag was set
func (flag AuthenticatorFlags) UserPresent() bool {
	return (flag & FlagUserPresent) == FlagUserPresent
}

// UserVerified returns if the UV flag was set
func (flag AuthenticatorFlags) UserVerified() bool {
	return (flag & FlagUserVerified) == FlagUserVerified
}

// HasAttestedCredentialData returns if the AT flag was set
func (flag AuthenticatorFlags) HasAttestedCredentialData() bool {
	return (flag & FlagAttestedCredentialData) == FlagAttestedCredentialData
}

// HasExtension returns if the ED flag was set
func (flag AuthenticatorFlags) HasExtension() bool {
	return (flag & FlagHasExtension) == FlagHasExtension
}

// Unmarshal will take the raw Authenticator Data and marshalls it into AuthenticatorData for further validation.
// The authenticator data has a compact but extensible encoding. This is desired since authenticators can be
// devices with limited capabilities and low power requirements, with much simpler software stacks than the client platform.
// The authenticator data structure is a byte array of 37 bytes or more, and is laid out in this table:
// https://www.w3.org/TR/webauthn/#table-authData
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

// If Attestation Data is present, unmarshall that into the appropriate public key structure
func (a *AuthenticatorData) unmarshalAttestedData(rawAuthData []byte) error {
	a.AAGUID = rawAuthData[37:53]

	idLength := binary.BigEndian.Uint16(rawAuthData[53:55])

	a.CredentialID = rawAuthData[55 : 55+idLength]

	pubKeyBytes := rawAuthData[55+idLength:]

	err := a.PublicKey.parseNewKey(pubKeyBytes)

	return err
}

// Figure out what kind of COSE material was provided and create the data for the new key
func (newKey *PublicKeyData) parseNewKey(keyBytes []byte) error {
	var cborHandler codec.Handle = new(codec.CborHandle)
	codec.NewDecoder(bytes.NewReader(keyBytes), cborHandler).Decode(&newKey)
	newKey.Raw = keyBytes
	switch COSEKeyType(newKey.KeyType) {
	case EllipticKey:
		return newKey.parseEllipticCurve()
	case RSAKey:
		return newKey.parseRSA()
	default:
		return ErrUnsupportedKey
	}
	return nil
}

// Parse the Elliptic Curve key material into a the KeyMaterial field
func (newKey *PublicKeyData) parseEllipticCurve() error {
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

// Parse the RSA key material into a the KeyMaterial field
func (newKey *PublicKeyData) parseRSA() error {
	return ErrNotImplemented
}

// Verify on AuthenticatorData handles Steps 9 through 12 for Registration
// and Steps 11 through 14 for Assertion.
func (a *AuthenticatorData) Verify(rpIdHash []byte, userVerificationRequired bool) error {

	// Registration Step 9 & Assertion Step 11
	// Verify that the RP ID hash in authData is indeed the SHA-256
	// hash of the RP ID expected by the RP.
	if !bytes.Equal(a.RPIDHash[:], rpIdHash) {
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
