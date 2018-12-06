package protocol

type AuthenticatorData struct {
	Flags            AuthenticatorFlags
	Counter          uint32
	RawAssertionData []byte
	RPIDHash         []byte
	Signature        []byte
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
