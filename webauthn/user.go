package webauthn

type User interface {
	// User ID according to the Relying Party
	WebAuthnID() []byte
	// User Name according to the Relying Party
	WebAuthnName() string
	// Display Name of the user
	WebAuthnDisplayName() string
	// User's icon url
	WebAuthnIcon() string
	// Credentials owned by the user
	WebAuthnCredentials() []Credential
}

type defaultUser struct {
	id []byte
}

var _ User = (*defaultUser)(nil)

func (user *defaultUser) WebAuthnID() []byte {
	return user.id
}

func (user *defaultUser) WebAuthnName() string {
	return "newUser"
}

func (user *defaultUser) WebAuthnDisplayName() string {
	return "New User"
}

func (user *defaultUser) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}

func (user *defaultUser) WebAuthnCredentials() []Credential {
	return []Credential{}
}
