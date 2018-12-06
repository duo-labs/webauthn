package webauthn

type User interface {
	// User ID according to the Relying Party
	WebAuthnID() []byte
	// User Name according to the Relaying party
	WebAuthnName() string
	// Display Name of the user
	WebAuthnDisplayName() string
	// User's icon url
	WebAuthnIcon() string
}

type defaultUser struct {
	id []byte
}

var _ User = (*defaultUser)(nil)

func (user *defaultUser) WebAuthnID() []byte {
	return user.id
}

func (user *defaultUser) WebAuthnName() string {
	return "user@default.com"
}

func (user *defaultUser) WebAuthnDisplayName() string {
	return "Jane Doe"
}

func (user *defaultUser) WebAuthnIcon() string {
	return "https://pics.com/avatar.png"
}
