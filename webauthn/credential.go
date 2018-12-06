package webauthn

type Credential interface {
	ID() []byte
	PublicKey() []byte
	Authenticator() Authenticator
}

type defaultCredential struct {
	id            []byte
	publicKey     []byte
	authenticator Authenticator
}

var _ Credential = (*defaultCredential)(nil)

func (a *defaultCredential) ID() []byte {
	return a.id
}

func (a *defaultCredential) PublicKey() []byte {
	return a.publicKey
}

func (a *defaultCredential) Authenticator() Authenticator {
	return a.authenticator
}
