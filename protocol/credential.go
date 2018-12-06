package protocol

type Credential struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type ParsedCredential struct {
	ID   string `codec:"id"`
	Type string `codec:"type"`
}

type PublicKeyCredential struct {
	Credential
	RawID      []byte                                `json:"rawId"`
	Extensions AuthenticationExtensionsClientOutputs `json:"results,omitempty"`
}

type ParsedPublicKeyCredential struct {
	ParsedCredential
	RawID []byte              `json:"rawId"`
	Raw   PublicKeyCredential `json:"raw"`
}
