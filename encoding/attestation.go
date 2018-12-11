package encoding

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

func B64Decode(decodeString string) ([]byte, error) {
	encoder := base64.RawURLEncoding
	return encoder.DecodeString(decodeString)
}

func URLEncode(origin string) (*url.URL, error) {
	return url.Parse(origin)
}

// HashClientData - SHA-256 Hash of the bytes provided. Used for several steps in
// Registration and assertion.
// In Registration (https://www.w3.org/TR/webauthn/#registering-a-new-credential)
// Steps 7 & 9
// In Assertion (https://www.w3.org/TR/webauthn/#verifying-assertion)
// Steps 11 & 15
func SHA256Hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}
