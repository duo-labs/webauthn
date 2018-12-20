package protocol

var androidAttestationKey = "android-key"

func init() {
	RegisterAttestationFormat(androidAttestationKey, verifyPackedFormat)
}

func verifyAndroidKeystoreFormat(att AttestationObject, clientDataHash []byte) (string, []interface{}, error) {
	return androidAttestationKey, nil, ErrNotImplemented
}
