package protocol

func init() {
	RegisterAttestationFormat("android-key", verifyPackedFormat)
}

func verifyAndroidKeystoreFormat(att AttestationObject, clientDataHash []byte) error {

	return nil
}
