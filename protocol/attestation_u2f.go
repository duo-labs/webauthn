package protocol

func init() {
	RegisterAttestationFormat("fido-u2f", verifyU2FFormat)
}

func verifyU2FFormat(att AttestationObject, clientDataHash []byte) error {
	return nil
}
