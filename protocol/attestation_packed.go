package protocol

func init() {
	RegisterAttestationFormat("packed", verifyPackedFormat)
}

func verifyPackedFormat(att AttestationObject, clientDataHash []byte) error {

	return nil
}
