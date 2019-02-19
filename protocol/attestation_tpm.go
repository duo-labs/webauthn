package protocol

var tpmAttestationKey = "tpm"

func init() {
	RegisterAttestationFormat(tpmAttestationKey, verifyTPMFormat)
}

func verifyTPMFormat(att AttestationObject, clientDataHash []byte) (string, []interface{}, error) {
	return tpmAttestationKey, nil, ErrNotImplemented
}
