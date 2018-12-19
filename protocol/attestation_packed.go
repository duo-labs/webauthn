package protocol

import (
	"crypto/x509"
	"encoding/asn1"
)

func init() {
	RegisterAttestationFormat("packed", verifyPackedFormat)
}

// verifyPackedFormat - Verifies the Packed Attestation Format
//
//packedStmtFormat = {
// 	alg: COSEAlgorithmIdentifier,
// 	sig: bytes,
// 	x5c: [ attestnCert: bytes, * (caCert: bytes) ]
// } OR
// {
// 	alg: COSEAlgorithmIdentifier, (-260 for ED256 / -261 for ED512)
// 	sig: bytes,
// 	ecdaaKeyId: bytes
// } OR
// {
// 	alg: COSEAlgorithmIdentifier
// 	sig: bytes,
// }
func verifyPackedFormat(att AttestationObject, clientDataHash []byte) error {
	// Step 1. Verify that attStmt is valid CBOR conforming to the syntax defined
	// above and perform CBOR decoding on it to extract the contained fields.

	// Get the alg value - A COSEAlgorithmIdentifier containing the identifier of the algorithm
	// used to generate the attestation signature.
	alg, present := att.AttStatement["alg"].(int64)
	if !present {
		return ErrAttestationFormat.WithDetails("Error retreiving alg value").WithInfo("Packed Attestation")
	}

	// Get the sig value - A byte string containing the attestation signature.
	sig, present := att.AttStatement["sig"].([]byte)
	if !present {
		return ErrAttestationFormat.WithDetails("Error retreiving sig value").WithInfo("Packed Attestation")
	}

	// Step 2. If x5c is present, this indicates that the attestation type is not ECDAA.
	x5c, x509present := att.AttStatement["x5c"].([]interface{})
	if x509present {
		// Handle Basic Attestation steps for the x509 Certificate
		return handleBasicAttestation(sig, att.RawAuthData, clientDataHash, alg, x5c)
	}

	// Step 3. If ecdaaKeyId is present, then the attestation type is ECDAA.
	// Also make sure the we did not have an x509 then
	ecdaaKeyId, ecdaaKeyPresent := att.AttStatement["ecdaaKeyId"].([]byte)
	if !x509present && ecdaaKeyPresent {
		// Handle ECDAA Attestation steps for the x509 Certificate
		return handleECDAAAttesation(sig, clientDataHash, ecdaaKeyId)
	}

	if !x509present && !ecdaaKeyPresent {
		return handleSelfAttestation(alg, att.AuthData.PublicKey, sig)
	}

	return nil
}

var idFidoGenCAAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

func handleBasicAttestation(signature, clientDataHash, authData []byte, alg int64, x5c []interface{}) error {
	// Step 2.1. Verify that sig is a valid signature over the concatenation of authenticatorData
	// and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
	attCertBytes, valid := x5c[0].([]byte)
	if !valid {
		return ErrAttestation.WithDetails("Error getting certificate from x5c cert chain").WithInfo("Packed Attestation")
	}

	verificationData := append(authData, clientDataHash...)

	attCert, err := x509.ParseCertificate(attCertBytes)
	if err != nil {
		return ErrAttestationFormat.WithDetails("Error parsing certificate from ASN.1 data").WithInfo("Packed Attestation")
	}

	certAlgorithm := COSEAlgorithmIdentifier(alg)
	if certAlgorithm != AlgES256 || certAlgorithm != AlgRS256 {
		return ErrAttestationFormat.WithDetails("alg format is invalid COSE format").WithInfo("Packed Attestation")
	}

	attCert.CheckSignature()
}

func handleECDAAAttesation(signature, clientDataHash, ecdaaKeyId []byte) error {
	return ErrNotSpecImplemented
}

func handleSelfAttestation(alg int64, pubKey PublicKeyData, signature []byte) error {
	return nil
}
