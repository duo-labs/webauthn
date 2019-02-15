package protocol

import (
	"crypto/x509"
	"fmt"
)

var androidAttestationKey = "android-key"

func init() {
	RegisterAttestationFormat(androidAttestationKey, verifyPackedFormat)
}

// From §8.4. https://www.w3.org/TR/webauthn/#android-key-attestation
// The android-key attestation statement looks like:
// $$attStmtType //= (
// 	fmt: "android-key",
// 	attStmt: androidStmtFormat
// )
// androidStmtFormat = {
// 		alg: COSEAlgorithmIdentifier,
// 		sig: bytes,
// 		x5c: [ credCert: bytes, * (caCert: bytes) ]
//   }
func verifyAndroidKeystoreFormat(att AttestationObject, clientDataHash []byte) (string, []interface{}, error) {
	// Given the verification procedure inputs attStmt, authenticatorData and clientDataHash, the verification procedure is as follows:
	// §8.4.1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract
	// the contained fields.

	// Get the alg value - A COSEAlgorithmIdentifier containing the identifier of the algorithm
	// used to generate the attestation signature.
	alg, present := att.AttStatement["alg"].(int64)
	if !present {
		return androidAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving alg value")
	}

	// Get the sig value - A byte string containing the attestation signature.
	sig, present := att.AttStatement["sig"].([]byte)
	if !present {
		return androidAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving sig value")
	}

	// Step 2. If x5c is present, this indicates that the attestation type is not ECDAA.
	x5c, x509present := att.AttStatement["x5c"].([]interface{})
	if x509present {
		// Handle Basic Attestation steps for the x509 Certificate
		return handleBasicAttestation(sig, clientDataHash, att.RawAuthData, att.AuthData.AttData.AAGUID, alg, x5c)
	}

	// §8.4.2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
	// using the public key in the first certificate in x5c with the algorithm specified in alg.
	attCertBytes, valid := x5c[0].([]byte)
	if !valid {
		return androidAttestationKey, x5c, ErrAttestation.WithDetails("Error getting certificate from x5c cert chain")
	}

	signatureData := append(att.RawAuthData, clientDataHash...)

	attCert, err := x509.ParseCertificate(attCertBytes)
	if err != nil {
		return androidAttestationKey, x5c, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing certificate from ASN.1 data: %+v", err))
	}

	err = attCert.CheckSignature(x509.SignatureAlgorithm(alg), signatureData, sig)

	if err != nil {
		return androidAttestationKey, x5c, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Signature validation error: %+v\n", err))
	}

	// §8.4.3. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
	// attCert.Extensions

	// As noted in §8.4.1 (https://w3c.github.io/webauthn/#key-attstn-cert-requirements) the Android Key Attestation attestation certificate's
	// android key attestation certificate extension data is identified by the OID "1.3.6.1.4.1.11129.2.1.17".
	// idExtData := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

	// This is about as far as I can get right now without testing. Need to test more with a Android Key Attestation Cert
	// Will update once I find a cert
	return androidAttestationKey, nil, ErrNotImplemented
}
