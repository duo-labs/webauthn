package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
)

func init() {
	RegisterAttestationFormat("fido-u2f", verifyU2FFormat)
}

// verifyU2FFormat - Follows verification steps set out by https://www.w3.org/TR/webauthn/#fido-u2f-attestation
func verifyU2FFormat(att AttestationObject, clientDataHash []byte) error {
	// Signing procedure step - If the credential public key of the given credential is not of
	// algorithm -7 ("ES256"), stop and return an error.
	if att.AuthData.PublicKey.Algorithm != -7 {
		return ErrUnsupportedAlgorithm.WithDetails("Non-ES256 Public Key algorithm used").WithInfo("U2F Attestation")
	}

	// U2F Step 1. Verify that attStmt is valid CBOR conforming to the syntax defined above
	// and perform CBOR decoding on it to extract the contained fields.

	// The Format/syntax is
	// u2fStmtFormat = {
	// 	x5c: [ attestnCert: bytes ],
	// 	sig: bytes
	// }

	// Check for "x5c" which is a single element array containing the attestation certificate in X.509 format.
	x5c, present := att.AttStatement["x5c"].([]interface{})
	if !present {
		return ErrAttestationFormat.WithDetails("Missing properly formatted x5c data").WithInfo("U2F Attestation")
	}

	// Check for "sig" which is The attestation signature. The signature was calculated over the (raw) U2F
	// registration response message https://www.w3.org/TR/webauthn/#biblio-fido-u2f-message-formats]
	// received by the client from the authenticator.
	signature, present := att.AttStatement["sig"].([]byte)
	if !present {
		return ErrAttestationFormat.WithDetails("Missing sig data").WithInfo("U2F Attestation")
	}

	// U2F Step 2. (1) Check that x5c has exactly one element and let attCert be that element. (2) Let certificate public
	// key be the public key conveyed by attCert. (3) If certificate public key is not an Elliptic Curve (EC) public
	// key over the P-256 curve, terminate this algorithm and return an appropriate error.

	// Step 2.1
	if len(x5c) > 1 {
		return ErrAttestationFormat.WithDetails("Received more than one element in x5c values").WithInfo("U2F Attestation")
	}

	// Note: Packed Attestation, FIDO U2F Attestation, and Assertion Signatures support ASN.1,but it is recommended
	// that any new attestation formats defined not use ASN.1 encodings, but instead represent signatures as equivalent
	// fixed-length byte arrays without internal structure, using the same representations as used by COSE signatures
	// as defined in RFC8152 (https://www.w3.org/TR/webauthn/#biblio-rfc8152)
	// and RFC8230 (https://www.w3.org/TR/webauthn/#biblio-rfc8230).

	// Step 2.2
	asn1Bytes, decoded := x5c[0].([]byte)
	if !decoded {
		return ErrAttestationFormat.WithDetails("Error decoding ASN.1 data from x5c").WithInfo("U2F Attestation")
	}

	attCert, err := x509.ParseCertificate(asn1Bytes)
	if err != nil {
		return ErrAttestationFormat.WithDetails("Error parsing certificate from ASN.1 data into certificate").WithInfo("U2F Attestation")
	}

	// Step 2.3
	if attCert.PublicKeyAlgorithm != x509.ECDSA && attCert.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P256() {
		return ErrAttestationFormat.WithDetails("Attestation certificate is in invalid format").WithInfo("U2F Attestation")
	}

	// Step 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey
	// from authenticatorData.attestedCredentialData.

	rpIdHash := att.AuthData.RPIDHash

	credentialID := att.AuthData.CredentialID

	credentialPublicKey := att.AuthData.PublicKey

	// Step 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of RFC8152 [https://www.w3.org/TR/webauthn/#biblio-rfc8152])
	// to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key
	// Representation Formats of FIDO-Registry [https://www.w3.org/TR/webauthn/#biblio-fido-registry]).

	// Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and confirm
	// its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and
	// return an appropriate error.

	// Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and confirm
	// its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and
	// return an appropriate error.

	if len(credentialPublicKey.XCoord) > 32 || len(credentialPublicKey.YCoord) > 32 {
		return ErrAttestation.WithDetails("X or Y Coordinate for key is invalid length").WithInfo("U2F Attestation")
	}

	// Let publicKeyU2F be the concatenation 0x04 || x || y.

	publicKeyU2F := bytes.NewBuffer([]byte{0x04})
	publicKeyU2F.Write(credentialPublicKey.XCoord)
	publicKeyU2F.Write(credentialPublicKey.YCoord)

	// Step 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
	// (see Section 4.3 of FIDO-U2F-Message-Formats [https://www.w3.org/TR/webauthn/#biblio-fido-u2f-message-formats]).

	verificationData := bytes.NewBuffer([]byte{0x00})
	verificationData.Write(rpIdHash)
	verificationData.Write(clientDataHash)
	verificationData.Write(credentialID)
	verificationData.Write(publicKeyU2F.Bytes())

	// Step 6. Verify the sig using verificationData and certificate public key per SEC1[https://www.w3.org/TR/webauthn/#biblio-sec1].
	sigErr := attCert.CheckSignature(x509.ECDSAWithSHA256, verificationData.Bytes(), signature)
	if sigErr != nil {
		return sigErr
	}

	// TODO: Step 7. If successful, return attestation type Basic with the attestation trust path set to x5c.
	return nil
}
