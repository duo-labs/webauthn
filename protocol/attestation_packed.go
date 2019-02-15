package protocol

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

var packedAttestationKey = "packed"

func init() {
	RegisterAttestationFormat(packedAttestationKey, verifyPackedFormat)
}

// From §8.2. https://www.w3.org/TR/webauthn/#packed-attestation
// The packed attestation statement looks like:
//		packedStmtFormat = {
//		 	alg: COSEAlgorithmIdentifier,
//		 	sig: bytes,
//		 	x5c: [ attestnCert: bytes, * (caCert: bytes) ]
//		 } OR
//		 {
//		 	alg: COSEAlgorithmIdentifier, (-260 for ED256 / -261 for ED512)
//		 	sig: bytes,
//		 	ecdaaKeyId: bytes
//		 } OR
//		 {
//		 	alg: COSEAlgorithmIdentifier
//		 	sig: bytes,
//		 }
func verifyPackedFormat(att AttestationObject, clientDataHash []byte) (string, []interface{}, error) {
	// Step 1. Verify that attStmt is valid CBOR conforming to the syntax defined
	// above and perform CBOR decoding on it to extract the contained fields.

	// Get the alg value - A COSEAlgorithmIdentifier containing the identifier of the algorithm
	// used to generate the attestation signature.
	alg, present := att.AttStatement["alg"].(int64)
	if !present {
		return packedAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving alg value")
	}

	// Get the sig value - A byte string containing the attestation signature.
	sig, present := att.AttStatement["sig"].([]byte)
	if !present {
		return packedAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving sig value")
	}

	// Step 2. If x5c is present, this indicates that the attestation type is not ECDAA.
	x5c, x509present := att.AttStatement["x5c"].([]interface{})
	if x509present {
		// Handle Basic Attestation steps for the x509 Certificate
		return handleBasicAttestation(sig, clientDataHash, att.RawAuthData, att.AuthData.AttData.AAGUID, alg, x5c)
	}

	// Step 3. If ecdaaKeyId is present, then the attestation type is ECDAA.
	// Also make sure the we did not have an x509 then
	ecdaaKeyID, ecdaaKeyPresent := att.AttStatement["ecdaaKeyId"].([]byte)
	if ecdaaKeyPresent {
		// Handle ECDAA Attestation steps for the x509 Certificate
		return handleECDAAAttesation(sig, clientDataHash, ecdaaKeyID)
	}

	// Step 4. If neither x5c nor ecdaaKeyId is present, self attestation is in use.
	return handleSelfAttestation(alg, att.AuthData.AttData.CredentialPublicKey, att.RawAuthData, clientDataHash, sig)
}

// Handle the attestation steps laid out in
func handleBasicAttestation(signature, clientDataHash, authData, aaguid []byte, alg int64, x5c []interface{}) (string, []interface{}, error) {
	// Step 2.1. Verify that sig is a valid signature over the concatenation of authenticatorData
	// and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
	attestationType := "Packed (Basic)"

	attCertBytes, valid := x5c[0].([]byte)
	if !valid {
		return attestationType, x5c, ErrAttestation.WithDetails("Error getting certificate from x5c cert chain")
	}

	signatureData := append(authData, clientDataHash...)

	attCert, err := x509.ParseCertificate(attCertBytes)
	if err != nil {
		return attestationType, x5c, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing certificate from ASN.1 data: %+v", err))
	}

	// YUBIKEYS on Chrome give an incorrect packed attestation, so if we see a yubico cert attempt to fix it.
	// yubikeys on firefox fall back to u2f format
	if strings.Contains(attCert.Subject.CommonName, "Yubico") {
		err = attCert.CheckSignature(x509.ECDSAWithSHA256, signatureData, signature)
	} else {
		err = attCert.CheckSignature(x509.SignatureAlgorithm(alg), signatureData, signature)
	}

	if err != nil {
		return attestationType, x5c, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Signature validation error: %+v\n", err))
	}

	// Step 2.2 Verify that attestnCert meets the requirements in §8.2.1 Packed attestation statement certificate requirements.
	// §8.2.1 can be found here https://www.w3.org/TR/webauthn/#packed-attestation-cert-requirements

	// Step 2.2.1 (from §8.2.1) Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
	if attCert.Version != 3 {
		return attestationType, x5c, ErrAttestationCertificate.WithDetails("Attestation Certificate is incorrect version")
	}

	// Step 2.2.2 (from §8.2.1) Subject field MUST be set to:

	// 	Subject-C
	// 	ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)

	//  TODO: Find a good, useable, country code library. For now, check stringy-ness
	subjectString := strings.Join(attCert.Subject.Country, "")
	if subjectString == "" {
		return attestationType, x5c, ErrAttestationCertificate.WithDetails("Attestation Certificate Country Code is invalid")
	}

	// 	Subject-O
	// 	Legal name of the Authenticator vendor (UTF8String)
	subjectString = strings.Join(attCert.Subject.Organization, "")
	if subjectString == "" {
		return attestationType, x5c, ErrAttestationCertificate.WithDetails("Attestation Certificate Organization is invalid")
	}

	// 	Subject-OU
	// 	Literal string “Authenticator Attestation” (UTF8String)
	subjectString = strings.Join(attCert.Subject.OrganizationalUnit, " ")
	if subjectString != "Authenticator Attestation" {
		// TODO: Implement a return error when I'm more certain this is general practice
	}

	// 	Subject-CN
	//  A UTF8String of the vendor’s choosing
	subjectString = attCert.Subject.CommonName
	if subjectString == "" {
		return attestationType, x5c, ErrAttestationCertificate.WithDetails("Attestation Certificate Common Name not set")
	}
	// TODO: And then what

	// Step 2.2.3 (from §8.2.1) If the related attestation root certificate is used for multiple authenticator models,
	// the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the
	// AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.

	idFido := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	var foundAAGUID []byte
	for _, extension := range attCert.Extensions {
		if extension.Id.Equal(idFido) {
			if extension.Critical {
				return attestationType, x5c, ErrInvalidAttestation.WithDetails("Attestation certificate FIDO extension marked as critical")
			}
			foundAAGUID = extension.Value
		}
	}

	// We validate the AAGUID as mentioned above
	// This is not well defined in§8.2.1 but mentioned in step 2.3: we validate the AAGUID if it is present within the certificate
	// and make sure it matches the auth data AAGUID
	// Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING. Thus, the
	// AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
	if len(foundAAGUID) > 0 {
		unMarshalledAAGUID := []byte{}
		asn1.Unmarshal(foundAAGUID, &unMarshalledAAGUID)
		if !bytes.Equal(aaguid, unMarshalledAAGUID) {
			return attestationType, x5c, ErrInvalidAttestation.WithDetails("Certificate AAGUID does not match Auth Data certificate")
		}
	}

	// Step 2.2.4 The Basic Constraints extension MUST have the CA component set to false.
	if attCert.IsCA {
		return attestationType, x5c, ErrInvalidAttestation.WithDetails("Attestation certificate's Basic Constraints marked as CA")
	}

	// Note for 2.2.5 An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL
	// Distribution Point extension [RFC5280](https://www.w3.org/TR/webauthn/#biblio-rfc5280) are
	// both OPTIONAL as the status of many attestation certificates is available through authenticator
	// metadata services. See, for example, the FIDO Metadata Service
	// [FIDOMetadataService] (https://www.w3.org/TR/webauthn/#biblio-fidometadataservice)

	// Step 2.4 If successful, return attestation type Basic and attestation trust path x5c.
	// We don't handle trust paths yet but we're done
	return attestationType, x5c, nil
}

func handleECDAAAttesation(signature, clientDataHash, ecdaaKeyID []byte) (string, []interface{}, error) {
	return "Packed (ECDAA)", nil, ErrNotSpecImplemented
}

func handleSelfAttestation(alg int64, pubKey []byte, clientDataHash, authData, signature []byte) (string, []interface{}, error) {
	attestationType := "Packed (Self)"
	// Step 4.1 Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.

	// Step 4.2 Verify that sig is a valid signature over the concatenation of authenticatorData and
	// clientDataHash using the credential public key with alg.

	verificationData := append(authData, clientDataHash...)

	key, err := parsePublicKey(pubKey)
	valid := false
	switch key.(type) {
	case OKPPublicKeyData:
		o := key.(OKPPublicKeyData)
		if alg != o.PublicKeyData.Algorithm {
			return attestationType, nil, ErrInvalidAttestation.WithDetails("Public key algorithm does not equal att statement algorithm").WithInfo("Packed (Self)")
		}
		valid, err = o.verify(verificationData, signature)
		if true != valid {
			return attestationType, nil, ErrAttestation.WithDetails("Failed to validate signature with OKP key for self attestation").WithInfo(err.Error())
		}
	case EC2PublicKeyData:
		e := key.(EC2PublicKeyData)
		if alg != e.PublicKeyData.Algorithm {
			return attestationType, nil, ErrInvalidAttestation.WithDetails("Public key algorithm does not equal att statement algorithm").WithInfo("Packed (Self)")
		}
		valid, err = e.verify(verificationData, signature)
		if true != valid {
			return attestationType, nil, ErrAttestation.WithDetails("Failed to validate signature with EC2 key for self attestation").WithInfo(err.Error())
		}
	case RSAPublicKeyData:
		r := key.(RSAPublicKeyData)
		if alg != r.PublicKeyData.Algorithm {
			return attestationType, nil, ErrInvalidAttestation.WithDetails("Public key algorithm does not equal att statement algorithm").WithInfo("Packed (Self)")
		}
		valid, err = r.verify(verificationData, signature)
		if true != valid {
			return attestationType, nil, ErrAttestation.WithDetails("Failed to validate signature with RSA key for self attestation").WithInfo(err.Error())
		}
	default:
		return "", nil, ErrUnsupportedKey
	}

	return attestationType, nil, nil
}
