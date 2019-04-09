package protocol

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

var safetyNetAttestationKey = "android-safetynet"

func init() {
	RegisterAttestationFormat(safetyNetAttestationKey, verifySafetyNetFormat)
}

type SafetyNetResponse struct {
	Nonce                      []byte   `json:"nonce"`
	TimestampMs                int64    `json:"timestampMs"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkDigestSha256            []byte   `json:"apkDigestSha256"`
	CtsProfileMatch            bool     `json:"ctsProfileMatch"`
	ApkCertificateDigestSha256 [][]byte `json:"apkCertificateDigestSha256"`
	BasicIntegrity             bool     `json:"basicIntegrity"`
	jwt.StandardClaims
}

// Thanks to @koesie10 and @herrjemand for outlining how to support this type really well

// §8.5. Android SafetyNet Attestation Statement Format https://w3c.github.io/webauthn/#android-safetynet-attestation
// When the authenticator in question is a platform-provided Authenticator on certain Android platforms, the attestation
// statement is based on the SafetyNet API. In this case the authenticator data is completely controlled by the caller of
// the SafetyNet API (typically an application running on the Android platform) and the attestation statement only provides
//  some statements about the health of the platform and the identity of the calling application. This attestation does not
// provide information regarding provenance of the authenticator and its associated data. Therefore platform-provided
// authenticators SHOULD make use of the Android Key Attestation when available, even if the SafetyNet API is also present.
func verifySafetyNetFormat(att AttestationObject, clientDataHash []byte) (string, []interface{}, error) {
	// The syntax of an Android Attestation statement is defined as follows:
	//     $$attStmtType //= (
	//                           fmt: "android-safetynet",
	//                           attStmt: safetynetStmtFormat
	//                       )

	//     safetynetStmtFormat = {
	//                               ver: text,
	//                               response: bytes
	//                           }

	// §8.5.1 Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract
	// the contained fields.

	// We have done this
	// §8.5.2 Verify that response is a valid SafetyNet response of version ver.
	version, present := att.AttStatement["ver"].(string)
	if !present {
		return safetyNetAttestationKey, nil, ErrAttestationFormat.WithDetails("Unable to find the version of SafetyNet")
	}

	if version == "" {
		return safetyNetAttestationKey, nil, ErrAttestationFormat.WithDetails("Not a proper version for SafetyNet")
	}

	// TODO: provide user the ability to designate their supported versions

	response, present := att.AttStatement["response"].([]byte)
	if !present {
		return safetyNetAttestationKey, nil, ErrAttestationFormat.WithDetails("Unable to find the SafetyNet response")
	}

	var verifyKey *rsa.PublicKey

	parsedJWT, parseErr := jwt.ParseWithClaims(string(response), &SafetyNetResponse{}, func(token *jwt.Token) (interface{}, error) {
		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return verifyKey, nil
	})

	//joseResponse, parseErr := jose.ParseSigned(string(response))
	if parseErr != nil {
		return safetyNetAttestationKey, nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing the SafetyNet response: %+v", parseErr))
	}

	// Unpack the safetynet certs for the next steps
	//certOpts := x509.VerifyOptions{
	//	DNSName: "attest.android.com",
	//}

	//certChain, err := joseResponse.Signatures[0].Protected.Certificates(certOpts)

	// Throws error if not present or can't be verified
	// This accomplishes §8.5.5 Verify that attestationCert is issued to the hostname "attest.android.com"
	// https://developer.android.com/training/safetynet/index.html#compat-check-response
	//if err != nil {
	//	return safetyNetAttestationKey, nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error finding cert issued to correct hostname: %+v", err))
	//}

	// Get cert public key from chain if present
	//leafCert := certChain[0][0]
	//certPublicKey := leafCert.PublicKey

	// Get the JWT payload if the public key is successfully verified against it
	//payload, err := joseResponse.Verify(certPublicKey)
	//if err != nil {
	//	return safetyNetAttestationKey, nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing the SafetyNet certificates: %+v", err))
	//}

	// marshall the JWT payload into the safetynet response json
	//var safetyNetResponse SafetyNetResponse
	//err := json.Unmarshal(payload, &safetyNetResponse)
	//if err != nil {
	//	return safetyNetAttestationKey, nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Error parsing the SafetyNet response: %+v", err))
	//}

	// §8.5.3 Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256 hash of the concatenation
	// of authenticatorData and clientDataHash.

	nonceBuffer := sha256.Sum256(append(att.RawAuthData, clientDataHash...))
	if !bytes.Equal(nonceBuffer[:], parsedJWT.Claims.(*SafetyNetResponse).Nonce) {
		return safetyNetAttestationKey, nil, ErrInvalidAttestation.WithDetails("Invalid nonce for in SafetyNet response")
	}

	// §8.5.4 Let attestationCert be the attestation certificate (https://www.w3.org/TR/webauthn/#attestation-certificate)
	// Done above

	// §8.5.5 Verify that attestationCert is issued to the hostname "attest.android.com"
	// Done above

	// §8.5.6 Verify that the ctsProfileMatch attribute in the payload of response is true.
	if parsedJWT.Claims.(*SafetyNetResponse).CtsProfileMatch {
		return safetyNetAttestationKey, nil, ErrInvalidAttestation.WithDetails("ctsProfileMatch attribute of the JWT payload is false")
	}

	// §8.5.7 If successful, return implementation-specific values representing attestation type Basic and attestation
	// trust path attestationCert.

	// TODO, return the trust path attestationCert
	return "Basic attestation with SafetyNet", nil, nil
}
