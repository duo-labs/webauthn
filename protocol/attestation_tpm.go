package protocol

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

var tpmAttestationKey = "tpm"

func init() {
	RegisterAttestationFormat(tpmAttestationKey, verifyTPMFormat)
}

func verifyTPMFormat(att AttestationObject, clientDataHash []byte) (string, []interface{}, error) {
	// Given the verification procedure inputs attStmt, authenticatorData
	// and clientDataHash, the verification procedure is as follows

	// Verify that attStmt is valid CBOR conforming to the syntax defined
	// above and perform CBOR decoding on it to extract the contained fields

	ver, present := att.AttStatement["ver"].(string)
	if !present {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving ver value")
	}

	if ver != "2.0" {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("WebAuthn only supports TPM 2.0 currently")
	}

	alg, present := att.AttStatement["alg"].(int64)
	if !present {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving alg value")
	}

	coseAlg := COSEAlgorithmIdentifier(alg)

	x5c, x509present := att.AttStatement["x5c"].([]interface{})
	if !x509present {
		// Handle Basic Attestation steps for the x509 Certificate
		return tpmAttestationKey, nil, ErrNotImplemented
	}

	_, ecdaaKeyPresent := att.AttStatement["ecdaaKeyId"].([]byte)
	if ecdaaKeyPresent {
		return tpmAttestationKey, nil, ErrNotImplemented
	}

	sigBytes, present := att.AttStatement["sig"].([]byte)
	if !present {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving sig value")
	}

	certInfoBytes, present := att.AttStatement["certInfo"].([]byte)
	if !present {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving certInfo value")
	}

	pubAreaBytes, present := att.AttStatement["pubArea"].([]byte)
	if !present {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Error retreiving pubArea value")
	}

	// Verify that the public key specified by the parameters and unique fields of pubArea
	// is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
	pubArea, err := tpm2.DecodePublic(pubAreaBytes)
	if err != nil {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Unable to decode TPMT_PUBLIC in attestation statement")
	}

	key, err := ParsePublicKey(att.AuthData.AttData.CredentialPublicKey)
	switch key.(type) {
	case EC2PublicKeyData:
		e := key.(EC2PublicKeyData)
		if pubArea.ECCParameters.CurveID != tpm2.EllipticCurve(e.Curve) ||
			pubArea.ECCParameters.Point.X != new(big.Int).SetBytes(e.XCoord) ||
			pubArea.ECCParameters.Point.Y != new(big.Int).SetBytes(e.YCoord) {
			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Mismatch between ECCParameters in pubArea and credentialPublicKey")
		}
	case RSAPublicKeyData:
		r := key.(RSAPublicKeyData)
		mod := new(big.Int).SetBytes(r.Modulus)
		exp := uint32(r.Exponent[0]) + uint32(r.Exponent[1])<<8 + uint32(r.Exponent[2])<<16
		if 0 != pubArea.RSAParameters.Modulus.Cmp(mod) ||
			pubArea.RSAParameters.Exponent != exp {
			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Mismatch between RSAParameters in pubArea and credentialPublicKey")
		}
	default:
		return "", nil, ErrUnsupportedKey
	}

	// Concatenate authenticatorData and clientDataHash to form attToBeSigned
	attToBeSigned := append(att.RawAuthData, clientDataHash...)

	// Validate that certInfo is valid:
	certInfo, err := tpm2.DecodeAttestationData(certInfoBytes)
	// 1/4 Verify that magic is set to TPM_GENERATED_VALUE.
	if certInfo.Magic != 0xff544347 {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Magic is not set to TPM_GENERATED_VALUE")
	}
	// 2/4 Verify that type is set to TPM_ST_ATTEST_CERTIFY.
	if certInfo.Type != tpm2.TagAttestCertify {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Type is not set to TPM_ST_ATTEST_CERTIFY")
	}
	// 3/4 Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
	f := HasherFromCOSEAlg(coseAlg)
	h := f()
	h.Write(attToBeSigned)
	if 0 != bytes.Compare(certInfo.ExtraData, h.Sum(nil)) {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("ExtraData is not set to hash of attToBeSigned")
	}
	// 4/4 Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in
	// [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea,
	// as computed using the algorithm in the nameAlg field of pubArea
	// using the procedure specified in [TPMv2-Part1] section 16.
	f, err = certInfo.AttestedCertifyInfo.Name.Digest.Alg.HashConstructor()
	h = f()
	h.Write(pubAreaBytes)
	if 0 != bytes.Compare(h.Sum(nil), certInfo.AttestedCertifyInfo.Name.Digest.Value) {
		return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Hash value mismatch attested and pubArea")
	}

	// Note that the remaining fields in the "Standard Attestation Structure"
	// [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion
	// are ignored. These fields MAY be used as an input to risk engines.

	// If x5c is present, this indicates that the attestation type is not ECDAA.
	if x509present {
		// In this case:
		// Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
		aikCertBytes, valid := x5c[0].([]byte)
		if !valid {
			return tpmAttestationKey, nil, ErrAttestation.WithDetails("Error getting certificate from x5c cert chain")
		}

		aikCert, err := x509.ParseCertificate(aikCertBytes)
		if err != nil {
			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Error parsing certificate from ASN.1")
		}

		sigAlg := SigAlgFromCOSEAlg(coseAlg)

		err = aikCert.CheckSignature(x509.SignatureAlgorithm(sigAlg), certInfoBytes, sigBytes)
		if err != nil {
			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Signature validation error: %+v\n", err))
		}
		// Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements

		// 1/6 Version MUST be set to 3.
		if aikCert.Version != 3 {
			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("AIK certificate version must be 3")
		}
		// 2/6 Subject field MUST be set to empty.
		if aikCert.Subject.String() != "" {
			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("AIK certificate subject must be empty")
		}

		// 3/6 The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9{}

		// TODO: figure out how to parse out the manufacturer/model/version from ASN.1 encoded format

		//var tpmProps []string
		//for _, ext := range aikCert.Extensions {
		//	if ext.Id.Equal([]int{2, 5, 29, 17}) {
		//		tpmProps, err = parseSANExtension(ext.Value)
		//	}
		//}

		//if string(tpmProps[0]) != "foo" {
		//	return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("Invalid SAN data in AIK certificate")
		//}

		// 4/6 The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
		// TODO: figure out how to parse out the AIK certificate EKU from ASN.1 encoded format

		//ekuFound := false
		//for _, ext := range aikCert.Extensions {
		//	if ext.Id.Equal([]int{2, 5, 29, 37}) {
		//		ekuFound = true
		//		var ekuVal asn1.ObjectIdentifier
		//		asn1.Unmarshal(ext.Value, &ekuVal)
		//		if !ekuVal.Equal(tcgKpAIKCertificate) {
		//			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("AIK certificate EKU missing 2.23.133.8.3")
		//		}
		//	}
		//}
		//if false == ekuFound {
		//	return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("AIK certificate missing EKU")
		//}
		// 5/6 The Basic Constraints extension MUST have the CA component set to false.
		type basicConstraints struct {
			IsCA        bool `asn1:"optional"`
			MaxPathhLen int  `asn1:"optional,default:-1"`
		}
		var constraints basicConstraints
		for _, ext := range aikCert.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 19}) {
				if rest, err := asn1.Unmarshal(ext.Value, &constraints); err != nil {
					return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("AIK certificate basic constraints malformed")
				} else if len(rest) != 0 {
					return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("AIK certificate basic constraints contains extra data")
				}
			}
		}
		if constraints.IsCA != false {
			return tpmAttestationKey, nil, ErrAttestationFormat.WithDetails("AIK certificate basic constraints missing or CA is true")
		}
		// 6/6 An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].
	}

	return tpmAttestationKey, x5c, err
}

func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}

const (
	nameTypeDN = 4
)

var (
	tcgKpAIKCertificate  = asn1.ObjectIdentifier{2, 23, 133, 2, 8}
	tcgAtTpmManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	tcgAtTpmModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	tcgAtTpmVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

type TPMManufacturerInfo struct {
	Manufacturer TPMManufacturer
	Model        TPMModel
	Version      TPMVersion
}

type TPMManufacturer struct {
	oid          asn1.ObjectIdentifier
	manufacturer string
}

type TPMModel struct {
	oid   asn1.ObjectIdentifier
	model string
}

type TPMVersion struct {
	oid     asn1.ObjectIdentifier
	version string
}

func parseSANExtension(value []byte) (directoryNames []string, err error) {
	err = forEachSAN(value, func(tag int, data []byte) error {
		switch tag {
		case nameTypeDN:
			var subject TPMManufacturerInfo
			asn1.Unmarshal(data, &subject)
			directoryNames = append(directoryNames, string(data))
		}
		return nil
	})
	return
}
