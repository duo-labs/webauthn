package protocol

import (
	"crypto"
	"hash"
)

// Algorithm enumerations used for 
type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	MD2WithRSA
	MD5WithRSA
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1
	DSAWithSHA256
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
)

var signatureAlgorithmDetails = []struct {
	algo    SignatureAlgorithm
	coseAlg COSEAlgorithmIdentifier
	name    string
	hasher  func() hash.Hash
}{
	{SHA1WithRSA, AlgRS1, "SHA1-RSA", crypto.SHA1.New},
	{SHA256WithRSA, AlgRS256, "SHA256-RSA", crypto.SHA256.New},
	{SHA384WithRSA, AlgRS384, "SHA384-RSA", crypto.SHA384.New},
	{SHA512WithRSA, AlgRS512, "SHA512-RSA", crypto.SHA512.New},
	{SHA256WithRSAPSS, AlgPS256, "SHA256-RSAPSS", crypto.SHA256.New},
	{SHA384WithRSAPSS, AlgPS384, "SHA384-RSAPSS", crypto.SHA384.New},
	{SHA512WithRSAPSS, AlgPS512, "SHA512-RSAPSS", crypto.SHA512.New},
	{ECDSAWithSHA256, AlgES256, "ECDSA-SHA256", crypto.SHA256.New},
	{ECDSAWithSHA384, AlgES384, "ECDSA-SHA384", crypto.SHA384.New},
	{ECDSAWithSHA512, AlgES512, "ECDSA-SHA512", crypto.SHA512.New},
	{UnknownSignatureAlgorithm, AlgEdDSA, "EdDSA", crypto.SHA512.New},
}
