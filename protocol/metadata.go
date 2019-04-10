package protocol

import "golang.org/x/text/language"

type AuthenticatorStatus int

const (
	NOT_FIDO_CERTIFIED AuthenticatorStatus = iota
	FIDO_CERTIFIED
	USER_VERIFICATION_BYPASS
	ATTESTATION_KEY_COMPROMISE
	USER_KEY_REMOTE_COMPROMISE
	USER_KEY_PHYSICAL_COMPROMISE
	UPDATE_AVAILABLE
	REVOKED
	SELF_ASSERTION_SUBMITTED
	FIDO_CERTIFIED_L1
	FIDO_CERTIFIED_L1plus
	FIDO_CERTIFIED_L2
	FIDO_CERTIFIED_L2plus
	FIDO_CERTIFIED_L3
	FIDO_CERTIFIED_L3plus
)

var UndesiredAuthenticatorStatus = [...]AuthenticatorStatus{
	ATTESTATION_KEY_COMPROMISE,
	USER_VERIFICATION_BYPASS,
	USER_KEY_REMOTE_COMPROMISE,
	USER_KEY_PHYSICAL_COMPROMISE,
	REVOKED,
}

func isUndesiredAuthenticatorStatus(status AuthenticatorStatus) bool {
	for _, s := range UndesiredAuthenticatorStatus {
		if s == status {
			return true
		}
	}
	return false
}

type StatusReport struct {
	Status                           AuthenticatorStatus `json:"status"`
	EffectiveDate                    string              `json:"effectiveDate"`
	Certificate                      string              `json:"certificate"`
	Url                              string              `json:"url"`
	CertificationDescriptor          string              `json:"certificationDescriptor"`
	CertificateNumber                string              `json:"certificateNumber"`
	CertificationPolicyVersion       string              `json:"certificationPolicyVersion"`
	CertificationRequirementsVersion string              `json:"certificationRequirementsVersion"`
}
type BiometricStatusReport struct {
	CertLevel                        uint16 `json:"certLevel"`
	Modality                         uint32 `json:"modality"`
	EffectiveDate                    string `json:"effectiveDate"`
	CertificationDescriptor          string `json:"certificationDescriptor"`
	CertificateNumber                string `json:"certificateNumber"`
	CertificationPolicyVersion       string `json:"certificationPolicyVersion"`
	CertificationRequirementsVersion string `json:"certificationRequirementsVersion"`
}
type MetadataTOCPayloadEntry struct {
	Aaid                                 string                  `json:"aaid"`
	AaGuid                               string                  `json:"aaguid"`
	AttestationCertificateKeyIdentifiers []string                `json:"attestationCertificateKeyIdentifiers"`
	Hash                                 string                  `json:"hash"`
	Url                                  string                  `json:"url"`
	BiometricStatusReports               []BiometricStatusReport `json:"biometricStatusReports"`
	StatusReports                        []StatusReport          `json:"statusReports"`
	TimeOfLastStatusChange               string                  `json:"timeOfLastStatusChange"`
	RogueListURL                         string                  `json:"rogueListURL"`
	RogueListHash                        string                  `json:"rogueListHash"`
	MetadataStatement                    MetadataStatement       `json:"metadataStatement"`
}
type RogueListEntry struct {
	Sk   string `json:"sk"`
	Date string `json:"date"`
}
type MetadataTOCPayload struct {
	LegalHeader string                    `json:"legalHeader"`
	Number      int                       `json:"no"`
	NextUpdate  string                    `json:"nextUpdate"`
	Entries     []MetadataTOCPayloadEntry `json:"entries"`
}
type AlternativeDescription struct {
	Language    language.Tag
	Description string
}

//type AlternativeDescriptions  {
//	Description AlternativeDescription `json:"alternativeDescriptions"`
//}
type Version struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
}
type CodeAccuracyDescriptor struct {
	Base          uint16 `json:"base"`
	MinLength     uint16 `json:"minLength"`
	MaxRetries    uint16 `json:"maxRetries"`
	BlockSlowdown uint16 `json:"blockSlowdown"`
}
type BiometricAccuracyDescriptor struct {
	SelfAttestedFRR int64  `json:"selfAttestedFRR "`
	SelfAttestedFAR int64  `json:"selfAttestedFAR "`
	MaxTemplates    uint16 `json:"maxTemplates"`
	MaxRetries      uint16 `json:"maxRetries"`
	BlockSlowdown   uint16 `json:"blockSlowdown"`
}
type PatternAccuracyDescriptor struct {
	MinComplexity uint32 `json:"minComplexity"`
	MaxRetries    uint16 `json:"maxRetries"`
	BlockSlowdown uint16 `json:"blockSlowdown"`
}
type VerificationMethodDescriptor struct {
	UserVerification uint32                      `json:"userVerification"`
	CaDesc           CodeAccuracyDescriptor      `json:"caDesc"`
	BaDesc           BiometricAccuracyDescriptor `json:"baDesc"`
	PaDesc           PatternAccuracyDescriptor   `json:"paDesc"`
}
type VerificationMethodANDCombinations struct {
	VerificationMethodAndCombinations []VerificationMethodDescriptor `json:"verificationMethodANDCombinations"`
}
type rgbPaletteEntry struct {
	R uint16 `json:"r"`
	G uint16 `json:"g"`
	B uint16 `json:"b"`
}
type DisplayPNGCharacteristicsDescriptor struct {
	Width       uint32            `json:"width"`
	Height      uint32            `json:"height"`
	BitDepth    byte              `json:"bitDepth"`
	ColorType   byte              `json:"colorType"`
	Compression byte              `json:"compression"`
	Filter      byte              `json:"filter"`
	Interlace   byte              `json:"interlace"`
	Plte        []rgbPaletteEntry `json:"plte"`
}
type EcdaaTrustAnchor struct {
	X       string `json:"x"`
	Y       string `json:"y"`
	C       string `json:"c"`
	SX      string `json:"sx"`
	SY      string `json:"sy"`
	G1Curve string `json:"G1Curve"`
}
type ExtensionDescriptor struct {
	Id              string `json:"id"`
	Tag             uint16 `json:"tag"`
	Data            string `json:"data"`
	Fail_If_Unknown bool   `json:"fail_if_unknown"`
}

type MetadataStatement struct {
	LegalHeader                          string                                `json:"legalHeader"`
	Aaid                                 string                                `json:"aaid"`
	AaGuid                               string                                `json:"aaguid"`
	AttestationCertificateKeyIdentifiers []string                              `json:"attestationCertificateKeyIdentifiers"`
	Description                          string                                `json:"description"`
	AlternativeDescriptions              []AlternativeDescription              `json:"alternativeDescriptions"`
	AuthenticatorVersion                 uint16                                `json:"authenticatorVersion"`
	ProtocolFamily                       string                                `json:"protocolFamily"`
	Upv                                  []Version                             `json:"upv"`
	AssertionScheme                      string                                `json:"assertionScheme"`
	AuthenticationAlgorithm              uint16                                `json:"authenticationAlgorithm"`
	AuthenticationAlgorithms             []uint16                              `json:"authenticationAlgorithms"`
	PublicKeyAlgAndEncoding              uint16                                `json:"publicKeyAlgAndEncoding"`
	PublicKeyAlgAndEncodings             []uint16                              `json:"publicKeyAlgAndEncodings"`
	AttestationTypes                     []uint16                              `json:"attestationTypes"`
	UserVerificationDetails              [][]VerificationMethodDescriptor      `json:"userVerificationDetails"`
	KeyProtection                        uint16                                `json:"keyProtection"`
	IsKeyRestricted                      bool                                  `json:"isKeyRestricted"`
	IsFreshUserVerificationRequired      bool                                  `json:"isFreshUserVerificationRequired"`
	MatcherProtection                    uint16                                `json:"matcherProtection"`
	CryptoStrength                       uint16                                `json:"cryptoStrength"`
	OperatingEnv                         string                                `json:"operatingEnv"`
	AttachmentHint                       uint32                                `json:"attachmentHint"`
	IsSecondFactorOnly                   bool                                  `json:"isSecondFactorOnly"`
	TcDisplay                            uint16                                `json:"tcDisplay"`
	TcDisplayContentType                 string                                `json:"tcDisplayContentType"`
	TcDisplayPNGCharacteristics          []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics"`
	AttestationRootCertificates          []string                              `json:"attestationRootCertificates"`
	EcdaaTrustAnchors                    []EcdaaTrustAnchor                    `json:"ecdaaTrustAnchors"`
	Icon                                 string                                `json:"icon"`
	SupportedExtensions                  []ExtensionDescriptor                 `json:"supportedExtensions"`
}
