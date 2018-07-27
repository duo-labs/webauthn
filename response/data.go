package response

import "github.com/duo-labs/webauthn/models"

import "encoding/base64"

// CredentialActionResponse shows the minted credential and success result
type CredentialActionResponse struct {
	Success    bool              `json:"success"`
	Credential models.Credential `json:"credential, omitempty"`
}

// FormattedCredential struct for user viewing
type FormattedCredential struct {
	CreateDate string `json:"create_date"`
	CredID     string `json:"id"`
	CredType   string `json:"type"`
	PubKeyType string `json:"pk_type"`
	PubKeyX    string `json:"pk_x"`
	PubKeyY    string `json:"pk_y"`
}

// MakeOptionRelyingParty is the relying party requesting the credential
type MakeOptionRelyingParty struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

// MakeOptionUser is the user requesting the credential
type MakeOptionUser struct {
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Icon        string `json:"icon,omitempty"`
	ID          uint   `json:"id,omitempty"`
}

// CredentialParameter is the credential type and alg being requested
type CredentialParameter struct {
	Type      string `json:"type,omitempty"`
	Algorithm string `json:"alg,omitempty"`
}

// AuthenticatorSelection denotes specific requests of the authenticator
type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	RequireResidentKey      bool   `json:"requireResidentKey"`
	UserVerification        string `json:"userVerification"`
}

// The Boolean value true to indicate that an extension is requested by the Relying Party
// This is currently in development
type Extensions struct {
	Extensions bool `json:"exts"`
}

// MakeCredentialResponse The response payload provided on the request of a new credential
type MakeCredentialResponse struct {
	Challenge              []byte                 `json:"challenge"`
	RP                     MakeOptionRelyingParty `json:"rp"`
	User                   MakeOptionUser         `json:"user"`
	Parameters             []CredentialParameter  `json:"pubKeyCredParams,omitempty"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection,omitempty"`
	Timeout                int                    `json:"timeout,omitempty"`
	ExcludeList            []string               `json:"excludeCredentials,omitempty"`
	Extensions             Extensions             `json:"extenstions,omitempty"`
	AttestationType        string                 `json:"attestation,omitempty"`
}

// FormatCredentials creates the formatted credential for viewing
func FormatCredentials(creds []models.Credential) ([]FormattedCredential, error) {
	fcs := make([]FormattedCredential, len(creds))
	for x, cred := range creds {
		pk, err := models.GetUnformattedPublicKeyForCredential(&cred)
		if err != nil {
			return nil, err
		}
		fcs[x] = FormattedCredential{
			CreateDate: cred.CreatedAt.Format("Mon, 3:04PM MST"),
			CredID:     cred.CredID,
			CredType:   cred.Format,
			PubKeyType: string(pk.Type),
			PubKeyX:    base64.URLEncoding.EncodeToString(pk.XCoord),
			PubKeyY:    base64.URLEncoding.EncodeToString(pk.YCoord),
		}
	}
	return fcs, nil
}
