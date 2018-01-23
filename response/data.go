package response

import "github.com/duo-labs/webauthn/models"

import "encoding/base64"

type CredentialActionResponse struct {
	Success    bool              `json:"success"`
	Credential models.Credential `json:"credential, omitempty"`
}

type FormattedCredential struct {
	CreateDate string `json:"create_date"`
	CredID     string `json:"id"`
	CredType   string `json:"type"`
	PubKeyType string `json:"pk_type"`
	PubKeyX    string `json:"pk_x"`
	PubKeyY    string `json:"pk_y"`
}

type MakeOptionRelyingParty struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}

type MakeOptionUser struct {
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Icon        string `json:"icon,omitempty"`
	ID          uint   `json:"id,omitempty"`
}

type CredentialParameter struct {
	Type      string `json:"type,omitempty"`
	Algorithm string `json:"alg,omitempty"`
}

type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	RequireResidentKey      bool   `json:"requireResidentKey"`
	UserVerification        string `json:"userVerification"`
}

type MakeCredentialResponse struct {
	Challenge              []byte                 `json:"challenge"`
	RP                     MakeOptionRelyingParty `json:"rp"`
	User                   MakeOptionUser         `json:"user"`
	Parameters             []CredentialParameter  `json:"pubKeyCredParams,omitempty"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection,omitempty"`
	Timeout                int                    `json:"timeout,omitempty"`
	ExcludeList            []string               `json:"exclude_list,omitempty"`
}

type PasswordResponse struct {
	Success  bool   `json:"success"`
	Password string `json:"password"`
}

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
