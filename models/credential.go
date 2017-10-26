package models

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/jinzhu/gorm"
)

// Credential is the stored credential for Auth
type Credential struct {
	gorm.Model
	Counter []byte `json:"sign_count" gorm:"not null"`

	RelyingParty   RelyingParty `json:"rp"`
	RelyingPartyID string       `json:"rp_id"`

	User   User `json:"user"`
	UserID uint `json:"user_id"`

	Type   string `json:"type,omitempty"`
	Format string `json:"format, omitempty"`
	Flags  []byte `json:"flags,omitempty" gorm:"type:byte[]"`

	CredID string `json:"credential_id, omitempty"`

	PublicKey PublicKey `json:"public_key,omitempty"`
}

// PublicKey is
type PublicKey struct {
	gorm.Model
	CredentialID uint   `json:"credential_id" gorm:"index,not null" codec:"-"`
	XCoord       []byte `json:"x" gorm:"not null" codec:"x"`
	YCoord       []byte `json:"y" gorm:"not null" codec:"y"`
	Type         string `json:"type" gorm:"not null" codec:"alg"`
}

// CreateCredential creates a new credential object
func CreateCredential(c *Credential) error {
	fmt.Println("Creating Credential")
	_, err := GetCredentialForUserAndRelyingParty(&c.User, &c.RelyingParty)
	if db.NewRecord(&c) {
		err = db.Save(&c).Error
		return err
	}
	return err
}

// UpdateCredential updates the credential with new attributes.
func UpdateCredential(c *Credential) error {
	err = db.Save(&c).Error
	return err
}

// GetCredentialForUserAndRelyingParty retrieves the first credential for a provided user and relying party.
func GetCredentialForUserAndRelyingParty(user *User, rp *RelyingParty) (Credential, error) {
	cred := Credential{}
	err := db.Where("user_id = ? AND relying_party_id = ?", user.ID, rp.ID).Preload("PublicKey").First(&cred).Error
	cred.User = *user
	cred.RelyingParty = *rp
	if err != nil {
		return cred, err
	}
	return cred, err
}

// GetCredentialsForUser retrieves all credentials for a provided user regardless of relying party.
func GetCredentialsForUser(user *User) ([]Credential, error) {
	creds := []Credential{}
	err := db.Where("user_id = ?", user.ID).Preload("PublicKey").Find(&creds).Error
	return creds, err
}

// DeleteCredentialByID gets a credential by its ID. In practice, this would be a bad function without
// some other checks (like what user is logged in) because someone could hypothetically delete ANY credential.
func DeleteCredentialByID(credentialID string) error {
	return db.Where("cred_id = ?", credentialID).Delete(&Credential{}).Error
}

func GetUnformattedPublicKeyForCredential(c *Credential) (PublicKey, error) {
	publicKey := PublicKey{}
	err := db.Model(&c).Related(&publicKey, "PublicKey").Error
	if err != nil {
		return PublicKey{}, err
	}
	return publicKey, err
}

// GetPublicKeyForCredential gets the formatted `models.PublicKey` for a provided credential
func GetPublicKeyForCredential(c *Credential) (ecdsa.PublicKey, error) {
	// Assuming ECDSA For now
	publicKey := PublicKey{}
	err := db.Model(&c).Related(&publicKey, "PublicKey").Error
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	return FormatPublicKey(publicKey)
}

// FormatPublicKey formats a `models.PublicKey` into an `ecdsa.PublicKey`
func FormatPublicKey(pk PublicKey) (ecdsa.PublicKey, error) {
	ecPoint, err := assembleUncompressedECPoint(pk.XCoord, pk.YCoord)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	xInt, yInt := elliptic.Unmarshal(elliptic.P256(), ecPoint)
	return ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     xInt,
		Y:     yInt,
	}, err
}

func assembleUncompressedECPoint(xCoord []byte, yCoord []byte) ([]byte, error) {
	point := make([]byte, 65)
	if len(xCoord) != 32 || len(yCoord) != 32 {
		fmt.Println("X coord byte length : ", len(xCoord))
		fmt.Println("Y coord byte length : ", len(yCoord))
		err := errors.New("Coordinates are not 32 bytes long")
		return point, err
	}
	point[0] = 0x04
	copy(point[1:33], xCoord)
	copy(point[33:], yCoord)
	return point, nil
}
