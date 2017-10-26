package models

import (
	"fmt"

	"github.com/jinzhu/gorm"
)

// User represents the user model.
type User struct {
	gorm.Model
	Name           string         `json:"name" sql:"not null;unique"`
	DisplayName    string         `json:"display_name"`
	Icon           string         `json:"icon,omitempty"`
	Credentials    []Credential   `json:"credentials,omitempty"`
	RelyingParties []RelyingParty `gorm:"many2many:user_relying_parties"`
}

// GetUser returns the user that the given id corresponds to. If no user is found, an
// error is thrown.
func GetUser(id int64) (User, error) {
	u := User{}
	err := db.Where("id=?", id).Preload("Credential").Find(&u).Error
	if err != nil {
		return u, err
	}
	err = db.Model(&u).Related(&u.Credentials).Error
	if err != nil {
		return u, err
	}
	return u, nil
}

// GetUserByUsername returns the user that the given username corresponds to. If no user is found, an
// error is thrown.
func GetUserByUsername(username string) (User, error) {
	u := User{}
	err := db.Where("name = ?", username).Preload("Credentials").Find(&u).Error

	if err != nil {
		return u, err
	}
	err = db.Model(&u).Related(&u.Credentials).Error
	if err != nil {
		return u, err
	}
	return u, err
}

// PutUser updates the given user
func PutUser(u *User) error {
	if db.NewRecord(&u) {
		fmt.Println("new record")
	}
	err := db.Save(&u).Error
	return err
}
