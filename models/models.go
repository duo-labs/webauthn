package models

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/duo-labs/webauthn/config"

	_ "github.com/go-sql-driver/mysql" // Blank import needed to import mysql
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3" // Blank import needed to import sqlite3
)

var db *gorm.DB
var err error

// ErrUsernameTaken is thrown when a user attempts to register a username that is taken.
var ErrUsernameTaken = errors.New("username already taken")

// Logger is a global logger used to show informational, warning, and error messages
var Logger = log.New(os.Stdout, " ", log.Ldate|log.Ltime|log.Lshortfile)

// Copy of auth.GenerateSecureKey to prevent cyclic import with auth library
func generateSecureKey() string {
	k := make([]byte, 32)
	io.ReadFull(rand.Reader, k)
	return fmt.Sprintf("%x", k)
}

// Setup initializes the Conn object
// It also populates the Config object
func Setup() error {
	createDb := false
	if _, err = os.Stat(config.Conf.DBPath); err != nil || config.Conf.DBPath == ":memory:" {
		createDb = true
	}
	// Open our database connection
	db, err = gorm.Open(config.Conf.DBName, config.Conf.DBPath)
	if err != nil {
		fmt.Printf("%#v", err)
		return err
	}
	db.LogMode(false)
	db.SetLogger(Logger)
	db.DB().SetMaxOpenConns(1)
	if err != nil {
		Logger.Println(err)
		return err
	}
	// Migrate up to the latest version
	//If the database didn't exist, we need to create the admin user
	err := db.AutoMigrate(
		&RelyingParty{},
		&User{},
		&Credential{},
		&PublicKey{},
		&SessionData{},
	).Error

	if err != nil {
		fmt.Printf("%#v", err)
		return err
	}

	gorm.NowFunc = func() time.Time {
		return time.Now().UTC()
	}

	if createDb {
		// Create the default user
		initUser := User{
			Name:        "admin",
			DisplayName: "Mr. Admin Face",
		}

		initRP := RelyingParty{
			ID:          config.Conf.HostAddress,
			DisplayName: "Acme, Inc",
			Icon:        "lol.catpics.png",
			Users:       []User{initUser},
		}

		err = db.Save(&initRP).Error
		if err != nil {
			Logger.Println(err)
			return err
		}

		err = db.Save(&initUser).Error
		if err != nil {
			Logger.Println(err)
			return err
		}
	}
	return nil
}
