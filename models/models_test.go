package models

import (
	"testing"

	"github.com/duo-labs/webauthn/config"
	"github.com/stretchr/testify/suite"
)

type ModelsSuite struct {
	suite.Suite
}

func (ms *ModelsSuite) SetupSuite() {
	config.Conf.DBName = "sqlite3"
	config.Conf.DBPath = ":memory:"
	config.Conf.HostAddress = "localhost"
	err := Setup()
	if err != nil {
		ms.T().Fatalf("Failed creating database: %v", err)
	}
}

func (ms *ModelsSuite) TearDownTest() {
	// Clear database tables between each test. If new tables are
	// used in this test suite they will need to be cleaned up here.
	db.Delete(Credential{})
	db.Delete(SessionData{})

	db.Not("id", 1).Delete(User{})
	db.Model(User{}).Update("name", "admin")

	db.Not("id", config.Conf.HostAddress).Delete(RelyingParty{})
}

func TestRunModelsSuite(t *testing.T) {
	suite.Run(t, new(ModelsSuite))
}
