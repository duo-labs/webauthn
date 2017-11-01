package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/duo-labs/webauthn/config"
	"github.com/duo-labs/webauthn/models"
	"github.com/stretchr/testify/suite"
)

type HandlersSuite struct {
	suite.Suite
}

var server = httptest.NewUnstartedServer(CreateRouter())

func (hs *HandlersSuite) SetupSuite() {
	config.Conf.DBName = "sqlite3"
	config.Conf.DBPath = ":memory:"
	config.Conf.HostAddress = "localhost"
	err := models.Setup()
	if err != nil {
		hs.T().Fatalf("Failed creating database: %v", err)
	}
	server.Config.Addr = config.Conf.HostAddress
	server.Start()
}

func (hs *HandlersSuite) TearDownSuite() {
	server.Close()
}

func (hs *HandlersSuite) TearDownTest() {
	// TODO: Figure out how we'll handle deletion from outside the `models` package.
	// db.Delete(Credential{})
	// db.Delete(SessionData{})

	// db.Not("id", 1).Delete(User{})
	// db.Model(User{}).Update("name", "admin")

	// db.Not("id", config.Conf.HostAddress).Delete(RelyingParty{})
}

func (hs *HandlersSuite) TestGetUser() {
	expected, _ := models.GetUserByUsername("rcrumb@duo.com")

	resp, err := http.Get(fmt.Sprintf("%s/user/%s", server.URL, expected.Name))
	if err != nil {
		hs.T().Fatalf("Unexpected error fetching user details: %s", err)
	}
	defer resp.Body.Close()

	got := models.User{}
	err = json.NewDecoder(resp.Body).Decode(&got)
	if err != nil {
		hs.T().Fatalf("Unexpected error when unmarshaling user response body: %s\nGot response %#v", err, got)
	}

	if reflect.DeepEqual(expected, got) {
		hs.T().Fatalf("Invalid user object received from getUser. Expected %#v\nGot%#v", expected, got)
	}
}

func TestHandlersSuite(t *testing.T) {
	suite.Run(t, new(HandlersSuite))
}
