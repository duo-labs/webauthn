package models

import (
	"reflect"

	"github.com/duo-labs/webauthn/config"
	"github.com/jinzhu/gorm"
)

func (ms *ModelsSuite) TestGetDefaultRelyingParty() {
	// We're assuming the default rp is always created...
	rp, err := GetDefaultRelyingParty()
	if err != nil {
		ms.T().Fatalf("Unexpected error getting default relying party %s", err)
	}
	if rp.ID != config.Conf.HostAddress {
		ms.T().Fatalf("Unexpected RP received. Expected %s, Got %s", config.Conf.HostAddress, rp.ID)
	}
}

func (ms *ModelsSuite) TestGetRelyingPartyByHost() {
	rp, err := GetRelyingPartyByHost(config.Conf.HostAddress)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying party by hostname: %s", err)
	}
	if rp.ID != config.Conf.HostAddress {
		ms.T().Fatalf("Unexpected RP received. Expected %s, Got %s", config.Conf.HostAddress, rp.ID)
	}

	_, err = GetRelyingPartyByHost("bogus_hostname")
	if err != gorm.ErrRecordNotFound {
		ms.T().Fatalf("Received unexpected error value when fetching non-existent RP: %s", err)
	}
}

func (ms *ModelsSuite) TestPutRelyingParty() {
	expected := &RelyingParty{
		ID:          "example.com",
		DisplayName: "Example",
		Icon:        "example.jpg",
	}
	err := PutRelyingParty(expected)
	if err != nil {
		ms.T().Fatalf("Unexpected error when adding a relying party: %s", err)
	}

	got, err := GetRelyingPartyByHost(config.Conf.HostAddress)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying party by hostname: %s", err)
	}

	if reflect.DeepEqual(expected, got) {
		ms.T().Fatalf("Unexpected relying party received.\nExpected: %#v\nGot%#v", expected, got)
	}

}
