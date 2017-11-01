package models

import (
	"net/http"
	"net/http/httptest"
	"reflect"

	"github.com/gorilla/sessions"

	"github.com/duo-labs/webauthn/config"
)

func (ms *ModelsSuite) TestCreateChallenge() {
	expected := 32
	got, err := createChallenge(expected)
	if err != nil {
		ms.T().Fatalf("Unexpected error when creating challenge %s", err)
	}
	if len(got) != expected {
		ms.T().Fatalf("Unexpected length of challenge. Expected %d, Got %d", len(got), expected)
	}
}

func (ms *ModelsSuite) getUserAndRelyingParty() (*User, *RelyingParty) {
	u, err := GetUser(1)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting user by ID: %s", err)
	}
	rp, err := GetDefaultRelyingParty()
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}
	return &u, &rp
}

func (ms *ModelsSuite) TestCreateNewSession() {
	u, rp := ms.getUserAndRelyingParty()
	st := "invalid"
	_, err := CreateNewSession(u, rp, st)
	if err != ErrInvalidSessionType {
		ms.T().Fatalf("Unexpected error received when creating invalid session: %s", err)
	}

	st = "reg"
	expected := SessionData{
		Origin:         rp.ID,
		UserID:         u.ID,
		RelyingPartyID: rp.ID,
		SessionType:    st,
	}

	got, err := CreateNewSession(u, rp, expected.SessionType)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when creating new session %s", err)
	}
	// We will just copy the gorm.Model value and the challenge since those are generated
	// at the time of save.
	expected.Challenge = got.Challenge
	expected.Model = got.Model
	if !reflect.DeepEqual(expected, got) {
		ms.T().Fatalf("Unexpected session received.\nExpected %#v\nGot %#v", expected, got)
	}
}

func (ms *ModelsSuite) TestGetSessionByUsernameAndRelyingParty() {
	u, rp := ms.getUserAndRelyingParty()
	st := "reg"
	expected, err := CreateNewSession(u, rp, st)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when creating new session %s", err)
	}

	got, err := GetSessionsByUsernameAndRelyingParty(u.ID, rp.ID)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when getting valid sessions %s", err)
	}
	expected.Model = got.Model
	if !reflect.DeepEqual(expected, got) {
		ms.T().Fatalf("Unexpected session received.\nExpected %#v\nGot %#v", expected, got)
	}
}

func (ms *ModelsSuite) TestGetSessionData() {
	u, rp := ms.getUserAndRelyingParty()
	st := "reg"
	expected, err := CreateNewSession(u, rp, st)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when creating new session %s", err)
	}

	got, err := GetSessionData(expected.ID)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when getting valid sessions %s", err)
	}
	expected.Model = got.Model
	// The way gorm loads models means that we need to copy this over to make sure
	// it's deeply equal. Otherwise, we just have to compare most known fields which would be
	// a lot of boilerplate.
	expected.User = got.User
	expected.RelyingParty = *rp
	if !reflect.DeepEqual(expected, got) {
		ms.T().Fatalf("Unexpected session received.\nExpected\n%#v\nGot\n%#v", expected, got)
	}
}

func (ms *ModelsSuite) TestGetSessionByUsername() {}

func (ms *ModelsSuite) TestGetSessionForRequest() {
	u, rp := ms.getUserAndRelyingParty()
	st := "reg"
	sd, err := CreateNewSession(u, rp, st)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when creating new session %s", err)
	}

	expected, err := GetSessionData(sd.ID)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when getting valid sessions %s", err)
	}

	// Save the session ID into the cookie store
	req, _ := http.NewRequest("GET", config.Conf.HostAddress, nil)
	var store = sessions.NewCookieStore([]byte("test"))
	session, _ := store.Get(req, "registration-session")
	session.Values["session_id"] = expected.ID
	resp := httptest.NewRecorder()
	session.Save(req, resp)

	// Now let's read it back out
	got, err := GetSessionForRequest(req, store)
	if err != nil {
		ms.T().Fatalf("Unexpected error received when getting valid sessions %s", err)
	}
	if !reflect.DeepEqual(expected, got) {
		ms.T().Fatalf("Unexpected session received.\nExpected\n%#v\nGot\n%#v", expected, got)
	}
}
