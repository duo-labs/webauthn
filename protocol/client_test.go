package protocol

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func setupCollectedClientData(challenge []byte) *CollectedClientData {
	ccd := &CollectedClientData{
		Type:   CreateCeremony,
		Origin: "example.com",
	}

	ccd.Challenge = base64.RawURLEncoding.EncodeToString(challenge)
	return ccd
}
func TestVerifyCollectedClientData(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge)
	var storedChallenge = newChallenge

	originURL, _ := url.Parse(ccd.Origin)
	err = ccd.Verify(storedChallenge.String(), ccd.Type, originURL.Hostname())
	if err != nil {
		t.Fatalf("error verifying challenge: expected %#v got %#v", Challenge(ccd.Challenge), storedChallenge)
	}
}

func TestVerifyCollectedClientDataIncorrectChallenge(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}
	ccd := setupCollectedClientData(newChallenge)
	bogusChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}
	storedChallenge := Challenge(bogusChallenge)
	err = ccd.Verify(storedChallenge.String(), ccd.Type, ccd.Origin)
	if err == nil {
		t.Fatalf("error expected but not received. expected %#v got %#v", Challenge(ccd.Challenge), storedChallenge)
	}
}
