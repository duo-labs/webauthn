package protocol

import (
	"encoding/base64"
	"testing"
)

func setupCollectedClientData(challenge []byte) *CollectedClientData {
	ccd := &CollectedClientData{
		Type:   CreateCeremony,
		Origin: "example.com",
	}

	newChallenge := make([]byte, base64.StdEncoding.EncodedLen(len(challenge)))
	base64.StdEncoding.Encode(newChallenge, challenge)
	ccd.Challenge = base64.RawURLEncoding.EncodeToString(newChallenge)
	return ccd
}

func TestVerifyCollectedClientData(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge)
	storedChallenge := newChallenge

	t.Logf("storedLen: %+s\n", storedChallenge)
	t.Logf("cLen: %+v\n", ccd.Challenge)

	err = ccd.Verify(storedChallenge, ccd.Type, ccd.Origin)
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
	err = ccd.Verify(storedChallenge, ccd.Type, ccd.Origin)
	if err == nil {
		t.Fatalf("error expected but not received. expected %#v got %#v", Challenge(ccd.Challenge), storedChallenge)
	}
}
