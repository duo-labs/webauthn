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
	storedChallenge := newChallenge

	originURL, _ := url.Parse(ccd.Origin)
	err = ccd.Verify(storedChallenge, ccd.Type, originURL.Hostname())
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

func TestCollectedClientData_Verify(t *testing.T) {
	type fields struct {
		Type         CeremonyType
		Challenge    string
		Origin       string
		TokenBinding *TokenBinding
		Hint         string
	}
	type args struct {
		storedChallenge    []byte
		ceremony           CeremonyType
		relyingPartyOrigin string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CollectedClientData{
				Type:         tt.fields.Type,
				Challenge:    tt.fields.Challenge,
				Origin:       tt.fields.Origin,
				TokenBinding: tt.fields.TokenBinding,
				Hint:         tt.fields.Hint,
			}
			if err := c.Verify(tt.args.storedChallenge, tt.args.ceremony, tt.args.relyingPartyOrigin); (err != nil) != tt.wantErr {
				t.Errorf("CollectedClientData.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
