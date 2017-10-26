package models

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"reflect"
)

func generateTestCodePoint() (x, y []byte) {
	// Constants taken from
	x, _ = hex.DecodeString("023819813ac969847059028ea88a1f30dfbcde03fc791d3a252c6b41211882ea")
	y, _ = hex.DecodeString("f93e4ae433cc12cf2a43fc0ef26400c0e125508224cdb649380f25479148a4ad")
	return
}

func createCredentialsForUserAndRelyingParty(u User, rp RelyingParty) (*Credential, error) {
	x, y := generateTestCodePoint()
	c := &Credential{
		User:           u,
		UserID:         u.ID,
		RelyingParty:   rp,
		RelyingPartyID: rp.ID,
		PublicKey: PublicKey{
			XCoord: x,
			YCoord: y,
		},
	}
	err := CreateCredential(c)
	return c, err
}

func (ms *ModelsSuite) TestGetCredentialsForUser() {
	u, err := GetUser(1)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting user by ID: %s", err)
	}
	cs, err := GetCredentialsForUser(&u)
	if err != nil {
		ms.T().Fatalf("Unexpected error when getting empty credentials: %s", err)
	}
	if len(cs) != 0 {
		ms.T().Fatalf("Unexpected credentials received. Expected: %d, Got: %d", 0, len(cs))
	}

	rp, err := GetDefaultRelyingParty()
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}

	// Now we'll add credentials
	_, err = createCredentialsForUserAndRelyingParty(u, rp)
	if err != nil {
		ms.T().Fatalf("Unexpected error when creating credentials: %s", err)
	}

	// And fetch them
	cs, err = GetCredentialsForUser(&u)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}
	if len(cs) != 1 {
		ms.T().Fatalf("Unexpected credentials received: Expected: %d, Got %d", 1, len(cs))
	}
	if cs[0].UserID != u.ID || cs[0].RelyingPartyID != rp.ID {
		ms.T().Fatalf("Unexpected credential received. Got: %#v", cs)
	}
}

func (ms *ModelsSuite) TestGetCredentialForUserAndRelyingParty() {
	u, err := GetUser(1)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting user by ID: %s", err)
	}
	rp, err := GetDefaultRelyingParty()
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}
	_, err = createCredentialsForUserAndRelyingParty(u, rp)
	cs, err := GetCredentialForUserAndRelyingParty(&u, &rp)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting credentials for user and relying party: %s", err)
	}
	if cs.UserID != u.ID || cs.RelyingPartyID != rp.ID {
		ms.T().Fatalf("Unexpected credential received. Got: %#v", cs)
	}
}

func (ms *ModelsSuite) TestGetPublicKeyForCredential() {
	u, err := GetUser(1)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting user by ID: %s", err)
	}
	rp, err := GetDefaultRelyingParty()
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}
	originalCredential, err := createCredentialsForUserAndRelyingParty(u, rp)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting credentials for user and relying party: %s", err)
	}
	c, err := GetCredentialForUserAndRelyingParty(&u, &rp)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting credentials for user and relying party: %s", err)
	}
	// Get the public key and verify it's formatted correctly
	pk, err := GetPublicKeyForCredential(&c)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting the public key for a credential: %s", err)
	}
	expected, _ := FormatPublicKey(originalCredential.PublicKey)
	if !reflect.DeepEqual(pk, expected) {
		ms.T().Fatalf("Unexpected ecdsa.PublicKey received.\nGot %#v\nExpected %#v", pk, expected)
	}
}

func (ms *ModelsSuite) TestCreateCredential() {
	u, err := GetUser(1)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting user by ID: %s", err)
	}
	cs, err := GetCredentialsForUser(&u)
	if err != nil {
		ms.T().Fatalf("Unexpected error when getting empty credentials: %s", err)
	}
	if len(cs) != 0 {
		ms.T().Fatalf("Unexpected credentials received. Expected: %d, Got: %d", 0, len(cs))
	}

	rp, err := GetDefaultRelyingParty()
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}

	// Now we'll add credentials
	_, err = createCredentialsForUserAndRelyingParty(u, rp)
	if err != nil {
		ms.T().Fatalf("Unexpected error when creating credentials: %s", err)
	}

	// And fetch them
	cs, err = GetCredentialsForUser(&u)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}
	if len(cs) != 1 {
		ms.T().Fatalf("Unexpected credentials received: Expected: %d, Got %d", 1, len(cs))
	}
	if cs[0].UserID != u.ID || cs[0].RelyingPartyID != rp.ID {
		ms.T().Fatalf("Unexpected credential received. Got: %#v", cs)
	}

	// Now we'll check about adding double credentials
	_, err = createCredentialsForUserAndRelyingParty(u, rp)
	if err != nil {
		ms.T().Fatalf("Error when adding already existing credentials: %s", err)
	}

	cs, err = GetCredentialsForUser(&u)
	if err != nil {
		ms.T().Fatalf("Unexpected error getting relying parties: %s", err)
	}
	if len(cs) != 1 {
		ms.T().Fatalf("Unexpected credentials received: Expected: %d, Got %d", 1, len(cs))
	}
	if cs[0].UserID != u.ID || cs[0].RelyingPartyID != rp.ID {
		ms.T().Fatalf("Unexpected credential received. Got: %#v", cs)
	}
}

func (ms *ModelsSuite) TestFormatPublicKey() {
	x, y := generateTestCodePoint()
	pk := PublicKey{
		XCoord: x,
		YCoord: y,
	}
	ecdsaPublicKey, err := FormatPublicKey(pk)
	if err != nil {
		ms.T().Fatalf("Received unexpected error: %s", err)
	}
	// elliptic.Unmarshal for a p256 curve just translates our inputs
	// to a big.Int
	xExpected := new(big.Int).SetBytes(x)
	yExpected := new(big.Int).SetBytes(y)

	if xExpected.Cmp(ecdsaPublicKey.X) != 0 {
		ms.T().Fatalf("Unexpected xInt:\n Got: %#v\nExpected: %#v", ecdsaPublicKey.X, xExpected)
	}
	if yExpected.Cmp(ecdsaPublicKey.Y) != 0 {
		ms.T().Fatalf("Unexpected yInt:\n Got: %#v\nExpected: %#v", ecdsaPublicKey.Y, yExpected)
	}
}

func (ms *ModelsSuite) TestAssembleUncompressedECPoint() {
	x, y := generateTestCodePoint()

	// Test the valid case of 32 bytes per coordinate
	formattedCodePoint, err := assembleUncompressedECPoint(x, y)
	if err != nil {
		ms.T().Fatalf("Received unexpected error: %s", err)
	}

	expected := []byte{0x04}
	expected = append(expected, x...)
	expected = append(expected, y...)

	if bytes.Compare(formattedCodePoint, expected) != 0 {
		ms.T().Fatalf("Invalid formatted code point.\n Got: %#v\nExpected: %#v", formattedCodePoint, expected)
	}

	// Test invalid length case
	x = append(x, 0x00)
	_, err = assembleUncompressedECPoint(x, y)
	if err == nil {
		ms.T().Fatalf("Received nil error. Expected coordinate length error")
	}
}
