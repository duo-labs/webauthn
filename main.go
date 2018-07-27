package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	"github.com/ugorji/go/codec"

	"github.com/duo-labs/webauthn/config"
	"github.com/duo-labs/webauthn/models"
	req "github.com/duo-labs/webauthn/request"
	res "github.com/duo-labs/webauthn/response"
)

var store = sessions.NewCookieStore([]byte("duo-rox"))

// renderTemplate renders the template to the ResponseWriter
func renderTemplate(w http.ResponseWriter, f string, data interface{}) {
	t, err := template.ParseFiles(fmt.Sprintf("./templates/%s", f))
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

// JSONResponse attempts to set the status code, c, and marshal the given
// interface, d, into a response that is written to the given ResponseWriter.
func JSONResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

// Index returns the static index template
func Index(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]

	if username == "" {
		fmt.Println("Getting default user for dashboard")
		username = "testuser@example.com"
	}

	user, err := models.GetUserByUsername(username + "@example.com")

	if err != nil {
		fmt.Println("Error retreiving user for dashboard: ", err)
		JSONResponse(w, "Error retreiving user", http.StatusInternalServerError)
		return
	}

	type TemplateData struct {
		User        string
		Credentials []res.FormattedCredential
	}

	creds, err := models.GetCredentialsForUser(&user)

	fcs, err := res.FormatCredentials(creds)

	td := TemplateData{
		User:        user.DisplayName,
		Credentials: fcs,
	}

	renderTemplate(w, "index.html", td)
}

// Login returns the static login page
func Login(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login.html", nil)
}

// RequestNewCredential begins Credential Registration Request when /MakeNewCredential gets hit
func RequestNewCredential(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]

	attType := r.FormValue("attType")
	timeout := 60000
	// Get Registrant User

	user, err := models.GetUserByUsername(username)
	if err != nil {
		user = models.User{
			DisplayName: strings.Split(username, "@")[0],
			Name:        username,
		}
		err = models.PutUser(&user)
		if err != nil {
			JSONResponse(w, "Error creating new user", http.StatusInternalServerError)
			return
		}
	}

	params := []res.CredentialParameter{
		res.CredentialParameter{
			Type:      "public-key",
			Algorithm: "-7",
		},
	}

	// Get the proper URL the request is coming from
	u, err := url.Parse(r.Referer())

	// Get Relying Party that is requesting Registration
	rp, err := models.GetRelyingPartyByHost(u.Hostname())

	if err == gorm.ErrRecordNotFound {
		fmt.Println("No RP found for host ", u.Hostname())
		fmt.Printf("Request: %+v\n", r)
		JSONResponse(w, "No relying party defined", http.StatusInternalServerError)
		return
	}

	// Log this Registration session
	sd, err := models.CreateNewSession(&user, &rp, "reg")
	if err != nil {
		fmt.Println("Something went wrong creating session data:", err)
		JSONResponse(w, "Session Data Creation Error", http.StatusInternalServerError)
		return
	}

	// Give us a safe (looking) way to manage the session btwn us and the client
	session, _ := store.Get(r, "registration-session")
	session.Values["session_id"] = sd.ID
	session.Save(r, w)

	makeOptRP := res.MakeOptionRelyingParty{
		Name: rp.DisplayName,
		ID:   rp.ID,
	}

	makeOptUser := res.MakeOptionUser{
		Name:        user.Name,
		DisplayName: user.DisplayName,
		ID:          user.ID,
	}

	authSelector := res.AuthenticatorSelection{
		AuthenticatorAttachment: "cross-platform",
		RequireResidentKey:      false,
		UserVerification:        "preferred",
	}

	makeResponse := res.MakeCredentialResponse{
		Challenge:              sd.Challenge,
		RP:                     makeOptRP,
		User:                   makeOptUser,
		Parameters:             params,
		Timeout:                timeout,
		AuthenticatorSelection: authSelector,
		AttestationType:        attType,
		Extensions:             res.Extensions{true},
	}

	JSONResponse(w, makeResponse, http.StatusOK)
}

// GetUserAndRelyingParty - Get the relevant user and rp for a given WebAuthn ceremony
func GetUserAndRelyingParty(username string, hostname string) (models.User, models.RelyingParty, error) {
	// Get Registering User
	user, err := models.GetUserByUsername(username)

	if err == gorm.ErrRecordNotFound {
		fmt.Println("No user record found with username ", username)
		err = errors.New("No User found")
		return user, models.RelyingParty{}, err
	}

	// Get Relying Party that is requesting Registration
	rp, err := models.GetRelyingPartyByHost(hostname)

	if err == gorm.ErrRecordNotFound {
		err = errors.New("No RP found")
		return user, rp, err
	}

	return user, rp, nil
}

// GetAssertion - assemble the data we need to make an assertion against
// a given user and authenticator
func GetAssertion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]
	timeout := 60000

	u, err := url.Parse(r.Referer())

	user, rp, err := GetUserAndRelyingParty(username, u.Hostname())
	if err != nil {
		fmt.Println("Couldn't Find the User or RP, most likely the User:", err)
		JSONResponse(w, "Couldn't Find User", http.StatusInternalServerError)
		return
	}

	sd, err := models.CreateNewSession(&user, &rp, "att")
	if err != nil {
		fmt.Println("Something went wrong creating session data:", err)
		JSONResponse(w, "Session Data Creation Error", http.StatusInternalServerError)
		return
	}

	creds, err := models.GetCredentialsForUserAndRelyingParty(&user, &rp)
	if err != nil {
		fmt.Println("No Credential Record Found:", err)
		JSONResponse(w, "Session Data Creation Error", http.StatusNotFound)
		return
	}

	session, _ := store.Get(r, "assertion-session")
	session.Values["session_id"] = sd.ID
	session.Save(r, w)

	type AllowedCredential struct {
		CredID     string   `json:"id"`
		Type       string   `json:"type"`
		Transports []string `json:"transports"`
	}

	type PublicKeyCredentialOptions struct {
		Challenge []byte              `json:"challenge,omitempty"`
		Timeout   int                 `json:"timeout,omitempty"`
		AllowList []AllowedCredential `json:"allowCredentials,omitempty"`
		RPID      string              `json:"rpId,omitempty"`
	}

	if err != nil {
		fmt.Println("Error Decoding Credential ID:", err)
		JSONResponse(w, "Error Decoding Credential ID", http.StatusNotFound)
		return
	}

	var acs []AllowedCredential

	for _, cred := range creds {
		ac := AllowedCredential{
			CredID:     cred.CredID,
			Type:       "public-key", // This should always be type 'public-key' for now
			Transports: []string{"usb", "nfc", "ble"},
		}
		acs = append(acs, ac)
	}

	assertionResponse := PublicKeyCredentialOptions{
		Challenge: sd.Challenge,
		Timeout:   timeout,
		AllowList: acs,
		RPID:      rp.ID,
	}

	JSONResponse(w, assertionResponse, http.StatusOK)
}

// MakeAssertion - Validate the Assertion Data provided by the authenticator and
// resond whether or not it was successful alongside the relevant credential.
func MakeAssertion(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "assertion-session")
	sessionID := session.Values["session_id"].(uint)
	sessionData, err := models.GetSessionData(sessionID)
	if err != nil {
		JSONResponse(w, "Missing Session Data Cookie", http.StatusBadRequest)
		return
	}

	encoder := b64.URLEncoding.Strict()
	encAssertionData, err := encoder.DecodeString(r.PostFormValue("authData"))
	if err != nil {
		fmt.Println("b64 Decode Error: ", err)
		JSONResponse(w, "Error decoding assertion data", http.StatusBadRequest)
		return
	}

	authData, err := ParseAssertionData(encAssertionData, r.PostFormValue("signature"))

	if err != nil {
		fmt.Println("Parse Assertion Error: ", err)
		JSONResponse(w, "Error parsing assertion data", http.StatusBadRequest)
		return
	}

	clientData, err := UnmarshallClientData(r.PostFormValue("clientData"))

	var credentialID string
	credentialID = r.FormValue("id")

	if credentialID == "" {
		JSONResponse(w, "Missing Credential ID", http.StatusBadRequest)
		return
	}

	verified, credential, _ := VerifyAssertionData(&clientData, &authData, &sessionData, credentialID)

	JSONResponse(w, res.CredentialActionResponse{
		Success:    verified,
		Credential: credential,
	}, http.StatusOK)
}

// CheckCredentialCounter - We may want to check for replay attacks but
// we definitely want to update the internal counter
// Note: this currently doesn't do that, lol
func CheckCredentialCounter(cred *models.Credential) error {
	return models.UpdateCredential(cred)
}

// VerifyAssertionData - Verifies that the Assertion data provided is correct and valid
func VerifyAssertionData(
	clientData *req.DecodedClientData,
	authData *req.DecodedAssertionData,
	sessionData *models.SessionData,
	credentialID string) (bool, models.Credential, error) {
	// Step 1. Using credential’s id attribute (or the corresponding rawId,
	// if base64url encoding is inappropriate for your use case), look up the
	// corresponding credential public key.

	fmt.Printf("Auth data is %+v\n", authData)

	// var credential models.Credential
	credential, err := models.GetCredentialForUser(&sessionData.User, credentialID)
	if err != nil {
		fmt.Println("Issue getting credential during Assertion")
		err := errors.New("Issue getting credential during Assertion")
		return false, credential, err
	}

	// Step 2. Let cData, aData and sig denote the value of credential’s
	// response's clientDataJSON, authenticatorData, and signature respectively.

	// Okeydoke

	// Step 3. Perform JSON deserialization on cData to extract the client data
	// C used for the signature.

	// Already done above

	fmt.Printf("Decoded Client Data: %+v\n", clientData)
	fmt.Printf("Auth Data: %+v\n", authData)

	credential.Counter = authData.Counter
	err = CheckCredentialCounter(&credential)
	if err != nil {
		fmt.Println("Error updating the the counter")
		err := errors.New("Error updating the the counter")
		return false, credential, err
	}

	// Step 4. Verify that the type in C is the string webauthn.create
	if clientData.ActionType != "webauthn.get" {
		fmt.Println("Client Request type is: ", string(clientData.ActionType))
		err := errors.New("The webauthn action type is incorrect")
		return false, credential, err
	}

	// Step 5. Verify that the challenge member of C matches the challenge that
	// was sent to the authenticator in the PublicKeyCredentialRequestOptions
	// passed to the get() call.
	sessionDataChallenge := strings.Trim(b64.URLEncoding.EncodeToString(sessionData.Challenge), "=")
	if sessionDataChallenge != clientData.Challenge {
		fmt.Println("Stored Challenge is: ", string(sessionDataChallenge))
		fmt.Println("Client Challenge is: ", string(clientData.Challenge))
		err := errors.New("Stored and Given Sessions do not match")
		return false, credential, err
	}

	// Step 6. Verify that the origin member of C matches the Relying Party's origin.
	cdo, err := url.Parse(clientData.Origin)
	if err != nil {
		fmt.Println("Error Parsing Client Data Origin: ", string(clientData.Origin))
		err := errors.New("Error Parsing the Client Data Origin")
		return false, credential, err
	}

	if sessionData.RelyingPartyID != cdo.Hostname() {
		fmt.Println("Stored Origin is: ", string(sessionData.RelyingPartyID))
		fmt.Println("Client Origin is: ", string(clientData.Origin))
		err := errors.New("Stored and Client Origin do not match")
		return false, credential, err
	}

	// Step 7. Verify that the tokenBindingId member of C (if present) matches the
	// Token Binding ID for the TLS connection over which the signature was obtained.

	// No Token Binding ID exists in this example. Sorry bruv

	// Step 8. Verify that the clientExtensions member of C is a subset of the extensions
	// requested by the Relying Party and that the authenticatorExtensions in C is also a
	// subset of the extensions requested by the Relying Party.

	// We don't have any clientExtensions

	// Step 9. Verify that the RP ID hash in aData is the SHA-256 hash of the RP ID expected
	// by the Relying Party.
	hasher := sha256.New()
	hasher.Write([]byte(config.Conf.HostAddress)) // We use our default RP ID - Host
	RPIDHash := hasher.Sum(nil)
	hexRPIDHash := hex.EncodeToString(RPIDHash)
	if hexRPIDHash != (authData.RPIDHash) {
		fmt.Println("Stored RP Hash is: ", hexRPIDHash)
		fmt.Println("Client RP Hash is: ", string(authData.RPIDHash))
		err := errors.New("Stored and Client RP ID Hash do not match")
		return false, credential, err
	}

	// Step 10. Let hash be the result of computing a hash over the cData using the
	// algorithm represented by the hashAlgorithm member of C.

	var clientDataHash []byte
	switch clientData.HashAlgorithm {
	case "SHA-512":
		h := sha512.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	case "SHA-256":
		h := sha256.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	default:
		// Currently, the Editor's Draft makes no mention of hashAlgorithm
		// in the client data, but we can default to SHA256.
		h := sha256.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	}

	// Step 11. Using the credential public key looked up in step 1, verify that sig
	// is a valid signature over the binary concatenation of aData and hash.
	binCat := append(authData.RawAssertionData, clientDataHash...)

	pubKey, err := models.GetPublicKeyForCredential(&credential)
	if err != nil {
		fmt.Println("Error retreiving Public Key for Credential")
		err := errors.New("Error retrieving public key for credential")
		return false, credential, err
	}

	var ecsdaSig struct {
		R, S *big.Int
	}

	sig := authData.Signature
	_, err = asn1.Unmarshal(sig, &ecsdaSig)
	if err != nil {
		return false, credential, errors.New("Error unmarshalling signature")
	}

	h := sha256.New()
	h.Write(binCat)

	return ecdsa.Verify(&pubKey, h.Sum(nil), ecsdaSig.R, ecsdaSig.S), credential, nil
}

// MakeNewCredential - Attempt to make a new credential given an authenticator's response
func MakeNewCredential(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}

	encodedAuthData, err := DecodeAttestationObject(r.PostFormValue("attObj"))
	decodedAuthData, err := ParseAuthData(encodedAuthData)

	if err != nil {
		JSONResponse(w, "Error parsing the authentication data", http.StatusNotFound)
		return
	}

	clientData, err := UnmarshallClientData(r.PostFormValue("clientData"))
	if err != nil {
		JSONResponse(w, "Error getting client data", http.StatusNotFound)
		return
	}

	session, err := store.Get(r, "registration-session")
	if err != nil {
		fmt.Println("Error getting session data", err)
		JSONResponse(w, "Error getting session data", http.StatusNotFound)
		return
	}

	sessionID := session.Values["session_id"].(uint)
	sessionData, err := models.GetSessionData(sessionID)

	verified, err := VerifyRegistrationData(&clientData, &decodedAuthData, &sessionData)

	if err != nil {
		fmt.Println("Error verifying credential", err)
		JSONResponse(w, "Error verifying credential", http.StatusBadRequest)
		return
	}

	if verified {
		newCredential := models.Credential{
			Counter:        decodedAuthData.Counter,
			RelyingPartyID: sessionData.RelyingPartyID,
			RelyingParty:   sessionData.RelyingParty,
			UserID:         sessionData.UserID,
			User:           sessionData.User,
			Format:         decodedAuthData.Format,
			Type:           r.PostFormValue("type"),
			Flags:          decodedAuthData.Flags,
			CredID:         r.PostFormValue("id"),
			PublicKey:      decodedAuthData.PubKey,
		}
		err := models.CreateCredential(&newCredential)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%+v\n", newCredential)
		JSONResponse(w, res.CredentialActionResponse{
			Success:    true,
			Credential: newCredential,
		}, http.StatusOK)
	} else {
		JSONResponse(w, res.CredentialActionResponse{
			Success:    false,
			Credential: models.Credential{},
		}, http.StatusOK)
	}
}

// VerifyRegistrationData - Verify that the provided Authenticator and Client
func VerifyRegistrationData(
	clientData *req.DecodedClientData,
	authData *req.DecodedAuthData,
	sessionData *models.SessionData) (bool, error) {

	fmt.Printf("Decoded Client Data: %+v\n", clientData)
	fmt.Printf("Auth Data: %+v\n", authData)

	// As per the spec we have already deserialized the
	// Auth Attestation Response and have extracted the client data (called C)
	// So step 1 is done, we have C

	// Step 2. Verify that the type in C is the string webauthn.create
	if clientData.ActionType != "webauthn.create" {
		fmt.Println("Client Request type is: ", string(clientData.ActionType))
		err := errors.New("The webauthn action type is incorrect")
		return false, err
	}

	// Step 3. Verify that the challenge in C matches the challenge
	// that was sent to the authenticator in the create() call.
	// C.challenge is returned without padding, so we trim our padding
	sessionDataChallenge := strings.Trim(b64.URLEncoding.EncodeToString(sessionData.Challenge), "=")
	if sessionDataChallenge != clientData.Challenge {
		fmt.Println("Stored Challenge is: ", string(sessionDataChallenge))
		fmt.Println("Client Challenge is: ", string(clientData.Challenge))
		err := errors.New("Stored and Given Sessions do not match")
		return false, err
	}

	// Step 4. Verify that to origin in C matches the relying party's origin
	cdo, err := url.Parse(clientData.Origin)
	if err != nil {
		fmt.Println("Error Parsing Client Data Origin: ", string(clientData.Origin))
		err := errors.New("Error Parsing the Client Data Origin")
		return false, err
	}

	if sessionData.RelyingPartyID != cdo.Hostname() {
		fmt.Println("Stored Origin is: ", string(sessionData.RelyingPartyID))
		fmt.Println("Client Origin is: ", string(clientData.Origin))
		err := errors.New("Stored and Client Origin do not match")
		return false, err
	}

	// Step 5. Verify that the tokenBindingID in C matches for the TLS connection
	// over which we handled this ceremony

	// we don't have this yet 'cus no TLS is necessary for local dev!

	// Step 6. Verify that the clientExtensions in C is a subset of the extensions
	// requested by the RP and that the authenticatorExtensions in C is also a
	// subset of the extensions requested by the RP.

	// We have no extensions yet!

	// Step 7. Compute the hash of clientDataJSON using the algorithm identified
	// by C.hashAlgorithm.
	// Let's also make sure that the Authenticator is using SHA-256 or SHA-512
	var clientDataHash []byte
	fmt.Println("Hash Alg:", clientData.HashAlgorithm)
	switch clientData.HashAlgorithm {
	case "SHA-512":
		h := sha512.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	case "SHA-256":
		h := sha256.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	default:
		// Currently, the Editor's Draft makes no mention of hashAlgorithm
		// in the client data, but we can default to SHA256.
		h := sha256.New()
		h.Write([]byte(clientData.RawClientData))
		clientDataHash = h.Sum(nil)
		fmt.Printf("Client data hash is %x\n", clientDataHash)
	}

	// Step 8. Perform CBOR decoding on the attestationObject field of
	// the AuthenticatorAttestationResponse structure to obtain the
	// attestation statement format fmt, the authenticator data authData,
	// and the attestation statement attStmt.

	// We've already done this an put it in authData

	// Step 9. Verify that the RP ID hash in authData is indeed the
	// SHA-256 hash of the RP ID expected by the RP.
	hasher := sha256.New()
	hasher.Write([]byte(config.Conf.HostAddress)) // We use our default RP ID - Host
	RPIDHash := hasher.Sum(nil)
	computedRPIDHash := hex.EncodeToString(RPIDHash)
	if string(computedRPIDHash) != (authData.RPIDHash) {
		fmt.Println("Stored RP Hash is: ", string(computedRPIDHash))
		fmt.Println("Client RP Hash is: ", string(authData.RPIDHash))
		err := errors.New("Stored and Client RP ID Hash do not match")
		return false, err
	}

	// Step 10. Determine the attestation statement format by performing
	// an USASCII case-sensitive match on fmt against the set of supported
	// WebAuthn Attestation Statement Format Identifier values.

	if authData.Format != "none" && authData.Format != "fido-u2f" {
		fmt.Println("Auth Data Format is incorrect:", authData.Format)
		err := errors.New("Auth data is not in proper format (none)")
		return false, err
	}

	isValid := false

	if authData.Format == "fido-u2f" {
		// Step 11. Verify that attStmt is a correct, validly-signed attestation
		// statement, using the attestation statement format fmt’s verification
		// procedure given authenticator data authData and the hash of the
		// serialized client data computed in step 6.

		// We start using FIDO U2F Specs here

		// If clientDataHash is 256 bits long, set tbsHash to this value.
		// Otherwise set tbsHash to the SHA-256 hash of clientDataHash.
		var tbsHash []byte
		if len(clientDataHash) == 32 {
			tbsHash = clientDataHash
		} else {
			hasher = sha256.New()
			hasher.Write(clientDataHash)
			tbsHash = hasher.Sum(nil)
		}

		// From authenticatorData, extract the claimed RP ID hash, the
		// claimed credential ID and the claimed credential public key.
		RPIDHash, err = hex.DecodeString(authData.RPIDHash)
		if err != nil {
			err := errors.New("Error decoding RPIDHash")
			return false, err
		}

		pubKey := authData.AttStatement.Certificate.PublicKey.(*ecdsa.PublicKey)
		fmt.Printf("Public Key from Certificate: %+v\n", authData.AttStatement.Certificate.PublicKey)
		fmt.Printf("Public Key from Auth Data: %+v\n", authData.PubKey)

		// We already have the claimed credential ID and PubKey

		assembledData, err := AssembleSignedRegistrationData(RPIDHash, tbsHash, authData.CredID, authData.PubKey)
		if err != nil {
			fmt.Println(err)
			return false, err
		}

		var ecsdaSig struct {
			R, S *big.Int
		}

		sig := authData.AttStatement.Signature

		_, err = asn1.Unmarshal(sig, &ecsdaSig)
		fmt.Printf("ECDSA SIG: %+v\n", ecsdaSig)
		if err != nil {
			return false, errors.New("Error unmarshalling signature")
		}

		h := sha256.New()
		h.Write(assembledData)
		isValid = ecdsa.Verify(pubKey, h.Sum(nil), ecsdaSig.R, ecsdaSig.S)
	} else {
		isValid = true
	}

	// Verification of attestation objects requires that the Relying Party has a trusted
	// method of determining acceptable trust anchors in step 11 above. Also, if certificates
	// are being used, the Relying Party must have access to certificate status information for
	// the intermediate CA certificates. The Relying Party must also be able to build the
	// attestation certificate chain if the client did not provide this chain in the attestation
	// information.

	// To avoid ambiguity during authentication, the Relying Party SHOULD check that
	// each credential is registered to no more than one user. If registration is
	// requested for a credential that is already registered to a different user, the
	// Relying Party SHOULD fail this ceremony, or it MAY decide to accept the registration,
	// e.g. while deleting the older registration.

	return isValid, err
}

// AssembleSignedRegistrationData - This takes data that was rendered during authenticatin and puts
// it into a format to be hashed and verified by the authenticator signature
func AssembleSignedRegistrationData(
	rpIDHash,
	tbsHash,
	credID []byte,
	pubKey models.PublicKey,
) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{0x00})
	buf.Write(rpIDHash)
	buf.Write(tbsHash)
	buf.Write(credID)
	buf.WriteByte(0x04)
	buf.Write(pubKey.XCoord)
	buf.Write(pubKey.YCoord)
	return buf.Bytes(), nil
}

// UnmarshallClientData - Unmarshall the ClientDataJSON provided by the authenticator.
// It is Base 64 encoded before being sent up to the server, so we b6 decode
// it first.
func UnmarshallClientData(clientData string) (req.DecodedClientData, error) {
	b64Decoder := b64.StdEncoding.Strict()
	clientDataBytes, _ := b64Decoder.DecodeString(clientData)
	var handler codec.Handle = new(codec.JsonHandle)
	var decoder = codec.NewDecoderBytes(clientDataBytes, handler)
	var ucd req.DecodedClientData
	err := decoder.Decode(&ucd)
	ucd.RawClientData = string(clientDataBytes)
	return ucd, err
}

// DecodeAttestationObject - Decode the authenticator Attestation Data from CBOR.
// It is Base 64 encoded before being sent up to the server, so we b6 decode
// it first.
func DecodeAttestationObject(rawAttObj string) (req.EncodedAuthData, error) {
	b64Decoder := b64.URLEncoding.Strict()
	attObjBytes, err := b64Decoder.DecodeString(rawAttObj)
	if err != nil {
		fmt.Println("b64 Decode error:", err)
		return req.EncodedAuthData{}, err
	}
	var handler codec.Handle = new(codec.CborHandle)
	var decoder = codec.NewDecoderBytes(attObjBytes, handler)
	var ead req.EncodedAuthData
	err = decoder.Decode(&ead)
	if err != nil {
		fmt.Println("CBOR Decode error:", err)
		return req.EncodedAuthData{}, err
	}
	return ead, err
}

// ParseAssertionData - Parses assertion data from byte array to a struct
func ParseAssertionData(assertionData []byte, hexSig string) (req.DecodedAssertionData, error) {
	decodedAssertionData := req.DecodedAssertionData{}

	rpID := assertionData[:32]
	rpIDHash := hex.EncodeToString(rpID)

	intFlags := assertionData[32]

	counter := assertionData[33:]

	if len(assertionData) > 38 {
		err := errors.New("assertionData byte array is too long")
		return decodedAssertionData, err
	}

	rawSig, err := hex.DecodeString(hexSig)
	if err != nil {
		return decodedAssertionData, err
	}

	decodedAssertionData = req.DecodedAssertionData{
		Flags:            intFlags,
		RPIDHash:         rpIDHash,
		Counter:          counter,
		RawAssertionData: assertionData,
		Signature:        rawSig,
	}

	return decodedAssertionData, err
}

// ParseAuthData - Parses the AuthData returned from the authenticator from a byte array
func ParseAuthData(ead req.EncodedAuthData) (req.DecodedAuthData, error) {
	decodedAuthData := req.DecodedAuthData{}

	rpID := ead.AuthData[:32]
	rpIDHash := hex.EncodeToString(rpID)

	intFlags := ead.AuthData[32]
	flags := fmt.Sprintf("%08b", intFlags)

	counter := ead.AuthData[33:38]

	if len(ead.AuthData) < 38 {
		err := errors.New("AuthData byte array is not long enough")
		return decodedAuthData, err
	}

	aaguid := ead.AuthData[38:54]

	credIDLen := ead.AuthData[53] + ead.AuthData[54]

	credID := ead.AuthData[55 : 55+credIDLen]

	cborPubKey := ead.AuthData[55+credIDLen:]

	var handler codec.Handle = new(codec.CborHandle)
	decoder := codec.NewDecoderBytes(cborPubKey, handler)

	var pubKey models.PublicKey
	err := decoder.Decode(&pubKey)
	if err != nil {
		fmt.Println("Error decoding the Public Key in Authentication Data")
		return decodedAuthData, err
	}

	decodedAuthData = req.DecodedAuthData{
		// Flags are used to determine user presence, user verification, and if attData is present
		Flags: []byte(flags),
		// Counter is used to prevent replay attacks
		Counter: counter,
		// RPIDHash is used to verify the Auth Request
		RPIDHash: rpIDHash,
		// AAGUID is the ID of the Authenticator device line
		AAGUID: aaguid,
		// CredID is the ID of the credential we are creating
		CredID: credID,
		// Public Key of the credential key pair
		PubKey: pubKey,
		// Format of the attestation statement (ex, "u2f", "safety-net"), currently defaults to "none"
		Format: ead.Format,
	}

	// If the format is one that contains an authenticator attestation certificate then parse it
	if ead.Format == "fido-u2f" {
		das, err := ParseAttestationStatement(ead.AttStatement)
		if err != nil {
			fmt.Println("Error parsing Attestation Statement from Authentication Data")
			return decodedAuthData, err
		}
		// The authenticator's attestation statement
		decodedAuthData.AttStatement = das
	}

	return decodedAuthData, err
}

// ParseAttestationStatement - parse the Attestation Certificate returned by the
// the authenticator
func ParseAttestationStatement(
	ead req.EncodedAttestationStatement) (req.DecodedAttestationStatement, error) {
	das := req.DecodedAttestationStatement{}
	// Currently, for fido-u2f formatted attStatements, we only support one x509 cert
	// but it is returned to us as an array
	cert, err := x509.ParseCertificate(ead.X509Cert[0])
	if err != nil {
		return das, err
	}
	das = req.DecodedAttestationStatement{
		Certificate: cert,
		Signature:   ead.Signature,
	}
	return das, nil
}

// CreateNewUser - hitting this endpoint with a new user will add it to the db
func CreateNewUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	icon := "example.icon.duo.com/123/avatar.png"
	if username == "" {
		JSONResponse(w, "username", http.StatusBadRequest)
		return
	}
	if email == "" {
		JSONResponse(w, "email", http.StatusBadRequest)
		return
	}

	u := models.User{
		Name:        email,
		DisplayName: username,
		Icon:        icon,
	}

	user, err := models.GetUserByUsername(u.Name)
	if err != gorm.ErrRecordNotFound {
		fmt.Println("Got user " + user.Name)
		JSONResponse(w, user, http.StatusOK)
		return
	}

	err = models.PutUser(&u)
	if err != nil {
		JSONResponse(w, "Error Creating User", http.StatusInternalServerError)
		return
	}

	JSONResponse(w, u, http.StatusCreated)
}

// GetUser - get a user from the db
func GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]
	u, err := models.GetUserByUsername(username)
	if err != nil {
		fmt.Println(err)
		JSONResponse(w, "User not found, try registering one first!", http.StatusNotFound)
		return
	}
	JSONResponse(w, u, http.StatusOK)
}

// GetCredentials - get a user's credentials from the db
func GetCredentials(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]
	u, _ := models.GetUserByUsername(username)
	cs, err := models.GetCredentialsForUser(&u)
	if err != nil {
		fmt.Println(err)
		JSONResponse(w, "", http.StatusNotFound)
	} else {
		JSONResponse(w, cs, http.StatusOK)
	}
}

// DeleteCredential - Delete a credential from the db
func DeleteCredential(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	credID := vars["id"]
	err := models.DeleteCredentialByID(credID)
	fmt.Println("Deleting credential with ID ", credID)
	if err != nil {
		fmt.Println(err)
		JSONResponse(w, "Credential not Found", http.StatusNotFound)
	} else {
		JSONResponse(w, "Success", http.StatusOK)
	}
}

// CreateRouter creates the http.Handler used for web-authn and sets up the valid endpoints
func CreateRouter() http.Handler {
	router := mux.NewRouter()
	// New handlers should be added here
	router.HandleFunc("/", Login)
	router.HandleFunc("/dashboard/{name}", Index)
	router.HandleFunc("/dashboard", Index)
	router.HandleFunc("/makeCredential/{name}", RequestNewCredential).Methods("GET")
	router.HandleFunc("/makeCredential", MakeNewCredential).Methods("POST")
	router.HandleFunc("/assertion/{name}", GetAssertion).Methods("GET")
	router.HandleFunc("/assertion", MakeAssertion).Methods("POST")
	router.HandleFunc("/user", CreateNewUser).Methods("POST")
	router.HandleFunc("/user/{name}", GetUser).Methods("GET")
	router.HandleFunc("/credential/{name}", GetCredentials).Methods("GET")
	router.HandleFunc("/credential/{id}", DeleteCredential).Methods("DELETE")
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
	return router
}

func main() {
	config.LoadConfig("config.json")
	fmt.Printf("Config: %+v\n", config.Conf)
	err := models.Setup()
	if err != nil {
		fmt.Println(err)
	}
	// Start Web Server
	if config.Conf.HasProxy {
		log.Fatal(http.ListenAndServe(config.Conf.HostPort, CreateRouter()))
	} else {
		log.Fatal(http.ListenAndServe(config.Conf.HostAddress+config.Conf.HostPort, CreateRouter()))
	}
}
