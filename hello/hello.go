package hello

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/duo-labs/webauthn/models"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
)

var store = sessions.NewCookieStore([]byte("duo-rox"))

// Microsoft's implementation of WebAuthn is *very* behind, so I'm
// seperating it out from main.go so when they inevitably catch up
// to the more recent spec reqs, it should be easy for us to cut over

type AccountInfo struct {
	RelyingPartyDisplayName string `json:"rpDisplayName"`
	UserDisplayName         string `json:"displayName"`
	Username                string `json:"type"`
	UserID                  string `json:"transports"`
}

// CryptoParams right now should always be set where the type is
// always 'ScopedCred' and algorithm is 'RS256' || 'RSASSA-PKCS1-v1_5'
type CryptoParams struct {
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
}

func NewCryptoParams() CryptoParams {
	params := CryptoParams{}
	params.Type = "ScopedCred"
	params.Algorithm = "RSASSA-PKCS1-v1_5"

	return params
}

type Credential struct {
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
}

type MakeCredentialOptions struct {
	Timeout        int          `json:"timeoutSeconds"`
	RelyingPartyID string       `json:"rpId"`
	ExcludeLists   []Credential `json:"excludeList"`
	// Add Extensions
}

type HelloResponse struct {
	AccountInfo          AccountInfo           `json:"accountInfo"`
	CryptoParams         []CryptoParams        `json:"cryptoParameters"`
	AttestationChallenge []byte                `json:"attestationChallenge"`
	Options              MakeCredentialOptions `json:"options"`
}

func createHelloChallenge(len int) ([]byte, error) {
	challenge := make([]byte, len)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	return challenge, nil
}

func MakeNewHelloCredential(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["name"]
	timeout := 60

	challenge, _ := createHelloChallenge(16)

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

	u, err := url.Parse(r.Referer())

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

	acct := AccountInfo{
		RelyingPartyDisplayName: rp.DisplayName,
		UserDisplayName:         user.DisplayName,
		Username:                user.Name,
		UserID:                  "42",
	}

	crypto := NewCryptoParams()

	options := MakeCredentialOptions{
		Timeout:        timeout,
		RelyingPartyID: rp.ID,
		ExcludeLists:   []Credential{},
	}

	resp := HelloResponse{
		AccountInfo:          acct,
		CryptoParams:         []CryptoParams{crypto},
		AttestationChallenge: challenge,
		Options:              options,
	}

	JSONResponse(w, resp, http.StatusOK)
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
