WebAuthn Library
=============
[![GoDoc](https://godoc.org/github.com/duo-labs/webauthn?status.svg)](https://godoc.org/github.com/duo-labs/webauthn)
![Build Status](https://github.com/duo-labs/webauthn/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/duo-labs/webauthn)](https://goreportcard.com/report/github.com/duo-labs/webauthn)


This library is meant to handle [Web Authentication](https://w3c.github.io/webauthn) for Go apps that wish to implement a passwordless solution for users. While the specification is currently in Candidate Recommendation, this library conforms as much as possible to 
the guidelines and implementation procedures outlined by the document.

### Demo at webauthn.io
An implementation of this library can be used at [webauthn.io](https://webauthn.io) and the code for this website can be found in the Duo Labs repository [`webauthn-io`](https://github.com/duo-labs/webauthn.io).

### Simplified demo
A simplified demonstration of this library can be found [here](https://github.com/hbolimovsky/webauthn-example). It includes a minimal interface and is great for quickly testing out the code. The associated blog post can be found [here]().

Quickstart
----------
`go get github.com/duo-labs/webauthn` and initialize it in your application with basic configuration values. 

Make sure your `user` model is able to handle the interface functions laid out in `webauthn/user.go`. This means also supporting the storage and retrieval of the credential and authenticator structs in `webauthn/credential.go` and `webauthn/authenticator.go`, respectively.

### Initialize the request handler
```golang
import "github.com/duo-labs/webauthn/webauthn"

var (
    web *webauthn.WebAuthn
    err error
)

// Your initialization function
func main() {
    web, err = webauthn.New(&webauthn.Config{
        RPDisplayName: "Duo Labs", // Display Name for your site
        RPID: "duo.com", // Generally the FQDN for your site
        RPOrigin: "https://login.duo.com", // The origin URL for WebAuthn requests
        RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
    })
    if err != nil {
        fmt.Println(err)
    }
}

```

### Registering an account

```golang
func BeginRegistration(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Find or create the new user  
    options, sessionData, err := web.BeginRegistration(&user)
    // handle errors if present
    // store the sessionData values 
    JSONResponse(w, options, http.StatusOK) // return the options generated
    // options.publicKey contain our registration options
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Get the user  
    // Get the session data stored from the function above
    // using gorilla/sessions it could look like this
    sessionData := store.Get(r, "registration-session")
    parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
    credential, err := web.CreateCredential(&user, sessionData, parsedResponse)
    // Handle validation or input errors
    // If creation was successful, store the credential object
    JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}
```

### Logging into an account
```golang
func BeginLogin(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Find the user
    options, sessionData, err := webauthn.BeginLogin(&user)
    // handle errors if present
    // store the sessionData values
    JSONResponse(w, options, http.StatusOK) // return the options generated
    // options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Get the user 
    // Get the session data stored from the function above
    // using gorilla/sessions it could look like this
    sessionData := store.Get(r, "login-session")
    parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
    credential, err := webauthn.ValidateLogin(&user, sessionData, parsedResponse)
    // Handle validation or input errors
    // If login was successful, handle next steps
    JSONResponse(w, "Login Success", http.StatusOK)
}
```

Modifying Credential Options
----------------------------
You can modify the default credential creation options for registration and login by providing optional structs to the `BeginRegistration` and `BeginLogin` functions. 

### Registration modifiers
You can modify the registration options in the following ways:
```golang
// Wherever you handle your WebAuthn requests
import "github.com/duo-labs/webauthn/protocol"
import "github.com/duo-labs/webauthn/webauthn"

var webAuthnHandler webauthn.WebAuthn // init this in your init function

func beginRegistration() {
    // Updating the AuthenticatorSelection options. 
    // See the struct declarations for values
    authSelect := protocol.AuthenticatorSelection{        
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey: protocol.ResidentKeyUnrequired(),
        UserVerification: protocol.VerificationRequired
    }

    // Updating the ConveyencePreference options. 
    // See the struct declarations for values
    conveyencePref := protocol.ConveyancePreference(protocol.PreferNoAttestation)

    user := datastore.GetUser() // Get the user  
    opts, sessionData, err webAuthnHandler.BeginRegistration(&user, webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))

    // Handle next steps
}

```

### Login modifiers
You can modify the login options to allow only certain credentials:
```golang
// Wherever you handle your WebAuthn requests
import "github.com/duo-labs/webauthn/protocol"
import "github.com/duo-labs/webauthn/webauthn"

var webAuthnHandler webauthn.WebAuthn // init this in your init function

func beginLogin() {
    // Updating the AuthenticatorSelection options. 
    // See the struct declarations for values
    allowList := make([]protocol.CredentialDescriptor, 1)
    allowList[0] = protocol.CredentialDescriptor{
        CredentialID: credentialToAllowID,
        Type: protocol.CredentialType("public-key"),
    }

    user := datastore.GetUser() // Get the user  

    opts, sessionData, err := webAuthnHandler.BeginLogin(&user, webauthn.wat.WithAllowedCredentials(allowList))

    // Handle next steps
}

```

Acknowledgements
----------------
I could not have made this library without the work of [Jordan Wright](https://twitter.com/jw_sec) and the designs done for our demo site by [Emily Rosen](http://www.emiroze.design/). When I began refactoring this library in December 2018, [Koen Vlaswinkel's](https://github.com/koesie10) Golang WebAuthn library really helped set me in the right direction. A huge thanks to [Alex Seigler](https://github.com/aseigler) for his continuing work on this WebAuthn library and many others. Thanks to everyone who submitted issues and pull requests to help make this library what it is today!
