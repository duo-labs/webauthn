WebAuthn Library
=============

This library is meant to handle [Web Authentication](https://w3c.github.io/webauthn) for Go apps that wish to implement a passwordless solution for users. While the specification is currently in Candidate Recommendation, this library conforms as much as possible to 
the guidelines and implementation procedures outlined by the document.


Quickstart
----------
Import `github.com/duo-labs/webauthn` into your golang web application and initialize it with basic configuration values. 

Make sure your `user` model is able to handle the interface functions laid out in `webauthn/user.go`. This means also supporting the storage and retrieval of the credential and authenticator structs in `webauthn/credential.go` and `webauthn/authenticator.go`, respectively.

```
import "github.com/duo-labs/webauthn"

var webauthn webauthn.WebAuthn

// Your initialization function
func main() {
    webauthn = webauthn.New(&webauthn.Config{
        RPDisplayName: "Duo Labs", // Display Name for your site
        RPID: "duo.com", // Generally the FQDN for your site
        RPOrigin: "https://login.duo.com", // The origin URL for WebAuthn requests
        RPID: "https://duo.com/logo.png", // Optional icon URL for your site
    })
}

// Registering an account

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Find or create the new user  
    options, sessionData, err := webauthn.BeginRegistration(&user)
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
    credential, err := webauthn.FinishRegistration(&user, sessionData, r)
    // Handle validation or input errors
    // If creation was successful, store the credential object
    JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}


// Logging into an account

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
    credential, err := webauthn.FinishLogin(&user, sessionData, r)
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
```
// Wherever you handle your WebAuthn requests
import "github.com/duo-labs/webauthn/protocol"
import "github.com/duo-labs/webauthn"

var webauthn webauthn.WebAuthn

func beginRegistration() {
    // Updating the AuthenticatorSelection options. 
    // See the struct declarations for values
    authSelect := protocol.AuthenticatorSelection{        
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey: false,
        UserVerification: protocol.VerificationRequired
    }
}

```

Acknowledgements
----------------
I could not have made this library without the work of [Jordan Wright](https://twitter.com/jw_sec) and the designs done for our demo site by [Emily Rosen](http://www.emiroze.design/). When I began refactoring this library in December 2018, [Koen Vlaswinkel's](https://github.com/koesie10) golang webauthn library really helped set me in the right direction. Thanks to everyone who submitted issues and pull requests to help make this library what it is today!