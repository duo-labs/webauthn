WebAuthn Library
=============

This Go application is meant to handle [Web Authentication](https://w3c.github.io/webauthn) for Go web applications that want to implement a passwordless solution for users. While the specification is currently in Candidate Recommendation, this library conforms as much as possible to 
the guidelines and implementation procedures outlined by the document.


Quickstart
----------
Import `github.com/duo-labs/webauthn` into your golang web application and initialize it with basic configuration values. 
```
import "github.com/duo-labs/webauthn"

var webauthn webauthn.webauthn

func main() {
    webauthn = webauthn.New(&webauthn.Config{
        RPDisplayName: "Duo Labs", // Display Name for your site
        RPID: "duo.com", // Generally the FQDN for your site
        RPOrigin: "https://login.duo.com", // The origin URL for WebAuthn requests
        RPID: "https://duo.com/logo.png", // Optional icon URL for your site
    })
}

func handleRegistration(w http.ResponseWriter, r *http.Request)
```
Acknowledgements
----------------