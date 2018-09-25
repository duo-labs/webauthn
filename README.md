WebAuthn Demo
=============

This Go application is meant to be a demonstration of how the [Web Authentication](https://w3c.github.io/webauthn) specification works.


Quickstart
----------

1. Clone the repo into your working directory
2. [Install Go](https://golang.org/doc/install) and set it up if you haven't already
3. Retrieve all go dependencies (`$ go get .`)
4. Copy or rename `config.template.json` to `config.json`, remove comments, and edit if need be.
5. Build and run the application (`$ go build; ./webauthn`)

Implementation Notes
---------------

Currently WebAuthn works in [Firefox](https://www.mozilla.org/en-US/firefox/new/) and [Chrome](https://www.google.com/chrome/).  Watch the the [up-to-date list of supported browsers](https://caniuse.com/#search=webauthn) to find out when other browsers support the Webauthn standard.

