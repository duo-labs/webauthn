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

Important Notes
---------------

Currently WebAuthn works in [Firefox's Nightly Build](https://download.mozilla.org/?product=firefox-nightly-latest-ssl&os=osx&lang=en-US) and [Chrome Canary](https://www.google.com/chrome/browser/canary.html).

If you're using Firefox, enable `webauthn`:
1. Open the Firefox advanced preferences at the URL (about:config)[about:config]. These are feature flags for FF Nightly.
2. Search for "webauth"
3. Enable `value=True` for:
* `security.webauth.webauthn`
4. Reload the page and you're ready to go!