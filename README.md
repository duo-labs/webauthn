WebAuthn Demo
=============

This Go application is meant to be a demonstration of how the [Web Authentication](https://w3c.github.io/webauthn) specification works.


Quickstart
----------

1. Clone the repo into your working directory
2. [Install Go](https://golang.org/doc/install) and set it up if you haven't already
3. Retrieve all go dependencies (`$ go get .`)
4. Copy or rename `config.template.json` to `config.json` and edit if need be.
5. Build and run the application (`$ ./webauthn`)

Important Notes
---------------
Currently WebAuthn only works in [Firefox's Beta Build](https://download.mozilla.org/?product=firefox-beta-latest-ssl&os=osx&lang=en-US) or [Chrome's Dev 
Channel](https://www.chromium.org/getting-involved/dev-channel) (U2F tokens only in Chrome)  
After installing:  
  
Firefox:
1. Open the Firefox advanced preferences at the URL (about:config)[about:config]. These are feature flags for FF Nightly.
2. Search for "webauth"
3. Enable `value=True` for:
* `security.webauth.webauthn`
4. Reload the page and you're ready to go!
  
Chrome:
1. Open the Chrome experimental features page at the URL(chrome://flags)[chrome://flags]. These are feature flags for Chrome.
2. Search for "Web Authentication"
3. Change `Web Authentication API` to `Enabled`
4. Restart Chrome and you're ready to go!

