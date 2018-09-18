function hexEncode(buf) {
    return Array.from(buf)
        .map(function (x) {
            return ("0" + x.toString(16)).substr(-2)
        })
        .join("");
}

function hexDecode(str) {
    return new Uint8Array(str.match(/../g).map(function (x) { return parseInt(x, 16) }));
}

function b64enc(buf) {
    return base64js.fromByteArray(buf)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

// Don't drop any blanks
function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function string2buffer(str) {
    return (new Uint8Array(str.length)).map(function (x, i) {
        return str.charCodeAt(i)
    });
}

function buffer2string(buf) {
    let str = "";
    if (!(buf.constructor === Uint8Array)) {
      buf = new Uint8Array(buf);
    }
    buf.map(function(x){ return str += String.fromCharCode(x) });
    return str;
}

var state = {
    createResponse: null,
    publicKeyCredential: null,
    credential: null,
    user: {
        name: "testuser@example.com",
        displayName: "testuser",
    },
}

function setUser() {
    username = $("#input-email").val();  
    state.user.name = username.toLowerCase().replace(/\s/g, '') + "@example.com";
    state.user.displayName = username.toLowerCase();
}

function checkUserExists() {    
    $.get('/user/' + state.user.name, {}, null, 'json')
        .done(function (response) {
            return true;
    }).catch(function() {return false;});
}

function getCredentials() {
    $.get('/credential/' + state.user.name, {}, null, 'json')
        .done(function (response) {
            console.log(response)
    });
}

function makeCredential() {
    hideErrorAlert();
    console.log("Fetching options for new credential");
    if ($("#input-email").val() === "") {
        showErrorAlert("Please enter a username");
        return;
    }
    setUser();
    var credential = null;
    swal({
        title: 'Registering...',
        text: 'Tap your security key to finish registration.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false,
    }).then(function () {
        swal({
            title: 'Registration Successful!',
            text: 'You\'ve registered successfully.',
            type: 'success',
            timer: 2000
        })
    }).catch(function(error) {
        console.log("Modal Error: " + error);
    });

    var attestation_type = $('#select-attestation').find(':selected').val();    
    var authenticator_attachment = $('#select-authenticator').find(':selected').val();    

    $.get('/makeCredential/' + state.user.name, {attType: attestation_type, authType: authenticator_attachment}, null, 'json')
        .done(function (makeCredentialOptions) {
            console.log("Credential Options Object");
            console.log(makeCredentialOptions);

            // Turn the challenge back into the accepted format
            makeCredentialOptions.challenge = Uint8Array.from(atob(makeCredentialOptions.challenge), c => c.charCodeAt(0));
            // Turn ID into a UInt8Array Buffer for some reason
            makeCredentialOptions.user.id = Uint8Array.from(makeCredentialOptions.challenge)

            console.log("Credential Options Formatted");
            console.log(makeCredentialOptions);

            console.log("Creating PublicKeyCredential");
            navigator.credentials.create({
                publicKey: makeCredentialOptions
            }).then(function (newCredential) {
                    console.log("PublicKeyCredential Created");
                    console.log(newCredential);
                    state.createResponse = newCredential;
                    registerNewCredential(newCredential);
                    swal.clickConfirm()
            }).catch(function (err) {
                console.log(err);
                swal.closeModal();
            });
        });
}

// This should be used to verify the auth data with the server
function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);

    $.post('/makeCredential', {
        id: newCredential.id,
        rawId: b64enc(rawId),
        type: newCredential.type,
        attObj: b64RawEnc(attestationObject),
        clientData: b64RawEnc(clientDataJSON),
     }).done(function(response){
        if (response.success) {
            window.location.href = "/dashboard/" + state.user.displayName;
        } else {
            console.log("Error creating credential");
            console.log(response);
        }
    });
}

function addUserErrorMsg(msg) {
    if (msg === "username") {
        msg = 'Please add username';
    } else {
        msg = 'Please add email';
    }
    document.getElementById("user-create-error").innerHTML = msg;
}

function getAssertion() {
    hideErrorAlert();
    if ($("#input-email").val() === "") {
        showErrorAlert("Please enter a username");
        return;
    }
    setUser();
    $.get('/user/' + state.user.name, {}, null, 'json').done(function (response) {
        console.log(response);
    }).then(function() {        
        swal({
            title: 'Logging In...',
            text: 'Tap your security key to login.',
            imageUrl: "/images/securitykey.min.svg",
            showCancelButton: true,
            showConfirmButton: false,
            focusConfirm: false,
            focusCancel: false,        
        }).then(function () {
            swal({
                title: 'Logged In!',
                text: 'You\'re logged in successfully.',
                type: 'success',
                timer: 2000
            })
        }).catch(function(error) {
            console.log("Modal Error: " + error);
        });
    }).catch(function(error) {    
        showErrorAlert(error.responseText);        
        return;
    });

    $.get('/assertion/' + state.user.name, {
    }, null, 'json')
        .done(function (makeAssertionOptions) {
            makeAssertionOptions.challenge = Uint8Array.from(atob(makeAssertionOptions.challenge), c => c.charCodeAt(0));
            makeAssertionOptions.allowCredentials.forEach(function (listItem) {
                var fixedId = listItem.id.replace(/\_/g, "/").replace(/\-/g, "+")
                listItem.id = Uint8Array.from(atob(fixedId), c => c.charCodeAt(0));
            });
            console.log(makeAssertionOptions);
            navigator.credentials.get({ publicKey: makeAssertionOptions })
                .then(function (credential) {
                    console.log(credential);
                    verifyAssertion(credential);
                    swal.clickConfirm();
                }).catch(function (err) {
                    console.log(err);
                    showErrorAlert(err.message);
                    swal.closeModal();
                });
        });
}

function verifyAssertion(assertedCredential) {
    // Move data into Arrays incase it is super long
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    $.post('/assertion', {
        id: assertedCredential.id,
        rawId: b64enc(rawId),
        type: assertedCredential.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
     }).done(function(response){
        console.log(response)
        if (response.success) {
            window.location.href = "/dashboard/" + state.user.displayName;
        } else {
            showErrorAlert("Error Doing Assertion");
            swal.closeModal();
        }
    });
}

function setCurrentUser(userResponse) {
    state.user.name = userResponse.name;
    state.user.displayName = userResponse.display_name;
}

function showErrorAlert(msg) {    
    $("#alert-msg").text(msg);    
    $("#user-alert").show();    
}

function hideErrorAlert() {
    $("#user-alert").hide();    
}