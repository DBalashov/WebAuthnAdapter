// COMMON
function WebAuthnFromBase64(base64) {
    var byteCharacters = atob(base64);
    var byteNumbers = new Array(byteCharacters.length);
    for (var i = 0; i < byteCharacters.length; i++)
        byteNumbers[i] = byteCharacters.charCodeAt(i);
    return new Uint8Array(byteNumbers);
}

function WebAuthnToBase64(o) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(o)));
}

// REGISTRATION
function WebAuthnRegBuildPublicKey(challenge, relyingPartyId, userName) {
    return {
        challenge: WebAuthnFromBase64(challenge),
        pubKeyCredParams: [{
            type: 'public-key',
            alg: -7 // Request ES256 algorithm,
        }],
        rp: {
            id: relyingPartyId,
            name: relyingPartyId
        },
        user: {
            id: new TextEncoder('utf-8').encode(userName),
            name: userName,
            displayName: userName
        }
    };
}

function WebAuthnCallRegistration(publicKey, callbackUrl, callbackSuccess, callbackFailed) {
    callbackFailed = callbackFailed || function () {
        console.log('WebAuthnCallRegistration: failed');
    };

    var userName = publicKey.user.name;
    if (navigator.credentials == null) {
        callbackFailed('HTTPS required');
        return;
    }

    navigator.credentials.create({publicKey}).then(function (credentials) {
        var data = {
            transports: credentials.response.getTransports(),
            attestationObject: WebAuthnToBase64(credentials.response.attestationObject),
            clientData: JSON.parse(new TextDecoder().decode(credentials.response.clientDataJSON)),
            userName: userName
        };
        
        fetch(callbackUrl, {
            method: "post",
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        }).then(response => {
            if (response.ok) callbackSuccess();
            else callbackFailed(response.statusText);
        }).catch(callbackFailed);
    }).catch(callbackFailed);
}

// AUTHENTICATION

function WebAuthnAuthBuildPublicKey(challenge, relyingPartyId, credentialId) {
    return {
        challenge: WebAuthnFromBase64(challenge),
        allowCredentials: [{
            type: 'public-key',
            id: WebAuthnFromBase64(credentialId)
        }],
        rpId: relyingPartyId
    };
}

function WebAuthnCallAuthentication(publicKey, userName, callbackUrl, callbackSuccess, callbackFailed) {
    callbackFailed = callbackFailed || function () {
        console.log('WebAuthnCallAuthentication: failed');
    };
    if (navigator.credentials == null) {
        callbackFailed('HTTPS required');
        return;
    }

    navigator.credentials.get({publicKey}).then(function (credentials) {
        var data = {
            credentialId: WebAuthnToBase64(credentials.rawId),
            authenticatorData: WebAuthnToBase64(credentials.response.authenticatorData),
            clientData: WebAuthnToBase64(credentials.response.clientDataJSON),
            signature: WebAuthnToBase64(credentials.response.signature),
            type: credentials.type,
            userName: userName
        };

        fetch(callbackUrl, {
            method: "post",
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        }).then(response => {
            if (response.ok) callbackSuccess();
            else callbackFailed(response.statusText);
        }).catch(callbackFailed);
    }).catch(callbackFailed);
}