class WebAuthn {
    // Encode Array Buffers to Base64 Values 
    EncodeB64(buf) {
        return btoa(new Uint8Array(buf).reduce((s, byte) => s + String.fromCharCode(byte), ''));
    }

    // Helper functions for parsing/examining the authenticator responses before
    // being sent to the server
    
    // Decode B64 to an array buffer
    DecodeB64(b64) {
        return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    }

    
}