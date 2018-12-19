package protocol

// Extensions are discussed in §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn/#extensions).
// While they are talked about and have examples in the spec, they are currently not implemented
// fully by browsers. Further work is planned to take place in Level 2 of the spec.

// This is currently not fully implemented in the specification.
type AuthenticationExtensionsClientOutputs map[interface{}]interface{}
