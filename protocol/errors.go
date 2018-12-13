package protocol

import (
	"net/http"
)

type Error struct {
	Type       string `json:"type"`
	Details    string `json:"error"`
	DevInfo    string `json:"debug"`
	StatusCode int    `json:"status_code,omitempty"`
}

var (
	ErrBadRequest = &Error{
		Type:       "invalid_request",
		Details:    "Error reading the requst data",
		StatusCode: http.StatusBadRequest,
	}
	ErrChallengeMismatch = &Error{}
	ErrParsingData       = &Error{
		Type:       "parse_error",
		Details:    "Error parsing the authenticator response",
		StatusCode: http.StatusBadRequest,
	}
	ErrVerification = &Error{
		Type:    "verification_error",
		Details: "Error validating the authenticator response",
	}
	ErrAttestationFormat = &Error{
		Type:    "invalid_attestation",
		Details: "Invalid Attestation Format",
	}
	ErrUnsupportedKey = &Error{
		Type:    "invalid_key_type",
		Details: "Unsupported Public Key Type",
	}
	ErrUnsupportedAlgorithm = &Error{
		Type:    "unsupported_key_algorithm",
		Details: "Unsupported public key algorithm",
	}
	ErrNotSpecImplemented = &Error{
		Type:    "spec_unimplemented",
		Details: "This field is not yet supported by the WebAuthn spec",
	}
	ErrNotImplemented = &Error{
		Type:    "not_implemented",
		Details: "This field is not yet supported by this library",
	}
)

func (err *Error) Error() string {
	return err.Details
}

func (passedError *Error) WithDetails(details string) *Error {
	err := *passedError
	err.Details = details
	return &err
}

func (passedError *Error) WithInfo(info string) *Error {
	err := *passedError
	err.DevInfo = info
	return &err
}
