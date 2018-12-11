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
