package protocol

import (
	"net/http"
)

type Error struct {
	Type       string `json:"error"`
	Details    string `json:"error"`
	StatusCode int    `json:"status_code,omitempty"`
}

var (
	ErrBadRequest = &Error{
		Type:       "invalid_request",
		Details:    "Error reading the requst data",
		StatusCode: http.StatusBadRequest,
	}
	ErrChallengeMismatch = &Error{}
)

func (err *Error) Error() string {
	return err.Type
}

func (passedError *Error) WithDetails(details string) *Error {
	err := *passedError
	err.Details = details
	return &err
}
