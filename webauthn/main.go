package webauthn

import (
	"fmt"
	"net/url"

	"github.com/duo-labs/webauthn/protocol"
)

var defaultTimeout = 60000

// WebAuthn is the primary interface of this package and contains the request handlers that should be called.
type WebAuthn struct {
	Config *Config
}

type Config struct {
	RelyingPartyDisplayName string
	RelyingPartyID          string
	RelyingPartyIcon        string
	// Defaults for generating options
	AttestationPreference  protocol.ConveyancePreference
	AuthenticatorSelection protocol.AuthenticatorSelection

	Timeout int
	Debug   bool
}

func (config *Config) validate() error {
	if len(config.RelyingPartyDisplayName) == 0 {
		return fmt.Errorf("Missing RelyingPartyDisplayName")
	}

	if len(config.RelyingPartyID) == 0 {
		return fmt.Errorf("Missing RelyingPartyID")
	}

	_, err := url.Parse(config.RelyingPartyID)
	if err != nil {
		return fmt.Errorf("RelyingPartyID not valid URI: %+v", err)
	}

	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}

	return nil
}

func New(config *Config) (*WebAuthn, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("Configuration error: %+v", err)
	}
	return &WebAuthn{
		config,
	}, nil
}
