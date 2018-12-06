package protocol

import (
	"crypto/rand"
)

// ChallengeLength - Length of bytes to generate for a challenge
const ChallengeLength = 32

// Challenge - Challenge that should be signed and returned by the authenticator
type Challenge []byte

// CreateChallenge - Create a new challenge to be sent to the authenticator
func CreateChallenge() (Challenge, error) {
	challenge := make([]byte, ChallengeLength)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	return challenge, nil
}
