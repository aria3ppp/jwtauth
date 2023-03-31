package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

func NewHMACKey(
	kid string,
	key []byte,
	signingMethod *jwt.SigningMethodHMAC,
) *Key {
	return &Key{
		Kid:           kid,
		SigningKey:    key,
		VerifyingKey:  key,
		SigningMethod: signingMethod,
	}
}

func NewECDSAKey(
	kid string,
	key *ecdsa.PrivateKey,
	signingMethod *jwt.SigningMethodECDSA,
) *Key {
	return &Key{
		Kid:           kid,
		SigningKey:    key,
		VerifyingKey:  &key.PublicKey,
		SigningMethod: signingMethod,
	}
}

func NewRSAKey(
	kid string,
	key *rsa.PrivateKey,
	signingMethod *jwt.SigningMethodRSA,
) *Key {
	return &Key{
		Kid:           kid,
		SigningKey:    key,
		VerifyingKey:  &key.PublicKey,
		SigningMethod: signingMethod,
	}
}

type Key struct {
	Kid           string            // jwt 'kid' header value to identify the correct key for verifying
	SigningKey    any               // key used for signing: symmetric methods have the same signing and verifying key
	VerifyingKey  any               // key used for verifying: symmetric methods have the same signing and verifying key
	SigningMethod jwt.SigningMethod // key signing method
	deprecated    bool
}

// Mark the key as deprecated.
// Deprecated keys are used only for verifying and not signing.
func (key *Key) Deprecated() *Key {
	key.deprecated = true
	return key
}
