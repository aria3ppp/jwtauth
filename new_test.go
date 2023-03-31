package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var (
	ecdsaPrivateKey *ecdsa.PrivateKey
	rsaPrivateKey   *rsa.PrivateKey
)

func init() {
	var err error

	keyBytes, err := os.ReadFile(
		filepath.Join("testdata", "ec_private_key.pem"),
	)
	if err != nil {
		panic(err)
	}
	ecdsaPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(keyBytes)
	if err != nil {
		panic(err)
	}

	keyBytes, err = os.ReadFile(
		filepath.Join("testdata", "rsa_private_key.pem"),
	)
	if err != nil {
		panic(err)
	}
	rsaPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		panic(err)
	}
}

func TestNew(t *testing.T) {
	require := require.New(t)

	type CustomClaims struct {
		UserID  string `json:"user_id"`
		IsAdmin bool   `json:"id_admin"`
	}

	require.PanicsWithValue("at least one key must provided", func() {
		_ = NewWithClock[CustomClaims](TimeClock{}, 0)
	})

	require.PanicsWithValue("kid \"kid\" set by another key", func() {
		_ = NewWithClock[CustomClaims](
			TimeClock{},
			0,
			NewHMACKey("kid", []byte{}, jwt.SigningMethodHS256),
			NewHMACKey("kid", []byte{}, jwt.SigningMethodHS256),
		)
	})

	keys := []*Key{
		NewECDSAKey(
			"kid#1",
			ecdsaPrivateKey,
			jwt.SigningMethodES256,
		),
		NewHMACKey(
			"kid#2",
			[]byte("secret"),
			jwt.SigningMethodHS256,
		).Deprecated(),
		NewRSAKey(
			"kid#3",
			rsaPrivateKey,
			jwt.SigningMethodRS256,
		),
		NewHMACKey(
			"kid#4",
			[]byte("another_secret"),
			jwt.SigningMethodHS256,
		).Deprecated(),
	}

	auth := NewWithClock[CustomClaims](TimeClock{}, 15*60, keys...)

	require.Equal(
		map[string]*Key{
			"kid#1": NewECDSAKey(
				"kid#1",
				ecdsaPrivateKey,
				jwt.SigningMethodES256,
			),
			"kid#2": NewHMACKey(
				"kid#2",
				[]byte("secret"),
				jwt.SigningMethodHS256,
			).Deprecated(),
			"kid#3": NewRSAKey(
				"kid#3",
				rsaPrivateKey,
				jwt.SigningMethodRS256,
			),
			"kid#4": NewHMACKey(
				"kid#4",
				[]byte("another_secret"),
				jwt.SigningMethodHS256,
			).Deprecated(),
		},
		auth.keyStore,
	)

	require.Equal([]string{"kid#1", "kid#3"}, auth.signingKids)
}
