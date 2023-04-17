# jwtauth
`jwtauth` handle multiple keys for jwt token signing and verification.
[![Tests](https://github.com/aria3ppp/jwtauth/actions/workflows/tests.yml/badge.svg)](https://github.com/aria3ppp/jwtauth/actions/workflows/tests.yml)
[![Coverage Status](https://coveralls.io/repos/github/aria3ppp/jwtauth/badge.svg?branch=master)](https://coveralls.io/github/aria3ppp/jwtauth?branch=master)

### Installation
```bash
go get -u github.com/aria3ppp/jwtauth
```

### Features overview
`jwtauth` support key deprecation and backward compatibility for verifying old tokens.
Tokens are signed by choosing a random key that is not marked as deprecated.
Deprecated keys can only verify old tokens and not sign new ones.
It also possibe to sign a token explicitly by providing kid.

### Example
```go
type CustomClaims struct {
    UserID string `json:"user_id"`
    IsAdmin bool `json:"is_admin"`
}

myClaims := &CustomClaims{
    UserID: "id",
    IdAdmin: true,
}

...

auth := jwtauth.New[CustomClaims](
    3600*24*30, // expiration duration in seconds

    // key suites
    jwtauth.SigningMethodHS256(
        "kid#1",
        []byte("secret"),
        jwt.SigningMethodES,
    ),
    jwtauth.NewECDSAKey(
		"kid#2",
		ecdsaPrivateKey,
		jwt.SigningMethodES256,
	),
    // keys marked as deprecated
	jwtauth.NewHMACKey(
		"kid#3",
		[]byte("another_secret"),
		jwt.SigningMethodHS256,
	).Deprecated(),
	jwtauth.NewRSAKey(
		"kid#4",
		rsaPrivateKey,
		jwt.SigningMethodRS256,
	).Deprecated(),
)

// Generate token
tokenString, expiresAt, err := auth.GenerateTokenWithKid("kid#1", myClaims)

// handle error

parsedClaims, err := auth.ParseToken(tokenString)

// handle error

assert.Equal(myClaims, parsedClaims)
```