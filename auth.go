package jwtauth

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Auth[CustomClaims any] struct {
	keyStore                  map[string]*Key
	signingKids               []string
	expirationDurationSeconds int   // token expiration duration in seconds
	clock                     Clock // clock used to get current time by invoking `Now` method
}

func New[CustomClaims any](
	expireSeconds int,
	keys ...*Key,
) *Auth[CustomClaims] {
	return NewWithClock[CustomClaims](TimeClock{}, expireSeconds, keys...)
}

func NewWithClock[CustomClaims any](
	clock Clock,
	expireSeconds int,
	keys ...*Key,
) *Auth[CustomClaims] {
	if len(keys) == 0 {
		panic("at least one key must provided")
	}

	keyStore := make(map[string]*Key, len(keys))
	signingKids := make([]string, 0)

	for _, k := range keys {
		if _, kidExists := keyStore[k.Kid]; kidExists {
			panic(fmt.Sprintf("kid %q set by another key", k.Kid))
		}

		keyStore[k.Kid] = k

		if !k.deprecated {
			signingKids = append(signingKids, k.Kid)
		}
	}

	return &Auth[CustomClaims]{
		keyStore:                  keyStore,
		signingKids:               signingKids,
		expirationDurationSeconds: expireSeconds,
		clock:                     clock,
	}
}

type jwtClaims[CustomClaims any] struct {
	CustomClaims *CustomClaims `json:"custom_claims"`
	jwt.RegisteredClaims
}

func (auth *Auth[CustomClaims]) GenerateToken(
	customClaims *CustomClaims,
) (token string, expiresAt time.Time, err error) {
	kid := auth.chooseRandomKid()
	return auth.GenerateTokenWithKid(kid, customClaims)
}

func (auth *Auth[CustomClaims]) chooseRandomKid() string {
	return auth.signingKids[rand.Intn(len(auth.signingKids))]
}

func (auth *Auth[CustomClaims]) GenerateTokenWithKid(
	kid string,
	customClaims *CustomClaims,
) (token string, expiresAt time.Time, err error) {
	var (
		key    *Key
		exists bool
	)

	// check key exists
	if key, exists = auth.keyStore[kid]; !exists {
		return "", time.Time{}, ErrInvalidKid
	}

	// calculate expiration
	expiresAt = auth.clock.Now().
		Add(time.Second * time.Duration(auth.expirationDurationSeconds))

	// set claims
	claims := jwtClaims[CustomClaims]{
		CustomClaims: customClaims,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	// sign token
	jwtToken := jwt.NewWithClaims(key.SigningMethod, claims)
	jwtToken.Header["kid"] = key.Kid
	token, err = jwtToken.SignedString(key.SigningKey)
	if err != nil {
		return "", time.Time{}, err
	}

	return token, expiresAt, nil
}

func (auth *Auth[CustomClaims]) ParseToken(
	tokenString string,
) (*CustomClaims, error) {
	// prepare key function
	keyFunc := func(t *jwt.Token) (any, error) {
		key, err := auth.fetchKey(t)
		if err != nil {
			return nil, err
		}
		return key.VerifyingKey, nil
	}

	// parse token string
	var claims jwtClaims[CustomClaims]
	_, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc)
	if err != nil {
		return nil, err
	}

	return claims.CustomClaims, nil
}

func (auth *Auth[CustomClaims]) fetchKey(token *jwt.Token) (*Key, error) {
	if kidValue, exists := token.Header["kid"]; exists {
		if kid, isString := kidValue.(string); isString {
			if key, exists := auth.keyStore[kid]; exists {
				return key, nil
			} else {
				return nil, ErrInvalidKid
			}
		} else {
			return nil, ErrInvalidKid
		}
	} else {
		return nil, ErrUnsetKid
	}
}
