package jwtauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aria3ppp/jwtauth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var (
	ecdsaPrivateKey        *ecdsa.PrivateKey
	anotherEcdsaPrivateKey *ecdsa.PrivateKey
	rsaPrivateKey          *rsa.PrivateKey
)

type MockClock struct {
	now time.Time
}

var _ jwtauth.Clock = MockClock{}

func (m MockClock) Now() time.Time {
	return m.now
}

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
		filepath.Join("testdata", "another_ec_private_key.pem"),
	)
	if err != nil {
		panic(err)
	}
	anotherEcdsaPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(keyBytes)
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

func TestGenerateToken(t *testing.T) {
	type CustomClaims struct {
		UserID  string `json:"user_id"`
		IsAdmin bool   `json:"is_admin"`
	}

	type fields struct {
		expireSeconds int
		keys          []*jwtauth.Key
	}
	type args struct {
		customClaims *CustomClaims
	}
	type want struct {
		err error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "invalid key",
			fields: fields{
				expireSeconds: 15 * 60,
				keys: []*jwtauth.Key{
					jwtauth.NewECDSAKey(
						"kid#2",
						// Copy the key so the modifications is not reflected
						// to other test cases that use the same key
						func(key ecdsa.PrivateKey) *ecdsa.PrivateKey {
							// modify elliptic curve to a value that do not match the singing method
							key.PublicKey.Curve = elliptic.P384()
							return &key
						}(*ecdsaPrivateKey),
						jwt.SigningMethodES256,
					),
				},
			},
			args: args{
				customClaims: &CustomClaims{
					UserID:  "999",
					IsAdmin: true,
				},
			},
			want: want{
				err: jwt.ErrInvalidKey,
			},
		},
		{
			name: "ok",
			fields: fields{
				expireSeconds: 15 * 60,
				keys: []*jwtauth.Key{
					jwtauth.NewHMACKey(
						"kid#1",
						[]byte("secret"),
						jwt.SigningMethodHS256,
					),
					jwtauth.NewECDSAKey(
						"kid#2",
						ecdsaPrivateKey,
						jwt.SigningMethodES256,
					),
					jwtauth.NewHMACKey(
						"kid#3",
						[]byte("another_secret"),
						jwt.SigningMethodHS256,
					),
					jwtauth.NewRSAKey(
						"kid#4",
						rsaPrivateKey,
						jwt.SigningMethodRS256,
					),
				},
			},
			args: args{
				customClaims: &CustomClaims{
					UserID:  "999",
					IsAdmin: true,
				},
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "ok hmac key",
			fields: fields{
				expireSeconds: 15 * 60,
				keys: []*jwtauth.Key{
					jwtauth.NewHMACKey(
						"kid#1",
						[]byte("secret"),
						jwt.SigningMethodHS256,
					),
				},
			},
			args: args{
				customClaims: &CustomClaims{
					UserID:  "999",
					IsAdmin: true,
				},
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "ok ecdsa key",
			fields: fields{
				expireSeconds: 15 * 60,
				keys: []*jwtauth.Key{
					jwtauth.NewECDSAKey(
						"kid#1",
						ecdsaPrivateKey,
						jwt.SigningMethodES256,
					),
				},
			},
			args: args{
				customClaims: &CustomClaims{
					UserID:  "999",
					IsAdmin: true,
				},
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "ok rsa key",
			fields: fields{
				expireSeconds: 15 * 60,
				keys: []*jwtauth.Key{
					jwtauth.NewRSAKey(
						"kid#4",
						rsaPrivateKey,
						jwt.SigningMethodRS256,
					),
				},
			},
			args: args{
				customClaims: &CustomClaims{
					UserID:  "999",
					IsAdmin: true,
				},
			},
			want: want{
				err: nil,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)

			timeNow := time.Now()

			auth := jwtauth.NewWithClock[CustomClaims](
				MockClock{timeNow},
				tt.fields.expireSeconds,
				tt.fields.keys...,
			)

			token, expiresAt, err := auth.GenerateToken(tt.args.customClaims)

			require.Equal(tt.want.err, err)

			if tt.want.err != nil {
				require.Equal("", token)
				require.Equal(time.Time{}, expiresAt)
			} else {
				expExpiresAt := timeNow.Add(time.Second * time.Duration(tt.fields.expireSeconds))
				require.Equal(expExpiresAt, expiresAt)

				var key *jwtauth.Key

				jwtToken, err := jwt.Parse(
					token,
					func(t *jwt.Token) (any, error) {
						kidValue, exists := t.Header["kid"]
						require.True(exists)
						kid, isString := kidValue.(string)
						require.True(isString)
						key = keyByKid(kid, tt.fields.keys)
						return key.VerifyingKey, nil
					},
				)
				require.NoError(err)

				claims, ok := jwtToken.Claims.(jwt.MapClaims)
				require.True(ok)

				claimsExpiresAtFloat64, ok := claims["exp"].(float64)
				require.True(ok)
				require.Equal(expExpiresAt.Unix(), int64(claimsExpiresAtFloat64))

				customClaims, ok := claims["custom_claims"].(map[string]any)
				require.True(ok)

				userID, ok := customClaims["user_id"].(string)
				require.True(ok)
				require.Equal(tt.args.customClaims.UserID, userID)

				isAdmin, ok := customClaims["is_admin"].(bool)
				require.True(ok)
				require.Equal(tt.args.customClaims.IsAdmin, isAdmin)
			}
		})
	}
}

func keyByKid(
	kid string,
	keys []*jwtauth.Key,
) *jwtauth.Key {
	for _, ss := range keys {
		if ss.Kid == kid {
			return ss
		}
	}
	return nil
}

func TestParseToken(t *testing.T) {
	type CustomClaims struct {
		UserID  string `json:"user_id"`
		IsAdmin bool   `json:"is_admin"`
	}

	expCustomClaims := &CustomClaims{
		UserID:  "999",
		IsAdmin: true,
	}

	type signingKey struct {
		kid           any
		key           any
		signingMethod jwt.SigningMethod
	}
	type fields struct {
		expireSeconds int
		signingKey    signingKey
		verifyingKey  *jwtauth.Key
	}
	type want struct {
		err error
	}
	tests := []struct {
		name   string
		fields fields
		want   want
	}{
		{
			name: "kid not set",
			fields: fields{
				expireSeconds: 10,
				signingKey: signingKey{
					kid:           nil,
					key:           []byte("secret"),
					signingMethod: jwt.SigningMethodHS256,
				},
				verifyingKey: jwtauth.NewHMACKey(
					"kid#1",
					[]byte("secret"),
					jwt.SigningMethodHS256,
				),
			},
			want: want{
				err: jwtauth.ErrUnsetKid,
			},
		},
		{
			name: "invalid kid: invalid value",
			fields: fields{
				expireSeconds: 10,
				signingKey: signingKey{
					kid: len(
						"length_of_this_string_is_an_invalid_value_for_kid",
					),
					key:           []byte("secret"),
					signingMethod: jwt.SigningMethodHS256,
				},
				verifyingKey: jwtauth.NewHMACKey(
					"kid#1",
					[]byte("secret"),
					jwt.SigningMethodHS256,
				),
			},
			want: want{
				err: jwtauth.ErrInvalidKid,
			},
		},
		{
			name: "invalid kid: kid not found",
			fields: fields{
				expireSeconds: 10,
				signingKey: signingKey{
					kid:           "kid#2",
					key:           []byte("secret"),
					signingMethod: jwt.SigningMethodHS256,
				},
				verifyingKey: jwtauth.NewHMACKey(
					"kid#1",
					[]byte("secret"),
					jwt.SigningMethodHS256,
				),
			},
			want: want{
				err: jwtauth.ErrInvalidKid,
			},
		},
		{
			name: "expired symmetric",
			fields: fields{
				expireSeconds: -10,
				signingKey: signingKey{
					kid:           "kid#1",
					key:           []byte("secret"),
					signingMethod: jwt.SigningMethodHS256,
				},
				verifyingKey: jwtauth.NewHMACKey(
					"kid#1",
					[]byte("secret"),
					jwt.SigningMethodHS256,
				),
			},
			want: want{
				err: jwt.ErrTokenExpired,
			},
		},
		{
			name: "expired asymmetric",
			fields: fields{
				expireSeconds: -10,
				signingKey: signingKey{
					kid:           "kid#1",
					key:           ecdsaPrivateKey,
					signingMethod: jwt.SigningMethodES256,
				},
				verifyingKey: jwtauth.NewECDSAKey(
					"kid#1",
					ecdsaPrivateKey,
					jwt.SigningMethodES256,
				),
			},
			want: want{
				err: jwt.ErrTokenExpired,
			},
		},
		{
			name: "invalid symmetric",
			fields: fields{
				expireSeconds: 10,
				signingKey: signingKey{
					kid:           "kid#1",
					key:           []byte("secret"),
					signingMethod: jwt.SigningMethodHS256,
				},
				verifyingKey: jwtauth.NewHMACKey(
					"kid#1",
					[]byte("another_secret"),
					jwt.SigningMethodHS256,
				),
			},
			want: want{
				err: jwt.ErrTokenSignatureInvalid,
			},
		},
		{
			name: "invalid asymmetric",
			fields: fields{
				expireSeconds: 10,
				signingKey: signingKey{
					kid:           "kid#1",
					key:           ecdsaPrivateKey,
					signingMethod: jwt.SigningMethodES256,
				},
				verifyingKey: jwtauth.NewECDSAKey(
					"kid#1",
					anotherEcdsaPrivateKey,
					jwt.SigningMethodES256,
				),
			},
			want: want{
				err: jwt.ErrTokenSignatureInvalid,
			},
		},
		{
			name: "ok symmetric",
			fields: fields{
				expireSeconds: 10,
				signingKey: signingKey{
					kid:           "kid#1",
					key:           []byte("secret"),
					signingMethod: jwt.SigningMethodHS256,
				},
				verifyingKey: jwtauth.NewHMACKey(
					"kid#1",
					[]byte("secret"),
					jwt.SigningMethodHS256,
				),
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "ok asymmetric",
			fields: fields{
				expireSeconds: 10,
				signingKey: signingKey{
					kid:           "kid#1",
					key:           rsaPrivateKey,
					signingMethod: jwt.SigningMethodRS256,
				},
				verifyingKey: jwtauth.NewRSAKey(
					"kid#1",
					rsaPrivateKey,
					jwt.SigningMethodRS256,
				),
			},
			want: want{
				err: nil,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)

			timeNow := time.Now()

			expiresAt := timeNow.
				Add(time.Second * time.Duration(tt.fields.expireSeconds))

			claims := struct {
				CustomClaims CustomClaims `json:"custom_claims"`
				jwt.RegisteredClaims
			}{
				CustomClaims: *expCustomClaims,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(expiresAt),
				},
			}

			jwtToken := jwt.NewWithClaims(
				tt.fields.signingKey.signingMethod,
				claims,
			)

			if tt.fields.signingKey.kid != nil {
				jwtToken.Header["kid"] = tt.fields.signingKey.kid
			}

			tokenString, err := jwtToken.SignedString(
				tt.fields.signingKey.key,
			)
			require.NoError(err)

			auth := jwtauth.NewWithClock[CustomClaims](
				MockClock{timeNow},
				tt.fields.expireSeconds,
				tt.fields.verifyingKey,
			)
			customClaims, err := auth.ParseToken(tokenString)

			if tt.want.err != nil {
				require.ErrorIs(err, tt.want.err)
				require.Nil(customClaims)
			} else {
				// require.NoError(err)
				require.Equal(expCustomClaims, customClaims)
			}
		})
	}
}
