package goauth

import (
	"context"

	jwt "github.com/dgrijalva/jwt-go"
)

// AuthenticatorOption represents an authenticator option
type AuthenticatorOption func(auth *authenticator)

type (
	// Authenticator is the top level Autenticator interface
	Authenticator interface {
		Authenticate(user interface{}) (context.Context, error)
	}

	// authenticator is the internal authenticator struct
	authenticator struct {
		twoFaMethod          TWOFAMethod
		authenticationMethod AuthenticationMethod
	}
)

// New will create a new Authenticator with the provided AuthenticatorOption (s)
func New(options ...AuthenticatorOption) Authenticator {
	auth := &authenticator{}

	for _, f := range options {
		f(auth)
	}

	return auth
}

// Authenticate will authenticate the user with the configured authentication method
func (auth *authenticator) Authenticate(user interface{}) (context.Context, error) {
	return context.Background(), nil
}

// AuthenticationMethod provides an interface to provide different autehntication methods
type AuthenticationMethod interface {
	String() string
}

type Jwt struct {
	SigningMethod jwt.SigningMethod
	Secret        []byte
}

func (jwt *Jwt) String() string {
	return "jwt"
}

func JWT(method string, secret []byte) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.authenticationMethod = newJwt(method, secret)
	}
}

func newJwt(method string, s []byte) AuthenticationMethod {
	var m jwt.SigningMethod

	switch method {
	case "HS512":
		m = jwt.SigningMethodHS512
	case "HS384":
		m = jwt.SigningMethodHS384
	case "HS256":
		m = jwt.SigningMethodHS256
	case "ES512":
		m = jwt.SigningMethodES512
	case "ES384":
		m = jwt.SigningMethodES384
	case "ES256":
		m = jwt.SigningMethodES256
	case "PS512":
		m = jwt.SigningMethodPS512
	case "PS384":
		m = jwt.SigningMethodPS384
	case "PS256":
		m = jwt.SigningMethodPS256
	case "RS512":
		m = jwt.SigningMethodRS512
	case "RS384":
		m = jwt.SigningMethodRS384
	case "RS256":
		m = jwt.SigningMethodRS256
	default:
		// TODO: Log fallback
		m = jwt.SigningMethodHS512
	}

	return &Jwt{
		SigningMethod: m,
		Secret:        s,
	}
}
