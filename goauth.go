package goauth

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo"
)

// AuthenticatorOption represents an authenticator option
type AuthenticatorOption func(auth *authenticator)

type (
	// Authenticator is the top level Authenticator interface
	Authenticator interface {
		Identify(user interface{}) (Context, error)
		Middleware(next http.Handler) http.Handler
		EchoMiddleware() echo.MiddlewareFunc
		GinMiddleware() gin.HandlerFunc
		AuthMethod() AuthenticationMethod
		TwoFAMethod(string) TwoFAMethod
		TwoFAMethods() map[string]TwoFAMethod
	}

	// authenticator is the internal struct
	authenticator struct {
		lookupMethod   LookupMethod
		twoFaMethods   map[string]TwoFAMethod
		authMethod     AuthenticationMethod
		redirect       bool
		redirectTarget string
		pool           sync.Pool
	}
)

// New will create a new Authenticator with the provided AuthenticatorOption(s)
func New(options ...AuthenticatorOption) Authenticator {
	auth := &authenticator{
		twoFaMethods: make(map[string]TwoFAMethod),
	}
	auth.pool.New = func() interface{} {
		return auth.newContext(nil)
	}

	for _, f := range options {
		f(auth)
	}

	return auth
}

// Identify identifies the user and returns a context to further authenticate the user
func (auth *authenticator) Identify(user interface{}) (Context, error) {
	user, err := auth.lookupMethod.Do(user)
	if err != nil {
		return nil, err
	}

	ctx := auth.newContext(user)
	return ctx, nil
}

func (auth *authenticator) AuthMethod() AuthenticationMethod {
	return auth.authMethod
}

func (auth *authenticator) TwoFAMethods() map[string]TwoFAMethod {
	return auth.twoFaMethods
}

func (auth *authenticator) TwoFAMethod(key string) TwoFAMethod {
	return auth.twoFaMethods[key]
}

// TODO: Extract user 2FA information
func (auth *authenticator) newContext(user interface{}) Context {
	tags := getTags(user)

	return &context{
		user:          user,
		authenticator: auth,
		twoFAMap:      tags,
	}
}
