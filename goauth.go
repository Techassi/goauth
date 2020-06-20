/*

Package goauth

*/

package goauth

import (
	"net/http"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/labstack/echo"
)

// AuthenticatorOption represents an authenticator option
type AuthenticatorOption func(auth *authenticator)

type (
	// Authenticator is the top level Authenticator interface
	Authenticator interface {
		Identify(interface{}, *http.Request) (Context, error)
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
func (auth *authenticator) Identify(user interface{}, r *http.Request) (Context, error) {
	// Look for a token, if found check if valid => user is already authenticated
	t, err := auth.authMethod.Lookup(r)
	token, err := auth.authMethod.Validate(t)
	if token.Valid && err == nil {
		ctx := auth.newContext(token.Claims.(jwt.MapClaims))
		ctx.SetAuthenticated()
		return ctx, nil
	}

	// Convert user interface to map
	var m map[string]interface{}
	err = interfaceToMap(user, &m)
	if err != nil {
		return nil, err
	}

	// User is not authenticated, so lookup user and create context
	user, err = auth.lookupMethod.Do(m)
	if err != nil {
		return nil, err
	}

	ctx := auth.newContext(m)
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

// TODO: Extract user 2FA information - do this more cleanly
func (auth *authenticator) newContext(usermap map[string]interface{}) Context {
	return &context{
		user:          usermap,
		authenticator: auth,
		// twoFAMap:      getTags(user),
	}
}
