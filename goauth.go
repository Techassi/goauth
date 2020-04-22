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
		Authenticate(user interface{}) (Context, error)
		Middleware(next http.Handler) http.Handler
		EchoMiddleware() echo.MiddlewareFunc
		GinMiddleware() gin.HandlerFunc
	}

	// authenticator is the internal struct
	authenticator struct {
		lookupMethod LookupMethod
		twoFaMethod  map[string]TwoFAMethod
		authMethod   AuthenticationMethod
		pool         sync.Pool
	}
)

// New will create a new Authenticator with the provided AuthenticatorOption(s)
func New(options ...AuthenticatorOption) Authenticator {
	auth := &authenticator{
		twoFaMethod: make(map[string]TwoFAMethod),
	}
	auth.pool.New = func() interface{} {
		return auth.newContext(nil, "")
	}

	for _, f := range options {
		f(auth)
	}

	return auth
}

// Authenticate will authenticate the user with the configured authentication method
// Authentication procedure:
// 	1. Check if token / key is provided, if yes check if valid
// 	2. Lookup the user and validate
// 	3. Create token / key
// 	4. Return context
func (auth *authenticator) Authenticate(user interface{}) (Context, error) {
	if exists, err := auth.lookupMethod.Do(user); !exists {
		return nil, err
	}

	claims := make(map[string]interface{})
	claims["user"] = user
	token, err := auth.authMethod.Create(claims)
	if err != nil {
		return nil, err
	}

	ctx := auth.newContext(user, token)
	return ctx, nil
}

// Middleware provides a middleware func for the net/http to protect routes
func (auth *authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, err := auth.authMethod.Lookup(r)
		if err != nil {
			auth.json(w, http.StatusInternalServerError, ErrorKeyLookup(err))
		}

		valid, err := auth.authMethod.Validate(t)
		if !valid || err != nil {
			auth.json(w, http.StatusUnauthorized, StatusUnauthorized(err))
		}

		next.ServeHTTP(w, r)
	})
}

// EchoMiddleware provides a middleware func for the echo framework to protect routes
func (auth *authenticator) EchoMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			t, err := auth.authMethod.Lookup(c.Request())
			if err != nil {
				return c.JSON(http.StatusInternalServerError, ErrorKeyLookup(err))
			}

			valid, err := auth.authMethod.Validate(t)
			if !valid || err != nil {
				return c.JSON(http.StatusUnauthorized, StatusUnauthorized(err))
			}

			return next(c)
		}
	}
}

// GinMiddleware provides a middleware func for the gin framework to protect routes
func (auth *authenticator) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		t, err := auth.authMethod.Lookup(c.Request)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorKeyLookup(err))
		}

		valid, err := auth.authMethod.Validate(t)
		if !valid || err != nil {
			c.JSON(http.StatusUnauthorized, StatusUnauthorized(err))
		}

		c.Next()
	}
}

func (auth *authenticator) newContext(user interface{}, token string) Context {
	return &context{
		user:          user,
		authenticator: auth,
		key:           token,
	}
}
