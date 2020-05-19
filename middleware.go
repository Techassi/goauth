package goauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo"
)

// Redirect sets the path to redirect to if the user is unauthorized
func Redirect(target string) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.redirect = true
		auth.redirectTarget = target
	}
}

// Middleware provides a middleware func for the net/http to protect routes
func (auth *authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, err := auth.authMethod.Lookup(r)
		if err != nil {
			auth.json(w, http.StatusInternalServerError, ErrorKeyLookup(err))
		}

		token, err := auth.authMethod.Validate(t)
		if !token.Valid || err != nil {
			if auth.redirect {
				auth.redirectTo(w, r, auth.redirectTarget)
			}
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
			// if err != nil {
			// 	return c.JSON(http.StatusInternalServerError, ErrorKeyLookup(err))
			// }

			token, err := auth.authMethod.Validate(t)
			if !token.Valid || err != nil {
				if auth.redirect {
					return c.Redirect(http.StatusMovedPermanently, auth.redirectTarget)
				}
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

		token, err := auth.authMethod.Validate(t)
		if !token.Valid || err != nil {
			if auth.redirect {
				c.Redirect(http.StatusMovedPermanently, auth.redirectTarget)
			}
			c.JSON(http.StatusUnauthorized, StatusUnauthorized(err))
		}

		c.Next()
	}
}
