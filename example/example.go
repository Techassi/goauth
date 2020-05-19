package main

import (
	"errors"
	"net/http"

	"github.com/Techassi/goauth"
	"github.com/labstack/echo"
)

type User struct {
	goauth.Fields
	Username string
	Password string
}

type App struct {
	Auth goauth.Authenticator
}

var users []User

func main() {
	// Your user store, a database for exmaple
	users = append(users, User{
		Username: "Test",
		Password: "Test",
	}, User{
		Username: "Test1",
		Password: "Test1",
	})

	users[0].UsesTwoFA = false
	users[0].TwoFAMethod = "totp"
	users[0].TwoFASecret = "secret"
	users[0].TwoFAUser = "test@test.de"

	// The authenticator
	g := goauth.New(
		// Here you define your user lookup function
		goauth.Lookup(lookupFunction),

		// Here you register JWT as an authenticator method
		goauth.JWT("HS512", []byte("mysupersecuresecret"), "cookie:Authorization"),

		// If there is an error while authenticating, redirect to "/error"
		goauth.Redirect("/error"),
	)

	// Your app
	app := &App{
		Auth: g,
	}

	// Your routes
	e := echo.New()
	e.GET("/login/:user", app.Login)
	e.GET("/error", app.Error)
	e.GET("/protected", app.Protected, g.EchoMiddleware())

	panic(e.Start(":8080"))
}

// Login handles the login route
func (a *App) Login(c echo.Context) error {
	// Identify your user, or if already authorized return context
	ctx, err := a.Auth.Identify(User{
		Username: c.Param("user"),
		Password: "Test",
	}, c.Request())

	// If there was an error identifying the user, return this error
	if err != nil {
		return c.JSON(200, Error(err))
	}

	// If the user is already authorized return early
	if ctx.Authenticated() {
		return c.JSON(200, Authorized(ctx.Token()))
	}

	// If the user is not authorized, do so with your claims, e.g. user data
	// Note: the user data is set as a claim per default with the key "user"
	claims := make(map[string]interface{})
	err = ctx.Authenticate(claims)
	if err != nil {
		return c.JSON(200, Unauthorized(err))
	}

	return c.JSON(200, Authorized(ctx.Token()))
}

// Error handles the error route
func (a *App) Error(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{
		"status":  http.StatusMovedPermanently,
		"message": "You are unauthorized and were moved to this error page",
	})
}

// Protected handles the protected route
func (a *App) Protected(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{
		"status":  http.StatusOK,
		"message": "Welcome to the protected area",
	})
}

func lookupFunction(i interface{}) (interface{}, error) {
	user := i.(User)
	for _, u := range users {
		if u.Username == user.Username && u.Password == user.Password {
			return u, nil
		}
	}
	return nil, errors.New("User not found")
}

func Authorized(token string) map[string]interface{} {
	return map[string]interface{}{
		"status": http.StatusOK,
		"token":  token,
	}
}

func Unauthorized(err error) map[string]interface{} {
	return map[string]interface{}{
		"status": http.StatusUnauthorized,
		"error":  err.Error(),
	}
}

func Error(err error) map[string]interface{} {
	return map[string]interface{}{
		"status": http.StatusInternalServerError,
		"error":  err.Error(),
	}
}
