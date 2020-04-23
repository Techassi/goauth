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

	// The authenticator
	g := goauth.New(
		goauth.Lookup(lookupFunction),
		goauth.JWT("HS512", []byte("mysupersecuresecret"), "cookie:Authorization"),
	)

	// Your app
	app := &App{
		Auth: g,
	}

	// Your routes
	e := echo.New()
	e.GET("/:user", app.Handle)
	e.GET("/protected", app.Protected, g.EchoMiddleware())

	panic(e.Start(":8080"))
}

func (a *App) Handle(c echo.Context) error {
	ctx, err := a.Auth.Identify(User{
		Username: c.Param("user"),
		Password: "Test",
	})

	if err != nil {
		return c.JSON(200, map[string]interface{}{
			"status": http.StatusInternalServerError,
			"error":  err.Error(),
		})
	}

	return c.JSON(200, map[string]interface{}{
		"status": http.StatusOK,
		"token":  ctx.Token(),
	})
}

func (a *App) Protected(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{
		"status":  http.StatusOK,
		"message": "Welcome to the protected area",
	})
}

func lookupFunction(i interface{}) (bool, error) {
	user := i.(User)
	for _, u := range users {
		if u.Username == user.Username && u.Password == user.Password {
			return true, nil
		}
	}
	return false, errors.New("User not found")
}
