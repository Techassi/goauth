# goauth

This library is very much under **active** development. It is **not** usable (yet)!

goauth provides a context-based and plugable authenticator for authentication on the web.

## Supported authentication methods

-   JWT (JSON Web Token)

## Supported 2FA methods

-   TOTP (Time-based One-time Password)

## Usage

Start off with importing this module

```golang
import "github.com/Techassi/goauth"
```

### Lookup function
With this function you can specify how the user data should be looked up upon calling 
`goauth.Authenticate()`.

```golang
auth := goauth.New(
	goauth.Lookup(yourLookupFunction),
)
```

Your lookup function has to be implemented like this

```golang
func yourLookupFunction(i interface{}) (valid bool, err error) {
	// Lookup your user and validate the credentials
	// If there was an error:
	return false, err

	// If everything went smoothly:
	return true, nil
}
```

### Authentication
The authentication is plugable just like the lookup function. There are currently two 
ready-to-use built-in authentication methods: JWT (JSON Web Token) and Sessions (work in
progress).

#### JWT (JSON Web Token) authentication

```golang
auth := goauth.New(
	goauth.JWT("HS512", []byte("secret"), "cookie:Authorization"),
)
```

`goauth.JWT()` provides many customization options like:
- The signing method: You can provide the signing method. Since `goauth.JWT()` uses `jwt-go` you can use every method `jwt-go` has to offer.
- The secret: You can provide a secret with will be used to sign the tokens. (Hint: Don't hardcode this into your source code and rather set this via database, config file or enviroment variable)
- Token lookup: You can specify how the token should be looked up in form of `<method>:<name>`, with `header` and `cookie` as possible values for `<method>`, e.g. `cookie:Authorization`.

#### Sessions authentication (work in progress)
Sessions are still in work. This section will be updated once they are finished.

### 2FA authentication
The 2FA autehntication is plugable just like the authentication function. There is currently one 
ready-to-use built-in authentication method: TOTP (Time-based One-time Passwords)

#### TOTP (Time-based One-time Passwords)

```golang
auth := goauth.New(
	goauth.TOTP("issuer", 16),
)
```

`goauth.TOTP()` provides the following customization options:
- The issuer: Specify the issuer to be used when generating the TOTP URI.
- The secret size: Specify the size of the secret, which gets generated with every new TOTP URI.

#### Custom TOTP secret method

```golang
auth := goauth.New(
	goauth.TOTPwithSecret("issuer", 16, secretMethod),
)
```

`goauth.TOTPwithSecret()` provides one additional option:
- Secret method: Provide a custom secret method in form of `func(length int) (secret string, err error)`.

### Complete example

```golang
auth := goauth.New(
	goauth.Lookup(yourLookupFunction),
	goauth.JWT("HS512", []byte("secret"), "cookie:Authorization"),
	goauth.TOTP("issuer", 16),
)
```

### Custom authentication & 2FA methods

Your authentication method must implement the `AuthenticationMethod` interface:

```golang
type AuthenticationMethod interface {
	Name() string
	Create(map[string]interface{}) (string, error)
	Validate(string) (bool, error)
	Lookup(*http.Request) (string, error)
}
```

Your 2FA method must implement the `TWOFAMethod` interface:

```golang
type TWOFAMethod interface {
	Secret() (string, error)
	Uri() string
	Validate() bool
}
```

## Ideas

- Add Redis support for authentication
- Add Email as 2FA
- Add Security Stick as 2FA

## Motivation
The motivation behind this project is to provide a simple but plugable authenticator and 
reduce the complications around authentication.
