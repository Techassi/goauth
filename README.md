# goauth

This library is very much under **active** development. It is **not** usable (yet)!

goauth provides a context-based and plugable authenticator for authentication on the web.

## Example

```golang
import "github.com/Techassi/goauth"

auth := goauth.New(
    goauth.JWT("HS512", []byte("secret")),
    goauth.TOTP("issuer", 16),
)
```

## Supported authentication methods
- JWT (JSON Web Token)

## Supported 2FA methods
- TOTP (Time-based One-time Password)

## Custom authentication & 2FA methods

Your authentication method must implement the `AuthenticationMethod` interface:

```golang
type AuthenticationMethod interface {
	String() string
}
```

Your 2FA method must implement the `TWOFAMethod` interface:

```golang
type TWOFAMethod interface {
	// Token is reponsible for token generation. Each token is unique for each user.
	Secret() (string, error)

	// Uri creates a Two Factor Authentication uri if needed.
	Uri() string

	// Validate validates the provided code
	Validate() bool
}
```