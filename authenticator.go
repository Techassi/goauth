package goauth

import (
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

// AuthenticationMethod provides an interface to provide different authentication methods
type AuthenticationMethod interface {
	Name() string
	Create(map[string]interface{}) (string, error)
	Validate(string) (JwtToken, error)
	Lookup(*http.Request) (string, error)
}

//////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// JWT METHODS //////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

// JwtToken is a wrapper around github.com/dgrijalva/jwt-go token
type JwtToken struct {
	Claims jwt.Claims
	Valid  bool
}

// Jwt is the top-level JWT authentication method
type Jwt struct {
	// Signing method, used to sign your JWT tokens
	// Required.
	SigningMethod jwt.SigningMethod

	// Secret, used to validate token
	// Required.
	Secret []byte

	// LookupString, used to lookup to token in form of <source>:<name>, e.g.
	// cookie:Authorization
	// Required.
	LookupString string
}

// JWT registers JWT as the authentication method
func JWT(method string, secret []byte, lookup string) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.authMethod = newJwt(method, secret, lookup)
	}
}

func newJwt(method string, s []byte, l string) AuthenticationMethod {
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
		panic("Unsupported signing method")
	}

	if len(s) == 0 {
		panic("Empty secret")
	}

	if l == "" {
		panic("Key lookup cannot be empty")
	}

	if !strings.Contains(l, "cookie") && !strings.Contains(l, "header") {
		panic("Unsupported key lookup")
	}

	return &Jwt{
		SigningMethod: m,
		Secret:        s,
		LookupString:  l,
	}
}

// Name returns the name of the authentication method
func (j *Jwt) Name() string {
	return "jwt"
}

// Create creates a new JWT token
func (j *Jwt) Create(c map[string]interface{}) (string, error) {
	var (
		claims jwt.MapClaims = make(jwt.MapClaims)
		token  *jwt.Token
	)

	for i, v := range c {
		claims[i] = v
	}

	token = jwt.NewWithClaims(j.SigningMethod, claims)
	return token.SignedString(j.Secret)
}

// Validate validates the JWT token
func (j *Jwt) Validate(key string) (JwtToken, error) {
	if key == "" {
		return JwtToken{}, ErrorEmptyKey
	}

	token, err := jwt.Parse(key, func(token *jwt.Token) (interface{}, error) {
		return j.Secret, nil
	})
	if err != nil {
		return JwtToken{}, err
	}

	t := JwtToken{
		Claims: token.Claims,
		Valid:  token.Valid,
	}

	return t, nil
}

// Lookup looks up the token
func (j *Jwt) Lookup(r *http.Request) (string, error) {
	l := strings.Split(j.LookupString, ":")
	switch l[0] {
	case "cookie":
		c, err := r.Cookie(l[1])
		if err != nil {
			return "", err
		}
		return c.Value, nil
	case "header":
		return r.Header.Get(l[1]), nil
	default:
		return "", ErrorUnsupportedKeyLookup
	}
}

//////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// SESSION METHODS ////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

// type Session struct {
// 	Store  *sessions.CookieStore
// 	Secret []byte
// }

// // SessionStore registers sessions as the authentication method
// func SessionStore(secret []byte) AuthenticatorOption {
// 	return func(auth *authenticator) {
// 		auth.authMethod = newSessionStore(secret)
// 	}
// }

// func newSessionStore(secret []byte) AuthenticationMethod {
// 	store := sessions.NewCookieStore(secret)
// 	return &Session{
// 		Secret: secret,
// 		Store:  store,
// 	}
// }

// // Name returns the name of the authentication method
// func (j *Session) Name() string {
// 	return "session"
// }

// // Create creates a new session
// func (j *Session) Create(c map[string]interface{}) (string, error) {
// 	return "", nil
// }

// // Validate validates the JWT token
// func (j *Session) Validate(key string) (interface{}, error) {
// 	return true, nil
// }

// // Lookup looks up the token
// func (j *Session) Lookup(r *http.Request) (string, error) {
// 	return "", nil
// }
