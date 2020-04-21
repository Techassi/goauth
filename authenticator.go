package goauth

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

// AuthenticationMethod provides an interface to provide different authentication methods
type AuthenticationMethod interface {
	String() string
	Create(map[string]interface{}) (string, error)
	Validate(string) (bool, error)
	Lookup() (string, error)
}

//////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// JWT METHODS //////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

// Jwt is the top-level JWT authentication method
type Jwt struct {
	SigningMethod jwt.SigningMethod
	Secret        []byte
	LookupString  string
}

// String returns the name of the authentication method
func (j *Jwt) String() string {
	return "jwt"
}

// Create creates a new JWT token
func (j *Jwt) Create(c map[string]interface{}) (string, error) {
	var (
		claims jwt.MapClaims
		token  *jwt.Token
	)

	for i, v := range c {
		claims[i] = v
	}

	token = jwt.NewWithClaims(j.SigningMethod, claims)
	return token.SignedString(j.Secret)
}

// Validate validates the JWT token
func (j *Jwt) Validate(key string) (bool, error) {
	token, err := jwt.Parse(key, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return j.Secret, nil
	})

	return token.Valid, err
}

// Lookup looks up the token
func (j *Jwt) Lookup() (string, error) {
	switch j.LookupString {
	case "cookie":
		return "", nil
	case "header":
		return "", nil
	default:
		return "", ErrorUnsupportedKeyLookup
	}
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

	if l == "" || (l != "cookie" && l != "header") {
		panic("Unsupported key lookup")
	}

	return &Jwt{
		SigningMethod: m,
		Secret:        s,
		LookupString:  l,
	}
}
