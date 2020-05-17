package goauth

import (
	"errors"
	"net/http"
)

var (
	ErrorUnsupportedKeyLookup = errors.New("Unsupported key lookup")
	ErrorEmptyKey             = errors.New("The key / token cannot be empty")
	Error2FAInavlidSecretSize = errors.New("The 2FA secret size must be > 0")
	Error2FANotValidated      = errors.New("The user uses 2FA and no code was validated")
)

// ErrorKeyLookup returns an key lookup error in JSON to respond to HTTP request
func ErrorKeyLookup(err error) map[string]interface{} {
	return map[string]interface{}{
		"status": http.StatusInternalServerError,
		"error":  err.Error(),
	}
}
