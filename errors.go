package goauth

import (
	"errors"
	"net/http"
)

var (
	// ErrorUnsupportedKeyLookup will throw an error if an unsupported key lookup is
	// specified
	ErrorUnsupportedKeyLookup = errors.New("Unsupported key lookup")
	ErrorEmptyKey             = errors.New("The key / token cannot be empty")
)

// ErrorKeyLookup returns an key lookup error in JSON to respond to HTTP request
func ErrorKeyLookup(err error) map[string]interface{} {
	return map[string]interface{}{
		"status": http.StatusInternalServerError,
		"error":  err.Error(),
	}
}
