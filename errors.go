package goauth

import (
	"errors"
	"net/http"
)

var (
	ErrorUnsupportedKeyLookup = errors.New("Unsupported key lookup")
)

func ErrorKeyLookup(err error) map[string]interface{} {
	return map[string]interface{}{
		"status": http.StatusInternalServerError,
		"error":  err.Error(),
	}
}
