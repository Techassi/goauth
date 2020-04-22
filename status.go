package goauth

import "net/http"

// StatusUnauthorized returns a JSON response indicating the user is not authorized
func StatusUnauthorized(err error) map[string]interface{} {
	return map[string]interface{}{
		"status":     http.StatusUnauthorized,
		"authorized": "no",
		"error":      err.Error(),
	}
}

// StatusAuthorized returns a JSON response indicating the user is authorized
func StatusAuthorized() map[string]interface{} {
	return map[string]interface{}{
		"status":     http.StatusOK,
		"authorized": "yes",
	}
}
