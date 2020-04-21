package goauth

import "net/http"

func StatusUnauthorized(err error) map[string]interface{} {
	return map[string]interface{}{
		"status":     http.StatusUnauthorized,
		"authorized": "no",
		"error":      err.Error(),
	}
}

func StatusAuthorized() map[string]interface{} {
	return map[string]interface{}{
		"status":     http.StatusOK,
		"authorized": "yes",
	}
}
