package goauth

import (
	"encoding/json"
	"net/http"
)

func (auth *authenticator) json(w http.ResponseWriter, code int, i interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc.Encode(i)
}
