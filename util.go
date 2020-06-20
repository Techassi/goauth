package goauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
)

type Tag struct {
	Name  string
	Value interface{}
}

// Write JSON to response writer
func (auth *authenticator) json(w http.ResponseWriter, code int, i interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc.Encode(i)
}

// Write JSON to response writer
func (auth *authenticator) redirectTo(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func interfaceToMap(i interface{}, m *map[string]interface{}) error {
	b, err := json.Marshal(i)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewBuffer(b))
	err = d.Decode(m)
	return err
}

func getTags(iface interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	tags := getDeepTags(iface)
	for i := 0; i < len(tags); i++ {
		m[tags[i].Name] = tags[i].Value
	}
	return m
}

func getDeepTags(iface interface{}) []Tag {
	fields := make([]Tag, 0)
	ifv := reflect.ValueOf(iface)
	ift := reflect.TypeOf(iface)

	for i := 0; i < ift.NumField(); i++ {
		v := ifv.Field(i)

		switch v.Kind() {
		case reflect.Struct:
			fields = append(fields, getDeepTags(v.Interface())...)
		default:
			if tag := ifv.Type().Field(i).Tag.Get("goauth"); tag != "" {
				fields = append(fields, Tag{
					Name:  tag,
					Value: ifv.Field(i).Interface(),
				})
			}

		}
	}

	return fields
}
