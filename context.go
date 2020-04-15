package goauth

import (
	"reflect"
)

type Context interface {
	User() interface{}
	TwoFA() string
	UsesTwoFA() bool
}

type context struct {
	user          interface{}
	valid         bool
	retries       int
	authenticator Authenticator
}

func (c *context) User() interface{} {
	return c.user
}

func (c *context) TwoFA() string {
	v := reflect.ValueOf(c.user)
	f := v.FieldByName("TwoFAMethod")

	if f.IsValid() && f.Kind() == reflect.String {
		return f.String()
	}

	return ""
}

func (c *context) UsesTwoFA() bool {
	v := reflect.ValueOf(c.user)
	f := v.FieldByName("UsesTwoFA")

	if f.IsValid() && f.Kind() == reflect.Bool {
		return f.Bool()
	}

	return false
}
