package goauth

import (
	"reflect"
)

type Context interface {
	Token() string
	User() interface{}
	UsesTwoFA() bool
	TwoFAMethod() string
	ValidateTwoFA(string) bool
	GenerateTwoFA() (string, error)
	Authenticator() Authenticator
}

type context struct {
	user          interface{}
	token         string
	twoFA         bool
	twoFAValid    bool
	twoFAMethod   string
	twoFASecret   string
	twoFAAccount  string
	authenticator Authenticator
}

func (c *context) Token() string {
	return c.token
}

func (c *context) User() interface{} {
	return c.user
}

func (c *context) ValidateTwoFA(code string) bool {
	return true
}

func (c *context) GenerateTwoFA() (string, error) {
	m := c.authenticator.TwoFAMethod(c.TwoFAMethod())
	return m.Generate(c.twoFAAccount)
}

// TODO: Add custom json tags
func (c *context) TwoFAMethod() string {
	v := reflect.ValueOf(c.user)
	f := v.FieldByName("TwoFAMethod")

	if f.IsValid() && f.Kind() == reflect.String {
		return f.String()
	}

	return ""
}

func (c *context) UsesTwoFA() bool {
	v := reflect.ValueOf(c.user)
	f := v.FieldByName("TwoFAUsed")

	if f.IsValid() && f.Kind() == reflect.Bool {
		return f.Bool()
	}

	return false
}

func (c *context) Authenticator() Authenticator {
	return c.authenticator
}
