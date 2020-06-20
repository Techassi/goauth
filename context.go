package goauth

// Context describes the current authentication context and allows the user to
// authenticate, validate and register 2FA
type Context interface {
	Token() string
	User() map[string]interface{}
	Authenticate(map[string]interface{}) error
	Authenticated() bool
	SetAuthenticated()
	UsesTwoFA() bool
	TwoFAMethod() string
	ValidateTwoFA(string) bool
	GenerateTwoFA() (string, error)
	RegisterTwoFA(string) (string, string, error)
	Authenticator() Authenticator
}

type context struct {
	user          map[string]interface{}
	authenticated bool
	token         string
	twoFAValid    bool
	twoFAMap      map[string]interface{}
	authenticator Authenticator
}

func (c *context) Token() string {
	return c.token
}

func (c *context) User() map[string]interface{} {
	return c.user
}

func (c *context) Authenticated() bool {
	return c.authenticated
}

func (c *context) SetAuthenticated() {
	c.authenticated = true
}

func (c *context) Authenticate(claims map[string]interface{}) error {
	// if !c.twoFAValid && c.UsesTwoFA() {
	// 	return Error2FANotValidated
	// }

	// TODO: Set exp time stamp
	claims["user"] = c.User()
	token, err := c.authenticator.AuthMethod().Create(claims)
	c.token = token
	return err
}

func (c *context) ValidateTwoFA(code string) bool {
	m := c.authenticator.TwoFAMethod(c.TwoFAMethod())
	c.twoFAValid = m.Validate(code, c.twoFAMap["twofa_secret"].(string))
	return c.twoFAValid
}

func (c *context) GenerateTwoFA() (string, error) {
	m := c.authenticator.TwoFAMethod(c.TwoFAMethod())
	return m.Generate(c.twoFAMap["twofa_user"].(string))
}

func (c *context) RegisterTwoFA(account string) (string, string, error) {
	m := c.authenticator.TwoFAMethod(c.TwoFAMethod())
	return m.Register(account)
}

func (c *context) TwoFAMethod() string {
	return c.twoFAMap["twofa_method"].(string)
}

func (c *context) UsesTwoFA() bool {
	return c.twoFAMap["uses_twofa"].(bool)
}

func (c *context) Authenticator() Authenticator {
	return c.authenticator
}
