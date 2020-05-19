package goauth

type Context interface {
	Token() string
	User() interface{}
	Authenticate(map[string]interface{}) error
	UsesTwoFA() bool
	TwoFAMethod() string
	ValidateTwoFA(string) bool
	GenerateTwoFA() (string, error)
	RegisterTwoFA() (string, error)
	Authenticator() Authenticator
}

type context struct {
	user          interface{}
	token         string
	twoFAValid    bool
	twoFAMap      map[string]interface{}
	authenticator Authenticator
}

func (c *context) Token() string {
	return c.token
}

func (c *context) User() interface{} {
	return c.user
}

func (c *context) Authenticate(claims map[string]interface{}) error {
	if !c.twoFAValid && c.UsesTwoFA() {
		return Error2FANotValidated
	}

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

func (c *context) RegisterTwoFA() (string, error) {
	return "", nil
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
