package goauth

// TWOFAMethod provides an interface to provide different 2FA methods
type TWOFAMethod interface {
	// Token is reponsible for token generation. Each token is unique for each user.
	Secret() (string, error)

	// Uri creates a Two Factor Authentication uri if needed.
	Uri() string

	// Validate validates the provided code
	Validate() bool
}

type Totp struct {
	SecretLength int
	Issuer       string
}

func (totp *Totp) Secret() (string, error) {
	return randomCryptoString(totp.SecretLength)
}

func (totp *Totp) Uri() string {
	return "totp"
}

func (totp *Totp) Validate() bool {
	return true
}

type Email struct {
}

func TOTP(issuer string, n int) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.twoFaMethod = newTotp(issuer, n)
	}
}

func newTotp(issuer string, n int) TWOFAMethod {
	return &Totp{
		Issuer:       issuer,
		SecretLength: n,
	}
}
