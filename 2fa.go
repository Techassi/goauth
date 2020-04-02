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
	CryptoMethod func(int) (string, error)
}

func (totp *Totp) Secret() (string, error) {
	return totp.CryptoMethod(totp.SecretLength)
}

func (totp *Totp) Uri() string {
	return "totp"
}

func (totp *Totp) Validate() bool {
	return true
}

type Email struct {
}

// TOTP registers TOTP (Time-based one-time password) as a 2FA method and uses the default
// secret method
func TOTP(issuer string, n int) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.twoFaMethod = newTotp(issuer, n, nil)
	}
}

// TOTPwithSecret registers TOTP (Time-based one-time password) as a 2FA method and you
// can provide a custom secret function
func TOTPwithSecret(issuer string, n int, crypto func(int) (string, error)) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.twoFaMethod = newTotp(issuer, n, crypto)
	}
}

func newTotp(issuer string, n int, c func(int) (string, error)) TWOFAMethod {
	if c != nil {
		return &Totp{
			Issuer:       issuer,
			SecretLength: n,
			CryptoMethod: c,
		}
	}

	return &Totp{
		Issuer:       issuer,
		SecretLength: n,
		CryptoMethod: randomCryptoString,
	}
}
