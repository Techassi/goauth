package goauth

// TwoFAMethod provides an interface to provide different 2FA methods
type TwoFAMethod interface {
	// Token is reponsible for token generation. Each token is unique for each user.
	Secret() (string, error)

	// Uri creates a Two Factor Authentication uri if needed.
	Uri() string

	// Validate validates the provided code
	Validate() bool
}

// Totp is the deafult TOTP struct
type Totp struct {
	name         string
	secretLength int
	issuer       string
	cryptoMethod func(int) (string, error)
}

// TOTP registers TOTP (Time-based one-time password) as a 2FA method and uses the default
// secret method
func TOTP(issuer string, n int) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.twoFaMethod["totp"] = newTotp(issuer, n, nil)
	}
}

// TOTPwithSecret registers TOTP (Time-based one-time password) as a 2FA method and you
// can provide a custom secret function
func TOTPwithSecret(issuer string, n int, crypto func(int) (string, error)) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.twoFaMethod["totp"] = newTotp(issuer, n, crypto)
	}
}

func newTotp(issuer string, n int, c func(int) (string, error)) TwoFAMethod {
	if c != nil {
		return &Totp{
			issuer:       issuer,
			secretLength: n,
			cryptoMethod: c,
		}
	}

	return &Totp{
		issuer:       issuer,
		secretLength: n,
		cryptoMethod: randomCryptoString,
	}
}

func (totp *Totp) Secret() (string, error) {
	return totp.cryptoMethod(totp.secretLength)
}

func (totp *Totp) Uri() string {
	return "totp"
}

func (totp *Totp) Validate() bool {
	return true
}
