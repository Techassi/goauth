package goauth

import "github.com/pquerna/otp/totp"

// TwoFAMethod provides an interface to provide different 2FA methods
type TwoFAMethod interface {
	// Generate generates a new key
	Generate(string) (string, error)

	// Secret is reponsible for token generation. Each token is unique for each user.
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
	cryptoMethod func(int) ([]byte, error)
}

// TOTP registers TOTP (Time-based one-time password) as a 2FA method and uses the default
// secret method
func TOTP(issuer string, n int) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.twoFaMethods["totp"] = newTotp(issuer, n, randomCryptoBytes)
	}
}

// TOTPwithSecret registers TOTP (Time-based one-time password) as a 2FA method and you
// can provide a custom secret function
func TOTPwithSecret(issuer string, n int, crypto func(int) ([]byte, error)) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.twoFaMethods["totp"] = newTotp(issuer, n, crypto)
	}
}

func newTotp(issuer string, n int, c func(int) ([]byte, error)) TwoFAMethod {
	if n <= 0 {
		panic(Error2FAInavlidSecretSize)
	}

	return &Totp{
		issuer:       issuer,
		secretLength: n,
		cryptoMethod: c,
	}
}

func (t *Totp) Generate(account string) (string, error) {
	secret, err := t.cryptoMethod(t.secretLength)
	if err != nil {
		return "", err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.issuer,
		AccountName: account,
		Secret:      secret,
	})

	if err != nil {
		return "", err
	}

	return key.String(), nil
}

func (t *Totp) Secret() (string, error) {
	s, err := t.cryptoMethod(t.secretLength)
	return bytesToString(s), err
}

func (t *Totp) Uri() string {
	return "totp"
}

func (t *Totp) Validate() bool {
	return true
}
