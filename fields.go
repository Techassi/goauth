package goauth

// Fields is a helper struct to implement fields into you user structs
type Fields struct {
	// TwoFAUsed, indicates if the user uses 2FA
	UsesTwoFA bool `json:"uses_twofa" goauth:"uses_twofa"`

	// TwoFAMethod, indicates what 2FA method the user uses
	TwoFAMethod string `json:"twofa_method" goauth:"twofa_method"`

	// TwoFASecret the OTP uses
	TwoFASecret string `json:"-" goauth:"twofa_secret"`

	// TwoFAUser indicates which user information is used (typically the users email)
	TwoFAUser string `json:"-" goauth:"twofa_user"`
}
