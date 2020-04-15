package goauth

type Fields struct {
	UsesTwoFA   bool   `json:"uses_twofa"`
	TwoFAMethod string `json:"twofa_method"`
}
