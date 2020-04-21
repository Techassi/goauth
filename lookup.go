package goauth

type LookupMethod interface {
	Lookup(interface{}) (bool, error)
}

type Lookup struct {
	Method func(interface{}) (bool, error)
}

// Lookup executes the lookup method
func (l *Lookup) Lookup(i interface{}) (bool, error) {
	return l.Method(i)
}

// LOOKUP registers a lookup method in form of func(interface{}) (bool, error)
func LOOKUP(f func(interface{}) (bool, error)) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.lookupMethod = newLookup(f)
	}
}

func newLookup(f func(interface{}) (bool, error)) LookupMethod {
	return &Lookup{
		Method: f,
	}
}
