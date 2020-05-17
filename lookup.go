package goauth

// LookupMethod represents how user data is looked up
type LookupMethod interface {
	Do(interface{}) (interface{}, error)
}

type lookup struct {
	Method func(interface{}) (interface{}, error)
}

// Do executes the lookup method
func (l *lookup) Do(i interface{}) (interface{}, error) {
	return l.Method(i)
}

// Lookup registers a lookup method in form of func(interface{}) (bool, error)
func Lookup(f func(interface{}) (interface{}, error)) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.lookupMethod = newLookup(f)
	}
}

func newLookup(f func(interface{}) (interface{}, error)) LookupMethod {
	return &lookup{
		Method: f,
	}
}
