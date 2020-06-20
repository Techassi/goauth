package goauth

// LookupMethod represents how user data is looked up
type LookupMethod interface {
	Do(map[string]interface{}) (interface{}, error)
}

type lookup struct {
	Method func(map[string]interface{}) (interface{}, error)
}

// Do executes the lookup method
func (l *lookup) Do(m map[string]interface{}) (interface{}, error) {
	return l.Method(m)
}

// Lookup registers a lookup method in form of func(interface{}) (bool, error)
func Lookup(f func(map[string]interface{}) (interface{}, error)) AuthenticatorOption {
	return func(auth *authenticator) {
		auth.lookupMethod = newLookup(f)
	}
}

func newLookup(f func(map[string]interface{}) (interface{}, error)) LookupMethod {
	return &lookup{
		Method: f,
	}
}
