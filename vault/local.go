package vault

import "context"

// Local is a Vault used in the same process, with the Client's methods (local development and tests, where no
// vaultd runs): the guard's mail connector takes either.
type Local struct{ V *Vault }

func (l Local) SealKey(context.Context) (string, error) {
	if k := l.V.SealKey(); k != "" {
		return k, nil
	}
	return "", ErrNoConn
}

func (l Local) ConnPut(_ context.Context, space, id string, s Sealed) (string, ConnInfo, error) {
	return l.V.ConnPut(space, id, s)
}

func (l Local) ConnCommit(_ context.Context, pending string) (ConnInfo, error) {
	return l.V.ConnCommit(pending)
}

func (l Local) ConnDiscard(_ context.Context, pending string) error {
	l.V.ConnDiscard(pending)
	return nil
}

func (l Local) ConnGet(_ context.Context, space, id string) (ConnInfo, error) {
	return l.V.ConnGet(space, id)
}

func (l Local) ConnList(_ context.Context, space string) ([]ConnInfo, string, error) {
	return l.V.ConnList(space), l.V.SealKey(), nil
}

func (l Local) ConnRemove(_ context.Context, space, id string) error {
	return l.V.ConnRemove(space, id)
}

func (l Local) Lease(_ context.Context, r Request) (*Secret, error) {
	v, lease, err := l.V.Lease(r)
	if err != nil {
		return nil, err
	}
	s := NewSecret(v, lease)
	clear(v)
	return s, nil
}
