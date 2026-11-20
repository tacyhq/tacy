package kmsvm_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/kmsdev"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/sealstate"
)

// M4 (security review 2026-11-20): a process whose lease is gone stops: a refused renewal calls OnLost at once, a
// renewal that can't get through calls it when the lease is about to lapse, and the register refuses its saves
// (sealstate.ErrRefused, which stops the Store) from then on.
func TestReviewM4LeaseLostFailsClosed(t *testing.T) {
	d, err := kmsdev.Start(kmsdev.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var lost []error
	cfg := func(now func() time.Time, t2 client.Transport) kmsvm.Config {
		return kmsvm.Config{KMSID: d.KMSID, Hosts: 1, Platform: "local", Purposes: []string{"state/v1"}, Holder: "agentd",
			Transport: func(int) client.Transport { return t2 }, Evidence: kmsvm.LocalEvidence("inst-1"), Wait: time.Second,
			Logf: t.Logf, Now: now, OnLost: func(err error) { lost = append(lost, err) },
			Sleep: func(context.Context, time.Duration) { time.Sleep(20 * time.Millisecond) }}
	}
	direct := gateway.KMSTransport{D: fixedHandler{d.Handler()}}
	k, err := kmsvm.Boot(ctx, cfg(time.Now, direct))
	if err != nil {
		t.Fatal(err)
	}
	// The lease is freed under it (here: dropped; in the review's case, moved or expired while renewals were
	// blocked): the next renewal is refused, OnLost runs, and the register takes nothing more.
	if err := k.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := k.RenewOnce(ctx); err == nil || len(lost) != 1 || k.Lost() == nil {
		t.Fatalf("renewal after the lease went: %v (lost %d)", err, len(lost))
	}
	if err := k.Register("state/v1").Reserve(ctx, "side", 1, "aa"); !errors.Is(err, sealstate.ErrRefused) {
		t.Fatalf("a reservation without the lease: %v", err)
	}

	// Renewals that never get through: nothing is lost while the lease is live; once it is about to lapse, it is.
	d2, _ := kmsdev.Start(kmsdev.Options{})
	clock := time.Now()
	now := func() time.Time { return clock }
	var down bool
	flaky := transportFunc(func(c context.Context, m, p string, b []byte) ([]byte, error) {
		if down {
			return nil, gateway.ErrUnreachable
		}
		return gateway.KMSTransport{D: fixedHandler{d2.Handler()}}.Do(c, m, p, b)
	})
	lost = nil
	cf := cfg(now, flaky)
	cf.KMSID = d2.KMSID
	k2, err := kmsvm.Boot(ctx, cf)
	if err != nil {
		t.Fatal(err)
	}
	down = true
	if err := k2.RenewOnce(ctx); err == nil || len(lost) != 0 {
		t.Fatalf("an unreachable renewal with time left: %v (lost %d)", err, len(lost))
	}
	clock = time.Unix(k2.Lease().Expires, 0).Add(-10 * time.Second)
	if err := k2.RenewOnce(ctx); err == nil || len(lost) != 1 {
		t.Fatalf("an unreachable renewal at the lease's end: %v (lost %d)", err, len(lost))
	}
}

type transportFunc func(ctx context.Context, method, path string, body []byte) ([]byte, error)

func (f transportFunc) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	return f(ctx, method, path, body)
}
