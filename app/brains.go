package main

import (
	"context"
	"log"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/runner"
)

// Brain restarts back off from brainBackoff to brainBackoffMax while brains keep ending within a minute.
const (
	brainBackoff    = 250 * time.Millisecond
	brainBackoffMax = 10 * time.Second
)

// runBrains keeps a brain running in a gVisor sandbox that runnerd starts (runner/v0, docs/22-sandbox-runner.md):
// one socketpair per brain, one end passed to runnerd with the create (the brain's fd 3: no socket path, no
// listener, nothing else can connect), the other served as the harness/v1 connection. When either side ends (the
// brain crashed or exited, the runtime closed a broken or hung brain, runnerd restarted) the sandbox is destroyed
// and a new one started, as the brain's container restart did before, and the runtime resumes the tasks from their
// checkpoints (safe reads interrupted by a runtime restart run again, docs/20). One brain at a time: one brain
// per space, and one space today.
func runBrains(ctx context.Context, rt *harness.Runtime, cl *runner.Client) {
	wait := brainBackoff
	for ctx.Err() == nil {
		start := time.Now()
		if err := runBrain(ctx, rt, cl); err != nil {
			log.Printf("brain sandbox: %v", err)
		}
		if time.Since(start) > time.Minute {
			wait = brainBackoff
		} else {
			wait = min(2*wait, brainBackoffMax)
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
}

// runBrain runs one brain sandbox until its connection ends, then destroys it.
func runBrain(ctx context.Context, rt *harness.Runtime, cl *runner.Client) error {
	local, remote, err := runner.SocketPair()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	sb, err := cl.Create(cctx, "brain", remote)
	cancel()
	remote.Close() // the sandbox holds the only other copy
	if err != nil {
		local.Close()
		return err
	}
	defer sb.Close()
	go func() {
		<-sb.Done() // the sandbox ended first: end the connection too
		local.Close()
	}()
	err = rt.Serve(ctx, local)
	log.Printf("brain sandbox %s ended (%v)", sb.ID, err)
	return nil
}
