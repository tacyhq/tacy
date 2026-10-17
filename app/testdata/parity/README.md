# Parity with the old loop

Recorded 2026-10-16 from `app/` before the runtime switchover (the old `app/agent.go` loop) by `app/parity_test.go` with `parity_old.go.txt` as its server side. `TestParity` runs the same scenarios through today's `/run` (runtime, guard, brain) and requires the same events, timings zeroed and site icons compared as a set.

To record again from an old commit: check it out, copy `app/parity_test.go` into its `app/` and `parity_old.go.txt` as `app/parity_server_test.go`, run `go test ./app -run TestParity -args -update-parity`, and copy `app/testdata/parity/*.json` back.

Not covered here (decided differences, see docs/20): the model's tool names (`web_fetch`, `web_images`), results and citation numbers in completion order when a step's calls finish out of call order, and a refused 5th call's result shown at the next step.
