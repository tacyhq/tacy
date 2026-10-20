package guard

import "context"

// labReasoning feeds a replayed run's reasoning delta where the gateway does (gateway.go: the mention watch).
func labReasoning(g *Guard, t *task, delta string) { g.watchMentions(t, delta) }

// labFast is the fast image search where the guard has one.
func labFast(e *exa, ctx context.Context, q string, n int) ([]ImageCandidate, error) {
	return e.ImagesFast(ctx, q, n)
}
