package guard

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// What the relay charges a run for (v0.16.0). The relay can't read the encrypted body, so the browser states in
// plaintext what it prices, and agentd checks each statement against the body (signed by the person's identity)
// before anything runs, as it checks X-Agent-Model:
//
//   - X-Agent-Kind: the built-in agent the run is ("a_chat", "a_research", "a_review"; the body's agent, "" being the
//     chat). The relay prices a research or review task at its own typical cost (the chat's plans.ts); a tab that doesn't
//     say is charged the dearest kind.
//   - X-Agent-Price-Model: the dearest model the run may call, its own or a fallback on Auto (safety.PriceRank). The
//     relay prices the run at it. A tab that doesn't say is charged at X-Agent-Model, and then no fallback dearer
//     than that is kept (ChargedModel), so a run never switches to a model it wasn't charged for.
//
// Each header is a few fixed words the relay could mostly guess anyway (which agent card or model the plan offers);
// never content. A mismatch is refused (400, inside the encrypted answer) before any model call.

// Errors CheckCharge returns: the run wasn't started (the answer is encrypted, so only the browser reads them).
var (
	ErrKindMismatch       = errors.New("kind_mismatch: the X-Agent-Kind header doesn't match the run's agent")
	ErrPriceModelMismatch = errors.New("price_model_mismatch: the X-Agent-Price-Model header isn't the dearest model the run may call")
)

// KnownKind: kind is a built-in agent a person's request may name (X-Agent-Kind's values).
func KnownKind(kind string) bool {
	_, ok := agentDefs[kind]
	return ok && Startable(kind)
}

// RunModels are the models a run may call, as the relay must price it: its own model, then (on Auto only) the
// fallbacks this guard would keep. The signed policy can only drop some of them later, never add one.
func RunModels(r *proto.RunRequest) []string {
	model := cmp.Or(r.Model, proto.DefaultModel)
	out := []string{model}
	if r.AutoFallback {
		out = append(out, fallbackModels(model, r.FallbackModels)...)
	}
	return out
}

// PriceModel is the X-Agent-Price-Model a request should carry: the dearest of RunModels (the first of equals).
func PriceModel(r *proto.RunRequest) string {
	ms := RunModels(r)
	best := ms[0]
	for _, m := range ms[1:] {
		if safety.PriceRank(m) > safety.PriceRank(best) {
			best = m
		}
	}
	return best
}

// CheckCharge checks the relay's pricing headers against the (decrypted, verified) request and notes in r what the
// run was charged at (ChargedModel). kind and price are the X-Agent-Kind and X-Agent-Price-Model headers, "" when the
// tab didn't send them. headerModel is X-Agent-Model, already checked to equal the body's model.
func CheckCharge(r *proto.RunRequest, headerModel, kind, price string) error {
	if kind != "" && kind != cmp.Or(r.Agent, AgentChat) {
		return ErrKindMismatch
	}
	if price == "" {
		r.ChargedModel = cmp.Or(headerModel, r.Model, proto.DefaultModel)
		return nil
	}
	// One of the request's own models (its model or a fallback it lists), and none it may call is dearer.
	if price != cmp.Or(r.Model, proto.DefaultModel) && !slices.Contains(r.FallbackModels, price) {
		return ErrPriceModelMismatch
	}
	for _, m := range RunModels(r) {
		if safety.PriceRank(m) > safety.PriceRank(price) {
			return fmt.Errorf("%w (%s is dearer)", ErrPriceModelMismatch, m)
		}
	}
	r.ChargedModel = price
	return nil
}

// chargedFallbacks are the fallbacks a run keeps (fallbackModels), less any dearer than the model the relay charged
// it at (ChargedModel; "": none dropped).
func chargedFallbacks(r *proto.RunRequest) []string {
	out := fallbackModels(r.Model, r.FallbackModels)
	if r.ChargedModel == "" {
		return out
	}
	limit := safety.PriceRank(r.ChargedModel)
	return slices.DeleteFunc(out, func(m string) bool { return safety.PriceRank(m) > limit })
}
