package guard

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// The relay's pricing headers against the request: a kind that isn't the run's, or a price model cheaper than a
// model the run may call (or one it doesn't name), is refused; what it was charged at is noted.
func TestCheckCharge(t *testing.T) {
	auto := func(model string, fb ...string) *proto.RunRequest {
		return &proto.RunRequest{Model: model, AutoFallback: true, FallbackModels: fb}
	}
	for _, tc := range []struct {
		name        string
		r           *proto.RunRequest
		kind, price string
		want        error
		charged     string
	}{
		{"no headers (an old tab)", auto("deepseek-v4-1-flash", "glm-5-3"), "", "", nil, "deepseek-v4-1-flash"},
		{"chat kind, empty agent", &proto.RunRequest{Model: "gpt-oss-120b"}, "a_chat", "", nil, "gpt-oss-120b"},
		{"research kind", &proto.RunRequest{Model: "gpt-oss-120b", Agent: AgentResearch}, "a_research", "", nil, "gpt-oss-120b"},
		{"review claimed for research", &proto.RunRequest{Model: "gpt-oss-120b", Agent: AgentResearch}, "a_review", "", ErrKindMismatch, ""},
		{"chat claimed for review", &proto.RunRequest{Model: "gpt-oss-120b", Agent: AgentReview}, "a_chat", "", ErrKindMismatch, ""},
		{"dearest fallback named", auto("deepseek-v4-1-flash", "glm-5-3", "gpt-oss-120b"), "a_chat", "glm-5-3", nil, "glm-5-3"},
		{"own model while a fallback is dearer", auto("deepseek-v4-1-flash", "glm-5-3"), "", "deepseek-v4-1-flash", ErrPriceModelMismatch, ""},
		{"a cheaper fallback named", auto("deepseek-v4-1-flash", "gpt-oss-120b"), "", "gpt-oss-120b", ErrPriceModelMismatch, ""},
		{"own model, cheaper fallbacks", auto("glm-5-3", "deepseek-v4-1-flash"), "", "glm-5-3", nil, "glm-5-3"},
		{"a model it doesn't name", auto("gpt-oss-120b"), "", "kimi-k3", ErrPriceModelMismatch, ""},
		// Without Auto the fallbacks are never called: the run's own model is the dearest it may call.
		{"no auto: own model", &proto.RunRequest{Model: "gpt-oss-120b", FallbackModels: []string{"kimi-k3"}}, "", "gpt-oss-120b", nil, "gpt-oss-120b"},
		{"default model", &proto.RunRequest{}, "a_chat", proto.DefaultModel, nil, proto.DefaultModel},
	} {
		err := CheckCharge(tc.r, "", tc.kind, tc.price)
		if !errors.Is(err, tc.want) || err == nil && tc.r.ChargedModel != tc.charged {
			t.Errorf("%s: err %v (want %v), charged %q (want %q)", tc.name, err, tc.want, tc.r.ChargedModel, tc.charged)
		}
	}
	// The header model counts when there's no price header (it equals the body's, checked before).
	r := &proto.RunRequest{}
	if CheckCharge(r, "gpt-oss-120b", "", "") != nil || r.ChargedModel != "gpt-oss-120b" {
		t.Fatalf("charged %q", r.ChargedModel)
	}
}

// A run keeps no fallback dearer than what it was charged at: a tab without the price header (charged at its own
// model) loses the dearer fallbacks, a priced one keeps them all.
func TestChargedFallbacks(t *testing.T) {
	r := &proto.RunRequest{Model: "deepseek-v4-1-flash", AutoFallback: true, FallbackModels: []string{"glm-5-3", "gemma4-31b", "kimi-k3", "gpt-oss-120b"}}
	if err := CheckCharge(r, "deepseek-v4-1-flash", "", ""); err != nil {
		t.Fatal(err)
	}
	if got := chargedFallbacks(r); !slices.Equal(got, []string{"gemma4-31b", "gpt-oss-120b"}) {
		t.Fatalf("unpriced: %v", got)
	}
	if PriceModel(r) != "kimi-k3" {
		t.Fatalf("PriceModel %q", PriceModel(r))
	}
	r.ChargedModel = ""
	if err := CheckCharge(r, "deepseek-v4-1-flash", "a_chat", PriceModel(r)); err != nil {
		t.Fatal(err)
	}
	if got := chargedFallbacks(r); !slices.Equal(got, []string{"glm-5-3", "gemma4-31b", "kimi-k3", "gpt-oss-120b"}) {
		t.Fatalf("priced: %v", got)
	}
	// The start a web run gets lists only the kept models (what the brain may switch to).
	r = &proto.RunRequest{Permissions: AllowAll(), Space: testSpace, Model: "deepseek-v4-1-flash", AutoFallback: true, FallbackModels: []string{"glm-5-3", "gpt-oss-120b"},
		Messages: []proto.Message{{Role: "user", Content: "q"}}}
	if err := CheckCharge(r, "deepseek-v4-1-flash", "", ""); err != nil {
		t.Fatal(err)
	}
	s, _, err := StartFor(r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Models, []string{"deepseek-v4-1-flash", "gpt-oss-120b"}) {
		t.Fatalf("start's models %v", s.Models)
	}
}

func TestKnownKind(t *testing.T) {
	for k, want := range map[string]bool{"a_chat": true, "a_research": true, "a_review": true, "a_scheduled": false, "": false, "a_bogus": false} {
		if KnownKind(k) != want {
			t.Errorf("%q: %v", k, !want)
		}
	}
}
