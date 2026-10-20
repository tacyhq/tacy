package safety

import (
	"errors"
	"flag"
	"strings"
	"time"
)

// Flags are the trust roots every process takes from the attested compose: the same values in agentd, gatewayd
// and vaultd.
type Flags struct {
	Firm, Operator, Admins string
	Threshold              int
	Genesis, Carry         string
	MaxStopAge             time.Duration
}

// Register adds the flags to fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.Firm, "firm", "f_chat", "the firm this VM serves (policies and stop lists are for it)")
	fs.StringVar(&f.Operator, "operator-key", "", "the operator's stop list key (ed25519:<base64>); empty: no heartbeat, always stale")
	fs.StringVar(&f.Admins, "admin-keys", "", "the firm's admin keys, comma-separated (ed25519:<base64>); empty: the release policy alone")
	fs.IntVar(&f.Threshold, "admin-threshold", 1, "admin signatures a policy or the firm's stop list needs")
	fs.StringVar(&f.Genesis, "keylog-genesis", "", "the firm key log's genesis hash (64 hex): admin signers come from the log (not with -admin-keys)")
	fs.StringVar(&f.Carry, "keylog-carry", "", "hashes of documents signed before the key log, by the key that is now its recovery kit, comma-separated")
	fs.DurationVar(&f.MaxStopAge, "stop-max-age", DefaultMaxStopAge, "how old the newest operator stop list may get")
}

// Config makes the State config with the release's ceiling and where to persist ("" for memory).
func (f *Flags) Config(release *Policy, dir string) (Config, error) {
	c := Config{Firm: f.Firm, Threshold: f.Threshold, Release: release, MaxStopAge: f.MaxStopAge, Dir: dir, Genesis: f.Genesis}
	for _, h := range strings.Split(f.Carry, ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.Carry = append(c.Carry, h)
		}
	}
	if f.Operator != "" {
		k, err := ParseKey(f.Operator)
		if err != nil {
			return c, err
		}
		c.Operator = k
	}
	admins, err := ParseKeys(f.Admins)
	if err != nil {
		return c, err
	}
	c.Admins = admins
	if f.Genesis != "" && len(admins) > 0 {
		return c, errors.New("safety: -keylog-genesis replaces -admin-keys: pin one or the other")
	}
	if f.Threshold < 1 || len(admins) > 0 && f.Threshold > len(admins) {
		return c, errors.New("safety: -admin-threshold must be 1 to the number of admin keys")
	}
	return c, nil
}
