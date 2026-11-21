package cftunnel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The confined variant (a third outside review, a research note
// §2): cloudflared in a container of its own (service cftunnel: its own uid and network, no capabilities), sharing
// one tmpfs volume with gatewayd, which holds only the ingress socket and the token file. gatewayd serves the
// Ingress there and publishes the token for cloudflared's uid (group read); Docker restarts cloudflared until the
// token is there (after the unlock).
const (
	ConfinedDir    = "/run/tacy/cft"
	ConfinedSocket = "/run/tacy/cft/ingress.sock"
	ConfinedToken  = "/run/tacy/cft/token"
	ConfinedUID    = TunnelUID
)

// PublishToken waits for the token and writes it to dir/token, 0640 with group gid (cloudflared's), atomically.
func PublishToken(ctx context.Context, dir string, gid int, token func(context.Context) ([]byte, error), logf func(string, ...any)) error {
	if err := checkTmpfs(dir); err != nil {
		return fmt.Errorf("cftunnel: %s: %w", dir, err)
	}
	s := &Supervisor{Token: token, Logf: logf}
	tok, err := s.waitToken(ctx)
	if err != nil {
		return err
	}
	defer clear(tok)
	tmp := filepath.Join(dir, ".token")
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	_, err = f.Write(tok)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chown(tmp, -1, gid)
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, "token"))
	}
	if err != nil {
		wipe(tmp)
		return err
	}
	if logf != nil {
		logf("cftunnel: token published for gid %d at %s", gid, time.Now().UTC().Format(time.RFC3339))
	}
	return nil
}
