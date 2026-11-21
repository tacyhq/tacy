package imapro_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/tacyhq/tacy/imapro"
	"github.com/tacyhq/tacy/imapro/imaptest"
)

// Review 2, L7: after a login (LOGIN, or AUTHENTICATE PLAIN when LOGIN is disabled), the client's write buffer holds
// neither the password nor the PLAIN token, and LoginBytes leaves the caller's bytes to the caller (who zeroes them).
func TestLoginLeavesNoPasswordInBuffers(t *testing.T) {
	const pw = "canary-pw-7f3a9e"
	for _, disabled := range []bool{false, true} {
		s := imaptest.New()
		s.LoginDisabled = disabled
		s.Users["me@example.com"] = pw
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := imapro.Dial(ctx, s.Config())
		if err != nil {
			t.Fatal(err)
		}
		pass := []byte(pw)
		if err := c.LoginBytes("me@example.com", pass); err != nil {
			t.Fatalf("login (LOGINDISABLED %v): %v", disabled, err)
		}
		buf := imapro.WriteBufferOf(c)
		tok := base64.StdEncoding.EncodeToString([]byte("\x00me@example.com\x00" + pw))
		if bytes.Contains(buf, []byte(pw)) || bytes.Contains(buf, []byte(tok)) || bytes.Contains(buf, []byte(tok[:16])) {
			t.Errorf("LOGINDISABLED %v: the write buffer still holds the password", disabled)
		}
		if string(pass) != pw {
			t.Error("LoginBytes changed the caller's bytes")
		}
		c.Close()
		cancel()
		s.Close()
	}
}
