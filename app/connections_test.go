package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/imapro/imaptest"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
	"github.com/tacyhq/tacy/vault"
)

const (
	connUser = "me@example.com"
	connPass = "abcd efgh ijkl mnop"
)

func connServer(t *testing.T) *imaptest.Server {
	t.Helper()
	s := imaptest.New()
	s.Users[connUser] = connPass
	s.Add("INBOX", []byte("Date: Tue, 27 Oct 2026 09:00:00 +0000\r\nFrom: Alice <alice@client.example>\r\nSubject: Invoice 4471\r\n\r\n"+
		"The invoice 4471 is 1,240 EUR, due 5 November.\r\n"), time.Now().Add(-time.Hour))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// mailReader answers the quarantined reader's mail calls: a fact per message or the message's own.
func mailReader(prompt string) string {
	facts := []string{"An invoice from Alice [R1]."}
	if strings.Contains(prompt, "Kind: one email message") {
		facts = []string{"Alice wants 1,240 EUR by 5 Nov."}
	}
	b, _ := json.Marshal(map[string]any{"summary": "An invoice.", "facts": facts, "entities": []string{"Alice"}, "dates": []string{},
		"amounts": []string{}, "source": map[string]any{"kind": "other", "title": "", "publisher": "", "published": ""},
		"quotes": []any{}, "wording": "", "instructions_found": false, "instruction_count": 0})
	return string(b)
}

func newConnEnv(t *testing.T, replies ...string) (*schedEnv, *imaptest.Server, *vault.Vault) {
	t.Helper()
	srv := connServer(t)
	v, err := vault.New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableConns(nil); err != nil {
		t.Fatal(err)
	}
	e := newSchedEnvWith(t, safeOpts{reader: mailReader,
		mail: &guard.MailConfig{Vault: vault.Local{V: v}, Dial: srv.Dial, TLS: srv.TLSConfig()}}, replies...)
	return e, srv, v
}

func (e *schedEnv) connList(a *runauth.Asker) (int, map[string]any) {
	return e.call(e.s.connList, e.where(a, runauth.ConnListLabel))
}

func (e *schedEnv) connPutBody(a *runauth.Asker, key, user, pass string) connPutRequest {
	return e.connBody(a, runauth.ConnPutLabel, key, user, pass)
}

// connBody is a Settings call with a sealed account, signed under label (test, or the old put).
func (e *schedEnv) connBody(a *runauth.Asker, label, key, user, pass string) connPutRequest {
	b, _ := json.Marshal(map[string]any{"type": vault.EmailType, "provider": "other", "host": imaptest.Host, "port": 993,
		"security": "tls", "address": user, "username": user, "password": pass})
	box, err := vault.SealConn(key, a.Space, vault.ConnEmail, b)
	if err != nil {
		e.t.Fatal(err)
	}
	return connPutRequest{Where: e.where(a, label, vault.ConnEmail, BoxDigest(box)), Connection: vault.ConnEmail, Sealed: box}
}

// Settings → Connections over agentd's routes (v1): signed calls only; a test logs in and keeps nothing (state
// "tested", never listed, never leased); a failed login says why; put is gone (410 per_request) whatever its body;
// replays and misdirected signatures are refused; under a policy without the mail connector nothing is tried.
// Never a password in an answer.
func TestConnectionRoutes(t *testing.T) {
	e, srv, v := newConnEnv(t)
	code, out := e.connList(e.me)
	key, _ := out["seal_key"].(string)
	if code != 200 || !strings.HasPrefix(key, "x25519:") || len(out["connections"].([]any)) != 0 {
		t.Fatalf("list %d %v", code, out)
	}
	test := func(body connPutRequest) (int, map[string]any) { return e.call(e.s.connTest, body) }
	if code, out := test(e.connBody(e.me, runauth.ConnTestLabel, key, connUser, "wrong")); code != 401 || errOf(out) != "login_failed" {
		t.Fatalf("bad password %d %v", code, out)
	}
	good := e.connBody(e.me, runauth.ConnTestLabel, key, connUser, connPass)
	code, out = test(good)
	if code != 200 || out["state"] != "tested" || out["read_only"] != true || out["address"] != connUser || out["host"] != imaptest.Host ||
		out["connected_at"] != nil {
		t.Fatalf("test %d %v", code, out)
	}
	if code, out := test(good); code != 409 || errOf(out) != "replayed" {
		t.Fatalf("replay %d %v", code, out)
	}
	if code, out := test(e.connBody(e.me, runauth.ConnPutLabel, key, connUser, connPass)); code != 403 || errOf(out) != "bad_proof" {
		t.Fatalf("signed for put %d %v", code, out)
	}
	// Nothing kept: not listed, no login in the vault.
	if code, out := e.connList(e.me); code != 200 || len(out["connections"].([]any)) != 0 {
		t.Fatalf("list after a test %d %v", code, out)
	}
	if v.RunCreds() != 0 {
		t.Fatal("a tested login is held")
	}
	// put: 410, nothing tried.
	n := len(srv.Commands())
	if code, out := e.call(e.s.connPut, e.connPutBody(e.me, key, connUser, connPass)); code != 410 || errOf(out) != "per_request" {
		t.Fatalf("put %d %v", code, out)
	}
	if len(srv.Commands()) != n {
		t.Fatal("a put reached the server")
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), connPass) {
		t.Fatal("a password in an answer")
	}
	code, out = e.call(e.s.connRemove, connRemoveRequest{Where: e.where(e.me, runauth.ConnRemoveLabel, vault.ConnEmail), Connection: vault.ConnEmail})
	if code != 200 || out["state"] != "removed" {
		t.Fatalf("remove %d %v", code, out)
	}
	// A policy without the mail connector: nothing is tried.
	e.mustPost(e.policy(2, func(p *safety.Policy) { delete(p.Connectors, "mail") }))
	n = len(srv.Commands())
	if code, out := test(e.connBody(e.me, runauth.ConnTestLabel, key, connUser, connPass)); code != 403 || errOf(out) != "policy_denied" {
		t.Fatalf("policy without mail %d %v", code, out)
	}
	if len(srv.Commands()) != n {
		t.Fatal("the server was reached under a policy without mail")
	}
	for _, c := range srv.CommandNames() {
		if !slices.Contains([]string{"CAPABILITY", "LOGIN", "LIST", "LOGOUT"}, c) {
			t.Fatalf("a test sent %s", c)
		}
	}
}

// v1 schedules can't use mail (R1 at install, through agentd's route): a definition with a mail tool is refused
// 403 bad_definition (mail_background_later; with a web tool, mail_and_web), and nothing is installed.
func TestScheduledMailRefusedAtInstall(t *testing.T) {
	e, _, _ := newConnEnv(t)
	for want, tools := range map[string][]string{
		"mail_background_later": {"mail.search", "mail.read"},
		"mail_and_web":          {"mail.search", "web.fetch"},
	} {
		d := e.daily(e.me, func(d *trigger.Definition) {
			d.Instructions = "Every morning, summarize my unread mail from clients."
			d.Tools = tools
			d.Allow = map[string]string{"mail.search": safety.PermAlways}
		})
		code, out := e.install(e.me, e.sign(d, e.me.Key))
		if detail, _ := out["detail"].(string); code != 403 || errOf(out) != "bad_definition" || !strings.Contains(detail, want) {
			t.Fatalf("%v: %d %v", tools, code, out)
		}
		if e.s.triggers.Get(d.Agent) != nil {
			t.Fatalf("%v: installed", tools)
		}
	}
}
