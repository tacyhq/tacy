package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
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
	if err := v.EnableConns(""); err != nil {
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
	b, _ := json.Marshal(map[string]any{"type": vault.EmailType, "provider": "other", "host": imaptest.Host, "port": 993,
		"security": "tls", "address": user, "username": user, "password": pass})
	box, err := vault.SealConn(key, a.Space, vault.ConnEmail, b)
	if err != nil {
		e.t.Fatal(err)
	}
	return connPutRequest{Where: e.where(a, runauth.ConnPutLabel, vault.ConnEmail, BoxDigest(box)), Connection: vault.ConnEmail, Sealed: box}
}

// Settings → Connections over agentd's routes: signed calls only, a box that logs in is kept, one that doesn't
// isn't, replays and misdirected signatures are refused, remove forgets it; under a policy without the mail
// connector nothing is kept. Never a password in an answer.
func TestConnectionRoutes(t *testing.T) {
	e, srv, v := newConnEnv(t)
	code, out := e.connList(e.me)
	key, _ := out["seal_key"].(string)
	if code != 200 || !strings.HasPrefix(key, "x25519:") || len(out["connections"].([]any)) != 0 {
		t.Fatalf("list %d %v", code, out)
	}
	if code, out := e.call(e.s.connPut, e.connPutBody(e.me, key, connUser, "wrong")); code != 401 || errOf(out) != "login_failed" {
		t.Fatalf("bad password %d %v", code, out)
	}
	good := e.connPutBody(e.me, key, connUser, connPass)
	code, out = e.call(e.s.connPut, good)
	if code != 200 || out["state"] != "connected" || out["read_only"] != true || out["address"] != connUser || out["host"] != imaptest.Host {
		t.Fatalf("put %d %v", code, out)
	}
	if code, out := e.call(e.s.connPut, good); code != 409 || errOf(out) != "replayed" {
		t.Fatalf("replay %d %v", code, out)
	}
	misdirected := e.connPutBody(e.me, key, connUser, connPass)
	misdirected.Where = e.where(e.me, runauth.ConnListLabel)
	if code, out := e.call(e.s.connPut, misdirected); code != 403 || errOf(out) != "bad_proof" {
		t.Fatalf("signed for another call %d %v", code, out)
	}
	// Another person can't see or remove it.
	other, _ := runauth.NewAsker()
	if code, out := e.connList(other); code != 200 || len(out["connections"].([]any)) != 0 {
		t.Fatalf("another space's list %d %v", code, out)
	}
	code, out = e.connList(e.me)
	if l := out["connections"].([]any); code != 200 || len(l) != 1 {
		t.Fatalf("list after put %d %v", code, out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), connPass) {
		t.Fatal("a password in an answer")
	}
	code, out = e.call(e.s.connRemove, connRemoveRequest{Where: e.where(e.me, runauth.ConnRemoveLabel, vault.ConnEmail), Connection: vault.ConnEmail})
	if code != 200 || out["state"] != "removed" {
		t.Fatalf("remove %d %v", code, out)
	}
	if _, err := v.ConnGet(e.me.Space, vault.ConnEmail); err == nil {
		t.Fatal("still in the vault")
	}
	// A policy without the mail connector: nothing is tried, nothing kept.
	e.mustPost(e.policy(2, func(p *safety.Policy) { delete(p.Connectors, "mail") }))
	n := len(srv.Commands())
	if code, out := e.call(e.s.connPut, e.connPutBody(e.me, key, connUser, connPass)); code != 403 || errOf(out) != "policy_denied" {
		t.Fatalf("policy without mail %d %v", code, out)
	}
	if len(srv.Commands()) != n {
		t.Fatal("the server was reached under a policy without mail")
	}
	for _, c := range srv.CommandNames() {
		if !slices.Contains([]string{"CAPABILITY", "LOGIN", "LIST", "LOGOUT"}, c) {
			t.Fatalf("a connect sent %s", c)
		}
	}
}

// A scheduled run reads the sponsor's email when its definition allows the mail tools always: searched and read
// through the reader, nothing marked read, its result sealed; with the mail tools on never, it is denied and the
// server never reached.
func TestScheduledRunReadsMail(t *testing.T) {
	e, srv, _ := newConnEnv(t, pCalls([3]string{"c1", "mail_search", `{"unread":true}`}), pCalls([3]string{"c2", "mail_read", `{"id":"m1"}`}),
		pText("Unread: an invoice from Alice, 1,240 EUR due 5 November [m1]."))
	_, out := e.connList(e.me)
	if code, out := e.call(e.s.connPut, e.connPutBody(e.me, out["seal_key"].(string), connUser, connPass)); code != 200 {
		t.Fatalf("connect %d %v", code, out)
	}
	before, seen := srv.Snapshot(), srv.SeenCount()
	mail := []string{"mail.search", "mail.read", "mail.folders"}
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Instructions = "Every morning, summarize my unread mail from clients."
		d.Tools = mail
		d.Allow = map[string]string{"mail.search": safety.PermAlways, "mail.read": safety.PermAlways, "mail.folders": safety.PermAlways}
	})
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	r := e.waitResult(task)
	if r.State != harness.OutcomeSucceeded {
		t.Fatalf("result %+v", r)
	}
	_, body := e.openResult(e.me, task)
	var searched, read bool
	for _, ev := range body.Events {
		if ev.Type == "tool_result" && ev.Name == "mail_search" && strings.Contains(string(ev.Result), `"m1"`) {
			searched = true
		}
		if ev.Type == "tool_result" && ev.Name == "mail_read" && strings.Contains(string(ev.Result), "1,240 EUR") {
			read = true
		}
	}
	if !searched || !read {
		t.Fatalf("the run didn't read the mail (%d events)", len(body.Events))
	}
	if srv.Snapshot() != before || srv.SeenCount() != seen {
		t.Fatal("the mailbox changed")
	}
}

func TestScheduledMailNeedsAlways(t *testing.T) {
	e, srv, _ := newConnEnv(t, pCalls([3]string{"c1", "mail_search", `{}`}), pText("I couldn't read your mail."))
	_, out := e.connList(e.me)
	if code, _ := e.call(e.s.connPut, e.connPutBody(e.me, out["seal_key"].(string), connUser, connPass)); code != 200 {
		t.Fatal("connect")
	}
	n := len(srv.Commands())
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Tools = []string{"mail.search"}
		d.Allow = map[string]string{"mail.search": safety.PermNever}
	})
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	e.waitResult(task)
	_, body := e.openResult(e.me, task)
	denied := false
	for _, ev := range body.Events {
		if ev.Type == "tool_result" && ev.Name == "mail_search" && strings.Contains(string(ev.Result), "permission_denied") {
			denied = true
		}
	}
	if !denied || len(srv.Commands()) != n {
		t.Fatalf("denied %v, server commands %v", denied, srv.Commands()[n:])
	}
}
