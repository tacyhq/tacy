package imapro_test

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/imapro"
	"github.com/tacyhq/tacy/imapro/imaptest"
)

// refusedCommands are commands a read-write client would send; the read-only client must refuse each before writing.
var refusedCommands = []string{
	"SELECT INBOX", "STORE 1 +FLAGS (\\Seen)", "STORE 1:* FLAGS (\\Deleted)", "EXPUNGE", "APPEND INBOX {3}",
	"COPY 1 Trash", "MOVE 1 Trash", "CREATE Junk2", "DELETE INBOX", "RENAME INBOX Old", "SUBSCRIBE INBOX",
	"UNSUBSCRIBE INBOX", "CLOSE", "UNSELECT", "IDLE", "ENABLE CONDSTORE", "SETMETADATA INBOX (/private/x y)",
	"ID NIL", "STATUS INBOX (MESSAGES)", "CHECK", "UID STORE 1 +FLAGS (\\Seen)", "UID COPY 1 Trash", "UID MOVE 1 Trash",
	"UID EXPUNGE 1", "UID", "AUTHENTICATE XOAUTH2", "AUTHENTICATE", "XLIST \"\" *", "NAMESPACE", "GETQUOTAROOT INBOX",
	"FETCH 1 BODY[]", "FETCH 1 RFC822", "FETCH 1 RFC822.TEXT", "FETCH 1 RFC822.HEADER", "FETCH 1 (FLAGS BODY[TEXT])",
	"FETCH 1 ALL", "FETCH 1 FULL", "FETCH 1 FAST", "UID FETCH 1 (BODY[]<0.10>)", "UID FETCH 1 BODY[HEADER]",
	"FETCH 1 (BODY.PEEK[] BODY[1])", "FETCH 1 BINARY[1]", "FETCH 1 (X-GM-LABELS)", "FETCH 1 BODY.PEEK[HEADER.FIELDS (FROM",
	"FETCH 1 (UID", "FETCH UID", "NOOP x", "LOGOUT now", "CAPABILITY x", "STARTTLS x", "XYZZY", "", "LOGIN a b\r\nSTORE 1 +FLAGS (\\Seen)",
}

var allowedCommands = []string{
	"CAPABILITY", "STARTTLS", "LOGIN \"a\" \"b\"", "AUTHENTICATE PLAIN", "EXAMINE \"INBOX\"", "SEARCH ALL",
	"UID SEARCH TEXT \"x\"", "LIST \"\" \"*\"", "NOOP", "LOGOUT", "FETCH 1 FLAGS", "UID FETCH 1,2,5:7 (UID FLAGS RFC822.SIZE)",
	"UID FETCH 9 (UID FLAGS RFC822.SIZE BODY.PEEK[]<0.1048576>)", "UID FETCH 9 (BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT)])",
	"FETCH 1 (ENVELOPE BODYSTRUCTURE INTERNALDATE)", "UID FETCH 3 BODY.PEEK[1.2.TEXT]", "UID FETCH 3 BODY.PEEK[TEXT]<0.100>",
}

func TestAllowedIsTheReadOnlyRule(t *testing.T) {
	for _, c := range refusedCommands {
		if err := imapro.Allowed(c); !errors.Is(err, imapro.ErrRefused) {
			t.Errorf("Allowed(%q) = %v, want refused", c, err)
		}
	}
	for _, c := range allowedCommands {
		if err := imapro.Allowed(c); err != nil {
			t.Errorf("Allowed(%q) = %v, want allowed", c, err)
		}
	}
}

const plainMsg = "Date: Mon, 26 Oct 2026 09:14:00 +0000\r\nFrom: Alice Client <alice@client.example>\r\nTo: Me <me@example.com>\r\n" +
	"Subject: Invoice for October\r\nMessage-ID: <1@client.example>\r\n\r\nHi, the October invoice is 1,240 EUR, due 5 November.\r\n"

func newServer(t *testing.T, sec string) *imaptest.Server {
	t.Helper()
	s := imaptest.New()
	s.Security = sec
	s.Users["me@example.com"] = "abcd efgh ijkl mnop"
	s.Add("INBOX", []byte(plainMsg), time.Date(2026, 10, 26, 9, 14, 0, 0, time.UTC))
	s.Add("INBOX", []byte(strings.Replace(strings.Replace(plainMsg, "Invoice for October", "Lunch on Friday?", 1),
		"the October invoice is 1,240 EUR, due 5 November", "lunch at noon on Friday", 1)),
		time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), `\Seen`)
	s.Add("Clients", []byte(strings.Replace(plainMsg, "Invoice for October", "Contract draft v2", 1)),
		time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func dial(t *testing.T, s *imaptest.Server) *imapro.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, err := imapro.Dial(ctx, s.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Login("me@example.com", "abcd efgh ijkl mnop"); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestReadOnlySessionChangesNothing(t *testing.T) {
	for _, sec := range []string{imapro.TLS, imapro.STARTTLS} {
		t.Run(sec, func(t *testing.T) {
			s := newServer(t, sec)
			before, seen := s.Snapshot(), s.SeenCount()
			c := dial(t, s)
			folders, err := c.List()
			if err != nil || len(folders) != 2 {
				t.Fatalf("List = %v, %v", folders, err)
			}
			mb, err := c.Examine("INBOX")
			if err != nil || mb.Exists != 2 || mb.UIDValidity != 7 {
				t.Fatalf("Examine = %+v, %v", mb, err)
			}
			uids, err := c.Search(imapro.Criteria{Words: []string{"invoice"}})
			if err != nil || len(uids) != 1 {
				t.Fatalf("Search = %v, %v", uids, err)
			}
			hs, err := c.FetchHeaders(uids)
			if err != nil || len(hs) != 1 || !hs[0].Unseen() {
				t.Fatalf("FetchHeaders = %+v, %v", hs, err)
			}
			if h := imapro.ParseHeaders(hs[0].Body); h.Subject != "Invoice for October" || h.From[0].Addr != "alice@client.example" {
				t.Fatalf("headers = %+v", h)
			}
			m, err := c.FetchMessage(uids[0], 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if p := imapro.ParseMessage(m.Body); !strings.Contains(p.Text, "1,240 EUR") {
				t.Fatalf("text = %q", p.Text)
			}
			if err := c.Logout(); err != nil {
				t.Fatal(err)
			}
			if after := s.Snapshot(); after != before || s.SeenCount() != seen {
				t.Fatalf("the mailbox changed:\n%s\n%s", before, after)
			}
			allowed := []string{"CAPABILITY", "STARTTLS", "LOGIN", "AUTHENTICATE", "LIST", "EXAMINE", "UID SEARCH", "UID FETCH", "LOGOUT", "NOOP"}
			for _, n := range s.CommandNames() {
				if !slices.Contains(allowed, n) {
					t.Errorf("the server got %s", n)
				}
			}
			for _, cmd := range s.Commands() {
				if strings.Contains(cmd, "BODY[") && !strings.Contains(cmd, "BODY.PEEK[") {
					t.Errorf("a non-PEEK fetch: %s", cmd)
				}
			}
			if sec == imapro.STARTTLS {
				names := s.CommandNames()
				if i, j := slices.Index(names, "STARTTLS"), slices.Index(names, "LOGIN"); i < 0 || j < i {
					t.Fatalf("LOGIN before STARTTLS: %v", names)
				}
			}
		})
	}
}

// Every write command is refused in code, before a byte reaches the server, even mid-session with a folder open.
func TestWriteCommandsNeverReachTheServer(t *testing.T) {
	s := newServer(t, imapro.TLS)
	before := s.Snapshot()
	c := dial(t, s)
	if _, err := c.Examine("INBOX"); err != nil {
		t.Fatal(err)
	}
	n := len(s.Commands())
	for _, cmd := range refusedCommands {
		if cmd == "" || strings.ContainsAny(cmd, "\r\n") {
			continue
		}
		f := strings.Fields(cmd)
		if err := c.Raw(f[0], f[1:]...); !errors.Is(err, imapro.ErrRefused) {
			t.Errorf("Raw(%q) = %v, want refused", cmd, err)
		}
	}
	if got := s.Commands()[n:]; len(got) != 0 {
		t.Fatalf("refused commands reached the server: %v", got)
	}
	// The session still works after the refusals, and nothing changed.
	if _, err := c.Search(imapro.Criteria{}); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot() != before {
		t.Fatal("the mailbox changed")
	}
}

// The fake server marks a message read on any non-PEEK fetch (Sloppy), even under EXAMINE: proof the stand-in would
// catch a client that didn't PEEK.
func TestSloppyServerCatchesNonPeek(t *testing.T) {
	s := newServer(t, imapro.TLS)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := tls.Dial("tcp", s.Addr(), &tls.Config{RootCAs: s.TLSConfig().RootCAs, ServerName: imaptest.Host})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = ctx
	buf := make([]byte, 4096)
	conn.Read(buf)
	for _, l := range []string{"a LOGIN \"me@example.com\" \"abcd efgh ijkl mnop\"\r\n", "b EXAMINE INBOX\r\n", "c FETCH 1 BODY[]\r\n"} {
		conn.Write([]byte(l))
		time.Sleep(50 * time.Millisecond)
		conn.Read(buf)
	}
	if s.SeenCount() != 2 {
		t.Fatalf("seen = %d, want 2 (the stand-in marks a non-PEEK fetch read)", s.SeenCount())
	}
}

func TestLoginRefusals(t *testing.T) {
	s := newServer(t, imapro.TLS)
	s.Refuse["app@example.com"] = "app_password"
	s.Refuse["web@example.com"] = "web_login"
	s.Refuse["off@example.com"] = "disabled"
	for user, want := range map[string]string{"me@example.com": imapro.LoginFailed, "app@example.com": imapro.AppPasswordRequired,
		"web@example.com": imapro.AppPasswordsBlocked, "off@example.com": imapro.AppPasswordsBlocked, "nobody@example.com": imapro.LoginFailed} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := imapro.Dial(ctx, s.Config())
		if err != nil {
			t.Fatal(err)
		}
		err = c.Login(user, "wrong")
		var le *imapro.LoginError
		if !errors.As(err, &le) || le.Code != want {
			t.Errorf("%s: %v, want %s", user, err, want)
		}
		c.Close()
		cancel()
	}
}

func TestAuthenticatePlainWhenLoginDisabled(t *testing.T) {
	s := imaptest.New()
	s.LoginDisabled = true
	s.Users["me@example.com"] = "pw"
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := imapro.Dial(ctx, s.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("me@example.com", "pw"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.CommandNames(), "AUTHENTICATE") || slices.Contains(s.CommandNames(), "LOGIN") {
		t.Fatalf("commands %v", s.CommandNames())
	}
}

func TestExamineMustBeReadOnly(t *testing.T) {
	s := newServer(t, imapro.TLS)
	s.ReadWriteExamine = true
	c := dial(t, s)
	if _, err := c.Examine("INBOX"); !errors.Is(err, imapro.ErrNotReadOnly) {
		t.Fatalf("Examine on a server that says READ-WRITE = %v", err)
	}
}

func TestCertificatesChecked(t *testing.T) {
	s := newServer(t, imapro.TLS)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := s.Config()
	cfg.TLS = nil // the system roots don't know the test CA
	if _, err := imapro.Dial(ctx, cfg); !errors.Is(err, imapro.ErrTLS) {
		t.Fatalf("untrusted certificate: %v", err)
	}
	cfg = s.Config()
	cfg.Host = "other.example"
	if _, err := imapro.Dial(ctx, cfg); !errors.Is(err, imapro.ErrTLS) {
		t.Fatalf("certificate for another name: %v", err)
	}
	cfg = s.Config()
	cfg.TLS = &tls.Config{InsecureSkipVerify: true}
	if _, err := imapro.Dial(ctx, cfg); !errors.Is(err, imapro.ErrTLS) {
		t.Fatalf("skip verify: %v", err)
	}
	cfg = s.Config()
	cfg.Security = "plain"
	if _, err := imapro.Dial(ctx, cfg); err == nil {
		t.Fatal("plaintext allowed")
	}
	// Implicit TLS against a STARTTLS server (plaintext greeting) fails at TLS, never sends anything in the clear.
	st := newServer(t, imapro.STARTTLS)
	cfg = st.Config()
	cfg.Security = imapro.TLS
	if _, err := imapro.Dial(ctx, cfg); !errors.Is(err, imapro.ErrTLS) {
		t.Fatalf("tls to a plaintext greeting: %v", err)
	}
	// The server saw a TLS ClientHello (binary), never an IMAP command.
	for _, n := range st.CommandNames() {
		for _, imap := range []string{"CAPABILITY", "LOGIN", "AUTHENTICATE", "STARTTLS", "LIST", "EXAMINE"} {
			if n == imap {
				t.Fatalf("sent in the clear: %v", n)
			}
		}
	}
}

func TestSearchCriteria(t *testing.T) {
	s := newServer(t, imapro.TLS)
	s.Add("INBOX", []byte("From: Zoë <zoe@example.org>\r\nSubject: =?UTF-8?Q?R=C3=A9union?=\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nÀ demain, réunion à 10h.\r\n"),
		time.Date(2026, 10, 28, 7, 0, 0, 0, time.UTC))
	c := dial(t, s)
	if _, err := c.Examine("INBOX"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cr   imapro.Criteria
		want int
	}{
		{imapro.Criteria{}, 3},
		{imapro.Criteria{Unseen: true}, 2},
		{imapro.Criteria{From: "alice"}, 2},
		{imapro.Criteria{Words: []string{"invoice", "october"}}, 1},
		{imapro.Criteria{Since: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)}, 2},
		{imapro.Criteria{Before: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)}, 1},
		{imapro.Criteria{Words: []string{"réunion"}}, 1},
	} {
		uids, err := c.Search(tc.cr)
		if err != nil || len(uids) != tc.want {
			t.Errorf("Search(%+v) = %v, %v; want %d", tc.cr, uids, err, tc.want)
		}
	}
	if !slices.ContainsFunc(s.Commands(), func(c string) bool { return strings.Contains(c, "CHARSET UTF-8") }) {
		t.Fatal("a non-ASCII word went without CHARSET UTF-8")
	}
}

func TestResponseCap(t *testing.T) {
	s := newServer(t, imapro.TLS)
	big := plainMsg + strings.Repeat("x", 200<<10)
	uid := s.Add("INBOX", []byte(big), time.Now())
	cfg := s.Config()
	cfg.MaxResponse = 64 << 10
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := imapro.Dial(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("me@example.com", "abcd efgh ijkl mnop"); err != nil {
		t.Fatal(err)
	}
	c.Examine("INBOX")
	if _, err := c.FetchMessage(uid, 1<<20); err == nil {
		t.Fatal("a response past the cap was taken")
	}
	// Within the cap, the partial fetch is cut where asked.
	c2 := dial(t, s)
	c2.Examine("INBOX")
	m, err := c2.FetchMessage(uid, 1000)
	if err != nil || len(m.Body) != 1000 {
		t.Fatalf("partial = %d, %v", len(m.Body), err)
	}
}

func TestParseMessage(t *testing.T) {
	raw := "From: =?UTF-8?B?Sm9zw6k=?= <jose@example.com>\r\nTo: a@example.com, \"B, C\" <b@example.com>\r\n" +
		"Subject: =?ISO-8859-1?Q?Caf=E9?= menu\r\nDate: Tue, 27 Oct 2026 10:00:00 +0100\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n" +
		"--inner\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nLe caf=E9 est pr=EAt.\r\n" +
		"--inner\r\nContent-Type: text/html\r\n\r\n<p>Le café</p>\r\n--inner--\r\n" +
		"--outer\r\nContent-Type: application/pdf; name=\"menu.pdf\"\r\nContent-Disposition: attachment; filename=\"menu.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--outer--\r\n"
	m := imapro.ParseMessage([]byte(raw))
	if m.Subject != "Café menu" || m.From[0].Name != "José" || len(m.To) != 2 || m.Text != "Le café est prêt." || m.HTML != "<p>Le café</p>" {
		t.Fatalf("%+v", m)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].Name != "menu.pdf" || m.Attachments[0].Size != 9 {
		t.Fatalf("attachments %+v", m.Attachments)
	}
	if m.Date.IsZero() {
		t.Fatal("no date")
	}
	// Cut mid-part: what decoded is kept.
	cut := imapro.ParseMessage([]byte(raw[:strings.Index(raw, "pr=EAt")]))
	if !strings.HasPrefix(cut.Text, "Le caf") {
		t.Fatalf("cut: %+v", cut)
	}
	// HTML only.
	h := imapro.ParseMessage([]byte("Content-Type: text/html; charset=utf-8\r\n\r\n<b>hi</b>"))
	if h.HTML != "<b>hi</b>" || h.Text != "" {
		t.Fatalf("%+v", h)
	}
}

func TestFolderNamesDecoded(t *testing.T) {
	s := newServer(t, imapro.TLS)
	s.AddFolder("&ZeVnLIqe-")       // 日本語
	s.AddFolder("Entw&APw-rfe")     // Entwürfe
	s.AddFolder("[Gmail]/All Mail") // brackets and spaces
	c := dial(t, s)
	fs, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	var shown []string
	for _, f := range fs {
		shown = append(shown, f.Display)
	}
	for _, want := range []string{"日本語", "Entwürfe", "[Gmail]/All Mail"} {
		if !slices.Contains(shown, want) {
			t.Errorf("%q not in %v", want, shown)
		}
	}
	if _, err := c.Examine("[Gmail]/All Mail"); err != nil {
		t.Fatal(err)
	}
}
