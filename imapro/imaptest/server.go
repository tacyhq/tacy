// Package imaptest is an in-process IMAP server for tests and the mail lab: TLS (implicit or STARTTLS) with its
// own certificate, users with app passwords and the refusals real providers give, folders of RFC 5322 messages with
// flags. It implements the commands a read-write client would use too (SELECT, STORE, EXPUNGE, APPEND, COPY, MOVE,
// CREATE, DELETE, RENAME) so that a test can prove the read-only client never sends them: every command line it
// receives is logged (Commands), and Sloppy marks a message \Seen on any non-PEEK body fetch even in a folder opened
// with EXAMINE, so "nothing was marked read" means the client used BODY.PEEK. Never in a release binary.
package imaptest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/imapro"
)

// Host is the name the server's certificate is for.
const Host = "imap.test.example"

// Message is one stored message.
type Message struct {
	UID      uint32
	Flags    []string
	Raw      []byte
	Internal time.Time
}

// Seen: the message has \Seen.
func (m *Message) Seen() bool { return slices.Contains(m.Flags, `\Seen`) }

// Server is the fake server. Set its fields before Start.
type Server struct {
	Security string            // imapro.TLS or imapro.STARTTLS
	Users    map[string]string // user -> app password
	// Refuse maps a user to the refusal its login gets whatever the password: "app_password" (Gmail's
	// "Application-specific password required"), "web_login" (Gmail's "Please log in via your web browser"),
	// "disabled" (IMAP turned off for the account).
	Refuse map[string]string
	// LoginDisabled announces LOGINDISABLED and AUTH=PLAIN: the client must use AUTHENTICATE PLAIN.
	LoginDisabled bool
	// Sloppy: a non-PEEK body fetch sets \Seen even under EXAMINE (stricter than a real server).
	Sloppy bool
	// ReadWriteExamine: EXAMINE answers [READ-WRITE] (a broken server: the client must hang up).
	ReadWriteExamine bool

	mu       sync.Mutex
	boxes    map[string][]*Message
	order    []string
	nextUID  map[string]uint32
	commands []string
	ln       net.Listener
	cert     tls.Certificate
	pool     *x509.CertPool
	wg       sync.WaitGroup
	logins   int
}

// New makes a server with an empty INBOX.
func New() *Server {
	s := &Server{Security: imapro.TLS, Users: map[string]string{}, Refuse: map[string]string{}, Sloppy: true,
		boxes: map[string][]*Message{}, nextUID: map[string]uint32{}}
	s.AddFolder("INBOX")
	return s
}

// AddFolder adds an empty folder.
func (s *Server) AddFolder(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.boxes[name]; !ok {
		s.boxes[name] = nil
		s.order = append(s.order, name)
		s.nextUID[name] = 100
	}
}

// Add stores a message in folder (made if missing) and returns its UID.
func (s *Server) Add(folder string, raw []byte, internal time.Time, flags ...string) uint32 {
	s.AddFolder(folder)
	s.mu.Lock()
	defer s.mu.Unlock()
	uid := s.nextUID[folder]
	s.nextUID[folder]++
	s.boxes[folder] = append(s.boxes[folder], &Message{UID: uid, Flags: slices.Clone(flags), Raw: raw, Internal: internal})
	return uid
}

// Snapshot is every folder's messages' UIDs and flags, for before/after comparisons.
func (s *Server) Snapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, name := range s.order {
		fmt.Fprintf(&b, "%s:", name)
		for _, m := range s.boxes[name] {
			fl := slices.Clone(m.Flags)
			slices.Sort(fl)
			fmt.Fprintf(&b, " %d%v", m.UID, fl)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// SeenCount is how many messages have \Seen.
func (s *Server) SeenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, box := range s.boxes {
		for _, m := range box {
			if m.Seen() {
				n++
			}
		}
	}
	return n
}

// Commands are the command lines received (names upper-cased; LOGIN's and AUTHENTICATE's arguments left out).
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.commands)
}

// CommandNames are the commands received, by name ("UID FETCH").
func (s *Server) CommandNames() []string {
	var out []string
	for _, c := range s.Commands() {
		f := strings.Fields(c)
		name := f[0]
		if name == "UID" && len(f) > 1 {
			name += " " + f[1]
		}
		out = append(out, name)
	}
	return out
}

// Logins is how many logins succeeded.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// Start listens on 127.0.0.1 and serves until Close.
func (s *Server) Start() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: Host},
		DNSNames: []string{Host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, _ := x509.ParseCertificate(der)
	s.pool = x509.NewCertPool()
	s.pool.AddCert(cert)
	s.cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(c)
			}()
		}
	}()
	return nil
}

// Close stops the server.
func (s *Server) Close() {
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}

// Addr is the listener's address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Port is the listener's port.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// TLSConfig trusts the server's certificate (and nothing else).
func (s *Server) TLSConfig() *tls.Config { return &tls.Config{RootCAs: s.pool} }

// Dial connects to the server whatever the address asked for (tests give the client Host as the name).
func (s *Server) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, s.Addr())
}

// Config is a client config for this server (TLS roots, dialer).
func (s *Server) Config() imapro.Config {
	return imapro.Config{Host: Host, Port: 993, Security: s.Security, TLS: s.TLSConfig(), Dial: s.Dial}
}

type sess struct {
	s        *Server
	c        net.Conn
	r        *bufio.Reader
	w        *bufio.Writer
	user     string
	box      string
	readOnly bool
	tls      bool
}

func (x *sess) send(format string, a ...any) {
	fmt.Fprintf(x.w, format+"\r\n", a...)
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute))
	x := &sess{s: s, c: c}
	if s.Security == imapro.TLS {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{s.cert}})
		if tc.Handshake() != nil {
			return
		}
		x.c, x.tls = tc, true
	}
	x.r, x.w = bufio.NewReader(x.c), bufio.NewWriter(x.c)
	x.send("* OK [CAPABILITY %s] imaptest ready", x.caps())
	x.w.Flush()
	for {
		line, err := x.readCommand()
		if err != nil {
			return
		}
		if !x.handle(line) {
			x.w.Flush()
			return
		}
		x.w.Flush()
	}
}

func (x *sess) caps() string {
	c := "IMAP4rev1 LITERAL+ ID UIDPLUS MOVE"
	if !x.tls {
		c += " STARTTLS LOGINDISABLED"
	} else if x.s.LoginDisabled {
		c += " LOGINDISABLED AUTH=PLAIN"
	} else {
		c += " AUTH=PLAIN"
	}
	return c
}

// readCommand reads one command line, with its literals inlined as tokens (a literal's bytes are wrapped as
// "\x00L<len>\x00<bytes>" so the tokenizer takes them whole).
func (x *sess) readCommand() (string, error) {
	var out strings.Builder
	for {
		line, err := x.r.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if i := strings.LastIndexByte(line, '{'); i >= 0 && strings.HasSuffix(line, "}") {
			nstr := strings.TrimSuffix(line[i+1:len(line)-1], "+")
			n, err := strconv.Atoi(nstr)
			if err == nil && n >= 0 && n < 8<<20 {
				out.WriteString(line[:i])
				if !strings.HasSuffix(line[i+1:len(line)-1], "+") {
					x.send("+ go ahead")
					x.w.Flush()
				}
				buf := make([]byte, n)
				if _, err := io.ReadFull(x.r, buf); err != nil {
					return "", err
				}
				out.WriteString("\x00L" + strconv.Itoa(n) + "\x00")
				out.Write(buf)
				continue
			}
		}
		out.WriteString(line)
		return out.String(), nil
	}
}

// token is a command argument: an atom, a string or a list.
type token struct {
	s    string
	str  bool
	list []token
	isL  bool
}

func tokenize(s string) ([]token, error) {
	var out []token
	i := 0
	var parse func() (token, error)
	parse = func() (token, error) {
		switch {
		case s[i] == '"':
			i++
			var b strings.Builder
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
				i++
			}
			i++
			return token{s: b.String(), str: true}, nil
		case s[i] == 0 && i+1 < len(s) && s[i+1] == 'L':
			end := strings.IndexByte(s[i+2:], 0)
			n, _ := strconv.Atoi(s[i+2 : i+2+end])
			start := i + 2 + end + 1
			i = start + n
			return token{s: s[start:i], str: true}, nil
		case s[i] == '(':
			i++
			t := token{isL: true}
			for i < len(s) && s[i] != ')' {
				if s[i] == ' ' {
					i++
					continue
				}
				e, err := parse()
				if err != nil {
					return t, err
				}
				t.list = append(t.list, e)
			}
			i++
			return t, nil
		}
		start, depth := i, 0
		for i < len(s) && (depth > 0 || s[i] != ' ' && s[i] != ')' && s[i] != '(') {
			if s[i] == '[' {
				depth++
			} else if s[i] == ']' {
				depth--
			}
			i++
		}
		if i == start { // a stray ")": a syntax error
			return token{}, fmt.Errorf("syntax error at %d in %q", i, s)
		}
		return token{s: s[start:i]}, nil
	}
	for i < len(s) {
		if s[i] == ' ' {
			i++
			continue
		}
		t, err := parse()
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (x *sess) handle(line string) bool {
	tag, rest, _ := strings.Cut(line, " ")
	toks, err := tokenize(rest)
	if err != nil || len(toks) == 0 {
		x.send("%s BAD syntax", tag)
		return true
	}
	cmd := strings.ToUpper(toks[0].s)
	args := toks[1:]
	uid := false
	if cmd == "UID" && len(args) > 0 {
		uid, cmd, args = true, strings.ToUpper(args[0].s), args[1:]
	}
	logged := cmd
	if uid {
		logged = "UID " + cmd
	}
	if cmd != "LOGIN" && cmd != "AUTHENTICATE" {
		var parts []string
		for _, a := range args {
			parts = append(parts, tokText(a))
		}
		if len(parts) > 0 {
			logged += " " + strings.Join(parts, " ")
		}
	}
	x.s.mu.Lock()
	x.s.commands = append(x.s.commands, logged)
	x.s.mu.Unlock()
	switch cmd {
	case "CAPABILITY":
		x.send("* CAPABILITY %s", x.caps())
		x.send("%s OK CAPABILITY done", tag)
	case "NOOP":
		x.send("%s OK NOOP", tag)
	case "LOGOUT":
		x.send("* BYE logging out")
		x.send("%s OK LOGOUT done", tag)
		return false
	case "STARTTLS":
		if x.tls {
			x.send("%s BAD already TLS", tag)
			return true
		}
		x.send("%s OK begin TLS", tag)
		x.w.Flush()
		tc := tls.Server(x.c, &tls.Config{Certificates: []tls.Certificate{x.s.cert}})
		if tc.Handshake() != nil {
			return false
		}
		x.c, x.tls = tc, true
		x.r, x.w = bufio.NewReader(tc), bufio.NewWriter(tc)
	case "LOGIN":
		if !x.tls || x.s.LoginDisabled {
			x.send("%s NO [PRIVACYREQUIRED] LOGIN disabled", tag)
			return true
		}
		if len(args) != 2 {
			x.send("%s BAD LOGIN needs two arguments", tag)
			return true
		}
		x.login(tag, args[0].s, args[1].s)
	case "AUTHENTICATE":
		if !x.tls || len(args) != 1 || !strings.EqualFold(args[0].s, "PLAIN") {
			x.send("%s NO unsupported", tag)
			return true
		}
		x.send("+ ")
		x.w.Flush()
		l, err := x.r.ReadString('\n')
		if err != nil {
			return false
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(l))
		parts := strings.Split(string(raw), "\x00")
		if err != nil || len(parts) != 3 {
			x.send("%s NO bad PLAIN", tag)
			return true
		}
		x.login(tag, parts[1], parts[2])
	case "LIST":
		if !x.authed(tag) {
			return true
		}
		x.s.mu.Lock()
		for _, name := range x.s.order {
			flags := `\HasNoChildren`
			switch name {
			case "Sent":
				flags += ` \Sent`
			case "Trash":
				flags += ` \Trash`
			}
			x.send(`* LIST (%s) "/" %q`, flags, name)
		}
		x.s.mu.Unlock()
		x.send("%s OK LIST done", tag)
	case "SELECT", "EXAMINE":
		if !x.authed(tag) || len(args) != 1 {
			return true
		}
		x.s.mu.Lock()
		box, ok := x.s.boxes[args[0].s]
		x.s.mu.Unlock()
		if !ok {
			x.send("%s NO [NONEXISTENT] no such mailbox", tag)
			return true
		}
		x.box, x.readOnly = args[0].s, cmd == "EXAMINE"
		x.send("* %d EXISTS", len(box))
		x.send(`* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)`)
		x.send("* OK [UIDVALIDITY 7] UIDs valid")
		mode := "READ-WRITE"
		if x.readOnly && !x.s.ReadWriteExamine {
			mode = "READ-ONLY"
		}
		x.send("%s OK [%s] %s done", tag, mode, cmd)
	case "SEARCH":
		if !x.selected(tag) {
			return true
		}
		x.search(tag, uid, args)
	case "FETCH":
		if !x.selected(tag) || len(args) < 2 {
			return true
		}
		x.fetch(tag, uid, args[0].s, args[1])
	case "STORE":
		if !x.selected(tag) || len(args) < 3 {
			return true
		}
		x.store(tag, uid, args)
	case "EXPUNGE", "CLOSE":
		if !x.selected(tag) {
			return true
		}
		if !x.readOnly {
			x.s.mu.Lock()
			box := x.s.boxes[x.box][:0]
			for _, m := range x.s.boxes[x.box] {
				if !slices.Contains(m.Flags, `\Deleted`) {
					box = append(box, m)
				}
			}
			x.s.boxes[x.box] = box
			x.s.mu.Unlock()
		}
		x.send("%s OK %s done", tag, cmd)
	case "APPEND":
		if !x.authed(tag) || len(args) < 2 {
			return true
		}
		x.s.Add(args[0].s, []byte(args[len(args)-1].s), time.Now())
		x.send("%s OK APPEND done", tag)
	case "COPY", "MOVE":
		if !x.selected(tag) || len(args) != 2 {
			return true
		}
		for _, m := range x.matchSet(uid, args[0].s) {
			x.s.Add(args[1].s, m.Raw, m.Internal, m.Flags...)
		}
		x.send("%s OK %s done", tag, cmd)
	case "CREATE":
		if !x.authed(tag) || len(args) != 1 {
			return true
		}
		x.s.AddFolder(args[0].s)
		x.send("%s OK CREATE done", tag)
	case "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE", "UNSELECT", "IDLE", "ENABLE", "ID", "STATUS", "CHECK":
		x.send("%s OK %s done", tag, cmd)
	default:
		x.send("%s BAD unknown command", tag)
	}
	return true
}

func tokText(t token) string {
	if t.isL {
		var p []string
		for _, e := range t.list {
			p = append(p, tokText(e))
		}
		return "(" + strings.Join(p, " ") + ")"
	}
	if t.str {
		return strconv.Quote(t.s)
	}
	return strings.ToUpper(t.s)
}

func (x *sess) login(tag, user, pass string) {
	switch x.s.Refuse[user] {
	case "app_password":
		x.send("%s NO [ALERT] Application-specific password required: https://support.google.com/accounts/answer/185833 (Failure)", tag)
		return
	case "web_login":
		x.send("%s NO [ALERT] Please log in via your web browser: https://support.google.com/mail/accounts/answer/78754 (Failure)", tag)
		return
	case "disabled":
		x.send("%s NO [ALERT] Your account is not enabled for IMAP use. (Failure)", tag)
		return
	}
	want, ok := x.s.Users[user]
	if !ok || want != pass {
		x.send("%s NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)", tag)
		return
	}
	x.user = user
	x.s.mu.Lock()
	x.s.logins++
	x.s.mu.Unlock()
	x.send("%s OK [CAPABILITY IMAP4rev1 UIDPLUS MOVE] %s authenticated (Success)", tag, user)
}

func (x *sess) authed(tag string) bool {
	if x.user == "" {
		x.send("%s NO not logged in", tag)
		return false
	}
	return true
}

func (x *sess) selected(tag string) bool {
	if !x.authed(tag) {
		return false
	}
	if x.box == "" {
		x.send("%s NO no mailbox selected", tag)
		return false
	}
	return true
}

// matchSet is the selected folder's messages in a set (UIDs or sequence numbers).
func (x *sess) matchSet(uid bool, set string) []*Message {
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	box := x.s.boxes[x.box]
	var out []*Message
	for i, m := range box {
		n := uint32(i + 1)
		if uid {
			n = m.UID
		}
		max := uint32(len(box))
		if uid && len(box) > 0 {
			max = box[len(box)-1].UID
		}
		if inSet(set, n, max) {
			out = append(out, m)
		}
	}
	return out
}

func inSet(set string, n, max uint32) bool {
	for _, part := range strings.Split(set, ",") {
		a, b, rng := strings.Cut(part, ":")
		lo := parseN(a, max)
		hi := lo
		if rng {
			hi = parseN(b, max)
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if n >= lo && n <= hi {
			return true
		}
	}
	return false
}

func parseN(s string, max uint32) uint32 {
	if s == "*" {
		return max
	}
	n, _ := strconv.ParseUint(s, 10, 32)
	return uint32(n)
}

func (x *sess) search(tag string, uid bool, args []token) {
	x.s.mu.Lock()
	box := slices.Clone(x.s.boxes[x.box])
	x.s.mu.Unlock()
	type crit func(m *Message, parsed *imapro.Message, text string) bool
	var crits []crit
	for i := 0; i < len(args); i++ {
		key := strings.ToUpper(args[i].s)
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i].s
			}
			return ""
		}
		switch key {
		case "ALL":
		case "CHARSET":
			next()
		case "TEXT", "BODY":
			w := strings.ToLower(next())
			crits = append(crits, func(_ *Message, p *imapro.Message, text string) bool { return strings.Contains(text, w) })
		case "SUBJECT":
			w := strings.ToLower(next())
			crits = append(crits, func(_ *Message, p *imapro.Message, _ string) bool {
				return strings.Contains(strings.ToLower(p.Subject), w)
			})
		case "FROM":
			w := strings.ToLower(next())
			crits = append(crits, func(_ *Message, p *imapro.Message, _ string) bool {
				for _, a := range p.From {
					if strings.Contains(strings.ToLower(a.Name+" "+a.Addr), w) {
						return true
					}
				}
				return false
			})
		case "TO":
			w := strings.ToLower(next())
			crits = append(crits, func(_ *Message, p *imapro.Message, _ string) bool {
				for _, a := range append(slices.Clone(p.To), p.Cc...) {
					if strings.Contains(strings.ToLower(a.Name+" "+a.Addr), w) {
						return true
					}
				}
				return false
			})
		case "SINCE", "BEFORE":
			d, _ := time.Parse("2-Jan-2006", next())
			since := key == "SINCE"
			crits = append(crits, func(m *Message, _ *imapro.Message, _ string) bool {
				day := time.Date(m.Internal.Year(), m.Internal.Month(), m.Internal.Day(), 0, 0, 0, 0, time.UTC)
				if since {
					return !day.Before(d)
				}
				return day.Before(d)
			})
		case "UNSEEN":
			crits = append(crits, func(m *Message, _ *imapro.Message, _ string) bool { return !m.Seen() })
		case "SEEN":
			crits = append(crits, func(m *Message, _ *imapro.Message, _ string) bool { return m.Seen() })
		default:
			x.send("%s BAD unsupported search key %s", tag, key)
			return
		}
	}
	var hits []string
	for i, m := range box {
		p := imapro.ParseMessage(m.Raw)
		text := strings.ToLower(string(m.Raw) + "\n" + p.Subject + "\n" + p.Text + "\n" + p.HTML)
		for _, a := range p.From {
			text += "\n" + strings.ToLower(a.Name+" "+a.Addr)
		}
		ok := true
		for _, c := range crits {
			if !c(m, p, text) {
				ok = false
				break
			}
		}
		if ok {
			if uid {
				hits = append(hits, strconv.FormatUint(uint64(m.UID), 10))
			} else {
				hits = append(hits, strconv.Itoa(i+1))
			}
		}
	}
	x.send("* SEARCH %s", strings.Join(hits, " "))
	x.send("%s OK SEARCH done", tag)
}

func (x *sess) fetch(tag string, uid bool, set string, items token) {
	list := items.list
	if !items.isL {
		list = []token{items}
	}
	msgs := x.matchSet(uid, set)
	x.s.mu.Lock()
	box := x.s.boxes[x.box]
	x.s.mu.Unlock()
	for _, m := range msgs {
		seq := 0
		for i, b := range box {
			if b == m {
				seq = i + 1
			}
		}
		var parts []string
		if uid {
			parts = append(parts, fmt.Sprintf("UID %d", m.UID))
		}
		var lits [][]byte
		for _, it := range list {
			u := strings.ToUpper(it.s)
			switch {
			case u == "UID":
				if !uid {
					parts = append(parts, fmt.Sprintf("UID %d", m.UID))
				}
			case u == "FLAGS":
			case u == "RFC822.SIZE":
				parts = append(parts, fmt.Sprintf("RFC822.SIZE %d", len(m.Raw)))
			case u == "INTERNALDATE":
				parts = append(parts, fmt.Sprintf("INTERNALDATE %q", m.Internal.Format("02-Jan-2006 15:04:05 -0700")))
			case u == "RFC822" || u == "RFC822.TEXT" || strings.HasPrefix(u, "BODY["):
				x.markSeen(m)
				fallthrough
			case strings.HasPrefix(u, "BODY.PEEK["):
				name, data := section(u, m.Raw)
				parts = append(parts, fmt.Sprintf("%s {%d}", name, len(data)))
				lits = append(lits, data)
			}
		}
		x.s.mu.Lock()
		flags := strings.Join(m.Flags, " ")
		x.s.mu.Unlock()
		parts = append(parts, "FLAGS ("+flags+")")
		// Literals go at the end of their item: write the response with each {n} followed by its bytes.
		fmt.Fprintf(x.w, "* %d FETCH (", seq)
		li := 0
		for i, p := range parts {
			if i > 0 {
				x.w.WriteString(" ")
			}
			x.w.WriteString(p)
			if strings.HasSuffix(p, "}") {
				x.w.WriteString("\r\n")
				x.w.Write(lits[li])
				li++
			}
		}
		x.w.WriteString(")\r\n")
	}
	x.send("%s OK FETCH done", tag)
}

func (x *sess) markSeen(m *Message) {
	if x.readOnly && !x.s.Sloppy {
		return
	}
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	if !m.Seen() {
		m.Flags = append(m.Flags, `\Seen`)
	}
}

// section is a BODY[…]/BODY.PEEK[…]/RFC822 item's response name and data.
func section(item string, raw []byte) (string, []byte) {
	if item == "RFC822" {
		return "RFC822", raw
	}
	if item == "RFC822.TEXT" {
		_, body, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
		return "RFC822.TEXT", body
	}
	open := strings.IndexByte(item, '[')
	end := strings.IndexByte(item, ']')
	sec := item[open+1 : end]
	partial := item[end+1:]
	head, body, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	var data []byte
	switch {
	case sec == "":
		data = raw
	case sec == "HEADER":
		data = append(slices.Clone(head), "\r\n\r\n"...)
	case sec == "TEXT":
		data = body
	case strings.HasPrefix(sec, "HEADER.FIELDS"):
		f := sec[strings.IndexByte(sec, '(')+1 : strings.IndexByte(sec, ')')]
		want := strings.Fields(f)
		var keep []string
		lines := strings.Split(string(head), "\r\n")
		for i := 0; i < len(lines); i++ {
			name, _, ok := strings.Cut(lines[i], ":")
			if !ok || !slices.ContainsFunc(want, func(w string) bool { return strings.EqualFold(w, name) }) {
				continue
			}
			keep = append(keep, lines[i])
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || strings.HasPrefix(lines[i+1], "\t")) {
				i++
				keep = append(keep, lines[i])
			}
		}
		data = []byte(strings.Join(keep, "\r\n") + "\r\n\r\n")
	default:
		data = raw
	}
	name := "BODY[" + sec + "]"
	if partial != "" {
		a, b, _ := strings.Cut(strings.Trim(partial, "<>"), ".")
		off, _ := strconv.Atoi(a)
		n, _ := strconv.Atoi(b)
		if off > len(data) {
			off = len(data)
		}
		data = data[off:]
		if n < len(data) {
			data = data[:n]
		}
		name += "<" + a + ">"
	}
	return name, data
}

func (x *sess) store(tag string, uid bool, args []token) {
	op := strings.ToUpper(args[1].s)
	var flags []string
	for _, f := range args[2].list {
		flags = append(flags, f.s)
	}
	if !args[2].isL {
		flags = []string{args[2].s}
	}
	if !x.readOnly {
		for _, m := range x.matchSet(uid, args[0].s) {
			x.s.mu.Lock()
			switch {
			case strings.HasPrefix(op, "+FLAGS"):
				for _, f := range flags {
					if !slices.Contains(m.Flags, f) {
						m.Flags = append(m.Flags, f)
					}
				}
			case strings.HasPrefix(op, "-FLAGS"):
				m.Flags = slices.DeleteFunc(m.Flags, func(f string) bool { return slices.Contains(flags, f) })
			default:
				m.Flags = flags
			}
			x.s.mu.Unlock()
		}
	}
	x.send("%s OK STORE done", tag)
}

// Folders are the folder names in order.
func (s *Server) Folders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.order)
	sort.Strings(out)
	return out
}
