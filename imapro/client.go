package imapro

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Security is how the connection is protected: implicit TLS (993) or STARTTLS (143). There is no plaintext mode.
const (
	TLS      = "tls"
	STARTTLS = "starttls"
)

// Config is one connection's settings.
type Config struct {
	Host     string // the server's DNS name (also the TLS server name)
	Port     int
	Security string // TLS or STARTTLS
	// Dial makes the TCP connection (gatewayd: a public-only dialer); nil: net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLS is the base TLS config (tests: their own roots); nil: the system roots. ServerName is always Host and the
	// minimum version TLS 1.2; certificate checks are never skipped (InsecureSkipVerify is refused).
	TLS *tls.Config
	// MaxResponse caps one server response (a message's literal included); 0: 4 MiB.
	MaxResponse int
}

// Errors a caller can tell apart (the connector maps them to the person's words).
var (
	ErrUnreachable = errors.New("imapro: server unreachable")
	ErrTLS         = errors.New("imapro: TLS failed")
	ErrNotIMAP     = errors.New("imapro: not an IMAP4rev1 server, or no way to log in over TLS")
	ErrNotReadOnly = errors.New("imapro: the server didn't open the folder read-only")
	ErrNoSuchMail  = errors.New("imapro: no such folder")
)

// LoginError is a refused login. Code is one of the fixed codes below; the server's own words stay inside (Text
// is for the operator's tests, never shown to a model).
type LoginError struct {
	Code string
	Text string
}

func (e *LoginError) Error() string { return "imapro: login refused: " + e.Code }

// Login failure codes (CONNECTIONS.md).
const (
	LoginFailed          = "login_failed"
	AppPasswordRequired  = "app_password_required"
	AppPasswordsBlocked  = "app_passwords_blocked"
	loginTextLimit       = 300
	defaultMaxResponse   = 4 << 20
	maxListedFolders     = 1000
	maxSearchResultCount = 1 << 20
)

// Client is one read-only IMAP session. Not safe for concurrent use.
type Client struct {
	conn  net.Conn
	r     *reader
	w     *bufio.Writer
	tag   int
	caps  []string
	Sent  []string // the commands written (names only: "UID FETCH"), in order, for tests and records
	state string   // "" not logged in, "auth" logged in, "examined"
	stop  func() bool
}

// Dial connects, sets up TLS (implicit, or STARTTLS before anything else) and reads the capabilities. ctx bounds
// the whole session: its deadline is the connection's.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Security != TLS && cfg.Security != STARTTLS {
		return nil, fmt.Errorf("%w: security must be tls or starttls", ErrNotIMAP)
	}
	if cfg.TLS != nil && cfg.TLS.InsecureSkipVerify {
		return nil, fmt.Errorf("%w: certificate checks can't be skipped", ErrTLS)
	}
	dial := cfg.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, errText(err))
	}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) })
	limit := cfg.MaxResponse
	if limit <= 0 {
		limit = defaultMaxResponse
	}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLS != nil {
		tcfg = cfg.TLS.Clone()
		tcfg.MinVersion = max(tcfg.MinVersion, tls.VersionTLS12)
	}
	tcfg.ServerName = cfg.Host
	tcfg.InsecureSkipVerify = false
	c := &Client{conn: raw, stop: stop}
	if cfg.Security == TLS {
		tc := tls.Client(raw, tcfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("%w: %v", ErrTLS, errText(err))
		}
		c.conn = tc
	}
	c.r = &reader{r: bufio.NewReaderSize(c.conn, 32<<10), limit: limit}
	c.w = bufio.NewWriter(c.conn)
	greet, err := c.r.read()
	if err != nil {
		c.conn.Close()
		if cfg.Security == TLS {
			return nil, fmt.Errorf("%w: no greeting", ErrNotIMAP)
		}
		return nil, fmt.Errorf("%w: no greeting", ErrUnreachable)
	}
	if greet.tag != "*" || greet.status != "OK" {
		c.conn.Close()
		return nil, fmt.Errorf("%w: greeting %s", ErrNotIMAP, greet.status)
	}
	c.noteCaps(greet.code)
	if cfg.Security == STARTTLS {
		if err := c.capability(); err != nil {
			c.conn.Close()
			return nil, err
		}
		if !c.Has("STARTTLS") {
			c.conn.Close()
			return nil, fmt.Errorf("%w: no STARTTLS", ErrNotIMAP)
		}
		if _, err := c.do("STARTTLS", nil); err != nil {
			c.conn.Close()
			return nil, fmt.Errorf("%w: STARTTLS refused", ErrTLS)
		}
		if c.r.r.Buffered() > 0 { // bytes before the handshake would be a plaintext injection
			c.conn.Close()
			return nil, fmt.Errorf("%w: data after STARTTLS", ErrTLS)
		}
		tc := tls.Client(raw, tcfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("%w: %v", ErrTLS, errText(err))
		}
		c.conn = tc
		c.r = &reader{r: bufio.NewReaderSize(c.conn, 32<<10), limit: limit}
		c.w = bufio.NewWriter(c.conn)
		c.caps = nil // forget what was said before TLS
	}
	if len(c.caps) == 0 {
		if err := c.capability(); err != nil {
			c.conn.Close()
			return nil, err
		}
	}
	if !c.Has("IMAP4REV1") && !c.Has("IMAP4REV2") {
		c.conn.Close()
		return nil, fmt.Errorf("%w: no IMAP4rev1", ErrNotIMAP)
	}
	return c, nil
}

// errText is a dial or TLS error without addresses: fixed words for the classes that matter.
func errText(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return "certificate not trusted"
	}
	var he x509.HostnameError
	if errors.As(err, &he) {
		return "certificate for another name"
	}
	var ue x509.UnknownAuthorityError
	if errors.As(err, &ue) {
		return "certificate not trusted"
	}
	return "failed"
}

// Close drops the connection without LOGOUT.
func (c *Client) Close() error {
	c.stop()
	return c.conn.Close()
}

// Has says whether the server announced a capability (upper case).
func (c *Client) Has(capability string) bool {
	return slices.Contains(c.caps, strings.ToUpper(capability))
}

func (c *Client) noteCaps(code string) {
	if rest, ok := strings.CutPrefix(code, "CAPABILITY "); ok {
		c.caps = strings.Fields(strings.ToUpper(rest))
	}
}

func (c *Client) capability() error {
	_, err := c.do("CAPABILITY", nil)
	return err
}

// arg is one argument as written: an atom (checked), a string (quoted, or a literal when it must be), or raw text
// the client itself made (a message set, a FETCH item list).
type arg struct {
	kind byte // 'a' atom, 's' string, 'r' raw
	s    string
}

func atom(s string) arg   { return arg{'a', s} }
func str(s string) arg    { return arg{'s', s} }
func rawArg(s string) arg { return arg{'r', s} }

// quotable: a string that can go in quotes (7-bit, no CR, LF or NUL).
func quotable(s string) bool {
	if len(s) > 1000 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x80 || c == '\r' || c == '\n' || c == 0 {
			return false
		}
	}
	return true
}

// write writes one command (tag, name, args), checks it against the read-only rule first, and sends literals with
// the server's go-ahead. It returns the tag.
func (c *Client) write(name string, args []arg) (string, error) {
	// The text as checked: name and args, literals as {n} only.
	var text strings.Builder
	text.WriteString(name)
	type piece struct {
		line    string
		literal []byte
	}
	var pieces []piece
	cur := name
	for _, a := range args {
		switch a.kind {
		case 'a':
			if a.s == "" || strings.ContainsAny(a.s, " \r\n\x00\"(){") {
				return "", fmt.Errorf("%w: bad atom", ErrRefused)
			}
			cur += " " + a.s
			text.WriteString(" " + a.s)
		case 'r':
			if strings.ContainsAny(a.s, "\r\n\x00") {
				return "", fmt.Errorf("%w: bad argument", ErrRefused)
			}
			cur += " " + a.s
			text.WriteString(" " + a.s)
		case 's':
			if quotable(a.s) {
				q := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(a.s) + `"`
				cur += " " + q
				text.WriteString(" " + q)
			} else {
				if !utf8.ValidString(a.s) || strings.ContainsRune(a.s, 0) || len(a.s) > 64<<10 {
					return "", fmt.Errorf("%w: bad string", ErrRefused)
				}
				lit := fmt.Sprintf("{%d}", len(a.s))
				cur += " " + lit
				text.WriteString(" " + lit)
				pieces = append(pieces, piece{line: cur, literal: []byte(a.s)})
				cur = ""
			}
		}
	}
	if err := Allowed(text.String()); err != nil {
		return "", err
	}
	c.tag++
	tag := "t" + strconv.Itoa(c.tag)
	label := strings.ToUpper(name)
	if label == "UID" && len(args) > 0 {
		label += " " + strings.ToUpper(args[0].s)
	}
	c.Sent = append(c.Sent, label)
	first := true
	send := func(s string) {
		if first {
			c.w.WriteString(tag + " ")
			first = false
		}
		c.w.WriteString(s)
	}
	for _, p := range pieces {
		send(p.line + "\r\n")
		if err := c.w.Flush(); err != nil {
			return "", err
		}
		// A synchronizing literal: wait for "+" (untagged data before it is skipped; a tagged answer refuses).
		for {
			r, err := c.r.read()
			if err != nil {
				return "", err
			}
			if r.tag == "+" {
				break
			}
			if r.tag == tag {
				return "", fmt.Errorf("imapro: %s refused: %s", label, r.status)
			}
		}
		c.w.Write(p.literal)
	}
	send(cur + "\r\n")
	return tag, c.w.Flush()
}

// do runs one command and collects its untagged responses until its tagged one. A NO or BAD is an error naming
// the command (the server's words are kept in status error only for login).
func (c *Client) do(name string, args []arg) ([]*response, error) {
	tag, err := c.write(name, args)
	if err != nil {
		return nil, err
	}
	return c.wait(tag, name)
}

func (c *Client) wait(tag, name string) ([]*response, error) {
	var out []*response
	for {
		r, err := c.r.read()
		if err != nil {
			return nil, err
		}
		if r.tag == "*" {
			if r.status == "BYE" {
				if strings.EqualFold(name, "LOGOUT") {
					continue
				}
				return nil, errors.New("imapro: the server closed the session")
			}
			if r.name == "CAPABILITY" {
				c.caps = nil
				for _, v := range r.values {
					c.caps = append(c.caps, strings.ToUpper(v.str()))
				}
			}
			if r.status == "OK" {
				c.noteCaps(r.code)
			}
			out = append(out, r)
			if len(out) > 200000 {
				return nil, errTooBig
			}
			continue
		}
		if r.tag == "+" {
			return nil, errors.New("imapro: unexpected continuation")
		}
		if r.tag != tag {
			return nil, errors.New("imapro: response for another command")
		}
		c.noteCaps(r.code)
		if r.status != "OK" {
			return append(out, r), &statusError{name: strings.ToUpper(name), resp: r}
		}
		return append(out, r), nil
	}
}

type statusError struct {
	name string
	resp *response
}

func (e *statusError) Error() string { return "imapro: " + e.name + " " + e.resp.status }

// Login logs in with LOGIN, or AUTHENTICATE PLAIN when the server disables LOGIN. A refusal is a *LoginError with
// a fixed code: app_password_required (Gmail's "Application-specific password required"), app_passwords_blocked
// (the provider refuses this kind of sign-in for the account: web login required, IMAP off), else login_failed.
func (c *Client) Login(user, pass string) error {
	if user == "" || pass == "" {
		return &LoginError{Code: LoginFailed}
	}
	var err error
	switch {
	case !c.Has("LOGINDISABLED"):
		_, err = c.do("LOGIN", []arg{str(user), str(pass)})
	case c.Has("AUTH=PLAIN"):
		err = c.authPlain(user, pass)
	default:
		return fmt.Errorf("%w: login disabled", ErrNotIMAP)
	}
	var se *statusError
	if errors.As(err, &se) {
		text := se.resp.code + " " + se.resp.text
		if len(text) > loginTextLimit {
			text = text[:loginTextLimit]
		}
		return &LoginError{Code: classifyLogin(se.resp.code, se.resp.text), Text: text}
	}
	if err != nil {
		return err
	}
	c.state = "auth"
	if !slices.Contains(c.caps, "IMAP4REV1") && !slices.Contains(c.caps, "IMAP4REV2") {
		if err := c.capability(); err != nil {
			return err
		}
	}
	return nil
}

// authPlain: AUTHENTICATE PLAIN with the credentials after the server's go-ahead.
func (c *Client) authPlain(user, pass string) error {
	tag, err := c.write("AUTHENTICATE", []arg{atom("PLAIN")})
	if err != nil {
		return err
	}
	r, err := c.r.read()
	if err != nil {
		return err
	}
	if r.tag != "+" {
		if r.tag == tag {
			return &statusError{name: "AUTHENTICATE", resp: r}
		}
		return errors.New("imapro: no go-ahead for AUTHENTICATE")
	}
	tok := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
	c.w.WriteString(tok + "\r\n")
	if err := c.w.Flush(); err != nil {
		return err
	}
	_, err = c.wait(tag, "AUTHENTICATE")
	return err
}

// classifyLogin maps a refused login's code and words to a fixed code.
func classifyLogin(code, text string) string {
	t := strings.ToLower(code + " " + text)
	switch {
	case strings.Contains(t, "application-specific password") || strings.Contains(t, "app password") ||
		strings.Contains(t, "app-specific password") || strings.Contains(t, "application specific password"):
		return AppPasswordRequired
	case strings.Contains(t, "web login required") || strings.Contains(t, "log in via your web browser") ||
		strings.Contains(t, "login via your web browser") || strings.Contains(t, "not enabled for imap") ||
		strings.Contains(t, "imap access is disabled") || strings.Contains(t, "imap is disabled") ||
		strings.Contains(t, "imap access disabled") || strings.Contains(t, "contact your administrator") ||
		strings.Contains(t, "administrator has disabled") || strings.Contains(t, "advanced protection"):
		return AppPasswordsBlocked
	}
	return LoginFailed
}

// Folder is one LIST entry: its name as the server spells it (for EXAMINE), the name decoded for people
// (modified UTF-7), and its flags (\Noselect, \Sent, \Trash, …).
type Folder struct {
	Name    string
	Display string
	Flags   []string
}

// List lists the folders (LIST "" "*"), at most maxListedFolders.
func (c *Client) List() ([]Folder, error) {
	rs, err := c.do("LIST", []arg{str(""), str("*")})
	if err != nil {
		return nil, err
	}
	var out []Folder
	for _, r := range rs {
		if r.name != "LIST" || len(r.values) < 3 || r.values[0].kind != 'l' {
			continue
		}
		name := r.values[2].str()
		if name == "" || strings.ContainsAny(name, "\r\n\x00") {
			continue
		}
		f := Folder{Name: name, Display: decodeUTF7(name)}
		for _, v := range r.values[0].list {
			f.Flags = append(f.Flags, v.str())
		}
		out = append(out, f)
		if len(out) >= maxListedFolders {
			break
		}
	}
	return out, nil
}

// Mailbox is an EXAMINEd folder.
type Mailbox struct {
	Name        string
	Exists      uint32
	UIDValidity uint32
}

// Examine opens a folder read-only. A server that doesn't say [READ-ONLY] is hung up on (ErrNotReadOnly).
func (c *Client) Examine(name string) (*Mailbox, error) {
	rs, err := c.do("EXAMINE", []arg{str(name)})
	var se *statusError
	if errors.As(err, &se) {
		return nil, ErrNoSuchMail
	}
	if err != nil {
		return nil, err
	}
	mb := &Mailbox{Name: name}
	last := rs[len(rs)-1]
	if !strings.HasPrefix(last.code, "READ-ONLY") {
		c.conn.Close()
		return nil, ErrNotReadOnly
	}
	for _, r := range rs {
		switch {
		case r.name == "EXISTS":
			mb.Exists = r.num
		case r.status == "OK" && strings.HasPrefix(r.code, "UIDVALIDITY "):
			n, _ := strconv.ParseUint(strings.TrimPrefix(r.code, "UIDVALIDITY "), 10, 32)
			mb.UIDValidity = uint32(n)
		case r.status == "OK" && strings.HasPrefix(r.code, "READ-WRITE"):
			c.conn.Close()
			return nil, ErrNotReadOnly
		}
	}
	c.state = "examined"
	return mb, nil
}

// Criteria is a search, all parts ANDed. Words are each searched in headers and text (TEXT).
type Criteria struct {
	Words  []string
	From   string
	To     string    // a recipient (To, Cc or Bcc as the server's TO key reads it): what was sent to someone
	Since  time.Time // on or after this date (the server's dates, day granularity)
	Before time.Time // before this date
	Unseen bool
}

// Search runs UID SEARCH in the examined folder and returns the matching UIDs, ascending.
func (c *Client) Search(cr Criteria) ([]uint32, error) {
	if c.state != "examined" {
		return nil, errors.New("imapro: no folder open")
	}
	var args []arg
	utf := false
	add := func(key, val string) {
		args = append(args, atom(key), str(val))
		if !quotable(val) {
			utf = true
		}
	}
	for _, w := range cr.Words {
		add("TEXT", w)
	}
	if cr.From != "" {
		add("FROM", cr.From)
	}
	if cr.To != "" {
		add("TO", cr.To)
	}
	if !cr.Since.IsZero() {
		args = append(args, atom("SINCE"), atom(imapDate(cr.Since)))
	}
	if !cr.Before.IsZero() {
		args = append(args, atom("BEFORE"), atom(imapDate(cr.Before)))
	}
	if cr.Unseen {
		args = append(args, atom("UNSEEN"))
	}
	if len(args) == 0 {
		args = append(args, atom("ALL"))
	}
	if utf {
		args = append([]arg{atom("CHARSET"), atom("UTF-8")}, args...)
	}
	rs, err := c.do("UID", append([]arg{atom("SEARCH")}, args...))
	if err != nil {
		return nil, err
	}
	var uids []uint32
	for _, r := range rs {
		if r.name != "SEARCH" {
			continue
		}
		for _, v := range r.values {
			if n, ok := v.num(); ok && n > 0 {
				uids = append(uids, n)
				if len(uids) > maxSearchResultCount {
					return nil, errTooBig
				}
			}
		}
	}
	slices.Sort(uids)
	return slices.Compact(uids), nil
}

func imapDate(t time.Time) string { return t.UTC().Format("2-Jan-2006") }

// Fetched is one message as a FETCH returned it.
type Fetched struct {
	UID   uint32
	Flags []string
	Size  uint32
	Body  []byte // the BODY.PEEK section asked for (headers, or the message's first bytes)
}

// Unseen: the message hasn't been read (no \Seen flag).
func (f *Fetched) Unseen() bool {
	for _, fl := range f.Flags {
		if strings.EqualFold(fl, `\Seen`) {
			return false
		}
	}
	return true
}

// HeaderFields is the header section the connector reads for a search's results.
const HeaderFields = "BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID CONTENT-TYPE)]"

// FetchHeaders fetches the given UIDs' flags, sizes and a few header fields (never marking anything read).
func (c *Client) FetchHeaders(uids []uint32) ([]Fetched, error) {
	return c.fetch(uids, HeaderFields)
}

// FetchMessage fetches one message's first max bytes (BODY.PEEK[]<0.max>), its flags and size.
func (c *Client) FetchMessage(uid uint32, max int) (*Fetched, error) {
	fs, err := c.fetch([]uint32{uid}, fmt.Sprintf("BODY.PEEK[]<0.%d>", max))
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, ErrNoSuchMail
	}
	return &fs[0], nil
}

func (c *Client) fetch(uids []uint32, section string) ([]Fetched, error) {
	if c.state != "examined" {
		return nil, errors.New("imapro: no folder open")
	}
	if len(uids) == 0 {
		return nil, nil
	}
	var set []string
	for _, u := range uids {
		set = append(set, strconv.FormatUint(uint64(u), 10))
	}
	rs, err := c.do("UID", []arg{atom("FETCH"), rawArg(strings.Join(set, ",")), rawArg("(UID FLAGS RFC822.SIZE " + section + ")")})
	if err != nil {
		return nil, err
	}
	var out []Fetched
	for _, r := range rs {
		if r.name != "FETCH" || len(r.values) != 1 || r.values[0].kind != 'l' {
			continue
		}
		var f Fetched
		l := r.values[0].list
		for i := 0; i+1 < len(l); i += 2 {
			key := strings.ToUpper(l[i].str())
			v := l[i+1]
			switch {
			case key == "UID":
				f.UID, _ = v.num()
			case key == "RFC822.SIZE":
				f.Size, _ = v.num()
			case key == "FLAGS":
				for _, fl := range v.list {
					f.Flags = append(f.Flags, fl.str())
				}
			case strings.HasPrefix(key, "BODY["):
				f.Body = []byte(v.str())
			}
		}
		if f.UID != 0 && slices.Contains(uids, f.UID) {
			out = append(out, f)
		}
	}
	return out, nil
}

// Logout ends the session politely and closes the connection.
func (c *Client) Logout() error {
	_, err := c.do("LOGOUT", nil)
	c.Close()
	return err
}

// Raw sends any command through the read-only rule (tests: proof that every other command is refused before it is
// written). It returns ErrRefused for one that isn't allowed.
func (c *Client) Raw(name string, args ...string) error {
	var as []arg
	for _, a := range args {
		as = append(as, rawArg(a))
	}
	_, err := c.do(name, as)
	return err
}
