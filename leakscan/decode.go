package leakscan

import (
	"unicode/utf8"
)

// A view is the input, or a decoded form of it, with a map back to the input: byte i of b came from the input's
// bytes [start[i], end[i]). The raw input has no map (identity). Decoding never reorders, so a match over
// decoded bytes [i, j) came from input bytes [start[i], end[j-1]), which also covers anything stripped between
// them (a zero-width space inside a key).
type view struct {
	b          []byte
	start, end []int32
	via        string // how it was decoded: "" for raw, "percent+html", "percent>base64", ...
	depth      int    // decoding levels applied
}

func (v *view) src(i int) (int, int) {
	if v.start == nil {
		return i, i + 1
	}
	return int(v.start[i]), int(v.end[i])
}

// span maps decoded bytes [i, j) (j > i) to the input.
func (v *view) span(i, j int) (int, int) {
	if v.start == nil {
		return i, j
	}
	return int(v.start[i]), int(v.end[j-1])
}

// builder writes a decoded view of src.
type builder struct {
	src        *view
	out        []byte
	start, end []int32
	changed    bool
}

func newBuilder(src *view) *builder {
	n := len(src.b)
	return &builder{src: src, out: make([]byte, 0, n), start: make([]int32, 0, n), end: make([]int32, 0, n)}
}

// keep copies src bytes [i, j) unchanged.
func (b *builder) keep(i, j int) {
	b.out = append(b.out, b.src.b[i:j]...)
	if b.src.start == nil {
		for k := i; k < j; k++ {
			b.start = append(b.start, int32(k))
			b.end = append(b.end, int32(k+1))
		}
		return
	}
	b.start = append(b.start, b.src.start[i:j]...)
	b.end = append(b.end, b.src.end[i:j]...)
}

// emit writes d as the decoding of src bytes [i, j).
func (b *builder) emit(d []byte, i, j int) {
	s, e := b.src.span(i, j)
	for _, c := range d {
		b.out = append(b.out, c)
		b.start = append(b.start, int32(s))
		b.end = append(b.end, int32(e))
	}
	b.changed = true
}

func (b *builder) emitRune(r rune, i, j int) {
	var tmp [utf8.UTFMax]byte
	b.emit(tmp[:utf8.EncodeRune(tmp[:], r)], i, j)
}

func (b *builder) view(via string) *view {
	if !b.changed {
		return nil
	}
	return &view{b: b.out, start: b.start, end: b.end, via: via, depth: b.src.depth}
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hexRune parses s (1 to 8 hex digits) as a code point.
func hexRune(s []byte) (rune, bool) {
	if len(s) == 0 || len(s) > 8 {
		return 0, false
	}
	var r rune
	for _, c := range s {
		v, ok := hexVal(c)
		if !ok {
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}

// percent decodes %XX. Within a token (text between spaces, quotes and angle brackets) that has a %XX, a '+'
// becomes a space too (form encoding); elsewhere '+' stays, so base64 and ordinary text (C++, a+b) keep theirs.
func percent(v *view) *view {
	b := v.b
	if !hasPercentHex(b) {
		return nil
	}
	w := newBuilder(v)
	last := 0
	for t := 0; t < len(b); {
		if tokenEdge(b[t]) {
			t++
			continue
		}
		e := t
		for e < len(b) && !tokenEdge(b[e]) {
			e++
		}
		if hasPercentHex(b[t:e]) {
			for i := t; i < e; i++ {
				switch b[i] {
				case '%':
					if i+2 < e {
						h, ok1 := hexVal(b[i+1])
						l, ok2 := hexVal(b[i+2])
						if ok1 && ok2 {
							w.keep(last, i)
							w.emit([]byte{h<<4 | l}, i, i+3)
							i += 2
							last = i + 1
						}
					}
				case '+':
					w.keep(last, i)
					w.emit([]byte{' '}, i, i+1)
					last = i + 1
				}
			}
		}
		t = e
	}
	w.keep(last, len(b))
	return w.view("percent")
}

func tokenEdge(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v', '"', '\'', '<', '>', '`':
		return true
	}
	return false
}

func hasPercentHex(b []byte) bool {
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			if _, ok := hexVal(b[i+1]); ok {
				if _, ok := hexVal(b[i+2]); ok {
					return true
				}
			}
		}
	}
	return false
}

// entities are the named HTML character references worth decoding: the ones that spell characters keys and
// tokens are made of, or that separate them.
var entities = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'', "nbsp": ' ', "sol": '/', "colon": ':',
	"period": '.', "lowbar": '_', "UnderBar": '_', "hyphen": '-', "dash": '-', "minus": '-', "equals": '=',
	"plus": '+', "num": '#', "excl": '!', "quest": '?', "commat": '@', "lsqb": '[', "rsqb": ']', "lbrack": '[',
	"rbrack": ']', "lcub": '{', "rcub": '}', "lbrace": '{', "rbrace": '}', "verbar": '|', "vert": '|', "Hat": '^',
	"grave": '`', "comma": ',', "semi": ';', "percnt": '%', "dollar": '$', "ast": '*', "midast": '*', "lpar": '(',
	"rpar": ')', "bsol": '\\', "tilde": '~', "Tab": '\t', "NewLine": '\n',
}

// html decodes character references: &#NN; and &#xHH; (the ';' optional, as browsers allow) and the names above.
func html(v *view) *view {
	b := v.b
	if !hasByte(b, '&') {
		return nil
	}
	w := newBuilder(v)
	last := 0
	for i := 0; i < len(b); i++ {
		if b[i] != '&' {
			continue
		}
		r, n := entityAt(b[i:])
		if n == 0 {
			continue
		}
		w.keep(last, i)
		w.emitRune(r, i, i+n)
		last = i + n
		i += n - 1
	}
	w.keep(last, len(b))
	return w.view("html")
}

// entityAt parses a character reference at the start of b ('&' first) and returns it and its length (0: none).
func entityAt(b []byte) (rune, int) {
	if len(b) < 3 {
		return 0, 0
	}
	if b[1] == '#' {
		i, digits := 2, 0
		var r rune
		hex := i < len(b) && (b[i] == 'x' || b[i] == 'X')
		if hex {
			i++
		}
		for ; i < len(b) && digits < 8; i++ {
			c := b[i]
			if hex {
				v, ok := hexVal(c)
				if !ok {
					break
				}
				r = r<<4 | rune(v)
			} else {
				if c < '0' || c > '9' {
					break
				}
				r = r*10 + rune(c-'0')
			}
			digits++
		}
		if digits == 0 || !utf8.ValidRune(r) {
			return 0, 0
		}
		if i < len(b) && b[i] == ';' {
			i++
		}
		return r, i
	}
	for i := 1; i < len(b) && i <= 10; i++ {
		c := b[i]
		if c == ';' {
			if r, ok := entities[string(b[1:i])]; ok {
				return r, i + 1
			}
			return 0, 0
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return 0, 0
		}
	}
	return 0, 0
}

// escapes decodes backslash escapes: JSON's (\" \\ \/ \b \f \n \r \t \uXXXX, with surrogate pairs) and the
// other unicode and byte forms (\u{X..}, \UXXXXXXXX, \xHH).
func escapes(v *view) *view {
	b := v.b
	if !hasByte(b, '\\') {
		return nil
	}
	w := newBuilder(v)
	last := 0
	for i := 0; i+1 < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		var n int
		var d []byte
		var r rune = -1
		switch c := b[i+1]; c {
		case '"', '\\', '/', '\'':
			d, n = []byte{c}, 2
		case 'b':
			d, n = []byte{'\b'}, 2
		case 'f':
			d, n = []byte{'\f'}, 2
		case 'n':
			d, n = []byte{'\n'}, 2
		case 'r':
			d, n = []byte{'\r'}, 2
		case 't':
			d, n = []byte{'\t'}, 2
		case 'x':
			if i+3 < len(b) {
				h, ok1 := hexVal(b[i+2])
				l, ok2 := hexVal(b[i+3])
				if ok1 && ok2 {
					d, n = []byte{h<<4 | l}, 4
				}
			}
		case 'U':
			if i+10 <= len(b) {
				if x, ok := hexRune(b[i+2 : i+10]); ok && utf8.ValidRune(x) {
					r, n = x, 10
				}
			}
		case 'u':
			if i+2 < len(b) && b[i+2] == '{' {
				for k := i + 3; k < len(b) && k <= i+11; k++ {
					if b[k] == '}' {
						if x, ok := hexRune(b[i+3 : k]); ok && utf8.ValidRune(x) {
							r, n = x, k+1-i
						}
						break
					}
				}
			} else if i+6 <= len(b) {
				if x, ok := hexRune(b[i+2 : i+6]); ok {
					r, n = x, 6
					// A high surrogate followed by \uDC00-\uDFFF is one code point.
					if x >= 0xD800 && x < 0xDC00 && i+12 <= len(b) && b[i+6] == '\\' && b[i+7] == 'u' {
						if lo, ok := hexRune(b[i+8 : i+12]); ok && lo >= 0xDC00 && lo < 0xE000 {
							r, n = 0x10000+(x-0xD800)<<10+(lo-0xDC00), 12
						}
					}
					if !utf8.ValidRune(r) {
						r, n = -1, 0
					}
				}
			}
		}
		if n == 0 {
			continue
		}
		w.keep(last, i)
		if r >= 0 {
			w.emitRune(r, i, i+n)
		} else {
			w.emit(d, i, i+n)
		}
		last = i + n
		i += n - 1
	}
	w.keep(last, len(b))
	return w.view("escape")
}

// fold strips invisible characters and maps look-alikes to ASCII, so a zero-width space inside a key or a
// Cyrillic A (U+0410) in "AKIA" doesn't hide it. Cheap cases only: no full confusables table.
func fold(v *view) *view {
	b := v.b
	ascii := true
	for _, c := range b {
		if c >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return nil
	}
	w := newBuilder(v)
	last := 0
	for i := 0; i < len(b); {
		if b[i] < 0x80 {
			i++
			continue
		}
		r, n := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && n <= 1 {
			i++
			continue
		}
		m, ok := foldRune(r)
		if ok {
			w.keep(last, i)
			if m >= 0 {
				w.emit([]byte{byte(m)}, i, i+n)
			} else {
				w.changed = true // stripped: no bytes, its span joins its neighbours'
			}
			last = i + n
		}
		i += n
	}
	w.keep(last, len(b))
	return w.view("fold")
}

// foldRune returns (-1, true) for a character to strip, (ASCII, true) for a look-alike, or (_, false).
func foldRune(r rune) (rune, bool) {
	switch {
	case r == 0x00AD, r == 0x034F, r == 0x061C, r == 0x115F, r == 0x1160, r == 0x17B4, r == 0x17B5,
		r == 0x180E, r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x206F,
		r == 0x3164, r >= 0xFE00 && r <= 0xFE0F, r == 0xFEFF, r == 0xFFA0, r >= 0xE0000 && r <= 0xE007F:
		return -1, true // soft hyphen, zero-width and joiners, bidi controls, invisible operators, variation selectors, tags
	case r >= 0xFF01 && r <= 0xFF5E:
		return r - 0xFEE0, true // fullwidth ASCII
	case r == 0x00A0, r == 0x1680, r >= 0x2000 && r <= 0x200A, r == 0x202F, r == 0x205F, r == 0x3000:
		return ' ', true
	case r >= 0x2010 && r <= 0x2015, r == 0x2212, r == 0xFE63, r == 0x058A:
		return '-', true
	}
	if m, ok := homoglyphs[r]; ok {
		return m, true
	}
	return 0, false
}

// homoglyphs: Cyrillic (U+04xx, U+05xx) and Greek (U+03xx) letters that look like the ASCII letter they map to.
var homoglyphs = map[rune]rune{
	// Cyrillic capitals
	'\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K', '\u041c': 'M', '\u041d': 'H', '\u041e': 'O', '\u0420': 'P',
	'\u0421': 'C', '\u0422': 'T', '\u0425': 'X', '\u0405': 'S', '\u0406': 'I', '\u0408': 'J', '\u04ae': 'Y', '\u051a': 'Q',
	'\u051c': 'W',
	// Cyrillic small
	'\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0455': 's',
	'\u0456': 'i', '\u0458': 'j', '\u0501': 'd', '\u04bb': 'h', '\u051b': 'q', '\u051d': 'w',
	// Greek
	'\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H', '\u0399': 'I', '\u039a': 'K', '\u039c': 'M',
	'\u039d': 'N', '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a5': 'Y', '\u03a7': 'X', '\u03bf': 'o', '\u03bd': 'v',
}

// decoders run in this order within one level; a level is one more decoding of everything that changed.
var decoders = []func(*view) *view{percent, html, escapes, fold}

// level applies every decoder once to v and returns the result, or nil if nothing changed. No decoder makes
// its input longer, so a level is at most as long as v.
func level(v *view) *view {
	cur, via := v, ""
	for _, d := range decoders {
		next := d(cur)
		if next == nil {
			continue
		}
		if via != "" {
			via += "+"
		}
		via += next.via
		cur = next
	}
	if cur == v {
		return nil
	}
	cur.via = joinVia(v.via, via)
	cur.depth = v.depth + 1
	return cur
}

func joinVia(parent, step string) string {
	if parent == "" {
		return step
	}
	return parent + ">" + step
}

func hasByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

// b64val is a liberal base64 alphabet: standard and URL-safe at once ('+' and '-' are 62, '/' and '_' are 63).
var b64val = func() (t [256]int8) {
	for i := range t {
		t[i] = -1
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" {
		t[c] = int8(i)
	}
	t['+'], t['-'], t['/'], t['_'] = 62, 62, 63, 63
	return t
}()

// b64run is one base64 segment of a view: the positions of its alphabet characters (line breaks of MIME-style
// wrapping skipped) and the view bytes it spans, padding included.
type b64run struct {
	pos      []int
	from, to int
}

// b64runs finds base64 segments with at least minLen alphabet characters.
func b64runs(b []byte, minLen int) []b64run {
	var runs []b64run
	var pos []int
	for i := 0; i < len(b); {
		if b64val[b[i]] < 0 {
			i++
			continue
		}
		from := i
		pos = pos[:0]
		for i < len(b) {
			if b64val[b[i]] >= 0 {
				pos = append(pos, i)
				i++
				continue
			}
			// A line break continues the run when the line so far is whole groups and more follows.
			j := i
			if j < len(b) && b[j] == '\r' {
				j++
			}
			if j < len(b) && b[j] == '\n' && len(pos)%4 == 0 && j+1 < len(b) && b64val[b[j+1]] >= 0 {
				i = j + 1
				continue
			}
			break
		}
		for k := 0; k < 2 && i < len(b) && b[i] == '='; k++ {
			i++
		}
		if len(pos) >= minLen {
			runs = append(runs, b64run{pos: append([]int(nil), pos...), from: from, to: i})
		}
	}
	return runs
}

// decodeRun decodes r skipping its first shift characters. Each group of 4 characters maps to the input span
// of those characters.
func decodeRun(v *view, r b64run, shift int) *view {
	pos := r.pos[shift:]
	w := &builder{src: v, changed: true}
	n := len(pos) * 3 / 4
	w.out, w.start, w.end = make([]byte, 0, n), make([]int32, 0, n), make([]int32, 0, n)
	var g [3]byte
	for k := 0; k+1 < len(pos); k += 4 {
		m := min(4, len(pos)-k)
		var acc uint32
		for q := 0; q < 4; q++ {
			acc <<= 6
			if q < m {
				acc |= uint32(b64val[v.b[pos[k+q]]])
			}
		}
		g[0], g[1], g[2] = byte(acc>>16), byte(acc>>8), byte(acc)
		w.emit(g[:m-1], pos[k], pos[k+m-1]+1)
	}
	return &view{b: w.out, start: w.start, end: w.end}
}

// textLike reports whether d reads as text: at most 1 in 10 bytes are control characters or invalid UTF-8.
// Base64 of a secret is base64 of text; decoded images and other binary are skipped (and so is the garbage a
// long word or a path decodes to, which keeps false positives and work down).
func textLike(d []byte) bool {
	bad := 0
	for i := 0; i < len(d); {
		c := d[i]
		if c < 0x80 {
			if c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c == 0x7f {
				bad++
			}
			i++
			continue
		}
		r, n := utf8.DecodeRune(d[i:])
		if r == utf8.RuneError && n <= 1 {
			bad++
		}
		i += n
	}
	return bad*10 <= len(d)
}
