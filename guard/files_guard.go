package guard

// The person's files never leave the VM (a_research with files, v0.13.0). The acting model never gets their text:
// only the quarantined reader's fields (its own words) and [quote N] references (files.go). So what it can send out
// is its own words: a search query or an address it writes. Those go out masked like any other (tools.go). What must
// never go out is the files' wording: a search or page read whose arguments carry a passage of the files (fileShingle
// words in a row, as they stand in a file) is refused here in gatewayd before the person is asked and before anything
// is sent (web.go Action), whatever the permissions, a grant or the policy say. Like the person's images
// (images_in.go on v0.12.0), the files reach one place only: the models in the attested inference enclave.
//
// Words are compared as code splits them: letters and digits, lower case, everything else a separator, so neither
// punctuation, case, percent-encoding nor a URL's slashes and hyphens hide a passage. Runs of words the brief also has
// don't count: the brief is the person's own words for the agent, and research searches from it as it always has.

import (
	"encoding/json"
	"hash/fnv"
	"net/url"
	"strings"
	"unicode"

	"github.com/tacyhq/tacy/harness"
)

// fileShingle is how many words in a row of a file make a passage: longer than a query needs to name a company, a
// product or a topic, shorter than any sentence worth hiding.
const fileShingle = 6

// FileTextDenied starts the refusal of an outbound action whose arguments carry a passage of the person's files.
const FileTextDenied = "file_text"

// fileWords splits s into its words: runs of letters and digits, lower case.
func fileWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

func shingleHash(ws []string) uint64 {
	h := fnv.New64a()
	for i, w := range ws {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(w))
	}
	return h.Sum64()
}

// passages is every run of fileShingle words of the task's files, but those the brief has too (built once, on the
// task's first outbound action; about 170,000 entries for 1,000,000 characters).
func (s *filesState) passages(opts TaskOptions) map[uint64]struct{} {
	s.guardOnce.Do(func() {
		set := map[uint64]struct{}{}
		for _, f := range opts.Files {
			ws := fileWords(f.Text)
			for i := 0; i+fileShingle <= len(ws); i++ {
				set[shingleHash(ws[i:i+fileShingle])] = struct{}{}
			}
		}
		ws := fileWords(opts.Question)
		for i := 0; i+fileShingle <= len(ws); i++ {
			delete(set, shingleHash(ws[i:i+fileShingle]))
		}
		s.shingles = set
	})
	return s.shingles
}

// argStrings is every string in an action's JSON arguments (keys too), each also percent-decoded (as a query and as
// a path) when that differs; arguments that aren't JSON are one string.
func argStrings(args []byte) []string {
	var v any
	if json.Unmarshal(args, &v) != nil {
		v = string(args)
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch y := x.(type) {
		case string:
			out = append(out, y)
			for _, dec := range []func(string) (string, error){url.QueryUnescape, url.PathUnescape} {
				if d, err := dec(y); err == nil && d != y {
					out = append(out, d)
				}
			}
		case []any:
			for _, e := range y {
				walk(e)
			}
		case map[string]any:
			for k, e := range y {
				walk(k)
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// fileTextInArgs says whether an action's arguments carry a passage of the task's files.
func (t *task) fileTextInArgs(args []byte) bool {
	if len(t.opts.Files) == 0 {
		return false
	}
	set := t.files.passages(t.opts)
	if len(set) == 0 {
		return false
	}
	for _, s := range argStrings(args) {
		ws := fileWords(s)
		for i := 0; i+fileShingle <= len(ws); i++ {
			if _, ok := set[shingleHash(ws[i:i+fileShingle])]; ok {
				return true
			}
		}
	}
	return false
}

// fileTextDenial is what the model sees for an outbound action carrying a passage of the files: nothing was sent.
func fileTextDenial(action string) *harness.ActionResult {
	return &harness.ActionResult{Status: harness.ActionDenied, Error: FileTextDenied + ": " + action +
		" was refused because its arguments contain a passage of the person's files, which never leave the VM; nothing was sent. Use a few short, generic words of your own."}
}
