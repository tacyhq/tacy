package storedfiles

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tacyhq/tacy/proto"
)

// The ids file-format.ts makes: a prefix, then 26 lowercase base32 characters for 128 random bits.
var idRe = map[string]*regexp.Regexp{}

func init() {
	for _, p := range []string{"fl", "ob", "ow"} {
		idRe[p] = regexp.MustCompile(`^` + p + `_[a-z2-7]{25}[aeimquy4]\z`)
	}
}

// IsID: s is a file-storage id with prefix ("fl", "ob", "ow").
func IsID(prefix, s string) bool { r := idRe[prefix]; return r != nil && r.MatchString(s) }

const (
	maxNameRunes = 255
	maxTypeBytes = 255
	maxURLBytes  = 4096
	keyBytes     = 32
)

// Check checks the stored files a run (urls: each needs its read URL) or a schedule's definition (no URLs) names:
// each one's ids, layout, name and key; one owner for all (one person's storage); no object twice; at most
// MaxRunFiles, and their stored bytes together at most MaxRunBytes. It doesn't check a URL's address: Fetcher does,
// when it reads.
func Check(files []proto.StoredFile, urls bool) error {
	if len(files) > MaxRunFiles {
		return fmt.Errorf("storedfiles: at most %d files a run", MaxRunFiles)
	}
	seen := map[string]bool{}
	var total int64
	for i := range files {
		f := &files[i]
		if err := checkOne(f, urls); err != nil {
			return fmt.Errorf("storedfiles: file %d: %w", i+1, err)
		}
		if f.Owner != files[0].Owner {
			return errors.New("storedfiles: the files are from more than one storage")
		}
		if seen[f.Object] {
			return fmt.Errorf("storedfiles: object %d named twice", i+1)
		}
		seen[f.Object] = true
		if total += ObjectBytes(f.Padded); total > MaxRunBytes {
			return fmt.Errorf("storedfiles: more than %d MB a run", MaxRunBytes>>20)
		}
	}
	return nil
}

func checkOne(f *proto.StoredFile, urls bool) error {
	switch {
	case !IsID("ob", f.Object) || !IsID("fl", f.File) || !IsID("ow", f.Owner):
		return errors.New("bad id")
	case f.Epoch < 1 || int64(f.Epoch) > MaxEpoch:
		return errors.New("bad epoch")
	case f.Size < 0 || f.Size > MaxFileBytes:
		return errors.New("bad size")
	case len(f.Key) != keyBytes:
		return errors.New("bad key")
	case urls && (f.URL == "" || len(f.URL) > maxURLBytes):
		return errors.New("no read URL")
	case !urls && f.URL != "":
		return errors.New("a URL where none belongs")
	case !validName(f.Name):
		return errors.New("bad name")
	case len(f.Type) > maxTypeBytes || !utf8.ValidString(f.Type) || strings.ContainsFunc(f.Type, unicode.IsControl):
		return errors.New("bad type")
	}
	if p, err := PaddedFor(f.Size); err != nil || p != f.Padded {
		return errors.New("the padded size doesn't fit the size")
	}
	return nil
}

// validName: a node's name as the browser allows it (1 to 255 characters, no NUL, no "/"), and no other control
// character either: it goes into the model's input.
func validName(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= 1 && n <= maxNameRunes && utf8.ValidString(s) && !strings.ContainsRune(s, '/') &&
		!strings.ContainsFunc(s, unicode.IsControl)
}
