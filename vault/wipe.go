package vault

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WipeConnFile removes the connections file a release before the keys plan kept on the CVM's disk (under Phala's
// disk key; "Keys: never a provider's"), with the temporary files a save leaves
// (".connections-*" next to it): each is overwritten with zeros, synced and removed, then the directory is synced.
// A missing file is fine. It returns how many files it removed (a count only: nothing of what they held is read).
//
// The overwrite is best effort against the file system (a journal or copy-on-write disk can keep older blocks); the
// real fix is a fresh disk, which a new CVM has (the keys plan §3.3).
func WipeConnFile(path string) (int, error) {
	dir := filepath.Dir(path)
	names := []string{path}
	if es, err := os.ReadDir(dir); err == nil {
		for _, e := range es {
			if e.Type().IsRegular() && strings.HasPrefix(e.Name(), ".connections-") {
				names = append(names, filepath.Join(dir, e.Name()))
			}
		}
	}
	n := 0
	var errs []error
	for _, name := range names {
		switch err := wipeFile(name); {
		case err == nil:
			n++
		case errors.Is(err, fs.ErrNotExist):
		default:
			errs = append(errs, err)
		}
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return n, errors.Join(errs...)
}

func wipeFile(name string) error {
	fi, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return os.Remove(name) // a link or something else: nothing of ours to overwrite
	}
	f, err := os.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	zeros := make([]byte, 64<<10)
	for left := fi.Size(); left > 0; {
		k := min(left, int64(len(zeros)))
		if _, err := f.Write(zeros[:k]); err != nil {
			f.Close()
			return err
		}
		left -= k
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Remove(name)
}
