//go:build !unix

package labexa

// lockFile: no file lock off unix (labs run on macOS and Linux); this process's own updates are still serialised.
func lockFile(string) (func(), error) { return func() {}, nil }
