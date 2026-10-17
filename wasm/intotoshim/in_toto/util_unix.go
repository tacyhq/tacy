//go:build (linux || darwin || !windows) && !js
// +build linux darwin !windows
// +build !js

// Changed for the WebAssembly verifier: "&& !js" added (golang.org/x/sys/unix has no Access for GOOS=js; see
// util_js.go).

package in_toto

import "golang.org/x/sys/unix"

func isWritable(path string) error {
	err := unix.Access(path, unix.W_OK)
	if err != nil {
		return err
	}
	return nil
}
