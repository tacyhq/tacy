//go:build js

// Added for the WebAssembly verifier (github.com/tacyhq/tacy/wasm): golang.org/x/sys/unix has no Access for
// GOOS=js. isWritable is only used by in-toto's layout runner, which the verifier never calls; Sigstore bundle
// verification only uses in-toto's statement types.
package in_toto

import "errors"

func isWritable(path string) error {
	return errors.New("isWritable: not available in the WebAssembly verifier")
}
