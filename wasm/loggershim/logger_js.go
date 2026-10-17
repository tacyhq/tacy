//go:build js

// Added for the WebAssembly verifier: github.com/google/logger v1.1.1 (Apache-2.0, copied unchanged in logger.go)
// has no setup() for GOOS=js. go-tdx-guest only logs at verbosity levels it never enables here; discard.
package logger

import "io"

func setup(src string) (io.Writer, io.Writer, io.Writer, error) {
	return io.Discard, io.Discard, io.Discard, nil
}
