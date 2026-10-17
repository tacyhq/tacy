// github.com/in-toto/in-toto-golang v0.11.0 (Apache-2.0), only the packages the WebAssembly verifier imports
// (in_toto and in_toto/slsa_provenance/*, tests and the CLI left out), unchanged except in_toto/util_unix.go
// (build tag) and in_toto/util_js.go (added). Used through a replace in ../go.mod only.
module github.com/in-toto/in-toto-golang

go 1.24.0

require (
	github.com/secure-systems-lab/go-securesystemslib v0.10.0
	github.com/shibumi/go-pathspec v1.3.0
	golang.org/x/sys v0.41.0
)
