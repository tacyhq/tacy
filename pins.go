// Package tacy embeds compose.yaml, the agent VM definition at this commit (it embeds the service source and pins
// the binary hash), and app-compose.json, the CVM manifest a release of it is deployed with (verifier.ReleaseAppCompose:
// that compose with every setting of the CVM). Only the WebAssembly verifier's deprecated exact mode uses the files
// (wasm verify(): the VM must run exactly these); release mode checks a signed release instead (package release) and
// derives the app-compose.json from the signed compose. Not imported by ./app, so it isn't part of the compose itself.
package tacy

import (
	_ "embed"

	"github.com/tacyhq/tacy/verifier"
)

//go:embed compose.yaml
var Compose []byte

// AppCompose is the release's app-compose.json, written by go run ./cmd/compose (pins_test.go checks it is
// ReleaseAppCompose(Compose)). The deploy sends verifier.DeployAppCompose(AppCompose) (app-compose.deploy.json).
//
//go:embed app-compose.json
var AppCompose []byte

// KMSFallback: a release takes its keys from the pinned KMS root (key_provider kms) instead of making them in the VM
// (key_provider none): on Phala a key_provider none CVM boots but its gateway can't route to it. So the VM keeps
// nothing on its disk: every volume is memory (the verifier's KMS fallback rule). cmd/compose -kms-fallback must
// match.
const KMSFallback = true

// ReleaseAppCompose is the app-compose.json a release of compose attests (no pre-launch script, the KMSFallback mode).
func ReleaseAppCompose(compose []byte) ([]byte, error) {
	return verifier.ReleaseAppCompose(compose, nil, KMSFallback)
}
