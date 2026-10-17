// Package tacy embeds compose.yaml, the agent VM definition at this commit (it embeds the service source and pins
// the binary hash). Only the WebAssembly verifier's deprecated exact mode uses it (wasm verify(): the VM must run
// exactly this file); release mode checks a signed release instead (package release), and this file goes once
// clients have switched. Not imported by ./app, so it isn't part of the compose itself.
package tacy

import _ "embed"

//go:embed compose.yaml
var Compose []byte
