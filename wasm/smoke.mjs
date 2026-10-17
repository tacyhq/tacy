// Smoke test for the WebAssembly verifier in Node (no network): it starts, exposes its API, and runs the release
// check with the embedded Sigstore root on a real GitHub Actions bundle (Tinfoil's, recorded in
// internal/tinfoil/testdata), which must verify cryptographically and then be refused as not this repo's release.
//   node wasm/smoke.mjs <verifier.wasm> <dir with wasm_exec.js>
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const [wasmPath, execDir] = process.argv.slice(2);
await import(join(execDir, "wasm_exec.js"));
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), go.importObject);
go.run(instance);
const api = globalThis.sealedAgentVM;
const fail = (msg) => { console.error("FAIL:", msg); process.exit(1); };
if (!api || typeof api.verifyRelease !== "function" || typeof api.verify !== "function") fail("API missing");
if (api.releaseIdentity !== "https://github.com/tacyhq/tacy/.github/workflows/release.yml@refs/tags/") fail(api.releaseIdentity);
if (!/^v\d+\.\d+\.\d+$/.test(api.minVersion)) fail(api.minVersion);

const rec = JSON.parse(readFileSync(new URL("../internal/tinfoil/testdata/router-release.json", import.meta.url)));
const real = JSON.parse(api.verifyReleaseBundle(JSON.stringify(rec.Bundle), rec.Digest));
if (real.ok || !real.error.includes("certificate identity")) fail(`real bundle: ${JSON.stringify(real)}`);
const wrong = JSON.parse(api.verifyReleaseBundle(JSON.stringify(rec.Bundle), createHash("sha256").update("x").digest("hex")));
if (wrong.ok || !wrong.error.includes("artifact")) fail(`wrong digest: ${JSON.stringify(wrong)}`);
const seen = JSON.parse(api.verifyReleaseBundle(JSON.stringify(rec.Bundle), rec.Digest, "not-a-version"));
if (seen.ok || !seen.error.includes("last seen")) fail(`bad lastSeenVersion: ${JSON.stringify(seen)}`);
const res = JSON.parse(await api.verifyRelease("{}", "00".repeat(32), "{}", async () => fail("no fetch expected")));
if (res.ok || res.hpkePublicKey) fail(`empty attestation: ${JSON.stringify(res)}`);
console.log(`wasm smoke OK (release identity ${api.releaseIdentity}vX.Y.Z, min ${api.minVersion})`);
process.exit(0);
