package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/vault"
)

// The chat's golden vectors for the connection calls (the chat's test/golden/v2-connection.json, made with node:crypto
// by scripts/gen-golden-v2-connection-vectors.mjs): the email connection sealed in the browser opens in the vault with
// its key (info and aad as the connections contract says) to the plaintext the chat wrote, and passes the vault's checks; every
// call's body decodes strictly as the VM's handler reads it, with its own items (the box's digest for a put), and its
// digest and identity signature check under its own label against the VM key, and under no other.
func TestConnectionGoldenVectors(t *testing.T) {
	b, err := os.ReadFile("../runauth/testdata/v2-connection.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		VMPrivate    string       `json:"vm_private"`
		VaultPrivate string       `json:"vault_private"`
		Seal         string       `json:"seal"`
		Space        string       `json:"space"`
		Connection   string       `json:"connection"`
		Plaintext    string       `json:"plaintext"`
		AAD          string       `json:"aad"`
		Sealed       vault.Sealed `json:"sealed"`
		BoxSHA256    string       `json:"box_sha256"`
		Identity     struct{ ID string }
		Calls        []struct {
			Call, Name, Label, Body, Digest string
			Own                             []string
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte { x, _ := hex.DecodeString(s); return x }
	vm, _ := ecdh.X25519().NewPrivateKey(unhex(v.VMPrivate))
	vk, err := ecdh.X25519().NewPrivateKey(unhex(v.VaultPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if aad, _ := base64.StdEncoding.DecodeString(v.AAD); string(aad) != string(vault.ConnAAD(v.Space, v.Connection)) {
		t.Fatalf("aad %q", aad)
	}
	if BoxDigest(v.Sealed) != v.BoxSHA256 {
		t.Fatalf("box digest %s", BoxDigest(v.Sealed))
	}
	// The box opens in a vault with that key and passes its checks.
	vt, err := vault.New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := vt.EnableConnsKey("", vk); err != nil {
		t.Fatal(err)
	}
	if vt.SealKey() != v.Sealed.Key {
		t.Fatalf("seal key %s, the vectors say %s", vt.SealKey(), v.Sealed.Key)
	}
	pid, info, err := vt.ConnPut(v.Space, v.Connection, v.Sealed)
	if err != nil || info.Host != "imap.gmail.com" || info.Address != "person@example.com" || info.Port != 993 || info.Security != "tls" {
		t.Fatalf("put: %+v %v", info, err)
	}
	s, _, err := vt.Lease(vault.Request{Secret: vault.ConnSecret, Connector: vault.MailConnector, Host: "imap.gmail.com", Task: "connect",
		Action: "login", Space: v.Space, Conn: v.Connection, Pending: pid})
	if err != nil || !strings.Contains(v.Plaintext, `"password":"`+string(s)+`"`) {
		t.Fatalf("the password in the box isn't the plaintext's: %v", err)
	}
	// Moved to another space it doesn't open.
	if _, _, err := vt.ConnPut("s_otherspaceotherspaceotherx", v.Connection, v.Sealed); err == nil {
		t.Fatal("a box opened under another space")
	}

	labels := map[string]string{"list": runauth.ConnListLabel, "put": runauth.ConnPutLabel, "remove": runauth.ConnRemoveLabel}
	if len(v.Calls) != 3 {
		t.Fatalf("%d calls", len(v.Calls))
	}
	for _, c := range v.Calls {
		var where *runauth.Where
		var own []string
		strict := func(x any) {
			if err := jsonv2.Unmarshal([]byte(c.Body), x, jsonv2.RejectUnknownMembers(true)); err != nil {
				t.Fatalf("%s: body: %v", c.Name, err)
			}
		}
		switch c.Call {
		case "list":
			var x runauth.Where
			strict(&x)
			where = &x
		case "put":
			var x connPutRequest
			strict(&x)
			where, own = &x.Where, []string{x.Connection, BoxDigest(x.Sealed)}
		case "remove":
			var x connRemoveRequest
			strict(&x)
			where, own = &x.Where, []string{x.Connection}
		default:
			t.Fatalf("unknown call %q", c.Call)
		}
		label := labels[c.Call]
		if label != c.Label || strings.Join(own, "|") != strings.Join(c.Own, "|") {
			t.Fatalf("%s: label %q own %q, the vectors say %q %q", c.Name, label, own, c.Label, c.Own)
		}
		dg := runauth.CallDigest(label, vm.PublicKey().Bytes(), where, own...)
		if hex.EncodeToString(dg[:]) != c.Digest {
			t.Fatalf("%s: digest %x", c.Name, dg)
		}
		who, err := runauth.CheckCall(vm, label, where, time.Unix(where.SignedAt, 0), own...)
		if err != nil || who.Space != v.Space {
			t.Fatalf("%s: %+v %v", c.Name, who, err)
		}
		for _, other := range labels {
			if other == label {
				continue
			}
			if _, err := runauth.CheckCall(vm, other, where, time.Unix(where.SignedAt, 0), own...); err == nil {
				t.Fatalf("%s: passed under %s", c.Name, other)
			}
		}
	}
}
