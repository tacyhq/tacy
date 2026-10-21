package identity

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestIDsAndKeys(t *testing.T) {
	id := IDFrom("i", make([]byte, 16))
	if !ValidID("i", id) || ValidID("s", id) || ValidID("i", id+"a") || ValidID("i", "i_"+string(make([]byte, 26))) {
		t.Fatalf("ValidID on %s", id)
	}
	// The last character carries 3 bits and 2 zero bits: a non-canonical encoding isn't an id.
	if ValidID("i", "i_aaaaaaaaaaaaaaaaaaaaaaaaab") {
		t.Fatal("non-canonical id accepted")
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	k, err := ParseKey(KeyString(pub))
	if err != nil || !k.Equal(pub) {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{"", "ed25519:", "x25519:" + KeyString(pub)[8:], "ed25519:AAAA", KeyString(pub) + "="} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) accepted", bad)
		}
	}
}

func TestStaticDirectory(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	var d Static
	if _, err := d.Key("f_a", "s_a", "i_x"); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	d.Add("f_a", "i_x", pub, "s_a")
	if k, err := d.Key("f_a", "s_a", "i_x"); err != nil || !k.Equal(pub) {
		t.Fatal(err)
	}
	if _, err := d.Key("f_b", "s_a", "i_x"); !errors.Is(err, ErrUnknown) {
		t.Fatal("other firm")
	}
	if _, err := d.Key("f_a", "s_b", "i_x"); !errors.Is(err, ErrNotHolder) {
		t.Fatal("other space")
	}
	d.Leave("f_a", "s_a", "i_x")
	if _, err := d.Key("f_a", "s_a", "i_x"); !errors.Is(err, ErrNotHolder) {
		t.Fatal("left")
	}
	d.Add("f_a", "i_x", pub, "s_a")
	d.Revoke("f_a", "i_x")
	if _, err := d.Key("f_a", "s_a", "i_x"); !errors.Is(err, ErrRevoked) {
		t.Fatal("revoked")
	}
}
