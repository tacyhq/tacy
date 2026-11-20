package passshare

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/kms"
)

// testParams keep the tests fast (the real cost is Default).
var testParams = Params{Time: 1, MemLog2: 6, Threads: 1}

func sealedShare(t *testing.T) (*ecdh.PrivateKey, kms.SealedShare, []byte) {
	t.Helper()
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	id, _, _ := ed25519.GenerateKey(rand.Reader)
	y := []byte("share-y-0123456789abcdef0123456789")
	box, err := kms.Seal(k.PublicKey(), kms.LabelShare, kms.ShareAAD(kms.IDString(id), 2, 0), y)
	if err != nil {
		t.Fatal(err)
	}
	return k, kms.SealedShare{Recipient: kms.RecipientString(k.PublicKey()), Index: 2, Epoch: 0, KMSID: kms.IDString(id), Sealed: box}, y
}

func TestRoundTripArmorAndPaper(t *testing.T) {
	k, sh, y := sealedShare(t)
	pass := []byte("correct horse battery staple, twice")
	ps, err := New(pass, k, sh, testParams)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"armor": Armor(ps), "paper": Paper(ps)} {
		if strings.Contains(text, string(pass)) || bytes.Contains([]byte(text), k.Bytes()) {
			t.Fatalf("%s shows the passphrase or the key", name)
		}
		got, err := Decode(text)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		k2, sh2, err := got.Open(pass)
		if err != nil || !bytes.Equal(k2.Bytes(), k.Bytes()) || sh2.Index != 2 || sh2.KMSID != sh.KMSID || sh2.Recipient != sh.Recipient {
			t.Fatalf("%s: open %v", name, err)
		}
		pt, err := kms.Open(k2, kms.LabelShare, kms.ShareAAD(sh2.KMSID, sh2.Index, sh2.Epoch), sh2.Sealed)
		if err != nil || !bytes.Equal(pt, y) {
			t.Fatalf("%s: the share doesn't open with the unwrapped key", name)
		}
		if _, _, err := got.Open([]byte("correct horse battery staple, thrice")); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("%s: a wrong passphrase: %v", name, err)
		}
	}
}

// Paper copies are typed back by hand: case, spacing and 0/O, 1/I, 8/B mix-ups don't matter; a changed character is
// found and its line named; a missing line too.
func TestPaperChecksums(t *testing.T) {
	k, sh, _ := sealedShare(t)
	ps, _ := New([]byte("a passphrase that is long enough"), k, sh, testParams)
	paper := Paper(ps)
	lines := strings.Split(strings.TrimSpace(paper), "\n")
	if !strings.HasPrefix(lines[0], "TACY KMS SHARE 2") || !strings.HasPrefix(lines[len(lines)-1], "END ") {
		t.Fatalf("paper:\n%s", paper)
	}
	if _, err := Decode(strings.ToLower(strings.ReplaceAll(paper, "  ", "   "))); err != nil {
		t.Fatalf("lower case and spacing: %v", err)
	}
	// Change one character on line 03.
	bad := strings.Split(paper, "\n")
	f := []rune(bad[3])
	for i := 4; i < len(f); i++ {
		if f[i] >= 'A' && f[i] <= 'Z' {
			f[i] = 'A' + (f[i]-'A'+1)%26
			break
		}
	}
	bad[3] = string(f)
	if _, err := Decode(strings.Join(bad, "\n")); !errors.Is(err, ErrChecksum) || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("a mistyped line: %v", err)
	}
	missing := append(append([]string{}, strings.Split(paper, "\n")[:2]...), strings.Split(paper, "\n")[3:]...)
	if _, err := Decode(strings.Join(missing, "\n")); !errors.Is(err, ErrChecksum) {
		t.Fatalf("a missing line: %v", err)
	}
	// The armored copy's checksum catches a changed byte too.
	raw := ps.Marshal()
	raw[80] ^= 1
	if _, err := Parse(raw); !errors.Is(err, ErrChecksum) {
		t.Fatalf("a changed byte: %v", err)
	}
}

func TestNewRefusesAnotherKey(t *testing.T) {
	_, sh, _ := sealedShare(t)
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := New([]byte("a passphrase that is long enough"), other, sh, testParams); err == nil {
		t.Fatal("wrapped a key that isn't the share's recipient")
	}
	if Default.MemLog2 < 20 || Default.Time < 3 {
		t.Fatalf("the default cost is too low: %+v", Default)
	}
}
