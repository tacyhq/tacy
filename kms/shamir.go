package kms

import (
	"errors"
	"io"
)

// Shamir secret sharing over GF(2^8) (the AES field, x^8+x^4+x^3+x+1), byte by byte: each byte of the secret is
// the constant term of its own random polynomial of degree t-1, and share i holds every polynomial at x = i. Any t
// shares give the secret back (Lagrange at 0); fewer give no information about it. Field operations are written
// without secret-dependent branches or table lookups.

// Share is one share: its x (1..255) and one y per secret byte.
type Share struct {
	X byte
	Y []byte
}

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= -(b & 1) & a
		hi := a >> 7
		a = (a << 1) ^ (-hi & 0x1b)
		b >>= 1
	}
	return p
}

// gfInv is a^254 (a^-1 for a != 0).
func gfInv(a byte) byte {
	r := byte(1)
	for e := byte(254); e > 0; e >>= 1 {
		if e&1 == 1 {
			r = gfMul(r, a)
		}
		a = gfMul(a, a)
	}
	return r
}

// Split makes n shares of secret, t of which rebuild it (2 <= t <= n <= 255; t == 1 is allowed for one share
// holder, but then every share is the secret).
func Split(secret []byte, n, t int, rand io.Reader) ([]Share, error) {
	if t < 1 || n < t || n > 255 || len(secret) == 0 {
		return nil, errors.New("kms: shamir needs 1 <= t <= n <= 255 and a secret")
	}
	coef := make([]byte, (t-1)*len(secret))
	if _, err := io.ReadFull(rand, coef); err != nil {
		return nil, err
	}
	defer clear(coef)
	shares := make([]Share, n)
	for i := range shares {
		x := byte(i + 1)
		y := make([]byte, len(secret))
		for j, s := range secret {
			// Horner: ((c_{t-1} x + c_{t-2}) x + ... + c_1) x + s
			var v byte
			for k := t - 2; k >= 0; k-- {
				v = gfMul(v, x) ^ coef[k*len(secret)+j]
			}
			y[j] = gfMul(v, x) ^ s
		}
		shares[i] = Share{X: x, Y: y}
	}
	return shares, nil
}

// Combine rebuilds the secret from shares (at least the threshold; the caller checks the result, since wrong or
// too few shares give a wrong secret, not an error).
func Combine(shares []Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("kms: no shares")
	}
	size := len(shares[0].Y)
	seen := map[byte]bool{}
	for _, s := range shares {
		if s.X == 0 || seen[s.X] || len(s.Y) != size || size == 0 {
			return nil, errors.New("kms: shares are duplicated, zero or of different sizes")
		}
		seen[s.X] = true
	}
	out := make([]byte, size)
	for i, si := range shares {
		// Lagrange basis at 0: prod_{j != i} x_j / (x_j - x_i); subtraction is xor.
		num, den := byte(1), byte(1)
		for j, sj := range shares {
			if i != j {
				num = gfMul(num, sj.X)
				den = gfMul(den, sj.X^si.X)
			}
		}
		l := gfMul(num, gfInv(den))
		for k := range out {
			out[k] ^= gfMul(si.Y[k], l)
		}
	}
	return out, nil
}
