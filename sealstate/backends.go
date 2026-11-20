package sealstate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ---- Mem: in this process (tests, and a VM without a backend) ----------------------------------------------------

// Mem is a Backend in memory.
type Mem struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func (m *Mem) Get(_ context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.blobs[name]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(b), nil
}

func (m *Mem) Put(_ context.Context, name string, blob []byte, prev uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blobs == nil {
		m.blobs = map[string][]byte{}
	}
	if err := checkPut(m.blobs[name], name, blob, prev); err != nil {
		return err
	}
	m.blobs[name] = bytes.Clone(blob)
	return nil
}

// checkPut is every backend's rule (the relay's too): the blob is sealed state of that name, one generation past
// prev, and prev is what is held.
func checkPut(held []byte, name string, blob []byte, prev uint64) error {
	n, gen, err := Header(blob)
	if err != nil || n != name || gen != prev+1 || len(blob) > MaxBlob {
		return fmt.Errorf("sealstate: put %s: not a sealed blob of the next generation", name)
	}
	var cur uint64
	if held != nil {
		_, cur, _ = Header(held)
	}
	if cur != prev {
		return ErrConflict
	}
	return nil
}

// ---- File: a directory (tests and local development only; the CVM uses the relay) -------------------------------

// File is a Backend in a directory: one file per state, written whole and renamed. For tests and local runs: on the
// CVM the disk is under the provider's key and a fresh CVM wouldn't find it (the keys plan §3.2).
type File struct {
	Dir string
	mu  sync.Mutex
}

func (f *File) path(name string) (string, error) {
	if !ValidName(name) {
		return "", ErrName
	}
	return filepath.Join(f.Dir, name+".sealed"), nil
}

func (f *File) Get(_ context.Context, name string) ([]byte, error) {
	p, err := f.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (f *File) Put(ctx context.Context, name string, blob []byte, prev uint64) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	held, err := f.Get(ctx, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := checkPut(held, name, blob, prev); err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(f.Dir, "."+name+"-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(blob)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// ---- Relay: the chat Worker (R2), ciphertext only ----------------------------------------------------------------

// Relay is the Backend the CVM uses: the chat Worker keeps each blob in R2. The Worker sees ciphertext only and
// never a key. Its API (to be built on the Worker; the keys plan §3.2):
//
//	GET  {Base}/api/vm/state/{name}
//	     200 application/octet-stream: the blob, header X-Tacy-Gen: its generation
//	     404: none yet
//	PUT  {Base}/api/vm/state/{name}    body: the blob (application/octet-stream, at most MaxBlob)
//	     headers X-Tacy-Gen: the blob's generation, X-Tacy-Prev-Gen: the generation it replaces (0: none)
//	     204: stored. The Worker checks the body starts with "TACYSEAL1", that the name and generation in its header
//	          are {name} and X-Tacy-Gen, that X-Tacy-Gen = X-Tacy-Prev-Gen + 1, and that the generation it holds is
//	          X-Tacy-Prev-Gen, atomically (a Durable Object or a database row per name: compare and set).
//	     409: the generation held isn't X-Tacy-Prev-Gen (another instance wrote; this one must reload, or stop)
//	     400: not a sealed blob of that name and generation; 413: too large
//	     It keeps the previous generation too (one step of undo for the operator, never served to the VM).
//	Both need the VM's authentication (Auth sets it): today the run token's sibling, later the relay-auth envelope
//	(the keys plan §3.4); anything else is 401. {name} matches ValidName. Each VM (app) has its own namespace in R2:
//	vm-state/<app>/<name>, the app from the authentication.
//
// The CVM's agentd has no network: Client must be a transport through gatewayd (TODO(kms): the same typed
// gateway/v0 op the Tacy key service's client uses to reach fixed hosts).
type Relay struct {
	Base   string // https://chat.tacy.io
	Client interface {
		Do(*http.Request) (*http.Response, error)
	}
	Auth func(*http.Request) // adds the VM's authentication
}

func (r *Relay) url(name string) (string, error) {
	if !ValidName(name) {
		return "", ErrName
	}
	return strings.TrimSuffix(r.Base, "/") + "/api/vm/state/" + url.PathEscape(name), nil
}

func (r *Relay) do(req *http.Request) (*http.Response, error) {
	if r.Auth != nil {
		r.Auth(req)
	}
	return r.Client.Do(req)
}

func (r *Relay) Get(ctx context.Context, name string) ([]byte, error) {
	u, err := r.url(name)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	res, err := r.do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 200:
	case 404:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("sealstate: relay GET %s: HTTP %d", name, res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxBlob+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBlob {
		return nil, fmt.Errorf("sealstate: relay GET %s: too large", name)
	}
	n, gen, err := Header(b)
	if err != nil || n != name || res.Header.Get("X-Tacy-Gen") != strconv.FormatUint(gen, 10) {
		return nil, ErrSealed
	}
	return b, nil
}

func (r *Relay) Put(ctx context.Context, name string, blob []byte, prev uint64) error {
	u, err := r.url(name)
	if err != nil {
		return err
	}
	_, gen, err := Header(blob)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, "PUT", u, bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Tacy-Gen", strconv.FormatUint(gen, 10))
	req.Header.Set("X-Tacy-Prev-Gen", strconv.FormatUint(prev, 10))
	res, err := r.do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	res.Body.Close()
	switch res.StatusCode {
	case 200, 204:
		return nil
	case 409:
		return ErrConflict
	}
	return fmt.Errorf("sealstate: relay PUT %s: HTTP %d", name, res.StatusCode)
}
