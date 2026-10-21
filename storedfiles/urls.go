package storedfiles

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// A schedule's runs have no browser to mint read URLs: the schedule's definition carries a read grant the Worker made
// at install (the person's objects, its owner and an end date, HMAC'd by the Worker), and each run asks the Worker for
// URLs for the objects it is about to read, with that grant (POST /api/vm/files/read-urls). The Worker checks the
// grant, that each object is in it and still live, and mints an hour's GET for each. It learns, at run time, that a
// schedule holding this grant reads these objects now (it already knows their sizes and that the grant exists); it
// never gets a key. Nothing the model writes reaches this call: the guard makes it from the refs.

// ChatHost is the chat's origin: the only host a run asks for read URLs.
const ChatHost = "chat.tacy.io"

// URLsPath is the Worker's route for a schedule run's read URLs.
const URLsPath = "/api/vm/files/read-urls"

// URLSource gives read URLs for objects of the grant's owner.
type URLSource interface {
	URLs(ctx context.Context, grant string, owner string, objects []string) (map[string]string, error)
}

// WorkerURLs asks the chat's Worker (POST https://<Host>/api/vm/files/read-urls).
type WorkerURLs struct {
	Client *http.Client // nil: DefaultClient()
	Host   string       // "": ChatHost
	Scheme string       // "": https (tests: http)
}

// maxURLsAnswer bounds the Worker's answer: 200 URLs of at most 4 KiB.
const maxURLsAnswer = 1 << 20

func (w *WorkerURLs) URLs(ctx context.Context, grant, owner string, objects []string) (map[string]string, error) {
	if grant == "" || len(objects) == 0 || len(objects) > MaxRunFiles {
		return nil, errors.New("storedfiles: nothing to ask read URLs for")
	}
	body, _ := json.Marshal(map[string]any{"grant": grant, "objects": objects})
	u := url.URL{Scheme: cmpOr(w.Scheme, "https"), Host: cmpOr(w.Host, ChatHost), Path: URLsPath}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	client := w.Client
	if client == nil {
		client = DefaultClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("storedfiles: read URLs: %w", scrubURL(err))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxURLsAnswer+1))
	if err != nil || len(b) > maxURLsAnswer {
		return nil, errors.New("storedfiles: read URLs: bad answer")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(b, &e)
		if e.Error == "" || len(e.Error) > 64 {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return nil, fmt.Errorf("storedfiles: read URLs: %d %s", resp.StatusCode, e.Error)
	}
	var a struct {
		Owner   string            `json:"owner"`
		Expires int64             `json:"expires"`
		URLs    map[string]string `json:"urls"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, errors.New("storedfiles: read URLs: bad answer")
	}
	if a.Owner != owner {
		return nil, errors.New("storedfiles: read URLs: the grant is another storage's")
	}
	out := make(map[string]string, len(objects))
	for _, o := range objects {
		if a.URLs[o] == "" {
			return nil, errors.New("storedfiles: read URLs: an object is missing")
		}
		out[o] = a.URLs[o]
	}
	return out, nil
}
