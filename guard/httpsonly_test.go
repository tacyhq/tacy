package guard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// seenURLs is a RoundTripper that records each request's URL and answers 200, or a redirect for "/moved".
type seenURLs struct{ urls []string }

func (s *seenURLs) RoundTrip(r *http.Request) (*http.Response, error) {
	s.urls = append(s.urls, r.URL.String())
	res := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}
	if r.URL.Path == "/moved" {
		res.StatusCode = 302
		res.Header.Set("Location", "http://other.example/after")
	}
	return res, nil
}

// Every fetch goes over HTTPS (the keys plan §3.4, PX-4): http:// is upgraded to the same host on https://, a plain http
// address naming another port is refused, a redirect to http:// is upgraded too, and the dialer allows 443 only.
func TestHTTPSOnly(t *testing.T) {
	base := &seenURLs{}
	c := &http.Client{Transport: httpsOnly{base}}
	for _, c2 := range []struct{ in, want string }{
		{"http://example.com/a?b=1", "https://example.com/a?b=1"},
		{"http://example.com:80/a", "https://example.com/a"},
		{"https://example.com/x", "https://example.com/x"},
		{"https://example.com:8443/x", "https://example.com:8443/x"},
		{"http://[2606:4700::1]/v6", "https://[2606:4700::1]/v6"},
	} {
		base.urls = nil
		res, err := c.Get(c2.in)
		if err != nil {
			t.Fatalf("%s: %v", c2.in, err)
		}
		res.Body.Close()
		if len(base.urls) != 1 || base.urls[0] != c2.want {
			t.Fatalf("%s went out as %v, want %s", c2.in, base.urls, c2.want)
		}
		if res.Request.URL.String() != c2.want {
			t.Fatalf("%s: the page read is %s", c2.in, res.Request.URL)
		}
	}
	for _, bad := range []string{"http://example.com:8080/", "ftp://example.com/"} {
		base.urls = nil
		if _, err := c.Get(bad); err == nil || len(base.urls) != 0 {
			t.Fatalf("%s: sent (%v, %v)", bad, err, base.urls)
		}
	}
	// A redirect to http:// is upgraded like any request.
	base.urls = nil
	res, err := c.Get("https://example.com/moved")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if len(base.urls) != 2 || base.urls[1] != "https://other.example/after" {
		t.Fatalf("redirect went out as %v", base.urls)
	}
	// The release's dialer: 443 only, so nothing plain gets out even past the upgrade.
	if publicOnly("tcp", "93.184.215.14:80", nil) == nil {
		t.Fatal("port 80 allowed")
	}
	if err := publicOnly("tcp", "93.184.215.14:443", nil); err != nil {
		t.Fatalf("443 refused: %v", err)
	}
	// fetch_page with the release's fetcher: an http:// address on another port is refused, and says why.
	tools := &Tools{fetcher: newWebFetcher()}
	out, _ := tools.Run(context.Background(), "fetch_page", json.RawMessage(`{"url":"http://93.184.215.14:8080/page"}`))
	if !strings.Contains(out.content, "plain http not allowed") {
		t.Fatalf("got %s", out.content)
	}
	if errText(errPlainHTTP) != "plain http not allowed (https only)" {
		t.Fatal("errText")
	}
}
