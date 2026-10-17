package verifier

import (
	"strings"
	"testing"
)

const d = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestComposeImages(t *testing.T) {
	ok := "services:\n  a:\n    image: ghcr.io/tacyhq/tacy/agentd" + d + "\n  b:\n    image: localhost:5000/x/y-z" + d + "\nvolumes:\n  v:\n"
	images, err := ComposeImages(ok)
	if err != nil || len(images) != 2 || images["a"] != "ghcr.io/tacyhq/tacy/agentd"+d {
		t.Fatal(images, err)
	}
	// Anchors resolve to the same rule (a digest by alias is still a digest).
	if _, err := ComposeImages("x-img: &i ghcr.io/a/b" + d + "\nservices:\n  a:\n    image: *i\n"); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"tag":                "services:\n  a:\n    image: ghcr.io/a/b:v1\n",
		"tag and digest":     "services:\n  a:\n    image: ghcr.io/a/b:v1" + d + "\n",
		"no registry path":   "services:\n  a:\n    image: busybox" + d + "\n",
		"short digest":       "services:\n  a:\n    image: ghcr.io/a/b@sha256:0123\n",
		"upper-case digest":  "services:\n  a:\n    image: ghcr.io/a/b" + strings.ToUpper(d) + "\n",
		"other algorithm":    "services:\n  a:\n    image: ghcr.io/a/b@sha512:" + strings.Repeat("0", 128) + "\n",
		"variable":           "services:\n  a:\n    image: ghcr.io/a/b@sha256:${DIGEST}\n",
		"variable name":      "services:\n  a:\n    image: ${IMAGE}\n",
		"build":              "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n    build: .\n",
		"build only":         "services:\n  a:\n    build: .\n",
		"extends":            "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n    extends:\n      file: other.yaml\n      service: x\n",
		"include":            "include:\n  - other.yaml\nservices:\n  a:\n    image: ghcr.io/a/b" + d + "\n",
		"no services":        "volumes:\n  v:\n",
		"service not a map":  "services:\n  a: ghcr.io/a/b" + d + "\n",
		"image not a string": "services:\n  a:\n    image: [ghcr.io/a/b" + d + "]\n",
		"two documents":      "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n---\nservices:\n  b:\n    build: .\n",
		"duplicate key":      "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n    image: ghcr.io/a/b:v1\n",
		"merge key build":    "x-b: &b\n  build: .\nservices:\n  a:\n    <<: *b\n    image: ghcr.io/a/b" + d + "\n",
		"newline":            "services:\n  a:\n    image: \"ghcr.io/a/b" + d + "\\n\"\n",
		"not yaml":           "services: [\n",
	} {
		if _, err := ComposeImages(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
