package verifier

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// digestRef is the only image reference a service may have: a full repository name (registry and at least one
// path component), then @sha256: and 64 hex digits. No tag (a tag can be moved; a digest names exactly one image),
// no variable (compose would interpolate it from the deployer's env).
var digestRef = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+@sha256:[0-9a-f]{64}$`)

// ComposeImages checks the docker compose a VM runs pins every container to an image digest, so the attested
// compose hash covers exactly the code that runs: one YAML document; every service has an image that is
// name@sha256:<64 hex> with no tag; no service has build: (code built on the VM from a context the hash doesn't
// cover) or extends:, and there is no top-level include: (both pull in another file). It returns each service's
// image.
func ComposeImages(compose string) (map[string]string, error) {
	dec := yaml.NewDecoder(strings.NewReader(compose))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	var more any
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return nil, errors.New("docker compose has more than one YAML document")
	}
	if _, ok := doc["include"]; ok {
		return nil, errors.New("docker compose has include: (another file's services)")
	}
	services, ok := doc["services"].(map[string]any)
	if !ok || len(services) == 0 {
		return nil, errors.New("docker compose has no services")
	}
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	images := map[string]string{}
	for _, n := range names {
		svc, ok := services[n].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("service %s isn't a mapping", n)
		}
		for _, k := range []string{"build", "extends"} {
			if _, ok := svc[k]; ok {
				return nil, fmt.Errorf("service %s has %s: (code the compose hash doesn't cover)", n, k)
			}
		}
		img, ok := svc["image"].(string)
		if !ok {
			return nil, fmt.Errorf("service %s has no image", n)
		}
		if !digestRef.MatchString(img) {
			return nil, fmt.Errorf("service %s's image %q isn't name@sha256:<digest> without a tag", n, img)
		}
		images[n] = img
	}
	return images, nil
}

// ImagesCheck is the name of the check ComposeImages backs (the last one).
const ImagesCheck = "docker compose pins every image by digest (no tag, no build, extends or include)"

// checkImages runs ComposeImages on the attested compose, records each service's image as the fact
// "image <service>", and adds the check.
func (r *Result) checkImages(compose string) bool {
	images, err := ComposeImages(compose)
	for svc, img := range images {
		r.Facts["image "+svc] = img
	}
	detail := ""
	if err == nil {
		detail = fmt.Sprintf("%d services, each name@sha256", len(images))
	}
	return r.add(ImagesCheck, err, detail)
}
