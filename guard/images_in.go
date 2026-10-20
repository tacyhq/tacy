package guard

// The person's own images (proto.Message.Images, releases since v0.12.0): "where can I buy this?" with a photo.
//
// They are the person's input, so they are trusted like their words, and they go to one place only: the run's
// model, when it can see images. They travel in the task's options (TaskOptions.Images), never in its start: the
// brain (in its sandbox) proposes model calls with text messages, and the gateway puts the images on the person's
// message as it builds each model request (withImages). So no action the brain proposes can carry them: a search,
// a page fetch and an image search get only their own arguments, and those are checked once more here
// (imageInArgs: a data URL or a piece of an image's data refuses the action before anything is sent). Search
// queries the model writes after seeing an image (a product name it read on a label) are ordinary queries and
// go through the same masking as any other. The activity record says how many images a run got and their size,
// never their content (app/activity.go). The quarantined reader never gets them: it reads pages, not the
// conversation.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// PersonImage is one of the person's images as a task keeps it: the user message it came with (its place among the
// input's user messages, and its text's SHA-256, so a model request gets it on that message only) and the data URL.
type PersonImage struct {
	User  int    `json:"user"`  // 0 for the input's first user message
	Hash  string `json:"hash"`  // hex SHA-256 of that message's content
	URL   string `json:"url"`   // "data:image/jpeg;base64,..."
	Bytes int    `json:"bytes"` // the JPEG's size (for the activity record)
}

// visionModels are the models that see images (Tinfoil's "multimodal": true, as the chat's imageTokens).
var visionModels = map[string]bool{"gemma4-31b": true, "kimi-k3": true, "deepseek-v4-1-flash": true}

// SeesImages says whether model can see images.
func SeesImages(model string) bool { return visionModels[model] }

// checkImage checks one image as a run request carries it and returns its JPEG's size: a JPEG data URL, strict
// standard base64, at most proto.MaxImageBytes, starting with a JPEG's first bytes.
func checkImage(u string) (int, error) {
	b64, ok := strings.CutPrefix(u, proto.ImageURLPrefix)
	if !ok {
		return 0, fmt.Errorf("an image must be a JPEG data URL")
	}
	if len(b64) > base64.StdEncoding.EncodedLen(proto.MaxImageBytes) {
		return 0, fmt.Errorf("an image is larger than %d KiB", proto.MaxImageBytes>>10)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return 0, fmt.Errorf("an image isn't valid base64")
	}
	if len(b) > proto.MaxImageBytes {
		return 0, fmt.Errorf("an image is larger than %d KiB", proto.MaxImageBytes>>10)
	}
	if len(b) < 4 || b[0] != 0xff || b[1] != 0xd8 || b[2] != 0xff {
		return 0, fmt.Errorf("an image isn't a JPEG")
	}
	return len(b), nil
}

// runImages checks a run request's images (only on user messages; at most proto.MaxRunImages; each one checkImage)
// and returns them as the task keeps them.
func runImages(ms []proto.Message) ([]PersonImage, error) {
	var out []PersonImage
	user := -1
	for _, m := range ms {
		if m.Role == "user" {
			user++
		}
		if len(m.Images) == 0 {
			continue
		}
		if m.Role != "user" {
			return nil, fmt.Errorf("images go only on the person's messages")
		}
		for _, u := range m.Images {
			if len(out) == proto.MaxRunImages {
				return nil, fmt.Errorf("a run takes at most %d images", proto.MaxRunImages)
			}
			n, err := checkImage(u)
			if err != nil {
				return nil, err
			}
			out = append(out, PersonImage{User: user, Hash: contentHash(m.Content), URL: u, Bytes: n})
		}
	}
	return out, nil
}

func contentHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// imageNote stands in for images on the person's message when the model can't see them: the model says so.
func imageNote(n int) string {
	what := "an image"
	if n > 1 {
		what = strconv.Itoa(n) + " images"
	}
	return "[The person attached " + what + " here, but this model can't see images. If the question depends on it, say plainly that you couldn't see the image.]"
}

// withImages puts the person's images on their messages in a model request's messages (out, toModel's from ms): as
// image_url parts before the text for a model that sees images, else as a note. Only the input's user message each
// came with gets it (its place among the user messages and its text must both match).
func withImages(out []map[string]any, ms []harness.Message, imgs []PersonImage, vision bool) {
	if len(imgs) == 0 {
		return
	}
	user := -1
	for i, m := range ms {
		if m.Role != "user" {
			continue
		}
		user++
		var mine []PersonImage
		for _, im := range imgs {
			if im.User == user {
				mine = append(mine, im)
			}
		}
		if len(mine) == 0 || mine[0].Hash != contentHash(m.Content) {
			continue
		}
		if !vision {
			out[i]["content"] = imageNote(len(mine)) + "\n" + m.Content
			continue
		}
		parts := make([]map[string]any, 0, len(mine)+1)
		for _, im := range mine {
			parts = append(parts, map[string]any{"type": "image_url", "image_url": map[string]any{"url": im.URL}})
		}
		if m.Content != "" {
			parts = append(parts, map[string]any{"type": "text", "text": m.Content})
		}
		out[i]["content"] = parts
	}
}

// imageSample is how much of an image's base64 one piece is (imageInArgs); pieces come from past the JPEG header,
// which many JPEGs share.
const imageSample = 40

// imageInArgs says whether an action's arguments carry an image: a data URL or base64 marker anywhere, or a piece
// of one of the person's images, in the arguments' JSON strings as they are and percent-decoded. Nothing the brain
// proposes should ever carry one (it never gets them); this refuses the action if one does.
func imageInArgs(args []byte, imgs []PersonImage) bool {
	var v any
	if json.Unmarshal(args, &v) != nil {
		v = string(args)
	}
	var texts []string
	var walk func(any)
	walk = func(x any) {
		switch y := x.(type) {
		case string:
			texts = append(texts, y)
			if d, err := url.QueryUnescape(y); err == nil && d != y {
				texts = append(texts, d)
			}
		case []any:
			for _, e := range y {
				walk(e)
			}
		case map[string]any:
			for k, e := range y {
				walk(k)
				walk(e)
			}
		}
	}
	walk(v)
	for _, s := range texts {
		l := strings.ToLower(s)
		if strings.Contains(l, "data:image") || strings.Contains(l, ";base64,") {
			return true
		}
		for _, im := range imgs {
			b64 := strings.TrimPrefix(im.URL, proto.ImageURLPrefix)
			for _, at := range []int{len(b64) / 3, len(b64) / 2, 2 * len(b64) / 3} {
				if at+imageSample <= len(b64) && strings.Contains(s, b64[at:at+imageSample]) {
					return true
				}
			}
		}
	}
	return false
}

// imageRefused is the outcome of an action whose arguments carry an image: nothing is sent.
func imageRefused() toolOutcome {
	o := errorOutcome("refused: the arguments contain the person's image, which never leaves Tacy's sealed hardware except to the model, so nothing was sent")
	o.ran, o.failed = true, "refused"
	return o
}
