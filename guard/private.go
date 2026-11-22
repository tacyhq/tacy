package guard

import (
	"encoding/json/v2"
	"regexp"
	"strings"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// Private content (privacy review 2026-11-20, #7): attachment text, a person's mail and a person's files are
// outside content like fetched pages (they can carry an injection), and more: what the model writes after reading
// them may carry their facts out in a search query. In code, not only in the prompt:
//
//   - a task whose input carries an attachment (the client's <attachment name="..."> blocks: attachment-text.ts
//     formatForModel) is tainted from its start (StartTaint "attachment"), so a page address the model composes is
//     refused as on any tainted task (ComposedFetch), on the first turn too;
//   - addresses inside an attachment aren't the person's own (personLinks skips attachment blocks): only what the
//     person typed counts as "from the person";
//   - a search or page read whose arguments carry a passage of an attachment is refused before anything is sent,
//     as one carrying a passage of the person's files already is (files_guard.go): attachmentTextInArgs;
//   - once the person's mail reached a task (a done mail search or read), each web search goes out only on the
//     person's approval of that exact query: Always allow and an earlier "always" in the run don't cover it, and a
//     run that can't ask (a schedule) sends none (PrivateSearch: agentd's Hold asks, gatewayd's permit takes only a
//     grant for that one request). Mail facts are short (a name, an amount, a date): a passage check can't see
//     them, so a person decides. Files and attachments keep the passage check, so research with files still
//     searches in the model's own words without a question each time.
//
// A person who types the marker themselves only taints their own task: the rules only ever take more care.

// attachmentMarker opens an attachment block in a user message.
const attachmentMarker = `<attachment name="`

// attachmentBlockRe is one attachment block (formatForModel escapes "</attachment>" inside the text, so the first
// one closes it).
var attachmentBlockRe = regexp.MustCompile(`(?s)<attachment name="[^"]*">.*?</attachment>`)

// hasAttachment: a user message of ms carries an attachment block.
func hasAttachment[M proto.Message | harness.Message](ms []M) bool {
	for _, m := range ms {
		role, content := roleContent(m)
		if role == "user" && strings.Contains(content, attachmentMarker) {
			return true
		}
	}
	return false
}

func roleContent[M proto.Message | harness.Message](m M) (string, string) {
	switch v := any(m).(type) {
	case proto.Message:
		return v.Role, v.Content
	case harness.Message:
		return v.Role, v.Content
	}
	return "", ""
}

// withoutAttachments is a user message's text with its attachment blocks taken out (an unclosed one: everything
// from its start).
func withoutAttachments(s string) string {
	s = attachmentBlockRe.ReplaceAllString(s, " ")
	if i := strings.Index(s, attachmentMarker); i >= 0 {
		s = s[:i]
	}
	return s
}

// MailTask: the person's mail reached the task (a done mail action in its journal). Fails closed (a journal that
// can't be read counts).
func MailTask(ti *harness.TaskInfo) bool {
	if ti == nil || ti.Journal == nil {
		return false
	}
	recs, err := ti.Journal()
	if err != nil {
		return true
	}
	for _, r := range recs {
		if r.Kind != harness.TypeAction || !r.Done {
			continue
		}
		var req harness.Action
		var res harness.ActionResult
		if json.Unmarshal(r.Req, &req) != nil || json.Unmarshal(r.Body, &res) != nil {
			continue
		}
		if res.Status == harness.ActionDone && isMailAction(req.Name) {
			return true
		}
	}
	return false
}

// PrivateSearch: a web or image search on a task the person's mail reached: it goes out only on the person's
// approval of that one query (an image search's query carries the model's words as much as a web search's).
func PrivateSearch(kind string, ti *harness.TaskInfo) bool {
	return (kind == "web.search" || kind == "web.images") && MailTask(ti)
}

// attachmentTextInArgs: an action's arguments carry a passage (fileShingle words) of an attachment in the task's
// input.
func attachmentTextInArgs(ti *harness.TaskInfo, args []byte) bool {
	if ti == nil || ti.Start == nil || !hasAttachment(ti.Start.Input) {
		return false
	}
	set := map[uint64]bool{}
	for _, m := range ti.Start.Input {
		if m.Role != "user" {
			continue
		}
		for _, blk := range attachmentBlockRe.FindAllString(m.Content, -1) {
			ws := fileWords(blk)
			for i := 0; i+fileShingle <= len(ws); i++ {
				set[shingleHash(ws[i:i+fileShingle])] = true
			}
		}
	}
	for _, a := range argStrings(args) {
		ws := fileWords(a)
		for i := 0; i+fileShingle <= len(ws); i++ {
			if set[shingleHash(ws[i:i+fileShingle])] {
				return true
			}
		}
	}
	return false
}
