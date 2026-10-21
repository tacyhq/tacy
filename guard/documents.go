package guard

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// Documents (agent feature 5, 2026-10-21; the chat's document cards): an agent run can put a
// document in its result, the way the plain chat's create_document does: "research X and give me a report as a
// .docx", a scheduled run whose result is a Word file. The action document.create is no egress and no effect: it
// sends nothing anywhere and changes nothing. Its arguments (a name, a format from a fixed list, Markdown or text
// content) are checked here and go only to the person's own conversation, inside the run's encrypted event stream
// (tool_call shows the content, tool_result the checked name and format), sealed with a scheduled run's result like
// the rest of it. The person's browser builds the file (Word, PDF, ...) when they download it; nothing is built here.
//
// What the model writes is untrusted (it may have read injected web text), and that is fine for the content: it is
// the person's report. The name and the format decide how the file is offered, so they can't mislead: the format is
// one of documentFormats (an alias like "Word" or ".docx" is mapped, anything else refused), and the name is cleaned
// as the chat cleans it (files.ts safeTitle): no path separators, control, hidden or bidi characters, no leading dots
// (a hidden file), no extension of its own (the format gives it), not a Windows device name, at most 80 characters.
// The chat cleans it again before it shows or saves anything.
//
// Class Read in the approval table (approval/class.go): nothing leaves, nothing changes, so no person approves it and
// no permission prompt asks about it; replay safe, and its result is no outside content (it doesn't taint the task).

const (
	// DocumentAction is the action; documentTool the tool name the model sees (harness.ModelToolName) and the
	// chat's events carry.
	DocumentAction = "document.create"
	documentTool   = "document_create"
	// MaxDocumentChars is the most content one document takes, in UTF-16 code units as the chat counts it
	// (files.ts MAX_FILE_CHARS: about 12,000 words).
	MaxDocumentChars = 50_000
	// maxDocumentName is a name's length in characters, before its extension (files.ts MAX_NAME_CHARS).
	maxDocumentName = 80
	// MaxDocuments caps the documents one task makes: each is up to ~100 KB in the event stream (and a scheduled
	// run's sealed result keeps at most 1 MiB).
	MaxDocuments = 3
	// DocumentCapDenied starts the refusal of a document past MaxDocuments.
	DocumentCapDenied = "document_cap"
	defaultDocName    = "document"
)

// documentFormats are the formats a document may have, as the chat offers them (files.ts FILE_FORMATS).
var documentFormats = []string{"docx", "pdf", "md", "txt", "csv", "html"}

// documentAliases: what a model writes for a format, lowercased and without a leading dot (files.ts ALIASES).
var documentAliases = map[string]string{
	"txt": "txt", "text": "txt", "plain": "txt", "plain text": "txt",
	"md": "md", "markdown": "md",
	"csv":  "csv",
	"html": "html", "htm": "html",
	"docx": "docx", "doc": "docx", "word": "docx",
	"pdf": "pdf",
}

func init() {
	toolDefs[documentTool] = def(documentTool,
		"Put a document in your result as a card the person can copy or download as a file (Word, PDF, Markdown, text, CSV or HTML; their browser builds it). "+
			"Use it only when the brief or instructions ask for a file, a document, a download or a format (\"as a Word doc\", \"a PDF report\", \"give me a CSV\"); otherwise answer in your message. "+
			"Make the document complete and ready to use: the whole report, not a summary of it. Write Markdown (# headings, - lists, 1. numbered lists, **bold**, | tables |) for docx, pdf and md; plain text for txt; a header row and rows for csv; a complete HTML document for html. "+
			"Cite sources inside it as [n] with the numbers the tool results gave, as in an answer (in a CSV or HTML table, put [n] where a source's link goes: Tacy writes its address there); don't write a list of sources or links: Tacy adds the sources list with their links. "+
			fmt.Sprintf("At most %d documents per task and %s characters each. ", MaxDocuments, "50,000")+
			"After the call, end with a short message (two or three sentences: what the document covers); don't repeat the document.",
		`{"type":"object","properties":{"name":{"type":"string","description":"the document's title, a few words, without an extension"},"format":{"type":"string","enum":["docx","pdf","md","txt","csv","html"],"description":"the format the person asked for; otherwise docx for a report or other prose, md for technical notes, csv for table data"},"content":{"type":"string","description":"the whole document"}},"required":["name","format","content"]}`)
}

// isDocumentAction: the action is the document connector's.
func isDocumentAction(action string) bool { return action == DocumentAction }

// IsDocumentAction is isDocumentAction for agentd.
func IsDocumentAction(action string) bool { return isDocumentAction(action) }

// DocumentFormat is the format a model's raw value names ("Word", ".docx", "PDF"), or "" for none of documentFormats.
func DocumentFormat(raw string) string {
	return documentAliases[strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), ".")]
}

var (
	// unsafeNameRe: characters a file name can't have on some system (path separators, Windows' reserved ones).
	unsafeNameRe = regexp.MustCompile(`[/\\:*?"<>|]`)
	spacesRe     = regexp.MustCompile(`\s+`)
	// knownExtRe: an extension the model added (the format gives the real one), a document's or one a name could use to
	// pass for a program or an archive ("report.exe" would download as "report.exe.docx").
	knownExtRe     = regexp.MustCompile(`(?i)\.(docx|pdf|md|txt|csv|html|doc|htm|markdown|text|rtf|odt|xlsx?|pptx?|docm|xlsm|pptm|exe|bat|cmd|com|scr|msi|ps1|sh|js|vbs|jar|app|dmg|pkg|lnk|apk|zip|iso)$`)
	windowsDevRe   = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])$`)
	edgeDotSpaceRe = regexp.MustCompile(`^[.\s]+|[.\s]+$`)
)

// hiddenRune: a format character (bidi overrides and isolates, zero-width ones, the BOM) or a tag character: with
// control characters, what HiddenChars refuses in a value that goes out.
func hiddenRune(r rune) bool {
	return unicode.Is(unicode.Cf, r) || r >= 0xE0000 && r <= 0xE007F
}

// DocumentName is a safe title to name files by (files.ts safeTitle): NFC; hidden characters removed; control
// characters, path separators and Windows' reserved characters as spaces; spaces collapsed; up to two extensions the
// model added dropped ("memo.pdf" is "memo"); no leading or trailing dots and spaces; at most maxDocumentName
// characters; a Windows device name gets "-file"; nothing left: "document".
func DocumentName(raw string) string {
	s := strings.ToValidUTF8(raw, "")
	s = norm.NFC.String(s)
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) {
			return ' '
		}
		if hiddenRune(r) {
			return -1
		}
		return r
	}, s)
	s = unsafeNameRe.ReplaceAllString(s, " ")
	s = strings.TrimSpace(spacesRe.ReplaceAllString(s, " "))
	for i := 0; i < 2 && knownExtRe.MatchString(s); i++ {
		s = strings.TrimSpace(knownExtRe.ReplaceAllString(s, ""))
	}
	s = edgeDotSpaceRe.ReplaceAllString(s, "")
	if r := []rune(s); len(r) > maxDocumentName {
		s = edgeDotSpaceRe.ReplaceAllString(string(r[:maxDocumentName]), "")
	}
	if s == "" {
		s = defaultDocName
	}
	if windowsDevRe.MatchString(s) {
		s += "-file"
	}
	return s
}

// utf16Len is s's length as JavaScript counts it (the chat's cap is a string's length).
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// documentArgs are document.create's arguments as the model sends them.
type documentArgs struct {
	Name    *string `json:"name"`
	Format  *string `json:"format"`
	Content *string `json:"content"`
}

// documentMade is the result the model and the person's events get for a document made: the checked name and
// format (the content stays in the call's arguments, shown once), its length, and what to do next.
type documentMade struct {
	Status string `json:"status"`
	Name   string `json:"name"`
	Format string `json:"format"`
	Chars  int    `json:"chars"`
	Note   string `json:"note"`
}

const documentMadeNote = "The document card is shown to the person with Copy and Download. Don't repeat the document: end with a short message (two or three sentences: what it covers, and anything they should check)."

// CheckDocument checks document.create's arguments: the made result (name cleaned, format from the list), or why
// it can't be made (an error the model sees, in plain words). Pure.
func CheckDocument(raw []byte) (documentMade, string) {
	var a documentArgs
	if len(raw) == 0 || json.Unmarshal(raw, &a) != nil {
		return documentMade{}, `document_create takes {"name": "…", "format": "docx", "content": "…"}`
	}
	format := ""
	if a.Format != nil {
		format = DocumentFormat(*a.Format)
	}
	if format == "" {
		got := ""
		if a.Format != nil && *a.Format != "" {
			got = fmt.Sprintf(" (not %q)", capRunes(*a.Format, 20))
		}
		return documentMade{}, "format must be one of " + strings.Join(documentFormats, ", ") + got
	}
	if a.Content == nil || strings.TrimSpace(*a.Content) == "" {
		return documentMade{}, "the document has no content"
	}
	if !utf8.ValidString(*a.Content) {
		return documentMade{}, "the document's content isn't valid text"
	}
	n := utf16Len(*a.Content)
	if n > MaxDocumentChars {
		return documentMade{}, fmt.Sprintf("the document would be %d characters, over the %d that fit in one, so it wasn't made: make it shorter, or split it into parts (at most %d documents)", n, MaxDocumentChars, MaxDocuments)
	}
	name := ""
	if a.Name != nil {
		name = *a.Name
	}
	return documentMade{Status: "created", Name: DocumentName(name), Format: format, Chars: n, Note: documentMadeNote}, ""
}

// documentAction runs document.create: checked against the space's policy, the task's cap on documents and its
// arguments, then shown to the person (tool_result under the model's call, whose tool_call event carried the
// content). Nothing is sent or stored anywhere else; the task isn't tainted by it (Untrusted: no) and it isn't
// held for approval or a prompt (approval class Read, no permission kind).
func (g *Guard) documentAction(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	t := g.task(ti)
	if err := g.checkSafety(t.opts.Space, req); err != nil {
		if d, ok := deniedResult(err); ok {
			return d, nil
		}
		return nil, err
	}
	args := json.RawMessage(req.Args)
	if !json.Valid(args) {
		args = json.RawMessage(`{}`)
	}
	call := t.claim(req.Call, id, documentTool, jsontext.Value(args))
	made, problem := CheckDocument(req.Args)
	if problem == "" {
		t.mu.Lock()
		if t.sent == nil {
			t.sent = map[string]int{}
		}
		if t.sent[DocumentAction] >= MaxDocuments {
			problem = fmt.Sprintf("%s: this task has made its %d documents, so no more is made. Don't call %s again: put anything else in your message.", DocumentCapDenied, MaxDocuments, documentTool)
		} else {
			t.sent[DocumentAction]++
		}
		t.mu.Unlock()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var out string
	if problem != "" {
		out = errorJSON(problem)
	} else {
		b, _ := json.Marshal(made)
		out = string(b)
	}
	// No Args: the content is in the tool_call event already (once is enough in a 1 MiB sealed result); the chat
	// takes the name and format from this result.
	t.emit(proto.Event{Type: "tool_result", ID: call, Name: documentTool, Result: json.RawMessage(out)})
	if problem != "" {
		return &harness.ActionResult{Status: harness.ActionFailed, Error: problem}, nil
	}
	return &harness.ActionResult{Status: harness.ActionDone, Output: jsontext.Value(out)}, nil
}
