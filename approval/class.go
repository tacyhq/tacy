// Package approval is approve before send (docs/27 section 4): which actions need a
// person's approval, the exact effect an approval binds (canonical JSON and its hash), the approval payload a
// person's passkey signs, the WebAuthn check in Go, the passkey certificates that tie a passkey to an identity,
// and the record of each held approval and its effect (held → approved → sending → sent | failed | unknown).
//
// The rule it keeps: the model only proposes. Nothing here asks a model anything; every check is plain code over
// signatures, hashes and lists, and agentd and gatewayd each run it themselves (Check). Standard library only.
package approval

// Class is what an action does, set per connector action in the release (never by a model or a policy): it
// decides whether a person must approve each one (docs/27 section 4).
type Class string

const (
	// Read: reads inside the space (files.read, task.wait). No approval.
	Read Class = "read"
	// ReadOut: a read that sends data out (web.search, web.fetch, mail.list). A permission, not approval.
	ReadOut Class = "read_out"
	// Change: a change inside the policy's scopes (mail.move, mail.draft). Approval when the task is tainted or the
	// policy lists it.
	Change Class = "change"
	// Send: sends or shares (mail.send, files.share, anything that publishes, deletes outside the space or pays).
	// Approval always, per action; no Always allow, no policy can remove it.
	Send Class = "send"
)

// classes is the release's table. sink.* is the test-only connector that proves the flow (guard/sink.go); it isn't
// in the production release ceiling (safety.ChatRelease), so a production policy can't allow it.
var classes = map[string]Class{
	"web.search": ReadOut,
	"web.fetch":  ReadOut,
	"web.images": ReadOut,
	// The person's attached files of a review or research task, read inside the VM (v0.13.0, guard/files.go):
	// nothing leaves, nothing changes.
	"files.list": Read,
	"files.read": Read,
	// Fetching the person's stored files' ciphertext for such a task (branch files-vm-read, guard/stored.go): a GET of
	// objects the person named, decrypted in the VM; nothing of theirs leaves, nothing changes.
	"files.fetch": Read,
	// A notify-changes schedule's "nothing changed" (guard/schedule.go): answered in the VM; it only marks the run's
	// own result quiet.
	"schedule.no_change": Read,
	// A document for the person's own conversation (guard/documents.go, agent feature 5): its content goes only into
	// the run's encrypted result; nothing leaves, nothing changes. Missing here it would be a Send, and every document
	// would wait for an approval nobody can give on a personal space (the v0.13.0 lesson; approval_test.go).
	"document.create": Read,
	"sink.post":       Send,
	"sink.put":        Change,
	"task.spawn":      Read,
	"task.wait":       Read,
	"person.ask":      Read,
}

// ClassOf is an action's class. An action the release doesn't know is a Send: unknown means it may send (fail
// closed).
func ClassOf(action string) Class {
	if c, ok := classes[action]; ok {
		return c
	}
	return Send
}

// Needs reports whether an action of class c needs a person's approval: a send always; a change when the task was
// tainted when the action was proposed (it had received outside content, docs/27 section 5) or the policy lists it
// (approve: [...]); anything else only when the policy lists it.
func Needs(c Class, tainted, listed bool) bool {
	switch c {
	case Send:
		return true
	case Change:
		return tainted || listed
	default:
		return listed
	}
}
