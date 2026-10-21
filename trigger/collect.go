package trigger

// Orphaned schedules stop themselves (decided 2026-10-21). A schedule's results wait on the VM until the person's
// browser collects them (it fetches each, saves it in the schedule's conversation, then deletes it). A schedule whose
// results nobody collects for MaxUncollected runs in a row (an account nobody opens any more, a browser that can't
// sign) stops itself when its next run is due: the VM decides alone, from its own side file, with no network call.
// A live account collects and deletes each result, so the count goes back to 0 every time. The count is read before a
// run fires; when it can't be read, the run doesn't fire (fail closed). The chat shows the state ("stopped: results not
// collected") with a Resume, which installs the next version: that starts the count again.

// MaxUncollected is how many runs in a row may leave a result nobody collected before the schedule stops itself.
const MaxUncollected = 7

// StopUncollected is the stop reason the list gives a schedule stopped for its results going uncollected.
const StopUncollected = "uncollected"

// CollectStore keeps, per schedule (agent), how many of its runs in a row stored a result the person hasn't
// collected, and the version stopped for that. The ResultStore that implements it counts as results come and go:
// PutResult adds one for its agent, DeleteResults (the person's delete) sets the agents of the rows it deleted back to
// 0, DeleteAgentResults (a removal) forgets the agent. PruneResults (results past their keep) changes nothing: those
// weren't collected either.
type CollectStore interface {
	// Uncollected is how many of agent's runs in a row stored a result nobody collected since.
	Uncollected(agent string) (int, error)
	// SetStoppedUncollected records that agent was stopped at version for its results going uncollected.
	SetStoppedUncollected(agent string, version uint64) error
	// StoppedUncollected reports whether agent was stopped at version for that.
	StoppedUncollected(agent string, version uint64) (bool, error)
	// ResetCollect starts agent's count again and clears its stop reason (a new version was installed).
	ResetCollect(agent string) error
}
