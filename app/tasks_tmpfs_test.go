package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/queue"
)

// The task queue in a host tmpfs (V1-DESIGN §6.2): agentd's -tasks-dir, through agentState.useTasksQueue as main.go
// calls it. The tests' directory isn't a tmpfs, so they say it is (Tmpfs.IsMemory) and give the kernel's boot id.

// tasksQueueAt is the queue agentd opens with -tasks-dir dir in kernel boot kernel, and its boot.
func tasksQueueAt(t *testing.T, dir, kernel string) (harness.Store, string) {
	t.Helper()
	k := newAgentState()
	err := k.useTasksQueue(queue.Tmpfs{Dir: dir, IsMemory: func(string) (bool, error) { return true, nil },
		BootID: func() (string, error) { return kernel, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := k.queue.(interface{ Close() error }); ok {
		t.Cleanup(func() { c.Close() })
	}
	return k.queue, k.queueBoot
}

// tasksDir is a directory as setup makes it for agentd: its uid's, 0700.
func tasksDir(t *testing.T) string {
	dir := filepath.Join(t.TempDir(), "tacy-tasks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// dstack's watchdog restarts agentd's container mid-task (no reboot): the new process opens the same tmpfs queue,
// takes the task up and finishes it once; the search that ran before the restart doesn't run again, and the
// task's boot is the same on both sides.
func TestTasksSurviveContainerRestart(t *testing.T) {
	dir := tasksDir(t)
	fs := &fakeSearch{}
	m := newStepModel(t, pCalls([3]string{"c1", "web_search", `{"query":"dstack release"}`}), "block", pText("v0.6.1 [1]."))
	q1, boot1 := tasksQueueAt(t, dir, "kernel-boot-1")
	p1 := bootTasksOn(t, q1, boot1, m, fs, false)
	c1 := p1.conn(t, tasksUser)
	tk, err := c1.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("latest dstack?")}, "k1")
	if err != nil {
		t.Fatalf("start: %+v %v", tk, err)
	}
	if tk.Boot != boot1 || c1.TaskBoot(tk.Task) != boot1 {
		t.Fatalf("the start's boot %q (the connection keeps %q), want %q", tk.Boot, c1.TaskBoot(tk.Task), boot1)
	}
	waitCalls(t, m, 2) // the search ran; the second model call is streaming when the container stops
	p1.kill()

	q2, boot2 := tasksQueueAt(t, dir, "kernel-boot-1")
	if boot2 != boot1 {
		t.Fatalf("after a container restart the queue's boot is %q, want %q (the same queue)", boot2, boot1)
	}
	p2 := bootTasksOn(t, q2, boot2, m, fs, false)
	c2 := p2.conn(t, tasksUser)
	c2.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task))
	c2.SetTaskBoot(tk.Task, c1.TaskBoot(tk.Task))
	evs := followAll(t, c2, tk.Task, 0)
	contiguous(t, evs, 1)
	text, done := "", 0
	for _, e := range evs {
		text += e.ev.Delta
		if e.ev.Type == "done" {
			done++
		}
	}
	if done != 1 || !strings.HasSuffix(text, "v0.6.1 [1].") {
		t.Fatalf("after the restart: %d done events, text %q (%s)", done, text, evTypes(evs))
	}
	st := waitTask(t, c2, tk.Task, func(s *agentclient.Task) bool { return s.State == harness.StateDone })
	if st.Outcome != harness.OutcomeSucceeded || st.Attempt != 2 || st.Boot != boot1 {
		t.Fatalf("status %+v", st)
	}
	fs.mu.Lock()
	searches := len(fs.queries)
	fs.mu.Unlock()
	if searches != 1 || m.calls.Load() != 3 {
		t.Fatalf("searches %d (want 1: never twice), model calls %d (want 3: the cut one ran again)", searches, m.calls.Load())
	}
	// A retried start with the same key finds the same task: nothing new runs.
	again, err := c2.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("latest dstack?")}, "k1")
	if err != nil || again.Task != tk.Task || !again.Existing {
		t.Fatalf("the same key after the restart: %+v %v", again, err)
	}
}

// The directory must be memory and agentd's alone: agentd refuses to keep tasks anywhere else, and writes nothing
// there first.
func TestQueueRefusesNonTmpfs(t *testing.T) {
	notMem := func(string) (bool, error) { return false, nil }
	boot := func() (string, error) { return "kernel-boot-1", nil }
	dir := tasksDir(t)
	k := newAgentState()
	mem, memBoot := k.queue, k.queueBoot
	err := k.useTasksQueue(queue.Tmpfs{Dir: dir, IsMemory: notMem, BootID: boot})
	if !errors.Is(err, queue.ErrNotMemory) {
		t.Fatalf("a directory that isn't tmpfs: %v", err)
	}
	if k.queue != mem || k.queueBoot != memBoot {
		t.Fatal("a refused directory replaced the queue")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("a refused directory has %d files", len(ents))
	}
	if runtime.GOOS != "linux" { // the default check (statfs) on a directory that isn't tmpfs
		if err := k.useTasksQueue(queue.Tmpfs{Dir: dir, BootID: boot}); !errors.Is(err, queue.ErrNotMemory) {
			t.Fatalf("the default check: %v", err)
		}
	}
	isMem := func(string) (bool, error) { return true, nil }
	open := filepath.Join(t.TempDir(), "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o750)
	if err := k.useTasksQueue(queue.Tmpfs{Dir: open, IsMemory: isMem, BootID: boot}); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("a directory another user can read: %v", err)
	}
	if err := k.useTasksQueue(queue.Tmpfs{Dir: filepath.Join(dir, "missing"), IsMemory: isMem, BootID: boot}); err == nil {
		t.Fatal("a directory setup didn't make")
	}
	if err := k.useTasksQueue(queue.Tmpfs{IsMemory: isMem, BootID: boot}); err == nil {
		t.Fatal("no directory")
	}
}

// A real boot: the tmpfs queue is gone (here: the marker names another kernel boot, so the queue is deleted). A
// status call for a task the old boot had answers task_unknown_after_restart with the new boot, nothing runs it
// again, and a caller who doesn't name the old boot gets no_such_task as before.
func TestTaskUnknownAfterReboot(t *testing.T) {
	dir := tasksDir(t)
	fs := &fakeSearch{}
	m := newStepModel(t, "block")
	q1, boot1 := tasksQueueAt(t, dir, "kernel-boot-1")
	p1 := bootTasksOn(t, q1, boot1, m, fs, false)
	c1 := p1.conn(t, tasksUser)
	tk, err := c1.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hello")}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	waitCalls(t, m, 1)
	p1.kill()

	q2, boot2 := tasksQueueAt(t, dir, "kernel-boot-2")
	if boot2 == boot1 || boot2 == "" {
		t.Fatalf("after a reboot the queue's boot is %q (was %q)", boot2, boot1)
	}
	if open, err := q2.OpenTasks(); err != nil || len(open) != 0 {
		t.Fatalf("the new boot's queue has %d open tasks (%v)", len(open), err)
	}
	p2 := bootTasksOn(t, q2, boot2, m, fs, false)
	c2 := p2.conn(t, tasksUser)
	c2.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task))
	c2.SetTaskBoot(tk.Task, boot1)
	_, err = c2.TaskStatus(context.Background(), tk.Task)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), `"error":"task_unknown_after_restart"`) ||
		!strings.Contains(err.Error(), `"boot":"`+boot2+`"`) {
		t.Fatalf("status of a task the old boot had: %v", err)
	}
	if err := c2.FollowTask(context.Background(), tk.Task, 0, func(int, proto.Event) {}); err == nil ||
		!strings.Contains(err.Error(), "task_unknown_after_restart") {
		t.Fatalf("events of a task the old boot had: %v", err)
	}
	// Without the old boot (an older client), or naming this boot: the old answer.
	c3 := p2.conn(t, tasksUser)
	c3.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task))
	if _, err := c3.TaskStatus(context.Background(), tk.Task); err == nil || !strings.Contains(err.Error(), "no_such_task") {
		t.Fatalf("without a boot: %v", err)
	}
	c3.SetTaskBoot(tk.Task, boot2)
	if _, err := c3.TaskStatus(context.Background(), tk.Task); err == nil || !strings.Contains(err.Error(), "no_such_task") {
		t.Fatalf("with this boot: %v", err)
	}
	// Never an automatic re-run: the new process made no model call and has no task.
	time.Sleep(200 * time.Millisecond)
	if n := m.calls.Load(); n != 1 {
		t.Fatalf("model calls after the reboot: %d, want 1", n)
	}
	if open, _ := q2.OpenTasks(); len(open) != 0 {
		t.Fatalf("the new boot runs %d tasks", len(open))
	}
	// A queue only in memory gets a new boot with each process.
	if a, b := newAgentState().queueBoot, newAgentState().queueBoot; a == b || !strings.HasPrefix(a, "qb_") {
		t.Fatalf("memory queues' boots %q %q", a, b)
	}
}

// Review 2, M3: rollback then roll forward in one kernel boot. A release without -tasks-dir ran in between (nothing
// beat the queue's heartbeat for longer than a container restart takes), so the person may have asked again; the
// next agentd with -tasks-dir doesn't resume the old task: the queue is wiped with a new boot, the task's status
// answers task_unknown_after_restart, and no model call runs for it.
func TestStaleQueueNotResumedAfterRollForward(t *testing.T) {
	dir := tasksDir(t)
	fs := &fakeSearch{}
	m := newStepModel(t, "block")
	q1, boot1 := tasksQueueAt(t, dir, "kernel-boot-1")
	p1 := bootTasksOn(t, q1, boot1, m, fs, false)
	c1 := p1.conn(t, tasksUser)
	tk, err := c1.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hello")}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	waitCalls(t, m, 1)
	p1.kill() // the rollback: this agentd stops, an older release (no -tasks-dir) serves for a while

	// The roll forward, the same kernel boot, an hour later.
	k := newAgentState()
	later := time.Now().Add(time.Hour)
	err = k.useTasksQueue(queue.Tmpfs{Dir: dir, IsMemory: func(string) (bool, error) { return true, nil },
		BootID: func() (string, error) { return "kernel-boot-1", nil }, Started: later, Now: func() time.Time { return later }})
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := k.queue.(interface{ Close() error }); ok {
		t.Cleanup(func() { c.Close() })
	}
	if k.queueBoot == boot1 {
		t.Fatalf("the roll forward took the stale queue up (boot %q)", boot1)
	}
	p2 := bootTasksOn(t, k.queue, k.queueBoot, m, fs, false)
	c2 := p2.conn(t, tasksUser)
	c2.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task))
	c2.SetTaskBoot(tk.Task, boot1)
	if _, err := c2.TaskStatus(context.Background(), tk.Task); err == nil || !strings.Contains(err.Error(), `"error":"task_unknown_after_restart"`) {
		t.Fatalf("status of the stale task: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := m.calls.Load(); n != 1 {
		t.Fatalf("model calls after the roll forward: %d, want 1 (the stale task never resumed)", n)
	}
}
