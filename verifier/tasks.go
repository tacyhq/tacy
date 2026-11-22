package verifier

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The task queue across container restarts (V1-DESIGN §6.2): agentd keeps its task queue in a host tmpfs (TasksDir,
// TD memory, gone at every real boot), so open tasks survive dstack's hourly container restarts. With key_provider
// none the one-shot setup container makes it for agentd's uid, 0700, and agentd alone mounts it (queue.OpenTmpfs
// also refuses a directory statfs doesn't call tmpfs). The tasks in it are people's content, so no other container
// may see it: TasksRules. The KMS fallback has none (its queue stays in agentd's memory).

// TasksDir is the host tmpfs agentd keeps its task queue in (agentd's -tasks-dir).
const TasksDir = "/run/tacy-tasks"

// AgentdService is agentd's service; AgentdUID its uid (cmd/compose).
const (
	AgentdService = "agentd"
	AgentdUID     = "10003"
)

// TasksRules checks who mounts TasksDir in a compose for key mode mode: nobody, or (key_provider none only) agentd
// at the same path, running as its own uid, and setup, which must make it for agentd's uid alone (0700). Nothing may
// mount a path inside it, or a parent of it.
func TasksRules(compose, mode string) error {
	var doc struct {
		Services map[string]struct {
			User    string   `yaml:"user"`
			Volumes []any    `yaml:"volumes"`
			Command []string `yaml:"command"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	agentd := false
	for name, s := range doc.Services {
		for _, v := range s.Volumes {
			src, dst := "", ""
			switch m := v.(type) {
			case string:
				var rest string
				src, rest, _ = strings.Cut(m, ":")
				dst, _, _ = strings.Cut(rest, ":")
			case map[string]any:
				src, _ = m["source"].(string)
				dst, _ = m["target"].(string)
			}
			if len(src) > 1 {
				src = strings.TrimSuffix(src, "/")
			}
			under := src == "/" || strings.HasPrefix(src, TasksDir+"/") || (src != TasksDir && strings.HasPrefix(TasksDir, src+"/"))
			if src != TasksDir {
				if under && strings.HasPrefix(src, "/") && name != E2EDiagService { // the diag service: throwaways only (noDiskVolumes)
					return fmt.Errorf("service %s mounts %s: only agentd may see its task queue (%s)", name, src, TasksDir)
				}
				continue
			}
			switch {
			case mode != KeyProviderNone:
				return fmt.Errorf("service %s mounts %s: the task queue in a host tmpfs needs key_provider none", name, TasksDir)
			case name == AgentdService && dst == TasksDir:
				agentd = true
			case name == SetupService:
			default:
				return fmt.Errorf("service %s mounts %s: only agentd may (its task queue: people's tasks)", name, TasksDir)
			}
		}
	}
	if !agentd {
		return nil
	}
	if uid, _, _ := strings.Cut(doc.Services[AgentdService].User, ":"); uid != AgentdUID {
		return errors.New("agentd mounts the task queue's directory but isn't its own uid")
	}
	setup, ok := doc.Services[SetupService]
	want := TasksDir + "=" + AgentdUID + ":" + AgentdUID + ":0700"
	made := false
	for i, a := range setup.Command {
		if a == "-dir" && i+1 < len(setup.Command) && strings.HasPrefix(setup.Command[i+1], TasksDir+"=") {
			if setup.Command[i+1] != want || made {
				return fmt.Errorf("setup makes %s as %s, want %s (agentd's alone)", TasksDir, setup.Command[i+1], want)
			}
			made = true
		}
	}
	if !ok || !made || !slices.ContainsFunc(setup.Volumes, func(v any) bool { s, _ := v.(string); return s == TasksDir+":"+TasksDir }) {
		return fmt.Errorf("agentd mounts %s but setup doesn't make it for agentd's uid (%s)", TasksDir, want)
	}
	return nil
}
