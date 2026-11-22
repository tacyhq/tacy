//go:build !linux

package queue

// isTmpfs: only Linux keeps the task queue in a tmpfs (agentd runs on Linux; elsewhere tests set Tmpfs.IsMemory).
func isTmpfs(string) (bool, error) { return false, nil }
