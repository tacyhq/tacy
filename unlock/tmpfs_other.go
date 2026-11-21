//go:build !linux

package unlock

// isTmpfs: only Linux keeps a keyring cache (unlockd runs on Linux; elsewhere tests set Cache.IsMemory).
func isTmpfs(string) (bool, error) { return false, nil }
