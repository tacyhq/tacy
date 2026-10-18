//go:build !linux

package sandbox

import "errors"

// DelegateCgroups needs Linux (cgroup v2).
func DelegateCgroups(string) error { return errors.New("sandbox: cgroups need linux") }
