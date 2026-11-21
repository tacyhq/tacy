package queue

import "syscall"

const tmpfsMagic = 0x01021994

// isTmpfs says whether dir is on a tmpfs (statfs).
func isTmpfs(dir string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, err
	}
	return st.Type == tmpfsMagic, nil
}
