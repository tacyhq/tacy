// Package runner is runner/v0: how agentd asks runnerd (cmd/runnerd) for gVisor sandboxes (see
// docs/22-sandbox-runner.md). runnerd is the only process that runs runsc, so agentd (which holds the tasks and the
// HPKE key) never needs runsc's privileges.
//
// One unix socket connection per sandbox, and the sandbox lives exactly as long as it: the first frame creates it
// from a fixed profile ("brain": our Go brain, its harness socket passed in with the frame as SCM_RIGHTS; "hands":
// a sandbox for exec, when runnerd is given a hands root), later frames exec in it (hands only) or destroy it, and
// when the connection closes for any reason (agentd exits, crashes, or is done) runnerd destroys the sandbox. When
// the sandbox's workload exits, runnerd says so ("exited") and closes the connection. agentd can't name a root,
// mount, flag, uid or limit: profiles are runnerd's. runnerd accepts only agentd's uid (SO_PEERCRED).
//
// Framing as harness/v1 (a 4-byte big-endian length, then one JSON object), strict decoding: unknown members,
// duplicate names, a bad length or trailing data end the connection. Internal and unfrozen.
package runner

import (
	"bytes"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

// Version names this protocol.
const Version = "runner/v0"

// MaxFrame bounds a frame: an exec's stdin (1 MiB) or its result (two 256 KiB streams), base64 in JSON.
const MaxFrame = 4 << 20

// maxFiles is the most descriptors a create may carry.
const maxFiles = 4

// Ops.
const (
	OpCreate  = "create"
	OpExec    = "exec"
	OpDestroy = "destroy"
)

// Request is agentd → runnerd.
type Request struct {
	Op        string   `json:"op"`
	Profile   string   `json:"profile,omitzero"`    // create
	Argv      []string `json:"argv,omitzero"`       // exec
	Stdin     []byte   `json:"stdin,omitzero"`      // exec
	TimeoutMs int64    `json:"timeout_ms,omitzero"` // exec; 0: the profile's default
}

// Reply is runnerd → agentd: one per request, plus "exited" when the workload ends.
type Reply struct {
	Sandbox string      `json:"sandbox,omitzero"` // create: the new sandbox's id
	Exec    *ExecResult `json:"exec,omitzero"`
	Exited  *int        `json:"exited,omitzero"` // the workload ended with this code; the connection closes next
	OK      bool        `json:"ok,omitzero"`     // destroy done
	Error   string      `json:"error,omitzero"`  // "code: detail"; the connection closes next
}

// ExecResult is a hands command's outcome. Stdout and Stderr are untrusted data.
type ExecResult struct {
	Exit      int    `json:"exit"`
	Stdout    []byte `json:"stdout,omitzero"`
	Stderr    []byte `json:"stderr,omitzero"`
	Truncated bool   `json:"truncated,omitzero"`
	TimedOut  bool   `json:"timed_out,omitzero"`
	OOM       bool   `json:"oom,omitzero"`
	Ms        int64  `json:"ms"`
}

var strict = json.JoinOptions(json.RejectUnknownMembers(true))

func decode[T any](b []byte) (*T, error) {
	var v T
	if err := json.Unmarshal(b, &v, strict); err != nil {
		return nil, fmt.Errorf("runner: bad frame: %w", err)
	}
	return &v, nil
}

// frame is v as one frame: its length, then its JSON.
func frame(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFrame {
		return nil, errors.New("runner: frame too large")
	}
	return append(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b))), b...), nil
}

// writeFrame writes v as one frame; files (create only) go with it as SCM_RIGHTS.
func writeFrame(c *net.UnixConn, v any, files ...*os.File) error {
	buf, err := frame(v)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		_, err = c.Write(buf)
		return err
	}
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	n, _, err := c.WriteMsgUnix(buf, syscall.UnixRights(fds...), nil)
	if err == nil && n < len(buf) {
		_, err = c.Write(buf[n:])
	}
	return err
}

// readFrame reads one frame's body.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("runner: frame length %d", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// readWithRights reads the first frame and the descriptors sent with it (close-on-exec, so no runsc started later
// inherits one). Descriptors sent with any later frame are dropped by the kernel: later frames are read without
// a control buffer.
func readWithRights(c *net.UnixConn) ([]byte, []*os.File, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 64<<10)
	oob := make([]byte, syscall.CmsgSpace(4*maxFiles))
	var n, oobn, flags int
	var rerr error
	err = raw.Read(func(fd uintptr) bool {
		n, oobn, flags, _, rerr = syscall.Recvmsg(int(fd), buf, oob, recvFlags)
		return rerr != syscall.EAGAIN
	})
	if err == nil {
		err = rerr
	}
	if err != nil {
		return nil, nil, err
	}
	files, ferr := parseRights(oob[:oobn])
	if ferr == nil && flags&syscall.MSG_CTRUNC != 0 {
		ferr = errors.New("runner: too many descriptors")
	}
	if ferr == nil && n == 0 {
		ferr = io.EOF
	}
	if ferr != nil {
		closeFiles(files)
		return nil, nil, ferr
	}
	body, err := readFrame(io.MultiReader(bytes.NewReader(buf[:n]), c))
	if err != nil {
		closeFiles(files)
		return nil, nil, err
	}
	return body, files, nil
}

func parseRights(oob []byte) ([]*os.File, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var files []*os.File
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			closeFiles(files)
			return nil, err
		}
		for _, fd := range fds {
			syscall.CloseOnExec(fd) // already set on Linux (MSG_CMSG_CLOEXEC)
			files = append(files, os.NewFile(uintptr(fd), "passed"))
		}
	}
	return files, nil
}

func closeFiles(fs []*os.File) {
	for _, f := range fs {
		f.Close()
	}
}
