package cftunnel

import (
	"io/fs"
	"os"
	"slices"
	"testing"
)

// The lines below are a real VM's (gate run 2026-11-21, cloudflared's network namespace): one UDP socket, Docker's
// resolver, and no abstract UNIX socket.
const vmUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops            
  973: 0B00007F:CCBE 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 6497 2 0000000025f07818 0          
`

const vmUnix = `Num       RefCount Protocol Flags    Type St Inode Path
000000004dae0497: 00000002 00000000 00010000 0001 01  6824 /run/tunnel/ingress.sock
0000000055278e6e: 00000002 00000000 00010000 0001 01  6816 /run/tacy/agent/gateway.sock
000000008be79ece: 00000003 00000000 00000000 0005 03  6790
00000000d3e7cbef: 00000003 00000000 00000000 0001 03 14283 /run/tacy/agent/http.sock
`

func TestUDPSocketsDockerResolverOnly(t *testing.T) {
	socks, res := udpSocketsIn("udp", vmUDP)
	if len(socks) != 1 || !res[socks[0]] {
		t.Fatalf("the VM's one UDP socket: %v, resolver %v", socks, res)
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	line := func(local, remote, st, uid string) string {
		return hdr + "  12: " + local + " " + remote + " " + st + " 00000000:00000000 00:00000000 00000000 " + uid + " 0 4242 2 0000000000000000 0\n"
	}
	for name, c := range map[string]string{
		"127.0.0.1, root's":         line("0100007F:CCBE", "00000000:0000", "07", "0"),
		"0.0.0.0, root's":           line("00000000:0035", "00000000:0000", "07", "0"),
		"127.0.0.11 of 10001":       line("0B00007F:CCBE", "00000000:0000", "07", "10001"),
		"127.0.0.11 of 10006":       line("0B00007F:CCBE", "00000000:0000", "07", "10006"),
		"127.0.0.110":               line("6E00007F:CCBE", "00000000:0000", "07", "0"),
		"127.0.0.11, connected":     line("0B00007F:CCBE", "0100007F:0035", "01", "0"),
		"127.0.0.11, a peer":        line("0B00007F:CCBE", "0100007F:0035", "07", "0"),
		"a lookup's socket (10001)": line("0200110A:9C40", "0B00007F:0035", "01", "10001"),
	} {
		socks, res := udpSocketsIn("udp", c)
		if len(socks) != 1 || res[socks[0]] {
			t.Errorf("%s: sockets %v, taken for the resolver %v", name, socks, res)
		}
	}
	// IPv6: never the resolver, whatever it looks like.
	if socks, res := udpSocketsIn("udp6", line("0B00007F:CCBE", "00000000:0000", "07", "0")); len(socks) != 1 || len(res) != 0 {
		t.Errorf("udp6: %v %v", socks, res)
	}
	if socks, _ := udpSocketsIn("udp", hdr); len(socks) != 0 {
		t.Errorf("header only: %v", socks)
	}
}

func TestAbstractUnixSockets(t *testing.T) {
	if a := abstractUnixIn(vmUnix); len(a) != 0 {
		t.Fatalf("the VM has no abstract socket: %v", a)
	}
	got := abstractUnixIn(vmUnix + "00000000aa: 00000002 00000000 00010000 0001 01  7001 @tacy-x\n" +
		"00000000ab: 00000002 00000000 00000000 0002 07  7002 @0001e\n" +
		"00000000ac: 00000002 00000000 00010000 0001 01  7003 @with space\n")
	if !slices.Equal(got, []string{"@tacy-x", "@0001e", "@with space"}) {
		t.Fatalf("abstract sockets: %v", got)
	}
}

// UDP-Lite and the read errors: udplite and udplite6 are read like udp, every socket there
// fails (never the resolver); a file that doesn't exist is skipped (but udp); any other read error is the error.
func TestUDPSocketsFromFiles(t *testing.T) {
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	lite := hdr + "  5: 0B00007F:46B5 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4243 2 0000000000000000 0\n"
	files := map[string]string{"udp": vmUDP, "udplite": lite, "udplite6": lite}
	read := func(errs map[string]error) func(string) ([]byte, error) {
		return func(f string) ([]byte, error) {
			if err := errs[f]; err != nil {
				return nil, err
			}
			if c, ok := files[f]; ok {
				return []byte(c), nil
			}
			return nil, &os.PathError{Op: "open", Path: "/proc/net/" + f, Err: fs.ErrNotExist}
		}
	}
	socks, res, err := udpSocketsFrom(read(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"udp 0B00007F:CCBE 00000000:0000 uid 0", "udplite 0B00007F:46B5 00000000:0000 uid 0", "udplite6 0B00007F:46B5 00000000:0000 uid 0"}
	if !slices.Equal(socks, want) || len(res) != 1 || !res[want[0]] {
		t.Fatalf("sockets %v, resolver %v (want %v, only the udp one the resolver)", socks, res, want)
	}
	for _, f := range []string{"udp", "udp6", "udplite", "udplite6"} {
		if _, _, err := udpSocketsFrom(read(map[string]error{f: &os.PathError{Op: "open", Path: "/proc/net/" + f, Err: fs.ErrPermission}})); err == nil {
			t.Errorf("%s unreadable (permission): no error", f)
		}
	}
	if _, _, err := udpSocketsFrom(read(map[string]error{"udp": &os.PathError{Op: "open", Path: "/proc/net/udp", Err: fs.ErrNotExist}})); err == nil {
		t.Error("no /proc/net/udp: no error")
	}
}

// Netlink: only NETLINK_USERSOCK sockets (protocol 2) are listed, whatever their port id; the kernel's
// and dockerd's NETLINK_ROUTE socket (a container's own, 2026-11-22) aren't.
func TestNetlinkUsersock(t *testing.T) {
	docker := `sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
00000000969b26ea 0   13         00000000 1152     0        0     2        0        3954069 
0000000058a40604 0   0          00000000 0        0        0     2        0        3957060 
00000000819f7892 4   0          00000000 0        0        0     2        0        3957065 
000000008168436d 12  0          00000000 0        0        0     2        0        3957066 
00000000898c524d 15  0          00000000 0        0        0     2        0        3957062 
`
	if n := netlinkUsersockIn(docker); len(n) != 0 {
		t.Fatalf("a container's netlink sockets: %v", n)
	}
	got := netlinkUsersockIn(docker + "00000000aaaaaaaa 2   4242       00000000 0        0        0     2        0        7001 \n" +
		"00000000bbbbbbbb 2   0          00000001 0        0        0     2        0        7002 \n" +
		"00000000cccccccc 2   77\n")
	if !slices.Equal(got, []string{"netlink usersock pid 4242 inode 7001", "netlink usersock pid 0 inode 7002"}) {
		t.Fatalf("usersock sockets: %v", got)
	}
}
