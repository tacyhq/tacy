// brain runs our Go agent loop as a harness/v1 brain (../../brain, docs/20-harness-protocol.md) on the socket the
// runtime made for it. It holds no keys and opens no other connection: model calls and tools go through the
// runtime. In the agent VM it runs in a gVisor sandbox that runnerd starts for agentd (docs/22-sandbox-runner.md):
// a root holding only this binary, no network, and its one link, an already connected socket, passed in as fd 3
// (--fd 3; there is no socket path inside). When the connection drops it exits, the sandbox ends with it, agentd
// asks runnerd for a new one, and the runtime resumes its tasks from their checkpoints. --socket dials a unix
// socket instead (development), waiting for it at start.
//
//	go run ./cmd/brain --socket /run/tacy/brain.sock
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tacyhq/tacy/brain"
	"github.com/tacyhq/tacy/internal/procinfo"
)

func main() {
	socket := flag.String("socket", "", "the runtime's unix socket")
	fd := flag.Int("fd", -1, "an already connected socket to the runtime, by descriptor (the sandbox passes 3)")
	wait := flag.Duration("wait", 10*time.Minute, "how long to wait for the socket at start (the first boot builds the binaries)")
	flag.Parse()
	log.Printf("brain: %s", procinfo.Line())
	if (*socket == "") == (*fd < 0) {
		log.Fatal("brain: one of --socket and --fd is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var conn net.Conn
	var err error
	if *fd >= 0 {
		f := os.NewFile(uintptr(*fd), "runtime")
		conn, err = net.FileConn(f)
		f.Close()
	} else {
		for deadline := time.Now().Add(*wait); ; {
			if conn, err = net.Dial("unix", *socket); err == nil || time.Now().After(deadline) || ctx.Err() != nil {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if err != nil {
		log.Fatalf("brain: %v", err)
	}
	log.Printf("brain %s connected", brain.Version)
	if err := brain.Run(ctx, conn); err != nil && ctx.Err() == nil {
		log.Fatalf("brain: %v", err)
	}
}
