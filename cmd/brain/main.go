// brain runs our Go agent loop as a harness/v1 brain (../../brain, docs/20-harness-protocol.md) on the unix socket
// the runtime made for its sandbox. It holds no keys and opens no other connection: model calls and tools go
// through the runtime. In the agent VM it runs in its own container (compose.yaml: no network, its own uid, read-only
// root). It waits for the socket at start (the runtime may still be starting); when the connection drops it exits,
// the container restarts it and the runtime resumes its tasks from their checkpoints.
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
	wait := flag.Duration("wait", 10*time.Minute, "how long to wait for the socket at start (the first boot builds the binaries)")
	flag.Parse()
	log.Printf("brain: %s", procinfo.Line())
	if *socket == "" {
		log.Fatal("brain: --socket is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var conn net.Conn
	var err error
	for deadline := time.Now().Add(*wait); ; {
		if conn, err = net.Dial("unix", *socket); err == nil || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		log.Fatalf("brain: %v", err)
	}
	log.Printf("brain %s connected", brain.Version)
	if err := brain.Run(ctx, conn); err != nil && ctx.Err() == nil {
		log.Fatalf("brain: %v", err)
	}
}
