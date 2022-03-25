//go:build integration && linux
// +build integration,linux

package nfqueue

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func startDummyPingTraffic(t *testing.T, ctx context.Context) {
	t.Helper()

	if err := exec.CommandContext(ctx, "ping6", "2606:4700:4700::1111").Start(); err != nil {
		t.Fatalf("failed to start IPv6 ping: %v", err)
	}
	if err := exec.CommandContext(ctx, "ping", "1.1.1.1").Start(); err != nil {
		t.Fatalf("failed to start IPv4 ping: %v", err)
	}
}

func TestLinuxNfqueue(t *testing.T) {
	pingCtx, pingCancel := context.WithCancel(context.Background())
	defer pingCancel()

	startDummyPingTraffic(t, pingCtx)

	// Set configuration options for nfqueue
	config := Config{
		NfQueue:      100,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     NfQnlCopyPacket,
	}
	// Open a socket to the netfilter log subsystem
	nfq, err := Open(&config)
	if err != nil {
		t.Fatalf("failed to open nfqueue socket: %v", err)
	}
	defer nfq.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(a Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		t.Logf("[%d]\t%v\n", id, *a.Payload)
		nfq.SetVerdict(id, NfAccept)
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nfq.Register(ctx, fn)
	if err != nil {
		t.Fatalf("failed to register hook function: %v", err)
	}

	// Block till the context expires
	<-ctx.Done()
}

func TestTimeout(t *testing.T) {
	// Set configuration options for nfqueue
	config := Config{
		NfQueue:      123,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     NfQnlCopyPacket,
	}

	nfq, err := Open(&config)
	if err != nil {
		t.Fatalf("failed to open nfqueue socket: %v", err)
	}
	defer nfq.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)

	fn := func(a Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		t.Logf("[%d]\t%v\n", id, *a.Payload)
		nfq.SetVerdict(id, NfAccept)
		return 0
	}

	// Register your function to listen on nflog group 123
	// This also does a reading on the netlink socket
	err = nfq.Register(ctx, fn)
	if err != nil {
		t.Fatalf("failed to register hook function: %v", err)
	}
	// cancel the context to remove the registered hook from the nfqueue.
	cancel()

	// Block till the context expires
	<-ctx.Done()
}
