//go:build integration && linux
// +build integration,linux

package nfqueue

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
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

func TestNfqueuePacketPath(t *testing.T) {
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		t.Fatalf("failed to unshare network namespace: %v", err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Bring up the loopback interface so that packets can be sent through the nfqueue path.
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("failed to bring lo up: %v: %s", err, out)
	}

	nftRules := strings.NewReader(`
table inet test-nfqueue {
	chain output {
		type filter hook output priority 0; policy accept;
		queue num 200
	}
}
`)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = nftRules
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to set up nftables: %v: %s", err, out)
	}

	nfq, err := Open(&Config{
		NfQueue:      200,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to open nfqueue: %v", err)
	}
	defer nfq.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var callbackFired atomic.Bool
	err = nfq.RegisterWithErrorFunc(ctx, func(a Attribute) int {
		callbackFired.Store(true)
		nfq.SetVerdict(*a.PacketID, NfAccept)
		return 0
	}, func(err error) int {
		// Timeouts return an error "netlink receive: use of closed file".
		// This is a workaround to avoid treating timeouts as test failures.
		if ctx.Err() == nil {
			t.Errorf("nfqueue error: %v", err)
		}
		return 0
	})
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Listen on a UDP port to receive the packet that will be sent through the nfqueue path
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send a UDP packet to trigger the nfqueue callback
	conn, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	conn.Write([]byte("test-packet"))
	conn.Close()

	buf := make([]byte, 256)
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("packet not delivered (nfqueue receive/verdict broken): %v", err)
	}
	if got := string(buf[:n]); got != "test-packet" {
		t.Errorf("received %q, want %q", got, "test-packet")
	}
	if !callbackFired.Load() {
		t.Error("nfqueue callback was never invoked")
	}
}
