//go:build integration && linux

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
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
	config := nfqueue.Config{
		NfQueue:      100,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}
	// Open a socket to the netfilter log subsystem
	nfq, err := nfqueue.Open(&config)
	if err != nil {
		t.Fatalf("failed to open nfqueue socket: %v", err)
	}
	defer nfq.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		t.Logf("[%d]\t%v\n", id, *a.Payload)
		nfq.SetVerdict(id, nfqueue.NfAccept)
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
	config := nfqueue.Config{
		NfQueue:      123,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nfq, err := nfqueue.Open(&config)
	if err != nil {
		t.Fatalf("failed to open nfqueue socket: %v", err)
	}
	defer nfq.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		t.Logf("[%d]\t%v\n", id, *a.Payload)
		nfq.SetVerdict(id, nfqueue.NfAccept)
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
	inNetNS(t, func() (err error) {
		const port = 9999
		cfg := nfqueue.Config{
			NfQueue:      200,
			MaxPacketLen: 0xFFFF,
			MaxQueueLen:  0xFF,
			Copymode:     nfqueue.NfQnlCopyPacket,
			WriteTimeout: 100 * time.Millisecond,
		}

		iface, cleanup, err := setupDummy("dummy0", dummyPrefix)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, cleanup()) }()

		nfq, addr, err := openQueue(cfg, port)
		if err != nil {
			return err
		}
		defer nfq.Close()

		// The dummy interface discards packets, but a packet socket on it sees
		// them on transmit, which happens only after NfAccept reinjects them.
		capture, err := capturePackets(iface, 2*time.Second)
		if err != nil {
			return err
		}
		defer unix.Close(capture)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		received := make(chan struct{})
		verdictErr := make(chan error, 1)
		var once sync.Once
		err = nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
			if a.Payload == nil || !bytes.HasSuffix(*a.Payload, []byte("test-packet")) {
				nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
				return 0
			}
			err := nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			// Report only the first test packet, so both channels are closed
			// exactly once.
			once.Do(func() {
				verdictErr <- err
				close(verdictErr)
				close(received)
			})
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
			return fmt.Errorf("failed to register: %v", err)
		}

		// Send a UDP packet to trigger the nfqueue callback
		conn, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			return fmt.Errorf("failed to dial: %v", err)
		}
		conn.Write([]byte("test-packet"))
		conn.Close()

		select {
		case <-received:
		case <-ctx.Done():
			return fmt.Errorf("nfqueue callback never received the packet")
		}
		if err := <-verdictErr; err != nil {
			return fmt.Errorf("failed to set verdict: %v", err)
		}

		buf := make([]byte, 256)
		for {
			n, _, err := unix.Recvfrom(capture, buf, 0)
			if err != nil {
				return fmt.Errorf("packet not reinjected after NfAccept: %v", err)
			}
			if bytes.HasSuffix(buf[:n], []byte("test-packet")) {
				return nil
			}
		}
	})
}
