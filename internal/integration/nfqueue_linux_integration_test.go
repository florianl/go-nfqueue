//go:build integration && linux

package integration

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/net/ipv4"
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
	inNetNS(t, func() error {
		// Bring up the loopback interface so that packets can be sent through the nfqueue path.
		if err := setLinkUp("lo"); err != nil {
			return err
		}

		// Prepare nft
		if err := queueOutput(200); err != nil {
			return err
		}

		// Prepare nfq
		nfq, err := nfqueue.Open(&nfqueue.Config{
			NfQueue:      200,
			MaxPacketLen: 0xFFFF,
			MaxQueueLen:  0xFF,
			Copymode:     nfqueue.NfQnlCopyPacket,
			WriteTimeout: 100 * time.Millisecond,
		})
		if err != nil {
			return fmt.Errorf("failed to open nfqueue: %v", err)
		}
		defer nfq.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var callbackFired atomic.Bool
		err = nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
			callbackFired.Store(true)
			nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
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

		// Listen on a UDP port to receive the packet that will be sent through the nfqueue path
		listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return fmt.Errorf("failed to listen: %v", err)
		}
		defer listener.Close()
		listener.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Send a UDP packet to trigger the nfqueue callback
		conn, err := net.Dial("udp", listener.LocalAddr().String())
		if err != nil {
			return fmt.Errorf("failed to dial: %v", err)
		}
		conn.Write([]byte("test-packet"))
		conn.Close()

		buf := make([]byte, 256)
		n, _, err := listener.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("packet not delivered (nfqueue receive/verdict broken): %v", err)
		}
		if got := string(buf[:n]); got != "test-packet" {
			return fmt.Errorf("received %q, want %q", got, "test-packet")
		}
		if !callbackFired.Load() {
			return fmt.Errorf("nfqueue callback was never invoked")
		}
		return nil
	})
}

func TestNfqueuePayloadNotOverwritten(t *testing.T) {
	inNetNS(t, func() error {
		if err := setLinkUp("lo"); err != nil {
			return err
		}
		if err := queueOutput(200); err != nil {
			return err
		}

		nfq, err := nfqueue.Open(&nfqueue.Config{
			NfQueue:      200,
			MaxPacketLen: 0xFFFF,
			MaxQueueLen:  0xFF,
			Copymode:     nfqueue.NfQnlCopyPacket,
		})
		if err != nil {
			return fmt.Errorf("failed to open nfqueue: %v", err)
		}
		defer nfq.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		const packets = 10
		// Gether payloads and block until N of them are received
		var mu sync.Mutex
		var payloads [][]byte
		done := make(chan struct{})
		err = nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
			mu.Lock()
			payloads = append(payloads, *a.Payload)
			if len(payloads) == packets {
				close(done)
			}
			mu.Unlock()
			nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			return 0
		}, func(err error) int {
			if ctx.Err() == nil {
				t.Errorf("nfqueue error: %v", err)
			}
			return 0
		})
		if err != nil {
			return fmt.Errorf("failed to register: %v", err)
		}

		listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return fmt.Errorf("failed to listen: %v", err)
		}
		defer listener.Close()

		conn, err := net.Dial("udp", listener.LocalAddr().String())
		if err != nil {
			return fmt.Errorf("failed to dial: %v", err)
		}
		defer conn.Close()
		for i := range packets {
			if _, err := fmt.Fprintf(conn, "packet-%d", i); err != nil {
				return fmt.Errorf("failed to send: %v", err)
			}
		}

		select {
		case <-done:
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %d packets", packets)
		}

		// We expect no writes to the payloads after <-done
		// but we lock anyways to be defensive.
		mu.Lock()
		defer mu.Unlock()

		// Map distinct received messages
		const udpHeaderLen = 8
		received := make(map[string]bool)
		for _, p := range payloads {
			received[string(p[ipv4.HeaderLen+udpHeaderLen:])] = true
		}
		for i := range packets {
			if want := fmt.Sprintf("packet-%d", i); !received[want] {
				return fmt.Errorf("payload %q missing or overwritten", want)
			}
		}
		return nil
	})
}
