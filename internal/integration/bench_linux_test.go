//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/net/ipv4"
)

func BenchmarkThroughput(b *testing.B) {
	cases := []struct {
		name       string
		packetSize int
	}{
		{"packet=128", 128},
		{"packet=1500", 1500},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			runReceiveBench(b, tc.packetSize)
		})
	}
}

func runReceiveBench(b *testing.B, packetSize int) {
	inNetNS(b, func() (err error) {
		const port = 9999
		cfg := nfqueue.Config{
			NfQueue:      200,
			Copymode:     nfqueue.NfQnlCopyPacket,
			MaxQueueLen:  4096,
			MaxPacketLen: 0xFFFF, // copy the whole packet
		}

		_, cleanup, err := setupDummy("dummy0", dummyPrefix)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, cleanup()) }()

		nfq, addr, err := openQueue(cfg, port)
		if err != nil {
			return err
		}
		defer nfq.Close()
		// Request a large socket buffer, which the kernel caps at
		// net.core.rmem_max.
		if err := nfq.Con.SetReadBuffer(64 << 20); err != nil {
			return fmt.Errorf("set read buffer: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		errc := make(chan error, 1)
		var handled atomic.Int64
		if err := nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
			// Accept every packet and close done once b.N have been handled.
			nfq.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			if handled.Add(1) == int64(b.N) {
				close(done)
			}
			return 0
		}, func(err error) int {
			// Cancelling ctx unblocks the receive with a "closed file" error.
			if ctx.Err() == nil {
				errc <- err
			}
			return 1
		}); err != nil {
			return fmt.Errorf("register: %w", err)
		}

		// Several writers, each with its own socket, keep the queue saturated.
		const writers = 4
		conns := make([]net.Conn, writers)
		for i := range conns {
			conn, err := net.DialUDP("udp4", nil, addr)
			if err != nil {
				return fmt.Errorf("dial: %w", err)
			}
			defer conn.Close()
			conns[i] = conn
		}
		var wg sync.WaitGroup
		// Cancel the writers and wait for them to stop before their sockets
		// are closed.
		defer func() {
			cancel()
			wg.Wait()
		}()

		// payloadSize is the wire packet minus the IP and UDP headers.
		const udpHeaderLen = 8
		payloadSize := packetSize - ipv4.HeaderLen - udpHeaderLen

		b.SetBytes(int64(packetSize))
		b.ReportAllocs()
		b.ResetTimer()
		for _, conn := range conns {
			wg.Go(func() {
				buf := make([]byte, payloadSize)
				for ctx.Err() == nil {
					conn.Write(buf)
				}
			})
		}
		select {
		case <-done:
		case err := <-errc:
			return fmt.Errorf("receive: %w", err)
		}
		b.StopTimer()
		return nil
	})
}
