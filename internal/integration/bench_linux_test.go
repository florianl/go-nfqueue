//go:build integration && linux

package integration

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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
	inNetNS(b, func() error {
		const port = 9999
		cfg := nfqueue.Config{
			NfQueue:      200,
			Copymode:     nfqueue.NfQnlCopyPacket,
			MaxQueueLen:  4096,
			MaxPacketLen: 0xFFFF, // copy the whole packet
		}

		if err := setupDummy("dummy0", netip.MustParsePrefix("10.0.0.1/24")); err != nil {
			return err
		}

		// Queue the writers' UDP traffic.
		if err := queueUDP(port, cfg.NfQueue); err != nil {
			return err
		}

		nfq, err := nfqueue.Open(&cfg)
		if err != nil {
			return fmt.Errorf("open nfqueue: %w", err)
		}
		defer nfq.Close()
		// Size the socket buffer for a full queue so no netlink message is dropped.
		if err := nfq.Con.SetReadBuffer(64 << 20); err != nil {
			return fmt.Errorf("set read buffer: %w", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
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
				b.Errorf("receive: %v", err)
			}
			return 1
		}); err != nil {
			return fmt.Errorf("register: %w", err)
		}

		addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: port}

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

		// payloadSize is the wire packet minus the IP and UDP headers.
		const udpHeaderLen = 8
		payloadSize := packetSize - ipv4.HeaderLen - udpHeaderLen

		b.SetBytes(int64(packetSize))
		b.ReportAllocs()
		b.ResetTimer()
		for _, conn := range conns {
			go func() {
				buf := make([]byte, payloadSize)
				for ctx.Err() == nil {
					conn.Write(buf)
				}
			}()
		}
		<-done
		b.StopTimer()
		return nil
	})
}
