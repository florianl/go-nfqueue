//+build linux

package nfqueue_test

import (
	"context"
	"fmt"
	"time"

	nfqueue "github.com/twistlock/go-nfqueue"
)

func ExampleNfqueue_Register() {
	// Send outgoing pings to nfqueue queue 100
	// # sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 100

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      100,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		// Just print out the id and payload of the nfqueue packet
		fmt.Printf("[%d]\t%v\n", id, *a.Payload)
		nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = nf.Register(ctx, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
