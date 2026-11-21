//go:build integration && linux

package integration

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/jsimonetti/rtnetlink/v2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// inNetNS runs fn in a fresh network namespace on a thread-locked goroutine,
// failing tb if fn returns an error.
func inNetNS(tb testing.TB, fn func() error) {
	tb.Helper()
	var g errgroup.Group
	g.Go(func() error {
		runtime.LockOSThread()
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			return fmt.Errorf("unshare network namespace: %w", err)
		}
		return fn()
	})
	if err := g.Wait(); err != nil {
		tb.Fatal(err)
	}
}

var (
	// dummyPrefix is the address and subnet assigned to the dummy interface.
	dummyPrefix = netip.MustParsePrefix("10.0.0.1/24")
	// dummyPeer is an address in dummyPrefix that is routed through the dummy
	// interface.
	dummyPeer = net.IPv4(10, 0, 0, 2)
)

// setupDummy creates an up dummy interface with the given address and returns
// it along with a function that deletes it. Send to another address in
// prefix, not the interface's own, to route through it.
func setupDummy(name string, prefix netip.Prefix) (*net.Interface, func() error, error) {
	con, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("dial rtnetlink: %w", err)
	}
	defer con.Close()

	if err := con.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{
			Name: name,
			Info: &rtnetlink.LinkInfo{Kind: "dummy"},
		},
	}); err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", name, err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup %s: %w", name, err)
	}
	cleanup := func() error {
		con, err := rtnetlink.Dial(nil)
		if err != nil {
			return fmt.Errorf("dial rtnetlink: %w", err)
		}
		defer con.Close()
		if err := con.Link.Delete(uint32(iface.Index)); err != nil {
			return fmt.Errorf("delete %s: %w", name, err)
		}
		return nil
	}

	addr := net.IP(prefix.Addr().AsSlice())
	if err := con.Address.New(&rtnetlink.AddressMessage{
		Family:       unix.AF_INET,
		PrefixLength: uint8(prefix.Bits()),
		Scope:        unix.RT_SCOPE_UNIVERSE,
		Index:        uint32(iface.Index),
		Attributes: &rtnetlink.AddressAttributes{
			Address: addr,
			Local:   addr,
		},
	}); err != nil {
		return nil, nil, errors.Join(fmt.Errorf("add %s to %s: %w", prefix, name, err), cleanup())
	}
	return iface, cleanup, nil
}

// capturePackets opens an AF_PACKET socket that sees packets transmitted on
// iface, with reads timing out after timeout.
func capturePackets(iface *net.Interface, timeout time.Duration) (int, error) {
	// Only ETH_P_ALL sockets see outgoing packets. The kernel expects it in
	// network byte order.
	proto := binaryutil.NativeEndian.Uint16(binaryutil.BigEndian.PutUint16(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return -1, fmt.Errorf("open packet socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: iface.Index}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind packet socket to %s: %w", iface.Name, err)
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set packet socket timeout: %w", err)
	}
	return fd, nil
}

// queueUDP installs an nftables rule that queues outgoing UDP packets for
// dport to the given nfqueue, like "udp dport <dport> queue num <queue>".
func queueUDP(dport, queue uint16) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables: %w", err)
	}
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "nfqueue-test",
	})
	policy := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // UDP destination port
				Len:          2,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(dport)},
			&expr.Queue{Num: queue},
		},
	})
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("install nftables rule: %w", err)
	}
	return nil
}

// openQueue queues outgoing UDP traffic for port to cfg.NfQueue and opens the
// queue. With a dummy interface on dummyPrefix, packets sent to the returned
// address go through the queue.
func openQueue(cfg nfqueue.Config, port uint16) (*nfqueue.Nfqueue, *net.UDPAddr, error) {
	if err := queueUDP(port, cfg.NfQueue); err != nil {
		return nil, nil, err
	}
	nfq, err := nfqueue.Open(&cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("open nfqueue: %w", err)
	}
	return nfq, &net.UDPAddr{IP: dummyPeer, Port: int(port)}, nil
}
