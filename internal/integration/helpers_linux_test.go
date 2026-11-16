//go:build integration && linux

package integration

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"

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

// setupDummy creates an up dummy interface with the given address. Send to
// another address in prefix, not the interface's own, to route through it.
func setupDummy(name string, prefix netip.Prefix) error {
	con, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial rtnetlink: %w", err)
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
		return fmt.Errorf("create %s: %w", name, err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", name, err)
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
		return fmt.Errorf("add %s to %s: %w", prefix, name, err)
	}
	return nil
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
