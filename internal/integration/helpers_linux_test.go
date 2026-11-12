//go:build integration && linux

package integration

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

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

// setLinkUp brings up the named interface with a 1500-byte MTU.
func setLinkUp(name string) error {
	const mtu = 1500
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", name, err)
	}
	con, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial rtnetlink: %w", err)
	}
	defer con.Close()

	if err := con.Link.Set(&rtnetlink.LinkMessage{
		Family:     unix.AF_UNSPEC,
		Index:      uint32(iface.Index),
		Flags:      unix.IFF_UP,
		Change:     unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{MTU: mtu},
	}); err != nil {
		return fmt.Errorf("set %s up: %w", name, err)
	}
	return nil
}

// queueOutput queues all locally generated packets to nfqueue num.
func queueOutput(num uint16) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(`
table inet test-nfqueue {
	chain output {
		type filter hook output priority 0; policy accept;
		queue num %d
	}
}
`, num))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set up nftables: %v: %s", err, out)
	}
	return nil
}
