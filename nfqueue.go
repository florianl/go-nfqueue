//+build linux

package nfqueue

import (
	"golang.org/x/sys/unix"

	"github.com/mdlayher/netlink"
)

// Nfqueue represents a netfilter queue handler
type Nfqueue struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn
}

// Open a connection to the netfilter queue subsystem
func Open() (*Nfqueue, error) {
	var nfqueue Nfqueue

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	nfqueue.Con = con

	return &nfqueue, nil
}

// Close the connection to the netfilter queue subsystem
func (nfqueue *Nfqueue) Close() error {
	return nfqueue.Con.Close()
}
