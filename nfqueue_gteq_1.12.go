//+build go1.12,linux

package nfqueue

import (
	"context"
	"encoding/binary"
	"log"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Nfqueue represents a netfilter queue handler
type Nfqueue struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	flags           []byte // uint32
	maxPacketLen    []byte // uint32
	family          uint8
	queue           uint16
	maxQueueLen     []byte // uint32
	copymode        uint8
	setReadTimeout  func() error
	setWriteTimeout func() error
}

// Open a connection to the netfilter queue subsystem
func Open(config *Config) (*Nfqueue, error) {
	var nfqueue Nfqueue

	if config.Flags >= nfQaCfgFlagMax {
		return nil, ErrInvFlag
	}

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: config.NetNS})
	if err != nil {
		return nil, err
	}
	nfqueue.Con = con
	// default size of copied packages to userspace
	nfqueue.maxPacketLen = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nfqueue.maxPacketLen, config.MaxPacketLen)
	nfqueue.flags = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nfqueue.flags, config.Flags)
	nfqueue.queue = config.NfQueue
	nfqueue.family = config.AfFamily
	nfqueue.maxQueueLen = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nfqueue.maxQueueLen, config.MaxQueueLen)
	if config.Logger == nil {
		nfqueue.logger = log.New(new(devNull), "", 0)
	} else {
		nfqueue.logger = config.Logger
	}
	nfqueue.copymode = config.Copymode

	if config.ReadTimeout > 0 {
		nfqueue.setReadTimeout = func() error {
			deadline := time.Now().Add(config.ReadTimeout)
			return nfqueue.Con.SetReadDeadline(deadline)
		}
	} else {
		nfqueue.setReadTimeout = func() error { return nil }
	}
	if config.WriteTimeout > 0 {
		nfqueue.setWriteTimeout = func() error {
			deadline := time.Now().Add(config.WriteTimeout)
			return nfqueue.Con.SetWriteDeadline(deadline)
		}
	} else {
		nfqueue.setWriteTimeout = func() error { return nil }
	}

	return &nfqueue, nil
}

func (nfqueue *Nfqueue) setVerdict(id uint32, verdict int, batch bool, attributes []byte) error {
	/*
		struct nfqnl_msg_verdict_hdr {
			__be32 verdict;
			__be32 id;
		};
	*/

	if verdict != NfDrop && verdict != NfAccept && verdict != NfStolen && verdict != NfQeueue && verdict != NfRepeat {
		return ErrInvalidVerdict
	}

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(id))
	verdictData := append([]byte{0x0, 0x0, 0x0, byte(verdict)}, buf...)
	cmd, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfQaVerdictHdr, Data: verdictData},
	})
	if err != nil {
		return err
	}
	data := putExtraHeader(nfqueue.family, unix.NFNETLINK_V0, nfqueue.queue)
	data = append(data, cmd...)
	data = append(data, attributes...)
	req := netlink.Message{
		Header: netlink.Header{
			Flags:    netlink.Request,
			Sequence: 0,
		},
		Data: data,
	}
	if batch {
		req.Header.Type = netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgVerdictBatch)
	} else {
		req.Header.Type = netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgVerdict)
	}

	if err := nfqueue.setWriteTimeout(); err != nil {
		nfqueue.logger.Printf("could not set write timeout: %v", err)
	}
	_, sErr := nfqueue.Con.Execute(req)
	return sErr

}

func (nfqueue *Nfqueue) socketCallback(ctx context.Context, fn HookFunc, seq uint32) {
	defer func() {
		// unbinding from queue
		_, err := nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
			{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdUnbind, 0x0, 0x0, byte(nfqueue.family)}},
		})
		if err != nil {
			nfqueue.logger.Printf("Could not unbind from queue: %v", err)
			return
		}
	}()
	for {
		if err := nfqueue.setReadTimeout(); err != nil {
			nfqueue.logger.Printf("could not set read timeout: %v", err)
		}
		replys, err := nfqueue.Con.Receive()
		if err != nil {
			nfqueue.logger.Printf("Could not receive message: %v", err)
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		for _, msg := range replys {
			if msg.Header.Type == netlink.Done {
				// this is the last message of a batch
				// continue to receive messages
				break
			}
			m, err := parseMsg(nfqueue.logger, msg)
			if err != nil {
				nfqueue.logger.Printf("Could not parse message: %v", err)
				continue
			}
			if ret := fn(m); ret != 0 {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
