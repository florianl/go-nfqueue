//+build linux

package nfqueue

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Nfqueue represents a netfilter queue handler
type Nfqueue struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	flags   []byte // uint16
	bufsize []byte // uint32
	family  uint8
	queue   uint16
}

// Open a connection to the netfilter queue subsystem
func Open(family uint8, queue uint16) (*Nfqueue, error) {
	var nfqueue Nfqueue

	if family != unix.AF_INET6 && family != unix.AF_INET {
		return nil, ErrAfFamily
	}

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	nfqueue.Con = con
	// default size of copied packages to userspace
	nfqueue.bufsize = []byte{0x0, 0x0, 0xff, 0xff}
	nfqueue.family = family
	nfqueue.queue = queue

	return &nfqueue, nil
}

// Close the connection to the netfilter queue subsystem
func (nfqueue *Nfqueue) Close() error {
	return nfqueue.Con.Close()
}

// HookFunc is a function, that receives events from a Netlinkgroup
// To stop receiving messages on this HookFunc, return something different than 0
type HookFunc func(m Msg) int

// SetVerdict signals the kernel the next action for a specified package id
func (nfqueue *Nfqueue) SetVerdict(id, verdict int) (uint32, error) {
	/*
		struct nfqnl_msg_verdict_hdr {
			__be32 verdict;
			__be32 id;
		};
	*/
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(id))
	verdictData := append([]byte{0x0, 0x0, 0x0, byte(verdict)}, buf...)
	cmd, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nfQaVerdictHdr, Data: verdictData},
	})
	if err != nil {
		return 0, err
	}
	data := putExtraHeader(nfqueue.family, unix.NFNETLINK_V0, nfqueue.queue)
	data = append(data, cmd...)
	req := netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgVerdict),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: 0,
		},
		Data: data,
	}
	return nfqueue.execute(req)
}

// Register your own function as callback for a netfilter log group
func (nfqueue *Nfqueue) Register(ctx context.Context, copyMode byte, fn HookFunc) error {

	// unbinding existing handler (if any)
	seq, err := nfqueue.setConfig(nfqueue.family, 0, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return err
	}

	// binding to family
	_, err = nfqueue.setConfig(nfqueue.family, seq, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return err
	}

	// binding to generic queue
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return err
	}

	// binding to the requested queue
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return err
	}

	// set copy mode and buffer size
	data := append(nfqueue.bufsize, copyMode)
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
		{Type: nfQaCfgParams, Data: data},
	})
	if err != nil {
		return err
	}

	go func() {
		defer func() {
			// unbinding from queue
			_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
				{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdUnbind, 0x0, 0x0, byte(nfqueue.family)}},
			})
			if err != nil {
				// TODO: handle this error
				return
			}
		}()
		for {
			reply, err := nfqueue.Con.Receive()
			if err != nil {
				return
			}

			for _, msg := range reply {
				if msg.Header.Type == netlink.HeaderTypeDone {
					// this is the last message of a batch
					// continue to receive messages
					break
				}
				m, err := parseMsg(msg)
				if err != nil {
					fmt.Println(err)
					return
				}
				if ret := fn(m); ret != 0 {
					return
				}
			}
		}
	}()

	return nil
}

// /include/uapi/linux/netfilter/nfnetlink.h:struct nfgenmsg{} res_id is Big Endian
func putExtraHeader(familiy, version uint8, resid uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, resid)
	return append([]byte{familiy, version}, buf...)
}

func (nfqueue *Nfqueue) setConfig(afFamily uint8, oseq uint32, resid uint16, attrs []netlink.Attribute) (uint32, error) {
	cmd, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return 0, err
	}
	data := putExtraHeader(afFamily, unix.NFNETLINK_V0, resid)
	data = append(data, cmd...)
	req := netlink.Message{
		Header: netlink.Header{
			Type:     netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgConfig),
			Flags:    netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge,
			Sequence: oseq,
		},
		Data: data,
	}
	return nfqueue.execute(req)
}

func (nfqueue *Nfqueue) execute(req netlink.Message) (uint32, error) {
	var seq uint32

	reply, e := nfqueue.Con.Execute(req)
	if e != nil {
		return 0, e
	}

	if e := netlink.Validate(req, reply); e != nil {
		return 0, e
	}
	for _, msg := range reply {
		if seq != 0 {
			return 0, fmt.Errorf("Received more than one message from the kernel")
		}
		seq = msg.Header.Sequence
	}

	return seq, nil
}

// ErrMsg as defined in nlmsgerr
type ErrMsg struct {
	Code  int
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

func unmarschalErrMsg(b []byte) (ErrMsg, error) {
	var msg ErrMsg

	msg.Code = int(nlenc.Uint32(b[0:4]))
	msg.Len = nlenc.Uint32(b[4:8])
	msg.Type = nlenc.Uint16(b[8:10])
	msg.Flags = nlenc.Uint16(b[10:12])
	msg.Seq = nlenc.Uint32(b[12:16])
	msg.Pid = nlenc.Uint32(b[16:20])

	return msg, nil
}

func parseMsg(msg netlink.Message) (Msg, error) {
	if msg.Header.Type&netlink.HeaderTypeError == netlink.HeaderTypeError {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%#v", errMsg)
	}
	m, err := extractAttributes(msg.Data)
	if err != nil {
		return nil, err
	}
	return m, nil
}
