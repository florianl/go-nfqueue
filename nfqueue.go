//+build linux

package nfqueue

import (
	"context"
	"encoding/binary"
	"log"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Nfqueue represents a netfilter queue handler
type Nfqueue struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	flags        []byte // uint32
	flagsMask    []byte // uint32
	maxPacketLen []byte // uint32
	family       uint8
	queue        uint16
	maxQueueLen  []byte // uint32

	verdicts []netlink.Message
}

// devNull satisfies io.Writer, in case *log.Logger is not provided
type devNull struct{}

func (devNull) Write(p []byte) (int, error) {
	return 0, nil
}

// Open a connection to the netfilter queue subsystem
func Open(config *Config) (*Nfqueue, error) {
	var nfqueue Nfqueue

	if config.AfFamily != unix.AF_INET6 && config.AfFamily != unix.AF_INET {
		return nil, ErrAfFamily
	}

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: config.NetNS})
	if err != nil {
		return nil, err
	}
	nfqueue.Con = con
	// default size of copied packages to userspace
	nfqueue.maxPacketLen = []byte{0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(nfqueue.maxPacketLen, config.MaxPacketLen)
	nfqueue.flags = nlenc.Uint32Bytes(config.Flags)
	nfqueue.flagsMask = nlenc.Uint32Bytes(config.FlagsMask)
	nfqueue.family = config.AfFamily
	nfqueue.queue = config.NfQueue
	nfqueue.maxQueueLen = nlenc.Uint32Bytes(config.MaxQueueLen)
	if config.Logger == nil {
		nfqueue.logger = log.New(new(devNull), "", 0)
	} else {
		nfqueue.logger = config.Logger
	}

	return &nfqueue, nil
}

// Close the connection to the netfilter queue subsystem
func (nfqueue *Nfqueue) Close() error {
	return nfqueue.Con.Close()
}

// SetVerdictWithMark signals the kernel the next action and the mark for a specified package id
func (nfqueue *Nfqueue) SetVerdictWithMark(id, verdict, mark int) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(mark))
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: nfQaMark,
		Data: buf,
	}})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, attributes)
}

// SetVerdict signals the kernel the next action for a specified package id
func (nfqueue *Nfqueue) SetVerdict(id, verdict int) error {
	return nfqueue.setVerdict(id, verdict, false, []byte{})
}

// SetVerdictBatch signals the kernel the next action for a batch of packages till id
func (nfqueue *Nfqueue) SetVerdictBatch(id, verdict int) error {
	return nfqueue.setVerdict(id, verdict, true, []byte{})
}

func (nfqueue *Nfqueue) setVerdict(id, verdict int, batch bool, attributes []byte) error {
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
			Flags:    netlink.HeaderFlagsRequest,
			Sequence: 0,
		},
		Data: data,
	}
	if batch {
		req.Header.Type = netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgVerdictBatch)
	} else {
		req.Header.Type = netlink.HeaderType((nfnlSubSysQueue << 8) | nfQnlMsgVerdict)
	}

	nfqueue.verdicts = append(nfqueue.verdicts, req)

	return nil
}

// Register your own function as callback for a netfilter queue
func (nfqueue *Nfqueue) Register(ctx context.Context, copyMode byte, fn HookFunc) error {

	// unbinding existing handler (if any)
	seq, err := nfqueue.setConfig(unix.AF_UNSPEC, 0, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return errors.Wrapf(err, "Could not unbind existing handlers (if any)")
	}

	// binding to family
	_, err = nfqueue.setConfig(unix.AF_UNSPEC, seq, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return errors.Wrapf(err, "Could not bind to family %d", nfqueue.family)
	}

	// binding to the requested queue
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdBind, 0x0, 0x0, 0x0}},
	})
	if err != nil {
		return errors.Wrapf(err, "Could not bind to requested queue %d", nfqueue.queue)
	}

	// set copy mode and buffer size
	data := append(nfqueue.maxPacketLen, copyMode)
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
		{Type: nfQaCfgParams, Data: data},
	})
	if err != nil {
		return err
	}

	var attrs []netlink.Attribute
	if nfqueue.flags[0] != 0 || nfqueue.flags[1] != 0 || nfqueue.flags[2] != 0 || nfqueue.flags[3] != 0 {
		// set flags
		attrs = append(attrs, netlink.Attribute{Type: nfQaCfgFlags, Data: nfqueue.flags})
		attrs = append(attrs, netlink.Attribute{Type: nfQaCfgMask, Data: nfqueue.flags})
	}
	attrs = append(attrs, netlink.Attribute{Type: nfQaCfgQueueMaxLen, Data: nfqueue.maxQueueLen})

	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, attrs)
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
				nfqueue.logger.Fatalf("Could not unbind from queue: %v", err)
				return
			}
		}()
		for {
			if err := nfqueue.sendVerdicts(); err != nil {
				return
			}
			replys, err := nfqueue.Con.Receive()
			if err != nil {
				return
			}
			for _, msg := range replys {
				if msg.Header.Type == netlink.HeaderTypeDone {
					// this is the last message of a batch
					// continue to receive messages
					break
				}
				m, err := parseMsg(msg)
				if err != nil {
					nfqueue.logger.Fatalf("Could not parse message: %v", err)
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
			return 0, errors.Wrapf(ErrUnexpMsg, "Number of received messages: %d", len(reply))
		}
		seq = msg.Header.Sequence
	}

	return seq, nil
}

func (nfqueue *Nfqueue) sendVerdicts() error {
	if len(nfqueue.verdicts) == 0 {
		return nil
	}
	_, err := nfqueue.Con.SendMessages(nfqueue.verdicts)
	if err != nil {
		nfqueue.logger.Fatalf("Could not send verdict: %v", err)
		return err
	}
	nfqueue.verdicts = []netlink.Message{}

	return nil
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
		return nil, errors.Wrapf(ErrRecvMsg, "%#v", errMsg)
	}
	m, err := extractAttributes(msg.Data)
	if err != nil {
		return nil, err
	}
	return m, nil
}
