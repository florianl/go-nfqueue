package nfqueue

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/florianl/go-nfqueue/internal/unix"

	"github.com/mdlayher/netlink"
)

// devNull satisfies io.Writer, in case *log.Logger is not provided
type devNull struct{}

func (devNull) Write(p []byte) (int, error) {
	return 0, nil
}

// Close the connection to the netfilter queue subsystem
func (nfqueue *Nfqueue) Close() error {
	err := nfqueue.Con.Close()
	nfqueue.wg.Wait()
	return err
}

// SetVerdictWithMark signals the kernel the next action and the mark for a specified package id
func (nfqueue *Nfqueue) SetVerdictWithMark(id uint32, verdict, mark int) error {
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

// SetVerdictWithConnMark signals the kernel the next action and the connmark for a specified package id
func (nfqueue *Nfqueue) SetVerdictWithConnMark(id uint32, verdict, mark int) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(mark))
	ctAttrs, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: ctaMark,
		Data: buf,
	}})
	if err != nil {
		return err
	}
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: netlink.Nested | nfQaCt,
		Data: ctAttrs,
	}})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, attributes)
}

// SetVerdictModPacket signals the kernel the next action for an altered packet
func (nfqueue *Nfqueue) SetVerdictModPacket(id uint32, verdict int, packet []byte) error {
	data, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: nfQaPayload,
		Data: packet,
	}})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, data)
}

// SetVerdictModPacketWithMark signals the kernel the next action and mark for an altered packet
func (nfqueue *Nfqueue) SetVerdictModPacketWithMark(id uint32, verdict, mark int, packet []byte) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(mark))
	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: nfQaPayload,
			Data: packet,
		},
		{
			Type: nfQaMark,
			Data: buf,
		},
	})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, data)
}

// SetVerdictModPacketWithConnMark signals the kernel the next action and connmark for an altered packet
func (nfqueue *Nfqueue) SetVerdictModPacketWithConnMark(id uint32, verdict, mark int, packet []byte) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(mark))
	ctAttrs, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: ctaMark,
		Data: buf,
	}})
	if err != nil {
		return err
	}
	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: nfQaPayload,
			Data: packet,
		},
		{
			Type: netlink.Nested | nfQaCt,
			Data: ctAttrs,
		},
	})
	if err != nil {
		return err
	}
	return nfqueue.setVerdict(id, verdict, false, data)
}

// SetVerdict signals the kernel the next action for a specified package id
func (nfqueue *Nfqueue) SetVerdict(id uint32, verdict int) error {
	return nfqueue.setVerdict(id, verdict, false, []byte{})
}

// SetVerdictBatch signals the kernel the next action for a batch of packages till id
func (nfqueue *Nfqueue) SetVerdictBatch(id uint32, verdict int) error {
	return nfqueue.setVerdict(id, verdict, true, []byte{})
}

// SetOption allows to enable or disable netlink socket options.
func (nfqueue *Nfqueue) SetOption(o netlink.ConnOption, enable bool) error {
	return nfqueue.Con.SetOption(o, enable)
}

// Register your own function as callback for a netfilter queue.
//
// The registered callback will stop receiving data if an error
// happened. To handle errors and continue receiving data with the
// registered callback use RegisterWithErrorFunc() instead.
//
// Deprecated: Use RegisterWithErrorFunc() instead.
func (nfqueue *Nfqueue) Register(ctx context.Context, fn HookFunc) error {
	return nfqueue.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		nfqueue.logger.Printf("Could not receive message: %v\n", err)
		return 1
	})
}

// RegisterWithErrorFunc attaches a callback function to a netfilter queue and allows
// custom error handling for errors encountered when reading from the underlying netlink socket.
func (nfqueue *Nfqueue) RegisterWithErrorFunc(ctx context.Context, fn HookFunc, errfn ErrorFunc) error {
	// unbinding existing handler (if any)
	seq, err := nfqueue.setConfig(unix.AF_UNSPEC, 0, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfUnbind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return fmt.Errorf("could not unbind existing handlers (if any): %w", err)
	}

	// binding to family
	_, err = nfqueue.setConfig(unix.AF_UNSPEC, seq, 0, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdPfBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return fmt.Errorf("could not bind to family %d: %w", nfqueue.family, err)
	}

	// binding to the requested queue
	_, err = nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
		{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdBind, 0x0, 0x0, byte(nfqueue.family)}},
	})
	if err != nil {
		return fmt.Errorf("could not bind to requested queue %d: %w", nfqueue.queue, err)
	}

	// set copy mode and buffer size
	data := append(nfqueue.maxPacketLen, nfqueue.copymode)
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

	nfqueue.wg.Add(1)
	go func() {
		defer nfqueue.wg.Done()
		nfqueue.socketCallback(ctx, fn, errfn, seq)
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
			Flags:    netlink.Request | netlink.Acknowledge,
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
			return 0, fmt.Errorf("number of received messages: %d: %w", len(reply), ErrUnexpMsg)
		}
		seq = msg.Header.Sequence
	}

	return seq, nil
}

func parseMsg(log *log.Logger, msg netlink.Message) (Attribute, error) {
	a, err := extractAttributes(log, msg.Data)
	if err != nil {
		return a, err
	}
	return a, nil
}

// Nfqueue represents a netfilter queue handler
type Nfqueue struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	wg sync.WaitGroup

	flags        []byte // uint32
	maxPacketLen []byte // uint32
	family       uint8
	queue        uint16
	maxQueueLen  []byte // uint32
	copymode     uint8

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
		nfqueue.logger.Printf("could not set write timeout: %v\n", err)
	}
	_, sErr := nfqueue.Con.Send(req)
	return sErr
}

func (nfqueue *Nfqueue) socketCallback(ctx context.Context, fn HookFunc, errfn ErrorFunc, seq uint32) {
	defer func() {
		// unbinding from queue
		_, err := nfqueue.setConfig(uint8(unix.AF_UNSPEC), seq, nfqueue.queue, []netlink.Attribute{
			{Type: nfQaCfgCmd, Data: []byte{nfUlnlCfgCmdUnbind, 0x0, 0x0, byte(nfqueue.family)}},
		})
		if err != nil {
			nfqueue.logger.Printf("Could not unbind from queue: %v\n", err)
		}
	}()

	nfqueue.wg.Add(1)
	go func() {
		defer nfqueue.wg.Done()

		// block until context is done
		<-ctx.Done()
		// Set the read deadline to a point in the past to interrupt
		// possible blocking Receive() calls.
		nfqueue.Con.SetReadDeadline(time.Now().Add(-1 * time.Second))
	}()

	for {
		if err := ctx.Err(); err != nil {
			nfqueue.logger.Printf("Stop receiving nfqueue messages: %v\n", err)
			return
		}
		replys, err := nfqueue.Con.Receive()
		if err != nil {
			if ret := errfn(err); ret != 0 {
				return
			}
			continue
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
	}
}
