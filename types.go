package nfqueue

import (
	"errors"
	"log"
	"time"
)

// HookFunc is a function, that receives events from a Netlinkgroup
// To stop receiving messages on this HookFunc, return something different than 0
type HookFunc func(m Msg) int

// Config contains options for a Conn.
type Config struct {
	// Network namespace the Nfqueue needs to operate in. If set to 0 (default),
	// no network namespace will be entered.
	NetNS int

	// Queue this Nfqueue socket will be assigned to
	NfQueue uint16
	// Maximum number of packages within the Nfqueue.
	MaxQueueLen uint32

	// Only used in combination with NfQnlCopyPacket.
	MaxPacketLen uint32

	// Specifies how the kernel handles a packet in the nfqueue queue.
	Copymode uint8

	// Optional flags for this Nfqueue socket.
	Flags uint32

	// AfFamily for this Nfqueue socket.
	AfFamily uint8

	// Time till a read action times out - only available for Go >= 1.12
	ReadTimeout time.Duration

	// Time till a write action times out - only available for Go >= 1.12
	WriteTimeout time.Duration

	// Interface to log internals.
	Logger *log.Logger
}

// Various errors
var (
	ErrRecvMsg        = errors.New("Received error message")
	ErrUnexpMsg       = errors.New("Received unexpected message from kernel")
	ErrInvFlag        = errors.New("Invalid Flag")
	ErrNotLinux       = errors.New("Not implemented for OS other than linux")
	ErrInvalidVerdict = errors.New("Invalid verdict")
)

// Msg contains all the information of a connection
type Msg map[int]interface{}

// nfLogSubSysQueue the netlink subsystem we will query
const nfnlSubSysQueue = 0x03

// Various identifier,that can be the key of Msg map
const (
	AttrPacketID = iota
	AttrHook
	AttrHwProtocol
	AttrIfIndexInDev
	AttrIfIndexOutDev
	AttrIfIndexPhysInDev
	AttrIfIndexPhysOutDev
	AttrPayload
	AttrCapLen
	AttrTimestamp
	AttrHwAddr
	AttrMark
	AttrUID
	AttrGID
	AttrL2HDR
	AttrCt
	AttrCtInfo
	AttrSkbInfo
	AttrExp
	AttrSecCtx
	AttrVlanProto
	AttrVlanTCI
)

const (
	nfQaUnspec = iota
	nfQaPacketHdr
	nfQaVerdictHdr        /* nfqnl_msg_verdict_hrd */
	nfQaMark              /* __u32 nfmark */
	nfQaTimestamp         /* nfqnl_msg_packet_timestamp */
	nfQaIfIndexInDev      /* __u32 ifindex */
	nfQaIfIndexOutDev     /* __u32 ifindex */
	nfQaIfIndexPhysInDev  /* __u32 ifindex */
	nfQaIfIndexPhysOutDev /* __u32 ifindex */
	nfQaHwAddr            /* nfqnl_msg_packet_hw */
	nfQaPayload           /* opaque data payload */
	nfQaCt                /* nf_conntrack_netlink.h */
	nfQaCtInfo            /* enum ip_conntrack_info */
	nfQaCapLen            /* __u32 length of captured packet */
	nfQaSkbInfo           /* __u32 skb meta information */
	nfQaExp               /* nf_conntrack_netlink.h */
	nfQaUID               /* __u32 sk uid */
	nfQaGID               /* __u32 sk gid */
	nfQaSecCtx            /* security context string */
	nfQaVLAN              /* nested attribute: packet vlan info */
	nfQaL2HDR             /* full L2 header */
)

const (
	_                  = iota
	nfQaCfgCmd         /* nfqnl_msg_config_cmd */
	nfQaCfgParams      /* nfqnl_msg_config_params */
	nfQaCfgQueueMaxLen /* __u32 */
	nfQaCfgMask        /* identify which flags to change */
	nfQaCfgFlags       /* value of these flags (__u32) */
)

const (
	_ = iota
	nfUlnlCfgCmdBind
	nfUlnlCfgCmdUnbind
	nfUlnlCfgCmdPfBind
	nfUlnlCfgCmdPfUnbind
)

const (
	nfQnlMsgPacket       = iota
	nfQnlMsgVerdict      /* verdict from userspace to kernel */
	nfQnlMsgConfig       /* connect to a particular queue */
	nfQnlMsgVerdictBatch /* batch from userspace to kernel */

)

// Various configuration flags
const (
	NfQaCfgFlagFailOpen  = (1 << iota)
	NfQaCfgFlagConntrack = (1 << iota)
	NfQaCfgFlagGSO       = (1 << iota)
	NfQaCfgFlagUIDGid    = (1 << iota)
	NfQaCfgFlagSecCx     = (1 << iota)
	nfQaCfgFlagMax       = (1 << iota)
)

// copy modes
const (
	NfQnlCopyNone = iota
	NfQnlCopyMeta
	NfQnlCopyPacket
)

// Verdicts
const (
	NfDrop = iota
	NfAccept
	NfStolen
	NfQeueue
	NfRepeat
)
