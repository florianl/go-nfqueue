package nfqueue

import (
	"errors"
	"log"
)

// HookFunc is a function, that receives events from a Netlinkgroup
// To stop receiving messages on this HookFunc, return something different than 0
type HookFunc func(m Msg) int

// Config contains options for a Conn.
type Config struct {
	// Network namespace the Nflog needs to operate in. If set to 0 (default),
	// no network namespace will be entered.
	NetNS int

	AfFamily uint8

	NfQueue uint16

	// Interface to log internals.
	Logger *log.Logger
}

// Various errors
var (
	ErrUnknownAttribute = errors.New("Received unsupported attribute")
	ErrAfFamily         = errors.New("Unsupported AF_Family type")
	ErrNoTimestamp      = errors.New("Timestamp was not set")
	ErrRecvMsg          = errors.New("Received error message")
	ErrUnexpMsg         = errors.New("Received unexpected message from kernel")
	ErrInvFlag          = errors.New("Invalid Flag")
	ErrNotLinux         = errors.New("Not implemented for OS other than linux")
	ErrInvalidVerdict   = errors.New("Invalid verdict")
)

// Msg contains all the information of a connection
type Msg map[int][]byte

// nfLogSubSysQueue the netlink subsystem we will query
const nfnlSubSysQueue = 0x03

// Various identifier,that can be the key of Msg map
const (
	AttrPacketID          = iota
	AttrHook              = iota
	AttrHwProtocol        = iota
	AttrIfIndexInDev      = iota
	AttrIfIndexOutDev     = iota
	AttrIfIndexPhysInDev  = iota
	AttrIfIndexPhysOutDev = iota
	AttrPayload           = iota
	AttrCapLen            = iota
	AttrTimestamp         = iota
	AttrHwAddr            = iota
	AttrMark              = iota
	AttrUID               = iota
	AttrGID               = iota
	AttrL2HDR             = iota
	AttrCt                = iota
	AttrCtInfo            = iota
	AttrSkbInfo           = iota
	AttrExp               = iota
	AttrSecCtx            = iota
	AttrVlanProto         = iota
	AttrVlanTCI           = iota
)

const (
	nfQaUnspec            = iota
	nfQaPacketHdr         = iota
	nfQaVerdictHdr        = iota /* nfqnl_msg_verdict_hrd */
	nfQaMark              = iota /* __u32 nfmark */
	nfQaTimestamp         = iota /* nfqnl_msg_packet_timestamp */
	nfQaIfIndexInDev      = iota /* __u32 ifindex */
	nfQaIfIndexOutDev     = iota /* __u32 ifindex */
	nfQaIfIndexPhysInDev  = iota /* __u32 ifindex */
	nfQaIfIndexPhysOutDev = iota /* __u32 ifindex */
	nfQaHwAddr            = iota /* nfqnl_msg_packet_hw */
	nfQaPayload           = iota /* opaque data payload */
	nfQaCt                = iota /* nf_conntrack_netlink.h */
	nfQaCtInfo            = iota /* enum ip_conntrack_info */
	nfQaCapLen            = iota /* __u32 length of captured packet */
	nfQaSkbInfo           = iota /* __u32 skb meta information */
	nfQaExp               = iota /* nf_conntrack_netlink.h */
	nfQaUID               = iota /* __u32 sk uid */
	nfQaGID               = iota /* __u32 sk gid */
	nfQaSecCtx            = iota /* security context string */
	nfQaVLAN              = iota /* nested attribute: packet vlan info */
	nfQaL2HDR             = iota /* full L2 header */
	nfMax                 = iota /* for internal use only */
)

const (
	nfQaCfgCmd         = 1 /* nfqnl_msg_config_cmd */
	nfQaCfgParams      = 2 /* nfqnl_msg_config_params */
	nfQaCfgQueueMaxLen = 3 /* __u32 */
	nfQaCfgMask        = 4 /* identify which flags to change */
	nfQaCfgFlags       = 5 /* value of these flags (__u32) */
)

const (
	nfUlnlCfgCmdBind     = 0x1
	nfUlnlCfgCmdUnbind   = 0x2
	nfUlnlCfgCmdPfBind   = 0x3
	nfUlnlCfgCmdPfUnbind = 0x4
)

const (
	nfQnlMsgVerdict      = 1 /* verdict from userspace to kernel */
	nfQnlMsgConfig       = 2 /* connect to a particular queue */
	nfQnlMsgVerdictBatch = 3 /* batchv from userspace to kernel */

)

// Various configuration flags
const (
	NfQaCfgFlagFailOpen  = (1 << iota)
	NfQaCfgFlagConntrack = (1 << iota)
	NfQaCfgFlagGSO       = (1 << iota)
	NfQaCfgFlagUidGid    = (1 << iota)
	NfQaCfgFlagSecCx     = (1 << iota)
	nfQaCfgFlagMax       = (1 << iota)
)

// copy modes
const (
	NfQnlCopyNone   = 0x0
	NfQnlCopyMeta   = 0x1
	NfQnlCopyPacket = 0x2
)

// Verdicts
const (
	NfDrop   = iota
	NfAccept = iota
	NfStolen = iota
	NfQeueue = iota
	NfRepeat = iota
)
