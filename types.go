//+build linux

package nfqueue

import "errors"

// Various errors
var (
	ErrUnknownAttribute = errors.New("Received unsupported attribute")
	ErrAfFamily         = errors.New("Unsupported AF_Family type")
	ErrNoTimestamp      = errors.New("Timestamp was not set")
)

// Msg contains all the information of a connection
type Msg map[int][]byte

// nfLogSubSysQueue the netlink subsystem we will query
const nfnlSubSysQueue = 0x03

// Various identifier,that can be the key of Msg map
const (
	AttrPacketID          = iota
	AttrHwProtocol        = iota
	AttrIfIndexInDev      = iota
	AttrIfIndexOutDev     = iota
	AttrIfIndexPhysInDev  = iota
	AttrIfIndexPhysOutDev = iota
	AttrPayload           = iota
	AttrTimestamp         = iota
	AttrHwAddr            = iota
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
	nfQaCfgUnspec      = iota
	nfQaCfgCmd         = iota /* nfqnl_msg_config_cmd */
	nfQaCfgParams      = iota /* nfqnl_msg_config_params */
	nfQaCfgQueueMaxLen = iota /* __u32 */
	nfQaCfgMask        = iota /* identify which flags to change */
	nfQaCfgFlags       = iota /* value of these flags (__u32) */
)

const (
	nfUlnlCfgCmdNone     = 0x0
	nfUlnlCfgCmdBind     = 0x1
	nfUlnlCfgCmdUnbind   = 0x2
	nfUlnlCfgCmdPfBind   = 0x3
	nfUlnlCfgCmdPfUnbind = 0x4
)

const (
	nfQnlMsgPacket       = iota /* packet from kernel to userspace */
	nfQnlMsgVerdict      = iota /* verdict from userspace to kernel */
	nfQnlMsgConfig       = iota /* connect to a particular queue */
	nfQnlMsgVerdictBatch = iota /* batchv from userspace to kernel */

)

// Various configuration flags
const (
	NfQaCfgFlagFailOpen  = (1 << iota)
	NfQaCfgFlagConntrack = (1 << iota)
	NfQaCfgFlagGSO       = (1 << iota)
	NfQaCfgFlagUidGid    = (1 << iota)
	NfQaCfgFlagSecCx     = (1 << iota)
	NfQaCfgFlagMax       = (1 << iota)
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
