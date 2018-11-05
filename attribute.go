//+build linux

package nfqueue

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// Timestamp returns the timestamp of the message
func (m *Msg) Timestamp() (time.Time, error) {
	/*
		struct nfulnl_msg_packet_timestamp {
		__aligned_be64	sec;
		__aligned_be64	usec;
		};
	*/
	var sec, usec int64
	data := (*m)[AttrTimestamp]
	if len(data) == 0 {
		return time.Unix(0, 0), ErrNoTimestamp
	}
	r := bytes.NewReader(data[:8])
	if err := binary.Read(r, binary.BigEndian, &sec); err != nil {
		return time.Unix(0, 0), err
	}
	r = bytes.NewReader(data[8:])
	if err := binary.Read(r, binary.BigEndian, &usec); err != nil {
		return time.Unix(0, 0), err
	}
	return time.Unix(sec, usec*1000), nil
}

func extractAttribute(m Msg, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)

	if err != nil {
		return err
	}

	for _, attr := range attributes {
		if int(attr.Type) >= nfMax || int(attr.Type) == nfQaUnspec {
			return ErrUnknownAttribute
		}
		switch attr.Type {
		case nfQaPacketHdr:
			m[AttrPacketID] = (attr.Data)[:4]
			m[AttrHwProtocol] = (attr.Data)[4:6]
		case nfQaIfIndexInDev:
			m[AttrIfIndexInDev] = attr.Data
		case nfQaIfIndexOutDev:
			m[AttrIfIndexOutDev] = attr.Data
		case nfQaIfIndexPhysInDev:
			m[AttrIfIndexPhysInDev] = attr.Data
		case nfQaIfIndexPhysOutDev:
			m[AttrIfIndexPhysOutDev] = attr.Data
		case nfQaPayload:
			m[AttrPayload] = attr.Data
		case nfQaTimestamp:
			m[AttrTimestamp] = attr.Data
		case nfQaHwAddr:
			hwAddrLen := binary.BigEndian.Uint16(attr.Data[:2])
			m[AttrHwAddr] = (attr.Data)[4 : 4+hwAddrLen]
		case nfQaMark:
			m[AttrMark] = attr.Data
		case nfQaUID:
			m[AttrUID] = attr.Data
		case nfQaGID:
			m[AttrGID] = attr.Data
		case nfQaCtInfo:
			m[AttrCtInfo] = attr.Data
		case nfQaSecCtx:
			m[AttrSecCtx] = attr.Data
		case nfQaCapLen:
			m[AttrCapLen] = attr.Data
		case nfQaL2HDR:
			m[AttrL2HDR] = attr.Data
		default:
			return errors.Wrapf(ErrUnknownAttribute, "Attribute Type: 0x%x", attr.Type)
		}
	}
	return nil
}

func checkHeader(data []byte) int {
	if (data[0] == unix.AF_INET || data[0] == unix.AF_INET6) && data[1] == unix.NFNETLINK_V0 {
		return 4
	}
	return 0
}

func extractAttributes(msg []byte) (Msg, error) {
	var data = make(map[int][]byte)

	offset := checkHeader(msg[:2])
	if err := extractAttribute(data, msg[offset:]); err != nil {
		return nil, err
	}
	return data, nil
}
