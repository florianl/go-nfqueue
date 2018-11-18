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

func extractAttribute(m Msg, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case nfQaPacketHdr:
			m[AttrPacketID] = binary.BigEndian.Uint32(ad.Bytes()[:4])
			m[AttrHwProtocol] = binary.BigEndian.Uint16(ad.Bytes()[4:6])
			m[AttrHook] = ad.Bytes()[6]
		case nfQaTimestamp:
			var sec, usec int64
			r := bytes.NewReader(ad.Bytes()[:8])
			if err := binary.Read(r, binary.BigEndian, &sec); err != nil {
				return err
			}
			r = bytes.NewReader(ad.Bytes()[8:])
			if err := binary.Read(r, binary.BigEndian, &usec); err != nil {
				return err
			}
			m[AttrTimestamp] = time.Unix(sec, usec*1000)
		case nfQaIfIndexInDev:
			m[AttrIfIndexInDev] = binary.BigEndian.Uint32(ad.Bytes())
		case nfQaIfIndexOutDev:
			m[AttrIfIndexOutDev] = binary.BigEndian.Uint32(ad.Bytes())
		case nfQaIfIndexPhysInDev:
			m[AttrIfIndexPhysInDev] = binary.BigEndian.Uint32(ad.Bytes())
		case nfQaIfIndexPhysOutDev:
			m[AttrIfIndexPhysOutDev] = binary.BigEndian.Uint32(ad.Bytes())
		case nfQaHwAddr:
			hwAddrLen := binary.BigEndian.Uint16(ad.Bytes()[:2])
			m[AttrHwAddr] = (ad.Bytes())[4 : 4+hwAddrLen]
		case nfQaPayload:
			m[AttrPayload] = ad.Bytes()
		case nfQaCt:
			m[AttrCt] = ad.Bytes()
		case nfQaCtInfo:
			m[AttrCtInfo] = ad.Bytes()
		case nfQaCapLen:
			m[AttrCapLen] = binary.BigEndian.Uint32(ad.Bytes())
		case nfQaSkbInfo:
			m[AttrSkbInfo] = ad.Bytes()
		case nfQaExp:
			m[AttrExp] = ad.Bytes()
		case nfQaUID:
			m[AttrUID] = binary.BigEndian.Uint32(ad.Bytes())
		case nfQaGID:
			m[AttrGID] = binary.BigEndian.Uint32(ad.Bytes())
		case nfQaSecCtx:
			m[AttrSecCtx] = ad.String()
		case nfQaL2HDR:
			m[AttrL2HDR] = ad.Bytes()
		default:
			return errors.Wrapf(ErrUnknownAttribute, "Attribute Type: 0x%x\tData: %v", ad.Type(), ad.Bytes())
		}
	}

	if err := ad.Err(); err != nil {
		return err
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
	var data = make(Msg)

	offset := checkHeader(msg[:2])
	if err := extractAttribute(data, msg[offset:]); err != nil {
		return nil, err
	}
	return data, nil
}
