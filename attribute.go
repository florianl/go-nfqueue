//+build linux

package nfqueue

import (
	"bytes"
	"encoding/binary"
	"log"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func extractAttribute(log *log.Logger, m Msg, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case nfQaPacketHdr:
			m[AttrPacketID] = binary.BigEndian.Uint32(ad.Bytes()[:4])
			m[AttrHwProtocol] = binary.BigEndian.Uint16(ad.Bytes()[4:6])
			m[AttrHook] = ad.Bytes()[6]
		case nfQaMark:
			m[AttrMark] = ad.Uint32()
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
			m[AttrIfIndexInDev] = ad.Uint32()
		case nfQaIfIndexOutDev:
			m[AttrIfIndexOutDev] = ad.Uint32()
		case nfQaIfIndexPhysInDev:
			m[AttrIfIndexPhysInDev] = ad.Uint32()
		case nfQaIfIndexPhysOutDev:
			m[AttrIfIndexPhysOutDev] = ad.Uint32()
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
			m[AttrCapLen] = ad.Uint32()
		case nfQaSkbInfo:
			m[AttrSkbInfo] = ad.Bytes()
		case nfQaExp:
			m[AttrExp] = ad.Bytes()
		case nfQaUID:
			m[AttrUID] = ad.Uint32()
		case nfQaGID:
			m[AttrGID] = ad.Uint32()
		case nfQaSecCtx:
			m[AttrSecCtx] = ad.String()
		case nfQaL2HDR:
			m[AttrL2HDR] = ad.Bytes()
		default:
			log.Printf("Unknown attribute Type: 0x%x\tData: %v\n", ad.Type(), ad.Bytes())
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

func extractAttributes(log *log.Logger, msg []byte) (Msg, error) {
	var data = make(Msg)

	offset := checkHeader(msg[:2])
	if err := extractAttribute(log, data, msg[offset:]); err != nil {
		return nil, err
	}
	return data, nil
}
