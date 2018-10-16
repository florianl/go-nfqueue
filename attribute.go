//+build linux

package nfqueue

import (
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func extractAttribute(m Msg, data []byte) error {
	attributes, err := netlink.UnmarshalAttributes(data)

	if err != nil {
		return err
	}

	for _, attr := range attributes {
		if int(attr.Type) >= attrMax || int(attr.Type) == NfQaUnspec {
			return ErrUnknownAttribute
		}
		m[int(attr.Type)] = attr.Data
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
