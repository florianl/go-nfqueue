//go:build go1.20

package nfqueue

import "bytes"

func clone(b []byte) []byte {
	return bytes.Clone(b)
}
