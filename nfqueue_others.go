//+build !linux

package nfqueue

import "errors"

var errNotLinux = errors.New("Not implemented for OS other than linux")

// Nfqueue is not implemented for OS other than linux
type Nfqueue struct{}

// Open is not implemented for OS other than Linux
func Open() (*Nfqueue, error) {
	return nil, errNotLinux
}

// Close is not implemented for OS other than Linux
func (_ *Nfqueue) Close() error {
	return errNotLinux
}
