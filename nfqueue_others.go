//+build !linux

package nfqueue

import (
	"context"
)

// Nfqueue is not implemented for OS other than linux
type Nfqueue struct{}

// Open is not implemented for OS other than Linux
func Open(_ *Config) (*Nfqueue, error) {
	return nil, ErrNotLinux
}

// Close is not implemented for OS other than Linux
func (nfq *Nfqueue) Close() error {
	return ErrNotLinux
}

// Register is not implemented for OS other than Linux
func (nfq *Nfqueue) Register(_ context.Context, _ HookFunc) error {
	return ErrNotLinux
}

// SetVerdict is not implemented for OS other than Linux
func (nfq *Nfqueue) SetVerdict(_ uint32, _ int) error {
	return ErrNotLinux
}

// SetVerdictBatch is not implemented for OS other than Linux
func (nfq *Nfqueue) SetVerdictBatch(_ uint32, _ int) error {
	return ErrNotLinux
}

// SetVerdictWithMark is not implemented for OS other than Linux
func (nfq *Nfqueue) SetVerdictWithMark(_ uint32, _, _ int) error {
	return ErrNotLinux
}
