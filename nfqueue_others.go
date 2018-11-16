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
func (nfe *Nfqueue) Register(_ context.Context, _ byte, _ HookFunc) error {
	return ErrNotLinux
}

// SetFlag is not implemented for OS other than Linux
func (nfq *Nfqueue) SetFlag(_ uint32) error {
	return ErrNotLinux
}

// SetVerdict is not implemented for OS other than Linux
func (nfq *Nfqueue) SetVerdict(_, _ int) error {
	return ErrNotLinux
}

// SetVerdictBatch is not implemented for OS other than Linux
func (nfq *Nfqueue) SetVerdictBatch(_, _ int) error {
	return ErrNotLinux
}

// SetVerdictWithMark is not implemented for OS other than Linux
func (nfqueue *Nfqueue) SetVerdictWithMark(_, _, _ int) error {
	return ErrNotLinux
}

// ShowFlags is not implemented for OS other than Linux
func (nfq *Nfqueue) ShowFlags() uint32 {
	return 0
}
