//+build !linux

package nfqueue

import (
	"context"
	"log"
)

// Nfqueue is not implemented for OS other than linux
type Nfqueue struct{}

// Open is not implemented for OS other than Linux
func Open() (*Nfqueue, error) {
	return nil, ErrNotLinux
}

// Close is not implemented for OS other than Linux
func (nfq *Nfqueue) Close() error {
	return ErrNotLinux
}

// Register is not implemented for OS other than Linux
func (nfq *Nfqueue) Register(_ context.Context, _ byte, _ *log.Logger, _ HookFunc) error {
	return ErrNotLinux
}

// SetFlag is not implemented for OS other than Linux
func (nfq *Nfqueue) SetFlag(_ uint32) error {
	return ErrNotLinux
}

// SetVerdict is not implemented for OS other than Linux
func (nfq *Nfqueue) SetVerdict(_, _ int) (uint32, error) {
	return 0, ErrNotLinux
}

// SetVerdictBatch is not implemented for OS other than Linux
func (nfq *Nfqueue) SetVerdictBatch(_, _ int) (uint32, error) {
	return 0, ErrNotLinux
}

// ShowFlags is not implemented for OS other than Linux
func (nfq *Nfqueue) ShowFlags() uint32 {
	return 0
}
