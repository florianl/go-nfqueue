package nfqueue

import (
	"os"
	"testing"
)

func TestMnlSocketBufferSize(t *testing.T) {
	tests := []struct {
		pageSize int
		want     int
	}{
		{4096, 4096},
		{8192, 8192},
		{16384, 8192},
		{65536, 8192},
	}
	for _, tc := range tests {
		if got := mnlSocketBufferSize(tc.pageSize); got != tc.want {
			t.Errorf("mnlSocketBufferSize(%d) = %d, want %d", tc.pageSize, got, tc.want)
		}
	}
}

func TestMessageBufferSize(t *testing.T) {
	overhead := mnlSocketBufferSize(os.Getpagesize()) / 2
	tests := []struct {
		name   string
		config Config
		want   int
	}{
		{"no packet copy", Config{Copymode: NfQnlCopyMeta, MaxPacketLen: 1500}, overhead},
		{"packet copy within range", Config{Copymode: NfQnlCopyPacket, MaxPacketLen: 1500}, overhead + 1500},
		{"packet copy defaults to max", Config{Copymode: NfQnlCopyPacket}, overhead + 65531},
		{"packet copy clamped to max", Config{Copymode: NfQnlCopyPacket, MaxPacketLen: 1 << 20}, overhead + 65531},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := messageBufferSize(&tc.config); got != tc.want {
				t.Errorf("messageBufferSize() = %d, want %d", got, tc.want)
			}
		})
	}
}
