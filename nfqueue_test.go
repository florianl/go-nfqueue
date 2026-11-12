package nfqueue

import "testing"

func TestMessageBufferSize(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   int
	}{
		{"no packet copy", Config{Copymode: NfQnlCopyMeta, MaxPacketLen: 1500}, 4096},
		{"packet copy within range", Config{Copymode: NfQnlCopyPacket, MaxPacketLen: 1500}, 4096 + 1500},
		{"packet copy defaults to max", Config{Copymode: NfQnlCopyPacket}, 4096 + 65531},
		{"packet copy clamped to max", Config{Copymode: NfQnlCopyPacket, MaxPacketLen: 1 << 20}, 4096 + 65531},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := messageBufferSize(&tc.config); got != tc.want {
				t.Errorf("messageBufferSize() = %d, want %d", got, tc.want)
			}
		})
	}
}
