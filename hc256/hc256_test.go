// Package hc256 implements the HC-256 stream cipher.
package hc256

import (
	"bytes"
	"testing"
)

func xordigest(msg []byte, n int) []byte {
	d := make([]byte, n)

	for i := range msg {
		d[i%len(d)] ^= msg[i]
	}

	return d
}

func TestKeyStream(t *testing.T) {
	for i, tc := range tests {
		c, err := New(tc.key, tc.iv)
		if err != nil {
			t.Fatalf("tests[%d]: New() err: %s\n", i, err)
		}

		lastchunk := tc.chunks[len(tc.chunks)-1]
		mlen := lastchunk.offset + len(lastchunk.val)
		ks := make([]byte, mlen)

		c.XORKeyStream(ks, ks)

		for j, chunk := range tc.chunks {
			kschunk := ks[chunk.offset : chunk.offset+len(chunk.val)]
			if !bytes.Equal(kschunk, chunk.val) {
				t.Errorf("tests[%d] chunk[%d]:\n\tks = %x\n\twant %x\n", i, j, kschunk, chunk.val)
			}
		}

		digest := xordigest(ks, len(tc.xor))
		if !bytes.Equal(digest, tc.xor) {
			t.Errorf("tests[%d] xor-digest = %x want %x\n", i, digest, tc.xor)
		}
	}
}
