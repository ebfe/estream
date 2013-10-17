package rabbit

import (
	"bytes"
	"testing"
)

func TestKeyStream(t *testing.T) {
	for i, tc := range tests {
		c, err := New(tc.key, tc.iv)
		if err != nil {
			t.Fatal("tests[%d]: New() err: %s\n", i, err)
		}

		lastchunk := tc.chunks[len(tc.chunks)-1]
		mlen := lastchunk.offset + len(lastchunk.val)
		ks := make([]byte, mlen)

		c.XORKeyStream(ks, ks)

		for j, chunk := range tc.chunks {
			kschunk := ks[chunk.offset : chunk.offset+len(chunk.val)]
			if !bytes.Equal(kschunk, chunk.val) {
				t.Errorf("tests[%d] chunk[%d]: ks = %x want %x\n", i, j, kschunk, chunk.val)
			}
		}
	}
}
