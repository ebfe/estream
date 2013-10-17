// Package hc256 implements the HC-256 stream cipher.
package hc256

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

type hc256 struct {
	p [1024]uint32
	q [1024]uint32
	i uint64

	s  [4]byte
	ks []byte
}

func NewCipher(key, iv []byte) (cipher.Stream, error) {
	if len(key) != 32 {
		return nil, errors.New("hc256: invalid key length")
	}

	if len(iv) != 32 {
		return nil, errors.New("hc256: invalid iv length")
	}

	var h hc256

	h.init(key, iv)

	return &h, nil
}

func (h *hc256) init(key, iv []byte) {
	var w [2560]uint32

	for i := 0; i < 8; i++ {
		w[i] = binary.LittleEndian.Uint32(key[i*4:])
		w[i+8] = binary.LittleEndian.Uint32(iv[i*4:])
	}

	for i := 16; i < len(w); i++ {
		w[i] = f2(w[i-2]) + w[i-7] + f1(w[i-15]) + w[i-16] + uint32(i)
	}

	copy(h.p[:], w[512:])
	copy(h.q[:], w[1536:])

	for i := 0; i < 4096; i++ {
		h.extract()
	}

	h.i = 0
	h.ks = nil
}

func (h *hc256) extract() {

	var s uint32

	j := uint32(h.i % 1024)

	if h.i%2048 < 1024 {
		h.p[j] += h.p[mod1024(j-10)] + h.g1(h.p[mod1024(j-3)], h.p[mod1024(j-1023)])
		s = h.h1(h.p[mod1024(j-12)]) ^ h.p[j]
	} else {
		h.q[j] += h.q[mod1024(j-10)] + h.g2(h.q[mod1024(j-3)], h.q[mod1024(j-1023)])
		s = h.h2(h.q[mod1024(j-12)]) ^ h.q[j]
	}

	h.i++

	binary.LittleEndian.PutUint32(h.s[:], s)
	h.ks = h.s[:]
}

func (h *hc256) XORKeyStream(dst, src []byte) {
	for i := range src {
		if len(h.ks) == 0 {
			h.extract()
		}
		dst[i] = src[i] ^ h.ks[0]
		h.ks = h.ks[1:]
	}
}

func (h *hc256) h1(x uint32) uint32 {
	return h.q[byte(x)] + h.q[256+((x>>8)&0xff)] + h.q[512+((x>>16)&0xff)] + h.q[768+(x>>24)]
}

func (h *hc256) h2(x uint32) uint32 {
	return h.p[byte(x)] + h.p[256+((x>>8)&0xff)] + h.p[512+((x>>16)&0xff)] + h.p[768+(x>>24)]
}

func (h *hc256) g1(x, y uint32) uint32 {
	return rotr(x, 10) ^ rotr(y, 23) + h.q[(x^y)%1024]
}

func (h *hc256) g2(x, y uint32) uint32 {
	return rotr(x, 10) ^ rotr(y, 23) + h.p[(x^y)%1024]
}

func rotr(v, n uint32) uint32 {
	return (v >> n) | (v << (32 - n))
}

func f1(x uint32) uint32 {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

func f2(x uint32) uint32 {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

func mod1024(x uint32) uint32 {
	return x & ((1 << 10) - 1)
}
