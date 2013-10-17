// Package hc128 implements the HC-128 stream cipher.
package hc128

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

type hc128 struct {
	p [512]uint32
	q [512]uint32
	i uint64

	s  [4]byte
	ks []byte
}

func NewCipher(key, iv []byte) (cipher.Stream, error) {
	if len(key) != 16 {
		return nil, errors.New("hc128: invalid key length")
	}

	if len(iv) != 16 {
		return nil, errors.New("hc128: invalid iv length")
	}

	var h hc128

	h.init(key, iv)

	return &h, nil
}

func (h *hc128) init(key, iv []byte) {
	var w [1280]uint32

	for i := 0; i < 8; i++ {
		w[i] = binary.LittleEndian.Uint32(key[(i*4)%16:])
		w[i+8] = binary.LittleEndian.Uint32(iv[(i*4)%16:])
	}

	for i := 16; i < len(w); i++ {
		w[i] = f2(w[i-2]) + w[i-7] + f1(w[i-15]) + w[i-16] + uint32(i)
	}

	copy(h.p[:], w[256:])
	copy(h.q[:], w[768:])

	for i := uint32(0); i < 512; i++ {
		h.p[i] = (h.p[i] + g1(h.p[mod512(i-3)], h.p[mod512(i-10)], h.p[mod512(i-511)])) ^ h.h1(h.p[mod512(i-12)])
	}
	for i := uint32(0); i < 512; i++ {
		h.q[i] = (h.q[i] + g2(h.q[mod512(i-3)], h.q[mod512(i-10)], h.q[mod512(i-511)])) ^ h.h2(h.q[mod512(i-12)])
	}
}

func (h *hc128) extract() {

	var s uint32

	j := uint32(h.i % 512)

	if h.i%1024 < 512 {
		h.p[j] += g1(h.p[mod512(j-3)], h.p[mod512(j-10)], h.p[mod512(j-511)])
		s = h.h1(h.p[mod512(j-12)]) ^ h.p[j]
	} else {
		h.q[j] += g2(h.q[mod512(j-3)], h.q[mod512(j-10)], h.q[mod512(j-511)])
		s = h.h2(h.q[mod512(j-12)]) ^ h.q[j]
	}

	h.i++

	binary.LittleEndian.PutUint32(h.s[:], s)
	h.ks = h.s[:]
}

func (h *hc128) XORKeyStream(dst, src []byte) {
	for i := range src {
		if len(h.ks) == 0 {
			h.extract()
		}
		dst[i] = src[i] ^ h.ks[0]
		h.ks = h.ks[1:]
	}
}

func (h *hc128) h1(x uint32) uint32 {
	return h.q[byte(x)] + h.q[256+((x>>16)&0xff)]
}

func (h *hc128) h2(x uint32) uint32 {
	return h.p[byte(x)] + h.p[256+((x>>16)&0xff)]
}

func rotl(v, n uint32) uint32 {
	return (v << n) | (v >> (32 - n))
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

func g1(x, y, z uint32) uint32 {
	return rotr(x, 10) ^ rotr(z, 23) + rotr(y, 8)
}

func g2(x, y, z uint32) uint32 {
	return rotl(x, 10) ^ rotl(z, 23) + rotl(y, 8)
}

func mod512(x uint32) uint32 {
	return x & ((1 << 9) - 1)
}
