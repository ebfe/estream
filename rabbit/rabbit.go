// Package rabbit implements the Rabbit stream cipher
package rabbit

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

var (
	_A = []uint32{
		0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
		0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3,
	}
)

type rabbit struct {
	x     [8]uint32
	c     [8]uint32
	carry uint32
	s     [16]byte
	ks    []byte
}

func New(key []byte, iv []byte) (cipher.Stream, error) {

	if len(key) != 16 {
		return nil, errors.New("rabbit: invalid key length")
	}

	if len(iv) != 0 && len(iv) != 8 {
		return nil, errors.New("rabbit: invalid iv length")
	}

	var k [4]uint32

	for i := range k {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}

	var r rabbit

	r.setupKey(k[:])

	if len(iv) != 0 {
		var v [4]uint16
		for i := range v {
			v[i] = binary.LittleEndian.Uint16(iv[i*2:])
		}
		r.setupIV(v[:])
	}

	return &r, nil
}

func (r *rabbit) setupKey(key []uint32) {

	r.x[0] = key[0]
	r.x[1] = key[3]<<16 | key[2]>>16
	r.x[2] = key[1]
	r.x[3] = key[0]<<16 | key[3]>>16
	r.x[4] = key[2]
	r.x[5] = key[1]<<16 | key[0]>>16
	r.x[6] = key[3]
	r.x[7] = key[2]<<16 | key[1]>>16

	r.c[0] = rotl(key[2], 16)
	r.c[1] = key[0] & 0xffff0000 | key[1] & 0xffff
	r.c[2] = rotl(key[3], 16)
	r.c[3] = key[1] & 0xffff0000 | key[2] & 0xffff
	r.c[4] = rotl(key[0], 16)
	r.c[5] = key[2] & 0xffff0000 | key[3] & 0xffff
	r.c[6] = rotl(key[1], 16)
	r.c[7] = key[3] & 0xffff0000 | key[0] & 0xffff

	for i := 0; i < 4; i++ {
		r.nextState()
	}

	r.c[0] ^= r.x[4]
	r.c[1] ^= r.x[5]
	r.c[2] ^= r.x[6]
	r.c[3] ^= r.x[7]
	r.c[4] ^= r.x[0]
	r.c[5] ^= r.x[1]
	r.c[6] ^= r.x[2]
	r.c[7] ^= r.x[3]
}

func (r *rabbit) setupIV(iv []uint16) {
	r.c[0] ^= uint32(iv[1])<<16 | uint32(iv[0])
	r.c[1] ^= uint32(iv[3])<<16 | uint32(iv[1])
	r.c[2] ^= uint32(iv[3])<<16 | uint32(iv[2])
	r.c[3] ^= uint32(iv[2])<<16 | uint32(iv[0])
	r.c[4] ^= uint32(iv[1])<<16 | uint32(iv[0])
	r.c[5] ^= uint32(iv[3])<<16 | uint32(iv[1])
	r.c[6] ^= uint32(iv[3])<<16 | uint32(iv[2])
	r.c[7] ^= uint32(iv[2])<<16 | uint32(iv[0])

	for i := 0; i < 4; i++ {
		r.nextState()
	}
}

func (r *rabbit) nextState() {
	var G [8]uint32

	for i := range r.c {
		r.carry, r.c[i] = adc32(_A[i], r.c[i], r.carry)
	}

	for i := range G {
		G[i] = g(r.x[i], r.c[i])
	}

	r.x[0] = G[0] + rotl(G[7], 16) + rotl(G[6], 16)
	r.x[1] = G[1] + rotl(G[0], 8) + G[7]
	r.x[2] = G[2] + rotl(G[1], 16) + rotl(G[0], 16)
	r.x[3] = G[3] + rotl(G[2], 8) + G[1]
	r.x[4] = G[4] + rotl(G[3], 16) + rotl(G[2], 16)
	r.x[5] = G[5] + rotl(G[4], 8) + G[3]
	r.x[6] = G[6] + rotl(G[5], 16) + rotl(G[4], 16)
	r.x[7] = G[7] + rotl(G[6], 8) + G[5]
}

func (r *rabbit) extract() {
	var sw [4]uint32

	r.nextState()

	// extract keystream
	sw[0] = r.x[0] ^ (r.x[5] >> 16 | r.x[3] << 16)
	sw[1] = r.x[2] ^ (r.x[7] >> 16 | r.x[5] << 16)
	sw[2] = r.x[4] ^ (r.x[1] >> 16 | r.x[7] << 16)
	sw[3] = r.x[6] ^ (r.x[3] >> 16 | r.x[1] << 16)

	for i := range sw {
		binary.LittleEndian.PutUint32(r.s[i*4:], sw[i])
	}
	r.ks = r.s[:]
}

func (r *rabbit) XORKeyStream(dst, src []byte) {
	for i := range src {
		if len(r.ks) == 0 {
			r.extract()
		}
		dst[i] = src[i] ^ r.ks[0]
		r.ks = r.ks[1:]
	}
}


func g(u, v uint32) uint32 {
	uv := uint64(u+v)
	uv *= uv
	return uint32(uv>>32) ^ uint32(uv)
}

func adc32(a, b, c uint32) (uint32, uint32) {
	x := uint64(a) + uint64(b) + uint64(c)
	return uint32(x >> 32), uint32(x)
}

func rotl(v, s uint32) uint32 {
	return (v << s) | (v >> (32 - s))
}
