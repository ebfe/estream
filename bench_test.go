package estream_test

import (
	"crypto/cipher"
	"testing"

	"github.com/ebfe/estream/hc128"
	"github.com/ebfe/estream/hc256"
	"github.com/ebfe/estream/rabbit"
)

func benchStream(b *testing.B, c cipher.Stream) {
	buf := make([]byte, 1024)

	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
	b.StopTimer()
}

func BenchmarkHC128(b *testing.B) {
	c, err := hc128.NewCipher(make([]byte, 16), make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	benchStream(b, c)
}

func BenchmarkHC256(b *testing.B) {
	c, err := hc256.NewCipher(make([]byte, 32), make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	benchStream(b, c)
}

func BenchmarkRabbit(b *testing.B) {
	c, err := rabbit.NewCipher(make([]byte, 16), make([]byte, 8))
	if err != nil {
		b.Fatal(err)
	}
	benchStream(b, c)
}
