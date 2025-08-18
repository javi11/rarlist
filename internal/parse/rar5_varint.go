package parse

import (
	"bufio"
	"errors"
	"io"
)

// ReadVarintFromSlice reads a RAR5 varint from a byte slice.
func ReadVarintFromSlice(b []byte) (uint64, int64, error) {
	var val uint64
	var n int64
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		val |= uint64(c&0x7F) << (7 * i)
		n++
		if c&0x80 == 0 {
			return val, n, nil
		}
	}
	if n == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return 0, n, errors.New("varint too long or truncated")
}

// ReadVarint reads RAR5 variable-length integer directly from reader.
func ReadVarint(br *bufio.Reader) (value uint64, n int64, err error) {
	for i := 0; i < 10; i++ {
		b, e := br.ReadByte()
		if e != nil {
			err = e
			return
		}
		value |= uint64(b&0x7f) << (7 * i)
		n++
		if b&0x80 == 0 {
			return
		}
	}
	err = errors.New("varint too long")
	return
}
