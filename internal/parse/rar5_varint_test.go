package parse

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func TestReadVarintSuccess(t *testing.T) {
	b := bytes.NewBuffer([]byte{0xAC, 0x02}) // 300
	br := bufio.NewReader(b)
	v, n, err := ReadVarint(br)
	if err != nil || v != 300 || n != 2 {
		t.Fatalf("unexpected v=%d n=%d err=%v", v, n, err)
	}
}

func TestReadVarintEOF(t *testing.T) {
	br := bufio.NewReader(bytes.NewBuffer(nil))
	if _, _, err := ReadVarint(br); err == nil {
		t.Fatalf("expected EOF error")
	}
}

func TestReadVarintTooLong(t *testing.T) {
	// 10 continuation bytes triggers too long
	br := bufio.NewReader(bytes.NewBuffer(bytes.Repeat([]byte{0x80}, 10)))
	_, _, err := ReadVarint(br)
	if err == nil {
		t.Fatalf("expected too long error")
	}
}

func TestReadVarintFromSliceCases(t *testing.T) {
	if v, n, err := ReadVarintFromSlice([]byte{0xAC, 0x02}); err != nil || v != 300 || n != 2 {
		t.Fatalf("slice success fail v=%d n=%d err=%v", v, n, err)
	}
	if _, _, err := ReadVarintFromSlice([]byte{}); err == nil {
		t.Fatalf("expected empty error")
	}
	if _, n, err := ReadVarintFromSlice(bytes.Repeat([]byte{0x80}, 9)); err == nil || n != 9 {
		t.Fatalf("expected truncated err n=%d err=%v", n, err)
	}
	if _, n, err := ReadVarintFromSlice(bytes.Repeat([]byte{0x80}, 10)); err == nil || n != 10 {
		t.Fatalf("expected too long err n=%d err=%v", n, err)
	}
}

// Ensure io imported
var _ io.Reader
