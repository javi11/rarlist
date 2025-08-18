package util

import "testing"

func TestDecodeRar3UnicodeSimple(t *testing.T) {
	if got := DecodeRar3Unicode([]byte("abc"), nil); got != "abc" {
		t.Fatalf("want abc got %s", got)
	}
}

func TestDecodeRar3UnicodeFlagPaths(t *testing.T) {
	if got := DecodeRar3Unicode([]byte("test"), []byte{0x00}); got != "test" {
		t.Fatalf("want test got %s", got)
	}
	if got := DecodeRar3Unicode([]byte{}, []byte{0x01, 'Z'}); got != "Z" {
		t.Fatalf("want Z got %s", got)
	}
	if got := DecodeRar3Unicode([]byte{}, []byte{0x03, 0x04, 0x02, 0x05}); got != string(rune(0x0405)) {
		t.Fatalf("unexpected %q", got)
	}
	if got := DecodeRar3Unicode([]byte("x"), []byte{0x80}); got != "x" {
		t.Fatalf("want x got %s", got)
	}
}
