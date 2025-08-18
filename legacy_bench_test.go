package rarlist

import (
	"bytes"
	"fmt"
	"io/fs"
	"testing"
	"time"
)

// local helper (duplicated from tests) to build a minimal legacy-style RAR3 file header
func benchBuildRar3FileHeader(name string, packSize, unpSize uint32) []byte {
	nameBytes := []byte(name)
	nameLen := len(nameBytes)
	headerSize := 7 + 25 + nameLen // basic size
	b := make([]byte, 0, headerSize)
	b = append(b, 0x00, 0x00)             // CRC
	b = append(b, 0x74)                   // type file
	b = append(b, 0x00, 0x00)             // flags
	b = append(b, byte(headerSize), 0x00) // size (little endian, assume <256)
	fixed := make([]byte, 25)
	fixed[0] = byte(packSize)
	fixed[4] = byte(unpSize)
	fixed[18] = 0x30 // stored method
	fixed[19] = byte(nameLen)
	fixed[20] = 0x00
	b = append(b, fixed...)
	b = append(b, nameBytes...)
	return b
}

// memFS is an in-memory FileSystem for benchmarks.
type memFS struct{ files map[string][]byte }

func (m memFS) Stat(path string) (fs.FileInfo, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return memFileInfo{name: path, size: int64(len(data))}, nil
}
func (m memFS) Open(path string) (fs.File, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &memFile{Reader: bytes.NewReader(data), name: path, data: data}, nil
}

type memFile struct {
	*bytes.Reader
	name string
	data []byte
}

func (m *memFile) Stat() (fs.FileInfo, error) {
	return memFileInfo{name: m.name, size: int64(len(m.data))}, nil
}
func (m *memFile) Close() error { return nil }

// slowMemFS wraps memFS returning files whose Read is artificially chunked to small sizes.
type slowMemFS struct {
	memFS
	chunk int
}

func (s slowMemFS) Open(path string) (fs.File, error) {
	data, ok := s.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &slowMemFile{memFile: memFile{Reader: bytes.NewReader(data), name: path, data: data}, chunk: s.chunk}, nil
}

type slowMemFile struct {
	memFile
	chunk int
}

func (s *slowMemFile) Read(p []byte) (int, error) {
	if len(p) > s.chunk {
		p = p[:s.chunk]
	}
	return s.memFile.Read(p)
}

// minimal legacy-triggering archive bytes (signature + truncated RAR3 area + valid legacy header)
func buildLegacyFallbackBytes() []byte {
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	filler := []byte{0x01, 0x02, 0x03} // insufficient for normal RAR3 parse
	legacyHeader := benchBuildRar3FileHeader("legacy-bench.bin", 10, 10)
	payload := append(append(sig, filler...), legacyHeader...)
	// add some random padding after to force scan window iteration
	padding := bytes.Repeat([]byte{0x55}, 1024)
	return append(payload, padding...)
}

func BenchmarkLegacyParser(b *testing.B) {
	data := buildLegacyFallbackBytes()
	fs := memFS{files: map[string][]byte{"bench_legacy.rar": data}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		idx, err := IndexVolumes(fs, []string{"bench_legacy.rar"})
		if err != nil {
			b.Fatalf("IndexVolumes error: %v", err)
		}
		if len(idx) != 1 || len(idx[0].FileBlocks) != 1 {
			b.Fatalf("unexpected index result")
		}
	}
}

func BenchmarkLegacyParserSlowRead(b *testing.B) {
	data := buildLegacyFallbackBytes()
	fs := slowMemFS{memFS: memFS{files: map[string][]byte{"bench_legacy.rar": data}}, chunk: 8}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		idx, err := IndexVolumes(fs, []string{"bench_legacy.rar"})
		if err != nil {
			b.Fatalf("IndexVolumes error: %v", err)
		}
		if len(idx) != 1 || len(idx[0].FileBlocks) != 1 {
			b.Fatalf("unexpected index result")
		}
	}
}

func BenchmarkLegacyParser50Parts(b *testing.B) {
	// Build 50 part files each containing a legacy fallback style single header
	parts := 50
	files := make(map[string][]byte, parts)
	for i := 1; i <= parts; i++ {
		name := fmt.Sprintf("multi.part%02d.rar", i)
		files[name] = buildLegacyFallbackBytes()
	}
	fs := memFS{files: files}
	first := "multi.part01.rar"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vols, err := DiscoverVolumesFS(fs, first)
		if err != nil {
			b.Fatalf("discover: %v", err)
		}
		if len(vols) != parts {
			b.Fatalf("expected %d vols got %d", parts, len(vols))
		}
		idx, err := IndexVolumesParallel(fs, vols, 0)
		if err != nil {
			b.Fatalf("index: %v", err)
		}
		if len(idx) != parts {
			b.Fatalf("idx len mismatch")
		}
	}
}

type memFileInfo struct {
	name string
	size int64
}

func (fi memFileInfo) Name() string       { return fi.name }
func (fi memFileInfo) Size() int64        { return fi.size }
func (fi memFileInfo) Mode() fs.FileMode  { return 0 }
func (fi memFileInfo) ModTime() time.Time { return time.Time{} }
func (fi memFileInfo) IsDir() bool        { return false }
func (fi memFileInfo) Sys() any           { return nil }
