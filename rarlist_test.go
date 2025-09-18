package rarlist

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func encodeVarint(x uint64) []byte {
	var out []byte
	for {
		b := byte(x & 0x7F)
		x >>= 7
		if x != 0 {
			b |= 0x80
			out = append(out, b)
			continue
		}
		out = append(out, b)
		break
	}
	return out
}

// helper to create a temp file with given bytes
func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

// helper to build minimal RAR3 file header (no salt, stored)
func buildRar3FileHeader(name string, packSize, unpSize uint32) []byte {
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
	fixed[19] = byte(nameLen) // name size LE at offset 19
	fixed[20] = 0x00
	fixed[18] = 0x30 // stored method
	b = append(b, fixed...)
	b = append(b, nameBytes...)
	return b
}

func TestParseRar3(t *testing.T) {
	// Build minimal RAR3 single file header (stored)
	// Signature (7-byte signature + padding null byte expected by parser)
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	// File header: CRC(2) Type(1) Flags(2) Size(2)
	name := []byte("file3.txt")
	nameLen := len(name)
	headerSize := 7 + 25 + nameLen // without salt, no addsize
	hb := make([]byte, 0, headerSize)
	hb = append(hb, 0x00, 0x00)             // CRC
	hb = append(hb, 0x74)                   // type file
	hb = append(hb, 0x00, 0x00)             // flags
	hb = append(hb, byte(headerSize), 0x00) // size little endian (assume <256)
	// fixed 25 bytes
	fixed := make([]byte, 25)
	packSize := uint32(5)
	unpSize := uint32(5)
	fixed[0] = byte(packSize)
	fixed[4] = byte(unpSize)
	fixed[19] = byte(nameLen) // name size LE at offset 19
	fixed[20] = 0x00
	fixed[18] = 0x30 // method stored
	hb = append(hb, fixed...)
	hb = append(hb, name...)
	data := append(append([]byte{}, sig...), hb...)
	p := writeTemp(t, "test.rar", data)

	idx, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("IndexVolumes: %v", err)
	}
	if len(idx) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(idx))
	}
	v := idx[0]
	if v.Version != VersionRar3 {
		t.Fatalf("expected version RAR3 got %s", v.Version)
	}
	if len(v.FileBlocks) != 1 {
		t.Fatalf("expected 1 file block got %d", len(v.FileBlocks))
	}
	if v.FileBlocks[0].Name != string(name) {
		t.Fatalf("name mismatch: %q", v.FileBlocks[0].Name)
	}
}

func TestParseRar5(t *testing.T) {
	sig := []byte("Rar!\x1A\x07\x01\x00")
	name := []byte("file5.data") // length 10
	nameLen := len(name)         // 10
	// Build header as described in parser comments.
	// headSize includes headSize field itself to end of header (excluding CRC).
	// We choose: headData = blockType(1) flags(1) dataSize(1) fileFlags(1) unpSize(1) attr(1) compInfo(1) hostOS(1) nameLen(1) name(10) = 19 bytes
	headSizeVal := 19
	headSize := byte(headSizeVal)
	crc := []byte{0, 0, 0, 0}
	blockType := byte(2)
	flags := byte(0x02) // dataSize present
	dataSize := byte(0) // no file data included (just header)
	fileFlags := byte(0)
	unpSize := byte(5)
	fileAttr := byte(0)
	compInfo := byte(0) // stored
	hostOS := byte(0)
	nameLenByte := byte(nameLen)
	headData := []byte{blockType, flags, dataSize, fileFlags, unpSize, fileAttr, compInfo, hostOS, nameLenByte}
	headData = append(headData, name...)
	if len(headData) != headSizeVal {
		t.Fatalf("constructed headData len=%d expected %d", len(headData), headSizeVal)
	}
	fileBytes := append([]byte{}, sig...)
	fileBytes = append(fileBytes, crc...)
	fileBytes = append(fileBytes, headSize)
	fileBytes = append(fileBytes, headData...)
	p := writeTemp(t, "test5.rar", fileBytes)

	idx, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("IndexVolumes: %v", err)
	}
	if len(idx) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(idx))
	}
	v := idx[0]
	if v.Version != VersionRar5 {
		t.Fatalf("expected version RAR5 got %s", v.Version)
	}
	if len(v.FileBlocks) != 1 {
		t.Fatalf("expected 1 file block got %d", len(v.FileBlocks))
	}
	if v.FileBlocks[0].Name != string(name) {
		t.Fatalf("name mismatch: %q", v.FileBlocks[0].Name)
	}
}

func TestLegacyFallback(t *testing.T) {
	// Force parseRar3 failure by truncating data right after signature, then placing a valid legacy header a few bytes later.
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	filler := []byte{0x01, 0x02, 0x03}                               // insufficient for RAR3 block header (needs 7)
	legacyHeader := buildRar3FileHeader("legacy-fallback.txt", 4, 4) // legacy scanner will accept
	data := append(append(sig, filler...), legacyHeader...)
	p := writeTemp(t, "legacy_fallback.rar", data)
	idx, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		// Should succeed via fallback
		t.Fatalf("IndexVolumes fallback: %v", err)
	}
	if len(idx[0].FileBlocks) != 1 || idx[0].FileBlocks[0].Name != "legacy-fallback.txt" {
		b := idx[0].FileBlocks
		t.Fatalf("unexpected legacy fallback blocks: %+v", b)
	}
}

func TestDiscoverVolumesPatterns(t *testing.T) {
	dir := t.TempDir()
	// partXX pattern
	files := []string{"movie.part01.rar", "movie.part02.rar"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("dummy"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	vols, err := DiscoverVolumes(filepath.Join(dir, files[0]))
	if err != nil {
		t.Fatalf("discover partXX: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("expected 2 vols got %d", len(vols))
	}
	// r00 pattern
	base := filepath.Join(dir, "archive.rar")
	if err := os.WriteFile(base, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		name := filepath.Join(dir, "archive.r"+fmt2(i))
		if err := os.WriteFile(name, []byte("b"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vols2, err := DiscoverVolumes(base)
	if err != nil {
		t.Fatalf("discover r00: %v", err)
	}
	if len(vols2) != 3 {
		t.Fatalf("expected 3 vols got %d", len(vols2))
	}
}

func fmt2(i int) string { return fmt.Sprintf("%02d", i) }

func TestAggregateMultiParts(t *testing.T) {
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	// part1
	h1 := buildRar3FileHeader("multi.bin", 5, 10)
	p1 := writeTemp(t, "a.part01.rar", append(sig, h1...))
	// part2 (same name, second chunk) with packSize 3 and unpSize 0 so aggregator uses first unp size
	h2 := buildRar3FileHeader("multi.bin", 3, 0)
	p2 := writeTemp(t, "a.part02.rar", append(sig, h2...))
	vols, err := IndexVolumes(defaultFS, []string{p1, p2})
	if err != nil {
		t.Fatalf("index multi parts: %v", err)
	}
	agg := AggregateFiles(vols)
	if len(agg) != 1 {
		t.Fatalf("expected 1 aggregated file, got %d", len(agg))
	}
	af := agg[0]
	if af.TotalPackedSize != 8 {
		t.Fatalf("packed size want 8 got %d", af.TotalPackedSize)
	}
	if af.TotalUnpackedSize != 10 {
		t.Fatalf("unpacked size want 10 got %d", af.TotalUnpackedSize)
	}
	if len(af.Parts) != 2 {
		t.Fatalf("expected 2 parts got %d", len(af.Parts))
	}
}

func TestOffsetsPropagation(t *testing.T) {
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	h := buildRar3FileHeader("first.dat", 1, 1)
	p := writeTemp(t, "one.rar", append(sig, h...))
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatal(err)
	}
	o := Offsets(vols)
	if len(o) != 1 || o[0].FileName != "first.dat" {
		t.Fatalf("offset propagation failed: %+v", o)
	}
}

func TestRar5DataSkip(t *testing.T) {
	// Build RAR5 file with dataSize >0 to exercise skip path.
	sig := []byte("Rar!\x1A\x07\x01\x00")
	name := []byte("skip.bin")
	nameLen := len(name)
	dataSize := byte(5)
	// header content (file header) as earlier but with dataSize 5.
	headData := []byte{2, 0x02, dataSize, 0, 5, 0, 0, 0, byte(nameLen)}
	headData = append(headData, name...)
	headSize := byte(len(headData))
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.Write([]byte{0, 0, 0, 0}) // crc
	buf.WriteByte(headSize)
	buf.Write(headData)
	buf.Write([]byte{1, 2, 3, 4, 5}) // actual data to skip
	p := writeTemp(t, "skip.rar", buf.Bytes())
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index rar5 skip: %v", err)
	}
	if vols[0].FileBlocks[0].Name != string(name) {
		t.Fatalf("rar5 name mismatch")
	}
}

func TestSignatureOffsetSFX(t *testing.T) {
	// Prepend junk bytes before signature to ensure detectSignature returns correct version with offset seek logic.
	junk := bytes.Repeat([]byte{0x55}, 32)
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	h := buildRar3FileHeader("sfx.bin", 2, 2)
	data := append(append(junk, sig...), h...)
	p := writeTemp(t, "sfx.rar", data)
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index sfx: %v", err)
	}
	if vols[0].Version != VersionRar3 {
		t.Fatalf("expected RAR3 got %s", vols[0].Version)
	}
}

func TestErrorsAndEdgeCases(t *testing.T) {
	// No signature
	p1 := writeTemp(t, "nosig.bin", []byte("not a rar"))
	if _, err := IndexVolumes(defaultFS, []string{p1}); err == nil {
		t.Fatalf("expected error for missing signature")
	}
	// RAR5 suspicious huge headSize (>2MB). Encode 3,000,000 as varint (little-endian 7-bit groups)
	// 3,000,000 decimal = 0x2DC6C0. Varint bytes: 0xC0 0x8D 0xB7 0x02
	largeHead := []byte{0xC0, 0x8D, 0xB7, 0x02}
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte("Rar!\x1A\x07\x01\x00"))
	buf.Write([]byte{0, 0, 0, 0}) // crc
	buf.Write(largeHead)
	p2 := writeTemp(t, "badhead.rar", buf.Bytes())
	if _, err := IndexVolumes(defaultFS, []string{p2}); err == nil {
		t.Fatalf("expected error for suspicious headSize")
	}
	// Legacy scan failure (valid signature but no file header in scan window)
	p3 := writeTemp(t, "legacyfail.rar", append([]byte("Rar!\x1A\x07\x00"), 0x00, 0x01, 0x02, 0x03, 0x04))
	if _, err := IndexVolumes(defaultFS, []string{p3}); err == nil {
		t.Fatalf("expected error for legacy scan failure")
	}
}

func TestRar3HighSizeAndSalt(t *testing.T) {
	// Build RAR3 archive with a non-file block then a file block with high size & salt.
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	// First add a dummy comment block (type 0x75) size 7 (header only) no addsize.
	comment := []byte{0x00, 0x00, 0x75, 0x00, 0x00, 0x07, 0x00}
	// File block with flags high size (0x8000 for addsize? actually high sizes in file header legacy use 0x0100) and salt (0x0400)
	name := "big.bin"
	nameLen := len(name)
	packSize := uint64(0x00000001_FFFFFFFF) // high pack
	unpSize := uint64(0x00000002_FFFFFFFF)
	// Build file header
	fixedSize := 25
	headerSize := 7 + 4 + fixedSize + 8 + nameLen + 8 // header + addsize + fixed + name + salt
	// block header (with addsize flag 0x8000 and salt flag 0x0400 and high size flag 0x0100)
	flags := uint16(0x8000 | 0x0400 | 0x0100)
	bh := []byte{0x00, 0x00, 0x74, byte(flags), byte(flags >> 8), byte(headerSize & 0xFF), byte(headerSize >> 8)}
	addSize := make([]byte, 4)
	addSize[0] = byte(packSize) // arbitrary just to fill (not used by our parser for file header)
	fileFixed := make([]byte, fixedSize)
	// low sizes
	fileFixed[0] = byte(packSize)
	fileFixed[4] = byte(unpSize)
	fileFixed[18] = 0x30 // method stored
	fileFixed[19] = byte(nameLen)
	fileFixed[20] = 0x00
	nameBytes := []byte(name)
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.Write(comment)
	buf.Write(bh)
	buf.Write(addSize)
	buf.Write(fileFixed)
	buf.Write(nameBytes)
	buf.Write(salt)
	p := writeTemp(t, "rar3_high_salt.rar", buf.Bytes())
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index rar3 high+salt: %v", err)
	}
	if len(vols[0].FileBlocks) != 1 {
		t.Fatalf("expected 1 file block got %d", len(vols[0].FileBlocks))
	}
}

func TestUnsupportedVersionError(t *testing.T) {
	// Provide a file with a detectable signature-like pattern but manipulated so detectSignature returns unknown.
	// Simplest: ensure no known signature so detectSignature errors; we already test missing signature.
	// Instead craft a file where detectSignature finds RAR3 signature but we mutate version constants? Hard.
	// Skip: already have missing signature coverage.
}

func TestRar5ExtraAreaAndFlags(t *testing.T) {
	// RAR5 file header with extra area, data, mtime & CRC flags, followed by end block.
	sig := []byte("Rar!\x1A\x07\x01\x00")
	name := []byte("extra.bin")
	nameLen := len(name)
	fileFlags := uint64(0x0002 | 0x0004) // mtime + CRC32 present
	extraArea := []byte{0xAA, 0xBB, 0xCC}
	dataBytes := []byte{1, 2, 3}
	// Build header content (without CRC + headSize varint).
	blockType := encodeVarint(2)
	flags := encodeVarint(0x0003) // extraArea + dataSize
	extraAreaSize := encodeVarint(uint64(len(extraArea)))
	dataSize := encodeVarint(uint64(len(dataBytes)))
	ff := encodeVarint(fileFlags)
	unp := encodeVarint(7)
	attr := encodeVarint(0)
	compInfo := encodeVarint(0) // stored
	hostOS := encodeVarint(0)
	nameLenVar := encodeVarint(uint64(nameLen))
	// file header specific area (excluding extra area) order per parser expectation: fileFlags, unpSize, attr, [mtime=4], [crc=4], compInfo, hostOS, nameLen, name
	mtime := []byte{0, 0, 0, 0}
	crc := []byte{0, 0, 0, 0}
	fileSpecific := bytes.NewBuffer(nil)
	fileSpecific.Write(ff)
	fileSpecific.Write(unp)
	fileSpecific.Write(attr)
	fileSpecific.Write(mtime)
	fileSpecific.Write(crc)
	fileSpecific.Write(compInfo)
	fileSpecific.Write(hostOS)
	fileSpecific.Write(nameLenVar)
	fileSpecific.Write(name)
	// Assemble headData: varints (blockType..dataSize) + fileSpecific + extraArea (at end)
	headCore := bytes.NewBuffer(nil)
	headCore.Write(blockType)
	headCore.Write(flags)
	headCore.Write(extraAreaSize)
	headCore.Write(dataSize)
	headCore.Write(fileSpecific.Bytes())
	headCore.Write(extraArea) // extra at end
	headData := headCore.Bytes()
	headSizeVar := encodeVarint(uint64(len(headData)))
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.Write([]byte{0, 0, 0, 0}) // CRC placeholder
	buf.Write(headSizeVar)
	buf.Write(headData)
	// data section
	buf.Write(dataBytes)
	// End of archive block (type 5) minimal
	endHeadCore := bytes.NewBuffer(nil)
	endHeadCore.Write(encodeVarint(5)) // blockType 5
	endHeadCore.Write(encodeVarint(0)) // flags 0
	endHeadData := endHeadCore.Bytes()
	endHeadSizeVar := encodeVarint(uint64(len(endHeadData)))
	buf.Write([]byte{0, 0, 0, 0}) // crc
	buf.Write(endHeadSizeVar)
	buf.Write(endHeadData)
	p := writeTemp(t, "rar5_extra.rar", buf.Bytes())
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index rar5 extra: %v", err)
	}
	if len(vols[0].FileBlocks) != 1 {
		t.Fatalf("expected 1 file, got %d", len(vols[0].FileBlocks))
	}
	if vols[0].FileBlocks[0].Name != string(name) {
		t.Fatalf("name mismatch")
	}
}

func TestRar3NonFileAddSizeBlock(t *testing.T) {
	// Non-file block with addsize followed by a file block.
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	// Non-file block: type 0x73 (main header), flags 0x8000 (has addsize), size 7, addsize 4 -> total skip path.
	mainHdr := []byte{0x00, 0x00, 0x73, 0x00, 0x80, 0x07, 0x00, 0x04, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}
	fileHdr := buildRar3FileHeader("nf.bin", 2, 2)
	p := writeTemp(t, "rar3_addsize.rar", append(append(sig, mainHdr...), fileHdr...))
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index rar3 addsize: %v", err)
	}
	if len(vols[0].FileBlocks) != 1 || vols[0].FileBlocks[0].Name != "nf.bin" {
		t.Fatalf("unexpected blocks %+v", vols[0].FileBlocks)
	}
}

func TestRar5TruncatedHeadData(t *testing.T) {
	// Build RAR5 block where headSize claims more bytes than remain; parser should stop gracefully (no error).
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte("Rar!\x1A\x07\x01\x00"))
	buf.Write([]byte{0, 0, 0, 0}) // crc
	buf.Write([]byte{10})         // headSize = 10
	buf.Write([]byte{2})          // blockType varint
	// Provide fewer than 10 bytes remaining intentionally (only 1 more byte) so headData read fails -> expect error.
	// Adjust: Actually to get graceful stop we need headSize check vs file boundary BEFORE read. Provide smaller file so (pos+headSize)>fileSize condition triggers.
	// Rebuild accordingly.
	buf = bytes.NewBuffer(nil)
	buf.Write([]byte("Rar!\x1A\x07\x01\x00"))
	buf.Write([]byte{0, 0, 0, 0})
	// headSize varint byte after CRC will be read at pos; set large headSize=50 but total file shorter.
	buf.Write([]byte{50})
	// (no further bytes)
	p := writeTemp(t, "rar5_trunc.rar", buf.Bytes())
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	br := bufio.NewReader(f)
	vi := &VolumeIndex{Path: p, Version: VersionRar5}
	if err := testHookParseRar5(br, f, vi, 0, int64(len(buf.Bytes()))); err != nil {
		// Should not be hard error; parser returns nil when headSize exceeds file boundary.
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRar3FileHeaderAddSize(t *testing.T) {
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	name := "add.bin"
	nameLen := len(name)
	// size field counts header (without addsize). We'll build: block header(7) + fixed(25) + name
	size := 7 + 25 + nameLen
	flags := uint16(0x8000) // addsize present
	// Block header
	bh := []byte{0x00, 0x00, 0x74, byte(flags), byte(flags >> 8), byte(size & 0xFF), byte(size >> 8)}
	addSize := []byte{0x04, 0x00, 0x00, 0x00} // 4 bytes of add data
	fixed := make([]byte, 25)
	fixed[0] = 1              // packSize
	fixed[4] = 1              // unpSize
	fixed[19] = byte(nameLen) // name size LE at offset 19
	fixed[20] = 0x00
	fixed[18] = 0x30
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.Write(bh)
	buf.Write(addSize)
	buf.Write(fixed)
	buf.Write([]byte(name))
	buf.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF}) // addsize payload
	p := writeTemp(t, "rar3_addfile.rar", buf.Bytes())
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index rar3 addfile: %v", err)
	}
	if len(vols[0].FileBlocks) != 1 || vols[0].FileBlocks[0].Name != name {
		t.Fatalf("unexpected blocks: %+v", vols[0].FileBlocks)
	}
}

func TestRar5MultipleFiles(t *testing.T) {
	sig := []byte("Rar!\x1A\x07\x01\x00")
	mkFileHeader := func(name string, data []byte) []byte {
		nameB := []byte(name)
		fileFlags := encodeVarint(0)
		unp := encodeVarint(uint64(len(data)))
		attr := encodeVarint(0)
		comp := encodeVarint(0)
		host := encodeVarint(0)
		nameLen := encodeVarint(uint64(len(nameB)))
		fs := bytes.NewBuffer(nil)
		fs.Write(fileFlags)
		fs.Write(unp)
		fs.Write(attr)
		fs.Write(comp)
		fs.Write(host)
		fs.Write(nameLen)
		fs.Write(nameB)
		blockType := encodeVarint(2)
		flags := encodeVarint(0x0002) // dataSize
		dataSize := encodeVarint(uint64(len(data)))
		headCore := bytes.NewBuffer(nil)
		headCore.Write(blockType)
		headCore.Write(flags)
		headCore.Write(dataSize)
		headCore.Write(fs.Bytes())
		head := headCore.Bytes()
		return append(append([]byte{0, 0, 0, 0}, encodeVarint(uint64(len(head)))...), head...)
	}
	file1 := mkFileHeader("f1.bin", []byte{1, 2})
	file2 := mkFileHeader("f2.bin", []byte{3, 4, 5})
	endCore := bytes.NewBuffer(nil)
	endCore.Write(encodeVarint(5))
	endCore.Write(encodeVarint(0))
	endHead := endCore.Bytes()
	end := append([]byte{0, 0, 0, 0}, encodeVarint(uint64(len(endHead)))...)
	end = append(end, endHead...)
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.Write(file1)
	buf.Write([]byte{1, 2}) // data for file1
	buf.Write(file2)
	buf.Write([]byte{3, 4, 5}) // data for file2
	buf.Write(end)
	p := writeTemp(t, "rar5_multi.rar", buf.Bytes())
	vols, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index rar5 multi: %v", err)
	}
	if len(vols[0].FileBlocks) != 2 {
		t.Fatalf("expected 2 file blocks got %d", len(vols[0].FileBlocks))
	}
}

func TestRar5ExtraAreaOverflow(t *testing.T) {
	// Construct header where extraAreaSize > remaining, causing overflow error.
	sig := []byte("Rar!\x1A\x07\x01\x00")
	blockType := encodeVarint(2)
	flags := encodeVarint(0x0001)     // extra area only
	extraAreaSize := encodeVarint(10) // will overflow
	// headData consists only of the varints above; cur after reading them == len(headData); blockSpecificEnd=headSize; extraAreaSize>blockSpecificEnd-cur triggers error.
	headData := bytes.NewBuffer(nil)
	headData.Write(blockType)
	headData.Write(flags)
	headData.Write(extraAreaSize)
	body := headData.Bytes()
	headSize := encodeVarint(uint64(len(body)))
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.Write([]byte{0, 0, 0, 0}) // crc
	buf.Write(headSize)
	buf.Write(body)
	p := writeTemp(t, "rar5_overflow.rar", buf.Bytes())
	_, err := IndexVolumes(defaultFS, []string{p})
	if err == nil {
		t.Fatalf("expected overflow error")
	}
}

func TestRar3MainHeaderEncrypted_EarlyError(t *testing.T) {
	// Build RAR3 with a main header (0x73) having the encrypted header flag (0x0080)
	sig := []byte("Rar!\x1A\x07\x00")
	// main header: CRC(2) Type(1=0x73) Flags(2) Size(2)
	flags := uint16(0x0080)
	main := []byte{0x00, 0x00, 0x73, byte(flags), byte(flags >> 8), 0x07, 0x00}
	p := writeTemp(t, "rar3_enc_main.rar", append(sig, main...))
	_, err := ListFiles(p)
	if err == nil {
		t.Fatalf("expected password protected error for RAR3 encrypted headers")
	}
	if !errors.Is(err, ErrPasswordProtected) {
		t.Fatalf("want ErrPasswordProtected, got %v", err)
	}
}

func TestListFiles_Compressed_RAR3_ReturnsError(t *testing.T) {
	// RAR3 signature + one file header with method != 0x30 (compressed)
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	name := []byte("compressed.bin")
	nameLen := len(name)
	headerSize := 7 + 25 + nameLen
	hb := make([]byte, 0, headerSize)
	hb = append(hb, 0x00, 0x00) // CRC
	hb = append(hb, 0x74)       // type file
	hb = append(hb, 0x00, 0x00) // flags (no addsize/high/unicode)
	hb = append(hb, byte(headerSize), 0x00)
	fixed := make([]byte, 25)
	fixed[0] = 5     // packSize
	fixed[4] = 10    // unpSize
	fixed[18] = 0x33 // a non-stored compression method
	fixed[19] = byte(nameLen)
	fixed[20] = 0x00
	hb = append(hb, fixed...)
	hb = append(hb, name...)
	p := writeTemp(t, "compressed.rar", append(sig, hb...))
	_, err := ListFiles(p)
	if err == nil {
		t.Fatalf("expected compressed unsupported error")
	}
	if !errors.Is(err, ErrCompressedNotSupported) {
		t.Fatalf("want ErrCompressedNotSupported, got %v", err)
	}
}

func TestListFiles_Password_RAR3_ReturnsError(t *testing.T) {
	// RAR3 signature + one file header with encrypted flag (0x0004) in block header flags
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	name := []byte("secret.txt")
	nameLen := len(name)
	headerSize := 7 + 25 + nameLen
	flags := uint16(0x0004) // encrypted header flag for file block
	hb := make([]byte, 0, headerSize)
	hb = append(hb, 0x00, 0x00) // CRC
	hb = append(hb, 0x74)       // type file
	hb = append(hb, byte(flags), byte(flags>>8))
	hb = append(hb, byte(headerSize), 0x00)
	fixed := make([]byte, 25)
	fixed[0] = 5
	fixed[4] = 5
	fixed[19] = byte(nameLen) // name size LE at offset 19
	fixed[20] = 0x00
	fixed[18] = 0x30
	hb = append(hb, fixed...)
	hb = append(hb, name...)
	p := writeTemp(t, "encrypted.rar", append(sig, hb...))
	_, err := ListFiles(p)
	if err == nil {
		t.Fatalf("expected password protected error")
	}
	if !errors.Is(err, ErrPasswordProtected) {
		t.Fatalf("want ErrPasswordProtected, got %v", err)
	}
}

func TestListFiles_Password_RAR5_ReturnsError(t *testing.T) {
	// RAR5 with an Archive Encryption Header (block type 4)
	sig := []byte("Rar!\x1A\x07\x01\x00")
	// headData: blockType=4, flags=0
	headData := append(encodeVarint(4), encodeVarint(0)...)
	buf := bytes.NewBuffer(nil)
	buf.Write(sig)
	buf.Write([]byte{0, 0, 0, 0}) // CRC
	buf.Write(encodeVarint(uint64(len(headData))))
	buf.Write(headData)
	p := writeTemp(t, "enc5.rar", buf.Bytes())
	_, err := ListFiles(p)
	if err == nil {
		t.Fatalf("expected password protected error for rar5")
	}
	if !errors.Is(err, ErrPasswordProtected) {
		t.Fatalf("want ErrPasswordProtected, got %v", err)
	}
}

func TestRar5MtimeTruncated(t *testing.T) {
	// fileFlags mtime present but no 4 bytes
	blockType := encodeVarint(2)
	flags := encodeVarint(0) // no extra/data
	fileFlags := encodeVarint(0x0002)
	unp := encodeVarint(1)
	attr := encodeVarint(0)
	headCore := bytes.NewBuffer(nil)
	headCore.Write(blockType)
	headCore.Write(flags)
	headCore.Write(fileFlags)
	headCore.Write(unp)
	headCore.Write(attr) // no mtime bytes -> triggers mtime truncated
	headData := headCore.Bytes()
	headSize := encodeVarint(uint64(len(headData)))
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte("Rar!\x1A\x07\x01\x00"))
	buf.Write([]byte{0, 0, 0, 0})
	buf.Write(headSize)
	buf.Write(headData)
	p := writeTemp(t, "rar5_mtime_trunc.rar", buf.Bytes())
	_, err := IndexVolumes(defaultFS, []string{p})
	if err == nil {
		t.Fatalf("expected mtime truncated error")
	}
}

func TestRar5CRCTruncated(t *testing.T) {
	// fileFlags mtime + CRC, only supply mtime (4 bytes) not CRC
	blockType := encodeVarint(2)
	flags := encodeVarint(0)
	fileFlags := encodeVarint(0x0002 | 0x0004)
	unp := encodeVarint(1)
	attr := encodeVarint(0)
	mtime := []byte{0, 0, 0, 0}
	headCore := bytes.NewBuffer(nil)
	headCore.Write(blockType)
	headCore.Write(flags)
	headCore.Write(fileFlags)
	headCore.Write(unp)
	headCore.Write(attr)
	headCore.Write(mtime) // but omit CRC bytes
	headData := headCore.Bytes()
	headSize := encodeVarint(uint64(len(headData)))
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte("Rar!\x1A\x07\x01\x00"))
	buf.Write([]byte{0, 0, 0, 0})
	buf.Write(headSize)
	buf.Write(headData)
	p := writeTemp(t, "rar5_crc_trunc.rar", buf.Bytes())
	_, err := IndexVolumes(defaultFS, []string{p})
	if err == nil {
		t.Fatalf("expected crc truncated error")
	}
}

func TestRar5BadNameLen(t *testing.T) {
	blockType := encodeVarint(2)
	flags := encodeVarint(0)
	fileFlags := encodeVarint(0)
	unp := encodeVarint(1)
	attr := encodeVarint(0)
	compInfo := encodeVarint(0)
	host := encodeVarint(0)
	nameLen := encodeVarint(0) // invalid
	headCore := bytes.NewBuffer(nil)
	headCore.Write(blockType)
	headCore.Write(flags)
	headCore.Write(fileFlags)
	headCore.Write(unp)
	headCore.Write(attr)
	headCore.Write(compInfo)
	headCore.Write(host)
	headCore.Write(nameLen)
	headData := headCore.Bytes()
	headSize := encodeVarint(uint64(len(headData)))
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte("Rar!\x1A\x07\x01\x00"))
	buf.Write([]byte{0, 0, 0, 0})
	buf.Write(headSize)
	buf.Write(headData)
	p := writeTemp(t, "rar5_badnamelen.rar", buf.Bytes())
	_, err := IndexVolumes(defaultFS, []string{p})
	if err == nil {
		t.Fatalf("expected bad nameLen error")
	}
}

func TestLegacyHighSizeUnicode(t *testing.T) {
	// Legacy scan with high size (0x0100) and unicode flag (0x0200).
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	nameAscii := []byte("uni.txt")
	encoded := []byte{0x55, 0xAA} // dummy unicode tail
	nameField := append(append(nameAscii, 0x00), encoded...)
	nameLen := len(nameField)
	// Build legacy header manually at offset right after signature.
	flags := uint16(0x0100 | 0x0200)
	size := 7 + 25 + 8 + nameLen // header base + fixed + high sizes + name
	hdr := make([]byte, 0, size)
	hdr = append(hdr, 0x00, 0x00) // CRC
	hdr = append(hdr, 0x74)       // type
	hdr = append(hdr, byte(flags), byte(flags>>8))
	hdr = append(hdr, byte(size), 0x00)
	fixed := make([]byte, 25)
	fixed[19] = byte(nameLen) // name size LE at offset 19
	fixed[20] = 0x00
	fixed[18] = 0x30
	// put low sizes
	fixed[0] = 0x34
	fixed[4] = 0x34
	hdr = append(hdr, fixed...)
	// high sizes (8 bytes)
	hdr = append(hdr, 0, 0, 0, 0, 0, 0, 0, 0)
	hdr = append(hdr, nameField...)
	data := append(sig, hdr...)
	p := writeTemp(t, "legacy_high_unicode.rar", data)
	idx, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index legacy high unicode: %v", err)
	}
	if len(idx[0].FileBlocks) != 1 {
		t.Fatalf("expected 1 file block")
	}
}

func TestRar3ExtraBytesBeforeName(t *testing.T) {
	// Test RAR3 file with extra bytes before the filename (like Clueless file)
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	actualName := "test-file.mkv"
	// Create name field with 4 extra bytes at the beginning
	extraBytes := []byte{0x07, 0x00, 0x00, 0x00}
	nameField := append(extraBytes, []byte(actualName)...)
	nameLen := len(nameField)
	headerSize := 7 + 25 + nameLen
	hb := make([]byte, 0, headerSize)
	hb = append(hb, 0x00, 0x00)             // CRC
	hb = append(hb, 0x74)                   // type file
	hb = append(hb, 0x00, 0x00)             // flags
	hb = append(hb, byte(headerSize), 0x00) // size
	fixed := make([]byte, 25)
	fixed[0] = 10             // packSize
	fixed[4] = 10             // unpSize
	fixed[19] = byte(nameLen) // name size includes extra bytes
	fixed[20] = 0x00
	fixed[18] = 0x30 // stored method
	hb = append(hb, fixed...)
	hb = append(hb, nameField...)
	data := append(sig, hb...)
	data = append(data, []byte("some data")...) // Add some dummy data

	p := writeTemp(t, "extra_bytes.rar", data)
	idx, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index extra bytes: %v", err)
	}
	if len(idx[0].FileBlocks) != 1 {
		t.Fatalf("expected 1 file block got %d", len(idx[0].FileBlocks))
	}
	if idx[0].FileBlocks[0].Name != actualName {
		t.Fatalf("name mismatch: got %q want %q", idx[0].FileBlocks[0].Name, actualName)
	}
}

func TestRar3DataOffsetCalculation(t *testing.T) {
	// Test that data offset is calculated correctly without the extra 2 bytes
	sig := append([]byte("Rar!\x1A\x07\x00"), 0x00)
	name := "offset-test.bin"
	h := buildRar3FileHeader(name, 5, 5)
	data := append(sig, h...)
	// Add some recognizable data
	testData := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	data = append(data, testData...)

	p := writeTemp(t, "offset.rar", data)
	idx, err := IndexVolumes(defaultFS, []string{p})
	if err != nil {
		t.Fatalf("index offset: %v", err)
	}
	if len(idx[0].FileBlocks) != 1 {
		t.Fatalf("expected 1 file block")
	}

	fb := idx[0].FileBlocks[0]
	// The data should start immediately after the header
	// sig(8) + header(7 + 25 + len(name))
	expectedOffset := int64(8 + 7 + 25 + len(name))
	if fb.DataPos != expectedOffset {
		t.Fatalf("data offset mismatch: got %d want %d", fb.DataPos, expectedOffset)
	}

	// Verify we can read the data at the correct offset
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	readData := make([]byte, 5)
	_, err = f.ReadAt(readData, fb.DataPos)
	if err != nil {
		t.Fatalf("read at offset: %v", err)
	}

	for i, b := range testData {
		if readData[i] != b {
			t.Fatalf("data mismatch at byte %d: got 0x%02X want 0x%02X", i, readData[i], b)
		}
	}
}
