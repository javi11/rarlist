package rarlist

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/javi11/rarlist/internal/util"
)

// Legacy RAR (1.5/2.x) lenient parser: scan for first file header (type 0x74) after signature when standard parser failed.
func parseRarLegacy(fs FileSystem, path string, vi *VolumeIndex, baseOffset int64) error {
	f, err := fs.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	if seeker, ok := f.(io.Seeker); ok {
		if _, err := seeker.Seek(baseOffset+8, io.SeekStart); err != nil {
			return err
		}
	} else {
		// manual discard
		d := baseOffset + 8
		if d < 0 {
			d = 0
		}
		if d > 0 {
			if _, err := io.CopyN(io.Discard, f, d); err != nil {
				return err
			}
		}
	}
	br := bufio.NewReader(r)
	const scanLimit = 512 * 1024
	peekBuf, _ := br.Peek(scanLimit)
	for i := 0; i+11 < len(peekBuf); i++ {
		// Minimal block header: CRC(2) Type(1) Flags(2) Size(2) ...
		if peekBuf[i+2] != 0x74 { // file header type
			continue
		}
		flags := binary.LittleEndian.Uint16(peekBuf[i+3 : i+5])
		size := binary.LittleEndian.Uint16(peekBuf[i+5 : i+7])
		if size < 32 { // minimal plausible file header
			continue
		}
		headEnd := i + int(size)
		if headEnd > len(peekBuf) { // incomplete
			break
		}
		fixedStart := i + 7
		if fixedStart+25 > headEnd { // need full fixed part
			continue
		}
		fixed := peekBuf[fixedStart : fixedStart+25]
		packSize32 := binary.LittleEndian.Uint32(fixed[0:4])
		unpSize32 := binary.LittleEndian.Uint32(fixed[4:8])
		method := fixed[18]
		nameSize := binary.LittleEndian.Uint16(fixed[19:21])
		// High sizes follow fixed if FlagHasHighSize (0x100)
		offset := fixedStart + 25
		var highPack, highUnp uint32
		if flags&0x0100 != 0 { // high sizes present
			if offset+8 > headEnd {
				continue // truncated
			}
			highPack = binary.LittleEndian.Uint32(peekBuf[offset : offset+4])
			highUnp = binary.LittleEndian.Uint32(peekBuf[offset+4 : offset+8])
			offset += 8
		}
		// Name field
		if offset+int(nameSize) > headEnd {
			continue
		}
		nameField := peekBuf[offset : offset+int(nameSize)]
		name := ""
		if flags&0x0200 != 0 { // Unicode name present (ASCII + 0 + encoded)
			// Split at first zero byte. Use ASCII part as base; ignore complex decoding for now.
			if zero := indexByte(nameField, 0); zero >= 0 {
				asciiPart := nameField[:zero]
				unicodePart := nameField[zero+1:]
				// Attempt simple unicode reconstruction
				name = util.DecodeRar3Unicode(asciiPart, unicodePart)
			} else {
				name = safeToString(nameField)
			}
		} else {
			name = safeToString(nameField)
		}
		// Build sizes (64-bit if high present)
		packSize := (int64(highPack) << 32) | int64(packSize32)
		unpSize := (int64(highUnp) << 32) | int64(unpSize32)
		stored := method == 0x30
		hdrStart := baseOffset + 8 + int64(i)
		fb := FileBlock{Name: name, HeaderPos: hdrStart, HeaderSize: int64(size), DataPos: hdrStart + int64(size), PackedSize: int64(packSize), UnpackedSize: int64(unpSize), Stored: stored}
		vi.FileBlocks = append(vi.FileBlocks, fb)
		vi.TotalHeaderBytes = fb.DataPos
		return nil
	}
	return fmt.Errorf("legacy scan: no file header found")
}
