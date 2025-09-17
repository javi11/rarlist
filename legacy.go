package rarlist

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/javi11/rarlist/internal/util"
)

// scanLegacy performs the byte scan starting AFTER signature (caller positions reader at baseOffset+sigLen).
func scanLegacy(br *bufio.Reader, vi *VolumeIndex, baseOffset int64) error {
	// Reduced scan window for speed (legacy headers appear near start). 64 KiB is typically sufficient.
	const scanLimit = 64 * 1024
	peekBuf, _ := br.Peek(scanLimit)
	// Early check: detect encrypted headers via main header (type 0x73) flags (0x0080)
	if len(peekBuf) >= 7 {
		// Scan first 64K window for a plausible main header: 2 bytes CRC, 0x73 type, flags, size
		// We don’t require exact alignment to avoid off-by-one due to padding.
		for i := 0; i+6 < len(peekBuf) && i < 512; i++ { // limit small scan range near start
			if peekBuf[i+2] == 0x73 { // type
				flags := binary.LittleEndian.Uint16(peekBuf[i+3 : i+5])
				// Basic sanity on size: at least 7
				if binary.LittleEndian.Uint16(peekBuf[i+5:i+7]) >= 7 {
					if flags&0x0080 != 0 || flags&0x0200 != 0 {
						return fmt.Errorf("%w (legacy headers encrypted)", ErrPasswordProtected)
					}
					break
				}
			}
		}
	}
	searchStart := 0
	for searchStart < len(peekBuf) {
		pos := bytes.IndexByte(peekBuf[searchStart:], 0x74)
		if pos < 0 {
			break
		}
		typePos := searchStart + pos
		hdrStart := typePos - 2
		if hdrStart < 0 || hdrStart+7 > len(peekBuf) {
			searchStart = typePos + 1
			continue
		}
		flags := binary.LittleEndian.Uint16(peekBuf[hdrStart+3 : hdrStart+5])
		size := binary.LittleEndian.Uint16(peekBuf[hdrStart+5 : hdrStart+7])
		if size < 32 {
			searchStart = typePos + 1
			continue
		}
		headEnd := hdrStart + int(size)
		if headEnd > len(peekBuf) {
			// Attempt to extend peek window to cover the full header before giving up.
			if nb, _ := br.Peek(headEnd); len(nb) >= headEnd {
				peekBuf = nb
			} else {
				break
			}
		}
		fixedStart := hdrStart + 7
		if fixedStart+25 > headEnd {
			searchStart = typePos + 1
			continue
		}
		fixed := peekBuf[fixedStart : fixedStart+25]
		packSize32 := binary.LittleEndian.Uint32(fixed[0:4])
		unpSize32 := binary.LittleEndian.Uint32(fixed[4:8])
		method := fixed[18]
		nameSize := binary.LittleEndian.Uint16(fixed[15:17]) // Match main RAR3 parser offset
		offset := fixedStart + 25
		var highPack, highUnp uint32
		if flags&0x0100 != 0 {
			if offset+8 > headEnd {
				searchStart = typePos + 1
				continue
			}
			highPack = binary.LittleEndian.Uint32(peekBuf[offset : offset+4])
			highUnp = binary.LittleEndian.Uint32(peekBuf[offset+4 : offset+8])
			offset += 8
		}
		if offset+int(nameSize) > headEnd {
			searchStart = typePos + 1
			continue
		}
		nameField := peekBuf[offset : offset+int(nameSize)]
		name := ""
		if flags&0x0200 != 0 {
			if zero := indexByte(nameField, 0); zero >= 0 {
				asciiPart := nameField[:zero]
				unicodePart := nameField[zero+1:]
				name = util.DecodeRar3Unicode(asciiPart, unicodePart)
			} else {
				name = safeToString(nameField)
			}
		} else {
			name = safeToString(nameField)
		}
		packSize := (int64(highPack) << 32) | int64(packSize32)
		unpSize := (int64(highUnp) << 32) | int64(unpSize32)
		stored := method == 0x30
		encrypted := (flags & 0x0004) != 0
	// RAR3/legacy signature is 7 bytes; our detectSignature returns the sig start (baseOffset)
	fileHeaderPos := baseOffset + 7 + int64(hdrStart)
		fb := FileBlock{Name: name, HeaderPos: fileHeaderPos, HeaderSize: int64(size), DataPos: fileHeaderPos + int64(size), PackedSize: int64(packSize), UnpackedSize: int64(unpSize), Stored: stored, Encrypted: encrypted}
		vi.FileBlocks = append(vi.FileBlocks, fb)
		vi.TotalHeaderBytes = fb.DataPos

		return nil
	}
	return fmt.Errorf("legacy scan: no file header found")
}

// parseRarLegacySeeker reuses an already opened ReadSeeker positioned at start; it seeks to baseOffset+8 then scans.
func parseRarLegacySeeker(rs io.ReadSeeker, vi *VolumeIndex, baseOffset int64) error {
	if _, err := rs.Seek(baseOffset+7, io.SeekStart); err != nil {
		return err
	}
	br := bufio.NewReader(rs)
	return scanLegacy(br, vi, baseOffset)
}

// Legacy RAR (1.5/2.x) lenient parser opening file via FileSystem (fallback when we don't have seeker externally).
func parseRarLegacy(fs FileSystem, path string, vi *VolumeIndex, baseOffset int64) error {
	f, err := fs.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if rs, ok := f.(io.ReadSeeker); ok {
		return parseRarLegacySeeker(rs, vi, baseOffset)
	}
	// Non-seeker fallback: manual discard then scan
	var r io.Reader = f
	d := baseOffset + 7
	if d < 0 {
		d = 0
	}
	if d > 0 {
		if _, err := io.CopyN(io.Discard, f, d); err != nil {
			return err
		}
	}
	br := bufio.NewReader(r)
	return scanLegacy(br, vi, baseOffset)
}
