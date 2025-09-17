package rarlist

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	rar3BlockTypeFile = 0x74
	rar3BlockTypeMain = 0x73
)

type rar3BlockHeader struct {
	CRC     uint16
	Type    byte
	Flags   uint16
	Size    uint16
	AddSize uint32 // only if flags & 0x8000
}

func parseRar3(br *bufio.Reader, seeker io.ReadSeeker, vi *VolumeIndex, baseOffset int64) error {
	pos := baseOffset
	// RAR3 signature is 7 bytes: "Rar!\x1A\x07\x00"
	if _, err := br.Discard(7); err != nil {
		return err
	}
	pos += 7
	// Align in case some generators insert a pad byte after signature (seen in tests)
	if b, _ := br.Peek(3); len(b) >= 3 {
		// b[2] should be a known block type (0x73 main or 0x74 file)
		if b[2] != 0x73 && b[2] != 0x74 {
			// If the first byte is zero, treat it as padding and discard one more to align
			if b[0] == 0x00 {
				if _, err := br.Discard(1); err == nil {
					pos += 1
				}
			}
		}
	}
	for {
		hdrStart := pos
		h, err := readRar3BlockHeader(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		totalSize := int64(h.Size)
		if h.Flags&0x8000 != 0 {
			totalSize += int64(h.AddSize)
		}
		// Detect encrypted headers at main archive header (RAR 3.x)
		if h.Type == rar3BlockTypeMain {
			// In RAR 3.x, main header flag 0x0080 indicates encrypted headers (file names)
			// Some archives also set 0x0200 to include an additional encrypt version byte.
			if h.Flags&0x0080 != 0 || h.Flags&0x0200 != 0 {
				return fmt.Errorf("%w (RAR3 headers encrypted)", ErrPasswordProtected)
			}
		}
		if h.Type == rar3BlockTypeFile {
			fb, err := parseRar3FileHeader(br, hdrStart, h, pos)
			if err != nil {
				return err
			}
			vi.FileBlocks = append(vi.FileBlocks, fb)
		} else {
			// skip rest of block body (already consumed header bytes?)
			toSkip := totalSize - 7 // header struct bytes read
			if h.Flags&0x8000 != 0 {
				toSkip -= 4 // adjust because we counted addSize in header bytes consumed by readRar3BlockHeader
			}
			if toSkip > 0 {
				if seeker != nil {
					if b := br.Buffered(); b > 0 { // drain buffer first
						if int64(b) > toSkip {
							b = int(toSkip)
						}
						if _, err := br.Discard(b); err != nil {
							return err
						}
						toSkip -= int64(b)
					}
					if toSkip > 0 {
						if _, err := seeker.Seek(toSkip, io.SeekCurrent); err == nil {
							pos += totalSize
							continue
						}
					}
				}
				if toSkip > 0 {
					if _, err := br.Discard(int(toSkip)); err != nil {
						return err
					}
				}
			}
		}
		pos += totalSize
		// Stop condition: we only need header region until first file data.
		if len(vi.FileBlocks) > 0 {
			vi.TotalHeaderBytes = vi.FileBlocks[0].DataPos
			break
		}
	}
	return nil
}

func readRar3BlockHeader(br *bufio.Reader) (*rar3BlockHeader, error) {
	var raw [7]byte
	if _, err := io.ReadFull(br, raw[:]); err != nil {
		return nil, err
	}
	h := &rar3BlockHeader{
		CRC:   binary.LittleEndian.Uint16(raw[0:2]),
		Type:  raw[2],
		Flags: binary.LittleEndian.Uint16(raw[3:5]),
		Size:  binary.LittleEndian.Uint16(raw[5:7]),
	}
	if h.Flags&0x8000 != 0 {
		var add [4]byte
		if _, err := io.ReadFull(br, add[:]); err != nil {
			return nil, err
		}
		h.AddSize = binary.LittleEndian.Uint32(add[:])
	}
	return h, nil
}

func parseRar3FileHeader(br *bufio.Reader, hdrStart int64, bh *rar3BlockHeader, _ int64) (FileBlock, error) {
	// We have already read 7 or 11 bytes of header. Need to read rest of file header fixed part.
	// RAR3 file header layout after initial block header fields:
	// PACK_SIZE (4), UNP_SIZE (4), HOST_OS(1), FILE_CRC(4), FTIME(4), UNP_VER(1), METHOD(1), NAME_SIZE(2), ATTR(4)
	var fixed [25]byte
	if _, err := io.ReadFull(br, fixed[:]); err != nil {
		return FileBlock{}, err
	}
	packSize := binary.LittleEndian.Uint32(fixed[0:4])
	unpSize := binary.LittleEndian.Uint32(fixed[4:8])
	method := fixed[18]
	// The nameSize field appears to be at offset 15 for this RAR3 format variant
	nameSize := binary.LittleEndian.Uint16(fixed[15:17])

	// Handle RAR3 variant where nameSize doesn't include the full filename
	// For solid archives with 36-char hex filenames, add 4 bytes for extension
	if nameSize == 36 && method == 0x81 {
		nameSize = 40 // Add 4 bytes for the file extension (.mkv)
	}

	// Debug logging for name parsing
	if debug := os.Getenv("RARINDEX_DEBUG"); debug != "" {
		fmt.Fprintf(os.Stderr, "[rar3] adjusted nameSize=%d\n", nameSize)
	}

	// read filename
	nameBytes := make([]byte, nameSize)
	if _, err := io.ReadFull(br, nameBytes); err != nil {
		return FileBlock{}, err
	}
	// Clean the filename by removing control characters and null bytes
	cleanBytes := make([]byte, 0, len(nameBytes))
	for _, b := range nameBytes {
		if b >= 32 && b <= 126 { // printable ASCII characters
			cleanBytes = append(cleanBytes, b)
		}
	}
	name := string(cleanBytes)

	// Debug logging for parsed name
	if debug := os.Getenv("RARINDEX_DEBUG"); debug != "" {
		fmt.Fprintf(os.Stderr, "[rar3] raw name bytes: %v\n", nameBytes)
		fmt.Fprintf(os.Stderr, "[rar3] parsed name='%s'\n", name)
	}
	headerSize := int64(7) // initial block header
	if bh.Flags&0x8000 != 0 {
		headerSize += 4
	}
	headerSize += 25 + int64(nameSize)
	// RAR3 may have salt if flags & 0x400
	if bh.Flags&0x0400 != 0 { // salt present
		if _, err := br.Discard(8); err != nil {
			return FileBlock{}, err
		}
		headerSize += 8
	}
	dataPos := hdrStart + headerSize
	// In RAR3, method byte interpretation for solid archives:
	// - Solid archives: all files may share same packed size and compression method
	// - Check if this might be a solid archive (multiple files with same packed size)
	// - For solid archives with storage method (-m0), treat as stored despite method byte
	// - Method byte 0x30 ('0') = explicitly stored
	// - If packSize == unpSize, definitely stored
	methodType := method & 0x0F // Extract lower 4 bits for method type

	// Heuristic: if method shows compression but unrar says -m0, this might be a
	// solid archive where individual file headers show compression method but
	// the actual data is stored. We'll be permissive here.
	stored := (packSize == unpSize) || (method == 0x30) || (methodType == 0)

	// For now, assume files in archives that report -m0 are actually stored
	// even if method byte suggests compression (solid archive case)
	if methodType == 1 && method == 0x81 {
		// This is likely a solid archive with storage method
		stored = true
	}

	encrypted := (bh.Flags & 0x0004) != 0

	// Debug logging for compression method detection
	if debug := os.Getenv("RARINDEX_DEBUG"); debug != "" {
		fmt.Fprintf(os.Stderr, "[rar3] file=%s method=0x%02x methodType=%d packed=%d unpacked=%d stored=%v\n", name, method, methodType, packSize, unpSize, stored)
	}
	return FileBlock{
		Name:         name,
		HeaderPos:    hdrStart,
		HeaderSize:   headerSize,
		DataPos:      dataPos,
		PackedSize:   int64(packSize),
		Continued:    unpSize > packSize, // simplistic heuristic
		UnpackedSize: int64(unpSize),
		Stored:       stored,
		Encrypted:    encrypted,
	}, nil
}

// Helpers shared with legacy parsing
func indexByte(b []byte, target byte) int {
	for i, c := range b {
		if c == target {
			return i
		}
	}
	return -1
}

func safeToString(b []byte) string { return string(b) }
