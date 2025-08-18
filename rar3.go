package rarlist

import (
	"bufio"
	"encoding/binary"
	"io"
)

const (
	rar3BlockTypeFile = 0x74
)

type rar3BlockHeader struct {
	CRC     uint16
	Type    byte
	Flags   uint16
	Size    uint16
	AddSize uint32 // only if flags & 0x8000
}

func parseRar3(br *bufio.Reader, vi *VolumeIndex, baseOffset int64) error {
	// first 7+1 bytes signature (7 + 1 null) already positioned
	pos := baseOffset
	// skip signature (7 + 1)
	if _, err := br.Discard(8); err != nil {
		return err
	}
	pos += 8
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
		if h.Type == rar3BlockTypeFile {
			fb, err := parseRar3FileHeader(br, hdrStart, h, pos)
			if err != nil {
				return err
			}
			vi.FileBlocks = append(vi.FileBlocks, fb)
		} else {
			// skip rest of block body (already consumed header bytes?)
			toSkip := totalSize - 7 // header struct bytes read
			if toSkip > 0 {
				if _, err := br.Discard(int(toSkip)); err != nil {
					return err
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

func parseRar3FileHeader(br *bufio.Reader, hdrStart int64, bh *rar3BlockHeader, pos int64) (FileBlock, error) {
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
	nameSize := binary.LittleEndian.Uint16(fixed[19:21])
	// read filename
	nameBytes := make([]byte, nameSize)
	if _, err := io.ReadFull(br, nameBytes); err != nil {
		return FileBlock{}, err
	}
	name := string(nameBytes)
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
	stored := method == 0x30 // '0' stored
	return FileBlock{
		Name:         name,
		HeaderPos:    hdrStart,
		HeaderSize:   headerSize,
		DataPos:      dataPos,
		PackedSize:   int64(packSize),
		Continued:    unpSize > packSize, // simplistic heuristic
		UnpackedSize: int64(unpSize),
		Stored:       stored,
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
