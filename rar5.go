package rarlist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/javi11/rarlist/internal/parse"
)

// parseRar5 implements spec-based parsing and collects all file headers.
func parseRar5(br *bufio.Reader, seeker io.ReadSeeker, vi *VolumeIndex, baseOffset int64, fileSize int64) error {
	if _, err := br.Discard(8); err != nil {
		return fmt.Errorf("discard signature: %w", err)
	}
	pos := baseOffset + 8
	debug := os.Getenv("RARINDEX_DEBUG") != ""
	logDebug := func(format string, a ...any) {
		if debug {
			fmt.Fprintf(os.Stderr, "[rar5] "+format+"\n", a...)
		}
	}
	for {
		if fileSize > 0 && pos >= fileSize {
			return nil
		}
		hdrStart := pos
		var crc [4]byte
		if _, err := io.ReadFull(br, crc[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read block crc at %d: %w", pos, err)
		}
		pos += 4
		headSize, headSizeLen, err := parse.ReadVarint(br)
		if err != nil {
			return fmt.Errorf("read headSize at %d: %w", pos, err)
		}
		pos += headSizeLen
		if headSize == 0 { // tolerant: treat as end marker / padding
			logDebug("zero headSize encountered at %d -> stop", hdrStart)
			return nil
		}
		if headSize > 2*1024*1024 {
			return fmt.Errorf("suspicious headSize %d at %d", headSize, hdrStart)
		}
		if fileSize > 0 && pos+int64(headSize) > fileSize { // truncated / misaligned -> stop gracefully
			logDebug("headSize exceeds remaining file (%d) at %d -> stop", headSize, hdrStart)
			return nil
		}
		headData := make([]byte, headSize)
		if _, err := io.ReadFull(br, headData); err != nil {
			return fmt.Errorf("read headData size=%d at %d: %w", headSize, hdrStart, err)
		}
		pos += int64(headSize)
		cur := 0
		readVar := func() (uint64, int, error) {
			v, n, e := parse.ReadVarintFromSlice(headData[cur:])
			if e != nil {
				return 0, 0, e
			}
			cur += int(n)
			return v, int(n), nil
		}
		blockType, _, err := readVar()
		if err != nil {
			return fmt.Errorf("blockType: %w", err)
		}
		flags, _, err := readVar()
		if err != nil {
			return fmt.Errorf("flags: %w", err)
		}
		var extraAreaSize, dataSize uint64
		if flags&0x0001 != 0 {
			v, _, e := readVar()
			if e != nil {
				return fmt.Errorf("extraAreaSize: %w", e)
			}
			extraAreaSize = v
		}
		if flags&0x0002 != 0 {
			v, _, e := readVar()
			if e != nil {
				return fmt.Errorf("dataSize: %w", e)
			}
			dataSize = v
		}
		// Extra area is at END of header. So block specific region excludes trailing extra area.
		blockSpecificEnd := int(headSize)
		if extraAreaSize > 0 {
			if extraAreaSize > uint64(blockSpecificEnd-cur) {
				return fmt.Errorf("extraAreaSize overflow %d > %d", extraAreaSize, blockSpecificEnd-cur)
			}
			blockSpecificEnd -= int(extraAreaSize)
		}
		if debug {
			logDebug("hdr @%d type=%d flags=%#x headSize=%d extra=%d data=%d cur=%d blockSpecificEnd=%d", hdrStart, blockType, flags, headSize, extraAreaSize, dataSize, cur, blockSpecificEnd)
		}
		if blockType == 2 { // File header
			if blockSpecificEnd < cur {
				return fmt.Errorf("blockSpecificEnd<cur")
			}
			bs := headData[cur:blockSpecificEnd]
			bcur := 0
			readFileVar := func() (uint64, int, error) {
				v, n, e := parse.ReadVarintFromSlice(bs[bcur:])
				if e != nil {
					return 0, 0, e
				}
				bcur += int(n)
				return v, int(n), nil
			}
			fileFlags, _, err := readFileVar()
			if err != nil {
				return fmt.Errorf("fileFlags: %w", err)
			}
			unpSizeVal, _, err := readFileVar()
			if err != nil {
				return fmt.Errorf("unpackedSize: %w", err)
			}
			_, _, err = readFileVar()
			if err != nil {
				return fmt.Errorf("fileAttr: %w", err)
			} // Attributes
			if fileFlags&0x0002 != 0 { // mtime
				if len(bs)-bcur < 4 {
					return fmt.Errorf("mtime truncated")
				}
				bcur += 4
			}
			if fileFlags&0x0004 != 0 { // CRC32
				if len(bs)-bcur < 4 {
					return fmt.Errorf("crc32 truncated")
				}
				bcur += 4
			}
			compInfo, _, err := readFileVar()
			if err != nil {
				return fmt.Errorf("compInfo: %w", err)
			}
			_, _, err = readFileVar()
			if err != nil {
				return fmt.Errorf("hostOS: %w", err)
			}
			nameLen, _, err := readFileVar()
			if err != nil {
				return fmt.Errorf("nameLen: %w", err)
			}
			if nameLen == 0 || int(nameLen) > len(bs)-bcur {
				return fmt.Errorf("bad nameLen %d", nameLen)
			}
			nameBytes := bs[bcur : bcur+int(nameLen)]
			bcur += int(nameLen)
			stored := compInfo == 0
			fb := FileBlock{HeaderPos: hdrStart, HeaderSize: 4 + headSizeLen + int64(headSize), DataPos: hdrStart + 4 + headSizeLen + int64(headSize), PackedSize: int64(dataSize), Name: string(nameBytes), UnpackedSize: int64(unpSizeVal), Stored: stored}
			vi.FileBlocks = append(vi.FileBlocks, fb)
			if vi.TotalHeaderBytes == 0 {
				vi.TotalHeaderBytes = fb.DataPos
			}
			if debug {
				logDebug("file name=%s unpacked=%d packed=%d stored=%v", fb.Name, unpSizeVal, dataSize, stored)
			}
		}
		if blockType == 5 { // end of archive
			return nil
		}
		// Skip data
		if dataSize > 0 {
			toSkip := int64(dataSize)
			if seeker != nil {
				// Drain buffered bytes first; they are part of the data section already read ahead.
				if b := br.Buffered(); b > 0 {
					// Never drain more than we intend to skip (safety guard in case of inconsistency).
					if int64(b) > toSkip {
						b = int(toSkip)
					}
					if _, err := br.Discard(b); err != nil {
						return fmt.Errorf("drain buffer before seek: %w", err)
					}
					pos += int64(b)
					toSkip -= int64(b)
				}
				if toSkip > 0 { // only seek remaining
					if _, err := seeker.Seek(toSkip, io.SeekCurrent); err == nil {
						pos += toSkip
						br.Reset(seeker)
						continue
					}
					// If seek fails we fall through to CopyN for remaining bytes.
				}
			}
			if toSkip > 0 { // CopyN remaining (either no seeker or seek failed)
				if _, err := io.CopyN(io.Discard, br, toSkip); err != nil {
					return fmt.Errorf("discard data: %w", err)
				}
				pos += toSkip
			}
		}
	}
}
