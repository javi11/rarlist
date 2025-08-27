package rarlist

import "errors"

// VolumeIndex holds header size accounting for a volume file.
type VolumeIndex struct {
	Path             string
	Version          string
	TotalHeaderBytes int64 // bytes from start of file up to first file payload (for a stored file)
	FileBlocks       []FileBlock
}

// FileBlock represents a file header encountered (RAR3 or RAR5 simplified)
type FileBlock struct {
	Name         string
	HeaderPos    int64 // offset where header starts
	HeaderSize   int64 // full header size
	DataPos      int64 // where the file's data would start within this volume
	PackedSize   int64 // size stored (for stored == original)
	Continued    bool  // continues in next volume
	UnpackedSize int64 // original size (if available)
	Stored       bool  // true if file data is stored (no compression)
	Encrypted    bool  // true if file data is encrypted/password-protected
}

func (v *VolumeIndex) DataOffset() int64 { return v.TotalHeaderBytes }

// Sentinel errors surfaced by high-level APIs like ListFiles/ListFilesFS.
var (
	ErrPasswordProtected      = errors.New("password protected")
	ErrCompressedNotSupported = errors.New("compressed file unsupported")
)
