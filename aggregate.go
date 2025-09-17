package rarlist

import "fmt"

// FileEntry summarizes a file within a volume.
type FileEntry struct {
	Name       string
	DataOffset int64
	PackedSize int64
}

// VolumeFiles lists all file entries for a volume.
type VolumeFiles struct {
	Path  string
	Files []FileEntry
}

// BuildVolumeFiles constructs per-volume file listings.
func BuildVolumeFiles(vs []*VolumeIndex) []VolumeFiles {
	out := make([]VolumeFiles, 0, len(vs))
	for _, v := range vs {
		vf := VolumeFiles{Path: v.Path}
		for _, fb := range v.FileBlocks {
			vf.Files = append(vf.Files, FileEntry{Name: fb.Name, DataOffset: fb.DataPos, PackedSize: fb.VolumeDataSize})
		}
		out = append(out, vf)
	}
	return out
}

// VolumeData summarizes per volume offset and first file name (if parsed).
type VolumeData struct {
	Path       string
	DataOffset int64
	FileName   string
}

// Offsets builds a slice of VolumeData from VolumeIndex slice.
func Offsets(vs []*VolumeIndex) []VolumeData {
	out := make([]VolumeData, 0, len(vs))
	lastName := ""
	for _, v := range vs {
		if len(v.FileBlocks) > 0 && v.FileBlocks[0].Name != "" {
			lastName = v.FileBlocks[0].Name
		}
		out = append(out, VolumeData{Path: v.Path, DataOffset: v.DataOffset(), FileName: lastName})
	}
	return out
}

// AggregatedFilePart represents one part of a (possibly split) file residing in a volume.
type AggregatedFilePart struct {
	Path         string `json:"path"`
	DataOffset   int64  `json:"dataOffset"`
	PackedSize   int64  `json:"packedSize"`
	UnpackedSize int64  `json:"unpackedSize"`
	Stored       bool   `json:"stored"`
	Encrypted    bool   `json:"encrypted"`
}

// AggregatedFile groups all parts (headers) for a given file name across volumes.
type AggregatedFile struct {
	Name              string               `json:"name"`
	TotalPackedSize   int64                `json:"totalPackedSize"`
	TotalUnpackedSize int64                `json:"totalUnpackedSize"`
	Parts             []AggregatedFilePart `json:"parts"`
	AnyEncrypted      bool                 `json:"anyEncrypted"`
	AllStored         bool                 `json:"allStored"`
}

// AggregateFiles builds aggregated file listing from volume indexes.
func AggregateFiles(vs []*VolumeIndex) []AggregatedFile {
	m := make(map[string]*AggregatedFile)
	order := []string{}
	for _, v := range vs {
		for _, fb := range v.FileBlocks {
			if fb.Name == "" {
				continue
			}
			ag, ok := m[fb.Name]
			if !ok {
				ag = &AggregatedFile{Name: fb.Name, AllStored: true}
				m[fb.Name] = ag
				order = append(order, fb.Name)
			}
			ag.Parts = append(ag.Parts, AggregatedFilePart{Path: v.Path, DataOffset: fb.DataPos, PackedSize: fb.VolumeDataSize, UnpackedSize: fb.UnpackedSize, Stored: fb.Stored, Encrypted: fb.Encrypted})
			ag.TotalPackedSize += fb.VolumeDataSize
			// Only take first reported unpacked size (do not sum across parts)
			if ag.TotalUnpackedSize == 0 && fb.UnpackedSize > 0 {
				ag.TotalUnpackedSize = fb.UnpackedSize
			}
			if fb.Encrypted {
				ag.AnyEncrypted = true
			}
			if !fb.Stored {
				ag.AllStored = false
			}
		}
	}
	out := make([]AggregatedFile, 0, len(order))
	for _, name := range order {
		out = append(out, *m[name])
	}
	return out
}

// ListFiles lists all files in the RAR archive starting from the specified volume.
func ListFilesFS(fs FileSystem, first string) ([]AggregatedFile, error) {
	vols, err := DiscoverVolumesFS(fs, first)
	if err != nil {
		return nil, err
	}
	idx, err := IndexVolumesParallel(fs, vols, 0)
	if err != nil {
		return nil, err
	}
	// Validate that files are not compressed or password protected
	for _, v := range idx {
		for _, fb := range v.FileBlocks {
			if fb.Encrypted {
				return nil, fmt.Errorf("%w: %s (%s)", ErrPasswordProtected, fb.Name, v.Path)
			}
			if !fb.Stored {
				return nil, fmt.Errorf("%w: %s (%s)", ErrCompressedNotSupported, fb.Name, v.Path)
			}
		}
	}
	return AggregateFiles(idx), nil
}

// ListFiles is a convenience using the default filesystem.
func ListFiles(first string) ([]AggregatedFile, error) { return ListFilesFS(defaultFS, first) }
