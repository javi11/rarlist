package rarlist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// IndexVolumes parses each volume to compute header sizes. Stops at first error.
func IndexVolumes(fs FileSystem, volPaths []string) ([]*VolumeIndex, error) {
	var res []*VolumeIndex
	for _, p := range volPaths {
		v, err := indexSingle(fs, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		res = append(res, v)
	}
	return res, nil
}

func indexSingle(fs FileSystem, path string) (*VolumeIndex, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, _ := f.Stat()
	fileSize := st.Size()
	br := bufio.NewReader(f)
	version, sigOffset, err := detectSignature(br)
	if err != nil {
		return nil, err
	}
	if s, ok := f.(io.Seeker); ok {
		if _, err := s.Seek(sigOffset, io.SeekStart); err != nil {
			return nil, err
		}
	} else {
		// If we cannot seek, we need to reset the reader to the start
		if _, err := br.Discard(int(sigOffset)); err != nil {
			return nil, fmt.Errorf("failed to seek to signature offset %d in %s: %w", sigOffset, path, err)
		}
	}
	br.Reset(f)
	vi := &VolumeIndex{Path: path, Version: version}
	switch version {
	case VersionRar3:
		if err := parseRar3(br, vi, sigOffset); err != nil {
			// fallback attempt for legacy (RAR 1.5/2.x) layout
			if err2 := parseRarLegacy(fs, path, vi, sigOffset); err2 == nil && len(vi.FileBlocks) > 0 {
				return vi, nil
			}
			return nil, err
		}
		if len(vi.FileBlocks) == 0 { // try legacy if no file headers parsed
			if err := parseRarLegacy(fs, path, vi, sigOffset); err != nil && len(vi.FileBlocks) == 0 {
				return nil, err
			}
		}
	case VersionRar5:
		// Attempt to provide seeker for optimized skipping
		var seeker io.ReadSeeker
		if rs, ok := f.(io.ReadSeeker); ok {
			seeker = rs
		}
		if err := parseRar5(br, seeker, vi, sigOffset, fileSize); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported/unknown version")
	}
	return vi, nil
}

func detectSignature(br *bufio.Reader) (string, int64, error) {
	buf, _ := br.Peek(1024)
	// search
	for i := 0; i+7 < len(buf); i++ {
		if i+len(rarrSigV5) <= len(buf) && string(buf[i:i+len(rarrSigV5)]) == string(rarrSigV5) {
			return VersionRar5, int64(i), nil
		}
		if i+len(rarrSigV3) <= len(buf) && string(buf[i:i+len(rarrSigV3)]) == string(rarrSigV3) {
			return VersionRar3, int64(i), nil
		}
	}
	return VersionUnknown, 0, errors.New("RAR signature not found in first 1KB")
}
