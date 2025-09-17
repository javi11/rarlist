package rarlist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
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

// IndexVolumesParallel indexes volumes concurrently. Results preserve input order.
// workers<=0 uses runtime.NumCPU(). Stops scheduling new work after first error, but in-flight tasks may finish.
func IndexVolumesParallel(fs FileSystem, volPaths []string, workers int) ([]*VolumeIndex, error) {
	if len(volPaths) == 0 {
		return nil, nil
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	res := make([]*VolumeIndex, len(volPaths))
	var firstErr atomic.Value // stores error
	jobs := make(chan int)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for i := range jobs {
			if firstErr.Load() != nil { // skip work after error recorded
				continue
			}
			v, err := indexSingle(fs, volPaths[i])
			if err != nil {
				// record first error
				if firstErr.Load() == nil {
					firstErr.Store(fmt.Errorf("%s: %w", volPaths[i], err))
				}
				continue
			}
			res[i] = v
		}
	}
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go worker()
	}
	for i := range volPaths {
		if firstErr.Load() != nil { // stop scheduling new work
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if e := firstErr.Load(); e != nil {
		return nil, e.(error)
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
		if _, err := br.Discard(int(sigOffset)); err != nil {
			return nil, fmt.Errorf("failed to seek to signature offset %d in %s: %w", sigOffset, path, err)
		}
	}
	br.Reset(f)
	vi := &VolumeIndex{Path: path, Version: version}
	switch version {
	case VersionRar3:
		var seeker io.ReadSeeker
		if rs, ok := f.(io.ReadSeeker); ok {
			seeker = rs
		}
		if err := parseRar3(br, seeker, vi, sigOffset, fileSize); err != nil {
			// If headers are encrypted/password-protected, don't attempt legacy fallback; bubble up immediately.
			if errors.Is(err, ErrPasswordProtected) {
				return nil, err
			}
			// fallback attempt for legacy (RAR 1.5/2.x) layout using existing handle
			if rs, ok := f.(io.ReadSeeker); ok {
				if err2 := parseRarLegacySeeker(rs, vi, sigOffset); err2 == nil && len(vi.FileBlocks) > 0 {
					return vi, nil
				}
			} else if err2 := parseRarLegacy(fs, path, vi, sigOffset); err2 == nil && len(vi.FileBlocks) > 0 {
				return vi, nil
			}
			return nil, err
		}

		if len(vi.FileBlocks) == 0 { // try legacy if no file headers parsed
			if rs, ok := f.(io.ReadSeeker); ok {
				if err := parseRarLegacySeeker(rs, vi, sigOffset); err != nil && len(vi.FileBlocks) == 0 {
					return nil, err
				}
			} else if err := parseRarLegacy(fs, path, vi, sigOffset); err != nil && len(vi.FileBlocks) == 0 {
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
