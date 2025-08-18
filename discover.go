package rarlist

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// DiscoverVolumes attempts to find all parts given the first volume path.
// Supports patterns like name.part01.rar / .part1.rar / .r00 style.
func DiscoverVolumes(first string) ([]string, error) {
	return DiscoverVolumesFS(defaultFS, first)
}

// DiscoverVolumesFS works like DiscoverVolumes but uses provided FileSystem (useful for virtual / in-memory tests).
func DiscoverVolumesFS(fs FileSystem, first string) ([]string, error) {
	base := filepath.Base(first)
	// Patterns we attempt to generalize: partXX.rar, partX.rar, .r00
	partRe := regexp.MustCompile(`(?i)(?P<prefix>.*?)(?P<sep>[_.-]?)(?:part)(?P<num>\d+)(?P<suffix>\.rar)`)
	if m := partRe.FindStringSubmatch(base); m != nil {
		prefix := m[1]
		sep := m[2]
		num := m[3]
		suffix := m[4]
		width := len(num)
		dir := filepath.Dir(first)
		// collect sequential numbers until gap
		var vols []string
		for i := 1; i < 10000; i++ { // arbitrary upper bound
			name := fmt.Sprintf("%s%spart%0*d%s", prefix, sep, width, i, suffix)
			p := filepath.Join(dir, name)
			if _, err := fs.Stat(p); err != nil {
				if i == 1 {
					return nil, fmt.Errorf("first volume not found: %s", p)
				}
				break
			}
			vols = append(vols, p)
		}
		return vols, nil
	}
	// .r00 style starting from .rar
	if strings.HasSuffix(strings.ToLower(base), ".rar") {
		prefix := strings.TrimSuffix(first, filepath.Ext(first))
		dir := filepath.Dir(first)
		var vols []string
		// first main .rar
		if _, err := fs.Stat(first); err == nil {
			vols = append(vols, first)
		} else {
			return nil, err
		}
		for i := 0; i < 1000; i++ {
			name := fmt.Sprintf("%s.r%02d", prefix, i)
			p := filepath.Join(dir, filepath.Base(name))
			if _, err := fs.Stat(p); err != nil {
				break
			}
			vols = append(vols, p)
		}
		return vols, nil
	}
	return []string{first}, nil
}
