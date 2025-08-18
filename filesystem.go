package rarlist

import (
	"io/fs"
	"os"
)

// FileSystem abstracts minimal operations needed to discover volumes.
type FileSystem interface {
	Stat(path string) (fs.FileInfo, error)
	Open(path string) (fs.File, error)
}

type osFS struct{}

func (osFS) Stat(p string) (fs.FileInfo, error) { return os.Stat(p) }
func (osFS) Open(p string) (fs.File, error)     { return os.Open(p) }

var defaultFS osFS
