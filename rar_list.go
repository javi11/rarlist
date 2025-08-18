package rarlist

// Package rarlist provides lightweight parsing utilities to discover RAR (v3 / v5 and
// some legacy 1.5/2.x) archive volume structures and compute offsets to the first
// file data (header region size). The implementation has been refactored into
// multiple focused source files:
//   version.go     - version constants & signatures
//   filesystem.go  - FileSystem abstraction
//   discover.go    - volume discovery helpers
//   types.go       - core data structures
//   index.go       - high level indexing logic & signature detection
//   rar3.go        - simplified RAR3 block parsing
//   rar5.go        - simplified RAR5 block parsing
//   legacy.go      - lenient legacy (pre-RAR3) scanning fallback
//   aggregate.go   - aggregation / listing helpers
//
// Public API (unchanged):
//   DiscoverVolumes / DiscoverVolumesFS
//   IndexVolumes
//   ListFiles / ListFilesFS
//   AggregateFiles, Offsets, BuildVolumeFiles
//
// See individual files for implementation details.
