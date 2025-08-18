# rarlist

Utility to parse multi‑part RAR (v3 and v5) archives and compute, for every volume, the cumulative header size (so you know the data payload offset) for non‑encrypted & non‑compressed stored files. This is useful to allow random or streaming access directly to file data across volumes.

Status: WIP

Lightweight Go library to parse multi‑part RAR archives (RAR3 and RAR5 + lenient legacy 1.5/2.x fallback) and compute:

* Per‑volume cumulative header size (offset to first stored file data)
* File header metadata (name, packed size, unpacked size, method, data offset)
* Aggregated logical files across multi‑part volumes (concatenation metadata only)

The library does NOT decompress data. It is useful when you need to:

* Quickly list files inside large multi‑part RAR sets without full extraction
* Locate the byte offset where raw (stored / uncompressed) file data begins for direct streaming
* Reconstruct stored (method 0 / 0x30 or compInfo==0) files by concatenating raw data pieces across volumes

Status: experimental / WIP. Parsing is intentionally conservative and incomplete versus official proprietary spec.

## Features

| Feature | RAR3 | RAR5 | Legacy 1.5/2.x |
|---------|------|------|----------------|
| Signature detection (with SFX offset) | ✅ | ✅ | ✅ (via fallback scan) |
| First file data offset | ✅ | ✅ | ✅ |
| Multiple file headers collection | ✅ | ✅ | ✅ (first only in fallback) |
| High 64‑bit size support | partial | ✅ | ✅ |
| Extra area (RAR5) skip | n/a | ✅ | n/a |
| Stored file reconstruction metadata | ✅ | ✅ | ✅ |
| Compressed data handling | ❌ | ❌ | ❌ |
| Encryption handling | ❌ | ❌ | ❌ |
| Recovery / protection blocks | ❌ | ❌ | ❌ |

## Installation

```bash
go get github.com/javi11/rarlist@latest
```

## Quick Start

List logical files (aggregated across volumes):

```go
files, err := rarlist.ListFiles("archive.part01.rar")
if err != nil { /* handle */ }
for _, f := range files {
    fmt.Printf("%s packed=%d unpacked=%d parts=%d stored=%v\n",
        f.Name, f.TotalPackedSize, f.TotalUnpackedSize, len(f.Parts), len(f.Parts) > 0 && f.Parts[0].Stored)
}
```

Obtain per‑volume first data offset:

```go
volPaths, _ := rarlist.DiscoverVolumes("archive.part01.rar")
idx, _ := rarlist.IndexVolumes(rarlist.DefaultFS(), volPaths) // or use rarlist.IndexVolumes if accessor added
for _, v := range idx {
    fmt.Printf("%s headerBytes=%d version=%s\n", v.Path, v.DataOffset(), v.Version)
}
```

(If you need only aggregated logical file listing, `ListFiles` does discovery + indexing internally.)

## Extracting Stored (Uncompressed) Files

See `example/extract` which concatenates raw stored segments:

```bash
go run ./example/extract ./data/myset.part01.rar ./out
```

Limitations:

* Works only for files stored (no compression). Compressed files require real decompression logic.
* No decryption or password support.

## Public API (Summary)

* `DiscoverVolumes(first string) ([]string, error)` – Find all volume paths (.partXX.rar, .r00 style)
* `IndexVolumes(fs FileSystem, []string) ([]*VolumeIndex, error)` – Low level parse per volume
* `ListFiles(first string) ([]AggregatedFile, error)` – One‑shot discovery + aggregation
* `AggregateFiles(vs []*VolumeIndex) []AggregatedFile` – Group multi‑part logical files
* `Offsets(vs []*VolumeIndex) []VolumeData` – Convenience for per‑volume offsets

Key structs:

* `VolumeIndex` – Version, header bytes, file blocks
* `FileBlock` – Individual file header (per volume)
* `AggregatedFile` – Logical file across volumes (with `Parts` slice)

## When To Use

Use this library when you need structural metadata quickly without relying on external `unrar` binaries and you only care about stored file payload offsets.

Do NOT use it when you need:

* Full extraction of compressed or encrypted files
* 100% spec compliance or recovery volumes

## Error Handling & Fallbacks

* RAR5 parser aborts early on suspicious or truncated headers (headSize sanity cap).
* RAR3 parser falls back to a legacy scanner if no file headers were parsed or the primary parsing fails.
* Legacy scan is limited: only first file header (for quick offset discovery) is returned.

## Testing

Synthetic tests build minimal RAR3/RAR5/legacy headers to exercise: discovery patterns, multiple file headers, extra area skipping, error branches (mtime/CRC truncation, varint overflow conditions) and fallback logic.

Run:

```bash
make test
```

Generate coverage:

```bash
make coverage
```

## Performance Notes

* Uses buffered readers and optional seeking to skip data blocks quickly for RAR5.
* Avoids full file reads; stops after first file data offset unless collecting all file headers.

## Roadmap / Possible Enhancements

* Optional decompression integration (external library) for compressed methods
* Streaming reader abstraction for stored multi‑part files
* CLI tool (list / json output)
* More robust Unicode filename decoding for legacy variants

## License

See [LICENSE](LICENSE).

## Disclaimer

RAR is a proprietary format. This project provides a limited, best‑effort structural parser and should not be relied upon for security‑sensitive or archival integrity purposes.
