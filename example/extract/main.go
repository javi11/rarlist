package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/javi11/rarlist"
)

// This example demonstrates how to reconstruct (concatenate) file contents from a
// multi‑part RAR archive using the structural metadata gathered by AggregateFromFirst.
// IMPORTANT: This only works correctly for files stored (no compression / encryption) in
// the archive, because this code just concatenates raw stored data segments.
// If the archive used compression you would need to invoke an actual RAR decompressor.
func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <first-volume>.part1.rar <output-dir>", os.Args[0])
	}
	first := os.Args[1]
	outDir := os.Args[2]

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	aggregated, err := rarlist.ListFiles(first)
	if err != nil {
		log.Fatalf("aggregate: %v", err)
	}

	for _, af := range aggregated {
		if len(af.Parts) == 0 {
			continue
		}
		// Skip if any part is not stored (simplistic: require all parts stored)
		allStored := true
		var totalUnpacked int64
		for _, p := range af.Parts {
			if !p.Stored {
				allStored = false
				break
			}
			if p.UnpackedSize > 0 {
				totalUnpacked += p.UnpackedSize
			}
		}
		if !allStored {
			fmt.Printf("Skipping %s (not stored / compressed)\n", af.Name)
			continue
		}
		outPath := filepath.Join(outDir, af.Name)

		err := os.MkdirAll(filepath.Dir(outPath), 0o755)
		if err != nil {
			log.Fatalf("create output dir: %v", err)
		}

		// Create (or truncate) output file for this aggregated logical file
		outF, err := os.Create(outPath)
		if err != nil {
			log.Fatalf("create %s: %v", outPath, err)
		}
		// Ensure closure per file (log on close error)
		func() {
			defer func() {
				if cerr := outF.Close(); cerr != nil {
					log.Printf("close %s: %v", outPath, cerr)
				}
			}()
			var written int64
			for idx, part := range af.Parts {
				f, err := os.Open(part.Path)
				if err != nil {
					log.Fatalf("open volume %s: %v", part.Path, err)
				}
				// Close volume file after this part
				func() {
					defer func() { _ = f.Close() }()
					// Seek to the data offset inside this volume
					if _, err := f.Seek(part.DataOffset, io.SeekStart); err != nil {
						log.Fatalf("seek %s: %v", part.Path, err)
					}
					// Copy exactly the packed size bytes (only valid for stored, non‑compressed data)
					copied, err := io.CopyN(outF, f, part.PackedSize)
					if err != nil {
						log.Fatalf("copy part %d of %s from %s: %v", idx, af.Name, part.Path, err)
					}
					written += copied
				}()
			}
			fmt.Printf("Extracted %s (%d bytes written, expected around %d) from %d stored part(s)\n", af.Name, written, totalUnpacked, len(af.Parts))
		}()
	}
}
